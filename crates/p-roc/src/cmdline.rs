//! The kernel command line.

use crate::cpuset::CpuSet;
use crate::error::Error;
use crate::root::{Root, read};

/// The tokens of a command line, in order. Quotes are honoured the way the
/// kernel does: whitespace inside double quotes does not split.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Cmdline {
    tokens: Vec<String>,
}

impl Cmdline {
    /// Splits a command line into tokens.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        let mut tokens = Vec::new();
        let mut cur = String::new();
        let mut quoted = false;
        for c in s.trim().chars() {
            match c {
                '"' => quoted = !quoted,
                c if c.is_whitespace() && !quoted => {
                    if !cur.is_empty() {
                        tokens.push(std::mem::take(&mut cur));
                    }
                }
                c => cur.push(c),
            }
        }
        if !cur.is_empty() {
            tokens.push(cur);
        }
        Self { tokens }
    }

    /// Reads `/proc/cmdline`.
    ///
    /// # Errors
    /// When the file cannot be read.
    pub fn read(root: &Root) -> Result<Self, Error> {
        Ok(Self::parse(&read(&root.proc.join("cmdline"))?))
    }

    /// The tokens as written.
    #[must_use]
    pub fn tokens(&self) -> &[String] {
        &self.tokens
    }

    /// The value of `key`: `Some(Some(v))` for `key=v`, `Some(None)` for a
    /// bare `key`, `None` when absent. The last occurrence wins, as in the kernel.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<Option<&str>> {
        self.tokens.iter().rev().find_map(|t| match t.split_once('=') {
            Some((k, v)) if k == key => Some(Some(v)),
            None if t == key => Some(None),
            _ => None,
        })
    }

    /// The CPU list of a key such as `isolcpus`, `nohz_full`, `rcu_nocbs`,
    /// `irqaffinity`. Flag tokens (`managed_irq`, `domain`, `nohz`) are
    /// skipped. `None` when the key is absent; an unparsable list is an error.
    ///
    /// # Errors
    /// When the list is malformed.
    pub fn cpu_list(&self, key: &str) -> Result<Option<CpuSet>, Error> {
        let Some(Some(v)) = self.get(key) else { return Ok(None) };
        let list = v.split(',').filter(|p| !p.is_empty() && !p.starts_with(|c: char| c.is_ascii_alphabetic()));
        let list: Vec<&str> = list.collect();
        CpuSet::parse_list(&list.join(","))
            .map(Some)
            .map_err(|source| Error::Cpus { what: format!("cmdline: {key}"), source })
    }
}

/// Whether `key` is one that matters to a realtime host: CPU isolation, tick
/// and RCU offload, IRQ placement, C- and P-states, timers, mitigations,
/// watchdogs, huge pages, the console.
#[must_use]
pub fn is_rt_key(key: &str) -> bool {
    const KEYS: [&str; 16] = [
        "isolcpus",
        "nohz_full",
        "rcu_nocbs",
        "rcu_nocb_poll",
        "irqaffinity",
        "kthread_cpus",
        "threadirqs",
        "skew_tick",
        "tsc",
        "nosmt",
        "idle",
        "mitigations",
        "nmi_watchdog",
        "hugepages",
        "transparent_hugepage",
        "console",
    ];
    KEYS.contains(&key) || key.ends_with(".max_cstate") || key.ends_with("_pstate")
}

impl Cmdline {
    /// The realtime-relevant keys present, in command line order, last
    /// occurrence of each; the value is `None` for a bare key.
    #[must_use]
    pub fn rt_keys(&self) -> Vec<(&str, Option<&str>)> {
        let mut out: Vec<(&str, Option<&str>)> = Vec::new();
        for t in &self.tokens {
            let (k, v) = t.split_once('=').map_or((t.as_str(), None), |(k, v)| (k, Some(v)));
            if !is_rt_key(k) {
                continue;
            }
            match out.iter_mut().find(|(x, _)| *x == k) {
                Some(slot) => slot.1 = v,
                None => out.push((k, v)),
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_values_and_flags() {
        let c = Cmdline::parse("BOOT_IMAGE=/vmlinuz root=\"/dev/x y\" ro isolcpus=managed_irq,domain,2-3 nohz_full=2-3 quiet isolcpus=4");
        assert_eq!(c.tokens().len(), 7);
        assert_eq!(c.get("root"), Some(Some("/dev/x y")));
        assert_eq!(c.get("quiet"), Some(None));
        assert_eq!(c.get("rcu_nocbs"), None);
        assert_eq!(c.cpu_list("nohz_full").unwrap().unwrap().to_string(), "2-3");
        assert_eq!(c.cpu_list("isolcpus").unwrap().unwrap().to_string(), "4"); // last wins
        assert!(Cmdline::parse("isolcpus=2-").cpu_list("isolcpus").is_err());
        let c = Cmdline::parse("quiet intel_pstate=disable processor.max_cstate=1 tsc=reliable tsc=nowatchdog threadirqs");
        assert_eq!(
            c.rt_keys(),
            [("intel_pstate", Some("disable")), ("processor.max_cstate", Some("1")), ("tsc", Some("nowatchdog")), ("threadirqs", None)]
        );
    }
}
