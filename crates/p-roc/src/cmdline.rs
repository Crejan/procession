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
    }
}
