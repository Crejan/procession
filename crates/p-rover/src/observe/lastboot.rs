//! `lastboot`: the previous boot's kernel log, for a freeze post-mortem.

use std::collections::BTreeMap;
use std::time::Duration;

use p_roc::Unreadable;
use p_roc::cmdline::Cmdline;
use serde::Serialize;

use crate::env::Env;
use crate::error::Error;
use crate::observe::finish;
use crate::report::{Cost, Finding, Metric, Report, Severity, Subject};
use crate::runner::Output;

/// What `journalctl --grep` filters the kernel log for.
pub const PATTERN: &str =
    "rcu|watchdog|stall|hung|blocked for more|oom|lockup|panic|BUG:|Oops|NMI|Call Trace|thermal|throttl";
/// Matching lines kept.
pub const LOG_LINES: usize = 120;
/// Last lines of the boot kept, to see how it ended.
pub const TAIL_LINES: usize = 40;
const JOURNAL_TIMEOUT: Duration = Duration::from_secs(90);

/// Arguments of `lastboot`.
#[derive(Clone, Debug)]
pub struct Args {
    /// The boot offset: `-1` the previous boot, `0` the current one.
    pub boot: String,
}

impl Default for Args {
    fn default() -> Self {
        Self { boot: "-1".into() }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record {
    Boots {
        known: usize,
        last: Vec<String>,
    },
    Detectors {
        values: BTreeMap<String, Option<String>>,
        nosoftlockup_on_cmdline: bool,
        nmi_watchdog_cmdline: Option<String>,
    },
    KernelLog {
        source: String,
        lines: Vec<String>,
    },
    Signature {
        categories: BTreeMap<&'static str, usize>,
    },
    BootTail {
        source: String,
        lines: Vec<String>,
        ends_in_orderly_shutdown: bool,
    },
}

/// The category of a kernel log line that matters to a freeze, if any.
fn category(line: &str) -> Option<&'static str> {
    let l = line.to_ascii_lowercase();
    let any = |ks: &[&str]| ks.iter().any(|k| l.contains(k));
    if any(&["stall"]) {
        Some("stall")
    } else if any(&["blocked for more than", "hung_task", "hung task"]) {
        Some("hung")
    } else if any(&["lockup"]) {
        Some("lockup")
    } else if any(&["kernel panic"]) {
        Some("panic")
    } else if any(&["bug:", "oops"]) {
        Some("bug")
    } else if l.contains("watchdog") && any(&["bug", "timeout", "not responding", "detected"]) {
        Some("watchdog")
    } else if any(&["out of memory", "oom-kill", "oom_reaper"]) {
        Some("oom")
    } else if any(&["thermal", "throttl"]) {
        Some("thermal")
    } else {
        None
    }
}

/// Categories that are a freeze signature by themselves.
const HARD: [&str; 5] = ["stall", "hung", "lockup", "panic", "bug"];

fn orderly(tail: &[String]) -> bool {
    tail.iter().any(|l| {
        (l.contains("Reached target") && (l.contains("Shutdown") || l.contains("Reboot") || l.contains("Power-Off")))
            || l.contains("systemd-shutdown")
    })
}

fn lines(o: &Output) -> Vec<String> {
    // journalctl banners (`-- No entries --`, `-- Logs begin at ...`) are not log lines.
    o.stdout.lines().filter(|l| !l.starts_with("-- ")).map(str::to_string).collect()
}

/// Runs `lastboot`.
///
/// # Errors
/// When the boot offset is not a number.
pub fn run(env: &Env, args: &Args) -> Result<Report, Error> {
    let boot = args.boot.as_str();
    let digits = boot.strip_prefix('-').unwrap_or(boot);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::Refused(format!("--boot {boot:?} is not a boot offset such as -1")));
    }
    let mut report = Report::new(env, "lastboot", Cost::Light);
    let journal = |report: &mut Report, what: &str, a: &[&str]| match env.runner.run("journalctl", a, JOURNAL_TIMEOUT) {
        Ok(o) if o.code == Some(0) || (o.code == Some(1) && o.stderr.trim().is_empty()) => Some(o),
        Ok(o) => {
            report
                .unreadable([Unreadable { source: format!("journalctl {what}"), reason: o.stderr.trim().to_string() }]);
            None
        }
        Err(e) => {
            report.unreadable([Unreadable::new("journalctl", &e)]);
            None
        }
    };

    if let Some(o) = journal(&mut report, "--list-boots", &["--list-boots", "--no-pager"]) {
        let all: Vec<String> = o.stdout.lines().filter(|l| !l.trim().is_empty()).map(str::to_string).collect();
        report.push(&Record::Boots { known: all.len(), last: all[all.len().saturating_sub(4)..].to_vec() });
    }

    let sysctl = |n: &str| {
        p_roc::text::read_to_string(env.root.proc.join("sys/kernel").join(n)).ok().map(|s| s.trim().to_string())
    };
    let cmd = Cmdline::read(&env.root).unwrap_or_default();
    report.push(&Record::Detectors {
        values: ["nmi_watchdog", "soft_watchdog", "watchdog", "hung_task_timeout_secs", "panic"]
            .iter()
            .map(|n| ((*n).to_string(), sysctl(n)))
            .collect(),
        nosoftlockup_on_cmdline: cmd.get("nosoftlockup").is_some(),
        nmi_watchdog_cmdline: cmd.get("nmi_watchdog").map(|v| format!("nmi_watchdog={}", v.unwrap_or_default())),
    });

    let n = LOG_LINES.to_string();
    let kernel = journal(
        &mut report,
        "-k --grep",
        &["-b", boot, "-k", "--no-pager", "-o", "short-iso", "--grep", PATTERN, "-n", &n],
    );
    let mut categories: BTreeMap<&'static str, usize> = BTreeMap::new();
    if let Some(o) = kernel {
        let l = lines(&o);
        for c in l.iter().filter_map(|x| category(x)) {
            *categories.entry(c).or_default() += 1;
        }
        report.push(&Record::KernelLog { source: format!("journalctl -b {boot} -k --grep"), lines: l });
        report.push(&Record::Signature { categories: categories.clone() });
    }

    let t = TAIL_LINES.to_string();
    let tail = journal(&mut report, "-n", &["-b", boot, "--no-pager", "-o", "short-iso", "-n", &t]);
    let mut clean = None;
    if let Some(o) = tail {
        let l = lines(&o);
        if l.is_empty() {
            report.unreadable([Unreadable {
                source: format!("journalctl -b {boot}"),
                reason: "no entries for that boot".into(),
            }]);
        } else {
            clean = Some(orderly(&l));
            report.push(&Record::BootTail {
                source: format!("journalctl -b {boot} -n {TAIL_LINES}"),
                ends_in_orderly_shutdown: orderly(&l),
                lines: l,
            });
        }
    }

    let hard: Vec<_> = categories.iter().filter(|(k, _)| HARD.contains(*k)).collect();
    if !categories.is_empty() && (!hard.is_empty() || categories.contains_key("watchdog")) {
        report.findings.push(Finding {
            id: "freeze-signature",
            severity: if hard.is_empty() { Severity::Warn } else { Severity::Crit },
            subject: Subject::Host,
            evidence: categories.iter().map(|(k, v)| Metric::new(k, v)).collect(),
            recommendation: "the previous boot's kernel log holds stall, hung-task or watchdog lines; read them in kernel_log, newest last".into(),
            changes: Vec::new(),
        });
    }
    if clean == Some(false) {
        report.findings.push(Finding {
            id: "unclean-shutdown",
            severity: Severity::Warn,
            subject: Subject::Host,
            evidence: vec![Metric::new("boot", boot)],
            recommendation: "the previous boot's log does not end in an orderly shutdown; with the watchdogs tuned off a hard freeze can leave no stall report, so a missing signature is not proof of a clean stop".into(),
            changes: Vec::new(),
        });
    }
    finish(env, &mut report);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categories() {
        assert_eq!(category("kernel: rcu: INFO: rcu_sched self-detected stall on CPU"), Some("stall"));
        assert_eq!(category("kernel: INFO: task foo:12 blocked for more than 120 seconds."), Some("hung"));
        assert_eq!(category("kernel: watchdog: BUG: soft lockup - CPU#3 stuck for 22s!"), Some("lockup"));
        assert_eq!(category("kernel: watchdog: Enabled. Permanently consumes one hw-PMU counter."), None);
        assert_eq!(category("kernel: Out of memory: Killed process 1"), Some("oom"));
        assert_eq!(category("kernel: usb 1-1: new device"), None);
    }
}
