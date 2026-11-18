//! `cmdline`: the live command line against the declared one, the kernel flavour, the sysctls.

use std::collections::BTreeMap;
use std::path::PathBuf;

use p_roc::cmdline::Cmdline;
use p_roc::{CpuSet, Unreadable};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::env::Env;
use crate::error::Error;
use crate::observe::{self, finish};
use crate::report::{Cost, Finding, Metric, Report, Severity, Subject};

/// Sysctls reported as they stand.
const SYSCTLS: [&str; 11] = [
    "kernel/nmi_watchdog",
    "kernel/soft_watchdog",
    "kernel/watchdog",
    "kernel/watchdog_cpumask",
    "kernel/hung_task_timeout_secs",
    "kernel/sched_rt_runtime_us",
    "kernel/timer_migration",
    "vm/stat_interval",
    "kernel/perf_event_paranoid",
    "net/core/busy_poll",
    "net/core/busy_read",
];

/// One `GRUB_CMDLINE_LINUX*` assignment, after substitution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Assignment {
    /// The file it came from.
    pub file: String,
    /// `GRUB_CMDLINE_LINUX` or `GRUB_CMDLINE_LINUX_DEFAULT`.
    pub key: String,
    /// The value after `$GRUB_CMDLINE_LINUX*` substitution.
    pub value: String,
}

/// Where the declared command line came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// `declared_cmdline` in the config.
    Config,
    /// A replay of the bootloader config.
    Grub,
    /// Nothing declares one.
    None,
}

/// What the host says its command line should be.
#[derive(Clone, Debug)]
pub struct Declared {
    /// Where it came from.
    pub source: Source,
    /// The files read.
    pub files: Vec<PathBuf>,
    /// Every assignment seen, in order (for a reader to follow the replay).
    pub assignments: Vec<Assignment>,
    /// The resulting command line; `None` when nothing declares one.
    pub cmdline: Option<Cmdline>,
}

const KEYS: [&str; 2] = ["GRUB_CMDLINE_LINUX_DEFAULT", "GRUB_CMDLINE_LINUX"];

/// Parses `GRUB_CMDLINE_LINUX="..."`; `None` for any other line.
fn assignment(line: &str) -> Option<(&'static str, String)> {
    let line = line.trim_start();
    let key = KEYS.iter().find(|k| line.strip_prefix(**k).is_some_and(|r| r.trim_start().starts_with('=')))?;
    let value = line[key.len()..].trim_start().strip_prefix('=')?.trim();
    let value = ["\"", "'"].iter().find_map(|q| value.strip_prefix(q)?.strip_suffix(q)).unwrap_or(value);
    Some((key, value.to_string()))
}

/// Replays `/etc/default/grub` and `/etc/default/grub.d/*.cfg` in the order
/// `grub-mkconfig` sources them, with `$GRUB_CMDLINE_LINUX*` and
/// `${GRUB_CMDLINE_LINUX*}` substituted; the command line is
/// `GRUB_CMDLINE_LINUX` then `GRUB_CMDLINE_LINUX_DEFAULT`, as grub builds it.
#[must_use]
pub fn replay_grub(etc: &std::path::Path) -> Declared {
    // Shown as the path on a real host, whatever root it was read from.
    let shown = |f: &std::path::Path| PathBuf::from("/etc").join(f.strip_prefix(etc).unwrap_or(f));
    let mut files = vec![etc.join("default/grub")];
    if let Ok(rd) = std::fs::read_dir(etc.join("default/grub.d")) {
        let mut cfg: Vec<PathBuf> =
            rd.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "cfg")).collect();
        cfg.sort();
        files.extend(cfg);
    }
    let mut vars: BTreeMap<&str, String> = KEYS.iter().map(|k| (*k, String::new())).collect();
    let (mut assignments, mut read_files) = (Vec::new(), Vec::new());
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else { continue };
        read_files.push(shown(&f));
        for line in text.lines() {
            let Some((key, mut value)) = assignment(line) else { continue };
            // Longest name first: $GRUB_CMDLINE_LINUX is a prefix of $GRUB_CMDLINE_LINUX_DEFAULT.
            for k in KEYS {
                value = value.replace(&format!("${{{k}}}"), &vars[k]).replace(&format!("${k}"), &vars[k]);
            }
            let value = value.split_whitespace().collect::<Vec<_>>().join(" ");
            vars.insert(key, value.clone());
            assignments.push(Assignment { file: shown(&f).display().to_string(), key: key.to_string(), value });
        }
    }
    let cmdline = (!assignments.is_empty())
        .then(|| Cmdline::parse(&format!("{} {}", vars["GRUB_CMDLINE_LINUX"], vars["GRUB_CMDLINE_LINUX_DEFAULT"])));
    Declared {
        source: if cmdline.is_some() { Source::Grub } else { Source::None },
        files: read_files,
        assignments,
        cmdline,
    }
}

/// The declared command line: the config's `declared_cmdline`, else the bootloader replay.
#[must_use]
pub fn declared(env: &Env) -> Declared {
    match &env.config.declared_cmdline {
        Some(c) => Declared {
            source: Source::Config,
            files: Vec::new(),
            assignments: Vec::new(),
            cmdline: Some(Cmdline::parse(c)),
        },
        None => replay_grub(&env.etc),
    }
}

/// The isolated set a command line declares: `isolcpus` ∪ `nohz_full`.
///
/// # Errors
/// When one of the lists is malformed.
pub fn declared_isolation(c: &Cmdline) -> Result<CpuSet, p_roc::Error> {
    Ok(c.cpu_list("isolcpus")?.unwrap_or_default().union(&c.cpu_list("nohz_full")?.unwrap_or_default()))
}

fn ignored(token: &str) -> bool {
    token.starts_with("BOOT_IMAGE=") || token.starts_with("root=") || token == "ro"
}

fn rt_map(c: &Cmdline) -> Map<String, Value> {
    c.rt_keys()
        .into_iter()
        .map(|(k, v)| (k.to_string(), v.map_or(Value::Bool(true), |v| Value::String(v.into()))))
        .collect()
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record {
    GrubAssignment(Assignment),
    Live {
        cmdline: String,
        rt: Map<String, Value>,
    },
    Declared {
        source: Source,
        files: Vec<String>,
        cmdline: Option<String>,
        rt: Map<String, Value>,
    },
    Diff {
        declared_not_live: Vec<String>,
        live_not_declared: Vec<String>,
        rt_value_differs: Vec<String>,
        in_sync: Option<bool>,
        isolated_live: CpuSet,
        isolated_declared: Option<CpuSet>,
    },
    Kernel {
        release: Option<String>,
        version: Option<String>,
        preempt_rt: bool,
    },
    Sysctl {
        values: BTreeMap<String, Option<String>>,
    },
}

/// Runs `cmdline`.
///
/// # Errors
/// When `/proc/cmdline` cannot be read.
pub fn run(env: &Env) -> Result<Report, Error> {
    let mut report = Report::new(env, "cmdline", Cost::Light);
    let cpus = observe::cpus(env, &mut report);
    let live = Cmdline::read(&env.root)?;
    let declared = declared(env);

    for a in &declared.assignments {
        report.push(&Record::GrubAssignment(a.clone()));
    }
    report.push(&Record::Live { cmdline: live.tokens().join(" "), rt: rt_map(&live) });
    report.push(&Record::Declared {
        source: declared.source,
        files: declared.files.iter().map(|f| f.display().to_string()).collect(),
        cmdline: declared.cmdline.as_ref().map(|c| c.tokens().join(" ")),
        rt: declared.cmdline.as_ref().map(rt_map).unwrap_or_default(),
    });

    let mut missing = Vec::new();
    let mut extra = Vec::new();
    let mut differs = Vec::new();
    let mut declared_iso = None;
    if let Some(want) = &declared.cmdline {
        let has = |c: &Cmdline, t: &String| c.tokens().contains(t);
        missing = want.tokens().iter().filter(|t| !ignored(t) && !has(&live, t)).cloned().collect();
        extra = live.tokens().iter().filter(|t| !ignored(t) && !has(want, t)).cloned().collect();
        let live_rt: BTreeMap<_, _> = live.rt_keys().into_iter().collect();
        differs = want
            .rt_keys()
            .into_iter()
            .filter(|(k, v)| live_rt.get(k).is_some_and(|lv| lv != v))
            .map(|(k, _)| k.to_string())
            .collect();
        match declared_isolation(want) {
            Ok(s) => declared_iso = Some(s),
            Err(e) => report.unreadable([Unreadable::new("declared cmdline: isolation", &e)]),
        }
    }
    let in_sync = declared.cmdline.as_ref().map(|_| missing.is_empty() && differs.is_empty());
    report.push(&Record::Diff {
        declared_not_live: missing.clone(),
        live_not_declared: extra,
        rt_value_differs: differs.clone(),
        in_sync,
        isolated_live: cpus.isolated.clone(),
        isolated_declared: declared_iso.clone(),
    });
    if in_sync == Some(false) {
        report.findings.push(Finding {
            id: "cmdline-drift",
            severity: Severity::Warn,
            subject: Subject::Host,
            evidence: vec![Metric::new("declared_not_live", &missing), Metric::new("rt_value_differs", &differs)],
            recommendation: "the live command line differs from the declared one; after a bootloader change the host needs a reboot, and isolcpus and nohz_full only apply at boot".into(),
            changes: Vec::new(),
        });
    }
    if let Some(d) = declared_iso.filter(|d| *d != cpus.isolated) {
        report.findings.push(Finding {
            id: "isolation-drift",
            severity: Severity::Warn,
            subject: Subject::Host,
            evidence: vec![Metric::new("live_isolated", &cpus.isolated), Metric::new("declared_isolated", &d)],
            recommendation: "the live isolated set differs from the declared one; probes refuse until they agree"
                .into(),
            changes: Vec::new(),
        });
    }

    let read = |p: &str| std::fs::read_to_string(env.root.proc.join(p)).ok().map(|s| s.trim().to_string());
    let version = read("sys/kernel/version");
    let realtime = std::fs::read_to_string(env.root.sys.join("kernel/realtime")).is_ok_and(|s| s.trim() == "1");
    report.push(&Record::Kernel {
        release: read("sys/kernel/osrelease"),
        preempt_rt: realtime || version.as_deref().is_some_and(|v| v.contains("PREEMPT_RT")),
        version,
    });
    report.push(&Record::Sysctl {
        values: SYSCTLS.iter().map(|n| ((*n).replace('/', "."), read(&format!("sys/{n}")))).collect(),
    });
    finish(env, &mut report);
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assignments() {
        assert_eq!(assignment("GRUB_CMDLINE_LINUX=\"a b\""), Some(("GRUB_CMDLINE_LINUX", "a b".into())));
        assert_eq!(
            assignment("  GRUB_CMDLINE_LINUX_DEFAULT = 'quiet'"),
            Some(("GRUB_CMDLINE_LINUX_DEFAULT", "quiet".into()))
        );
        assert_eq!(assignment("GRUB_CMDLINE_LINUX=quiet"), Some(("GRUB_CMDLINE_LINUX", "quiet".into())));
        assert_eq!(assignment("# GRUB_CMDLINE_LINUX=\"x\""), None);
        assert_eq!(assignment("GRUB_CMDLINE_LINUXX=\"x\""), None);
    }
}
