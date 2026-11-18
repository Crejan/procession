//! `procs`: RT threads, and every thread currently on an isolated CPU.

use p_roc::change::Change;
use p_roc::{CpuSet, task};
use serde::Serialize;

use crate::env::Env;
use crate::error::Error;
use crate::observe::{self, finish};
use crate::report::{Cost, Finding, Metric, Report, Severity, Subject};

/// Findings kept at most (one per RT thread on a housekeeping CPU); the summary says when more were found.
pub const FINDINGS_CAP: usize = 100;
/// Records at most this many threads unless `--max` says otherwise.
pub const DEFAULT_MAX: usize = 80;

/// Arguments of `procs`.
#[derive(Clone, Debug)]
pub struct Args {
    /// Cap on the thread records; the summary says how many there were.
    pub max: usize,
}

impl Default for Args {
    fn default() -> Self {
        Self { max: DEFAULT_MAX }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record {
    Thread {
        pid: i32,
        tid: i32,
        comm: String,
        uid: u32,
        kthread: bool,
        policy: String,
        rtprio: Option<u32>,
        cpu: u32,
        state: String,
        cpus_allowed: CpuSet,
        on_isolated: bool,
        rt: bool,
    },
    Summary {
        isolated_cpus: CpuSet,
        housekeeping_cpus: CpuSet,
        rt_threads: usize,
        threads_on_isolated: usize,
        shown: usize,
        truncated: bool,
    },
}

/// Runs `procs`.
///
/// # Errors
/// When the process list cannot be read.
pub fn run(env: &Env, args: &Args) -> Result<Report, Error> {
    let mut report = Report::new(env, "procs", Cost::Light);
    let cpus = observe::cpus(env, &mut report);
    let scan = task::scan(&env.root, |s| s.policy.is_rt() || cpus.isolated.contains(s.processor))?;
    report.unreadable(scan.unreadable);

    let mut tasks = scan.items;
    // RT threads first, then by thread id, so a cap keeps what matters.
    tasks.sort_by_key(|t| (!t.stat.policy.is_rt(), t.tid));

    let (mut rt_threads, mut on_isolated, mut shown) = (0, 0, 0);
    let mut findings_found = 0;
    for t in &tasks {
        let rt = t.stat.policy.is_rt();
        let iso = cpus.isolated.contains(t.stat.processor);
        rt_threads += usize::from(rt);
        on_isolated += usize::from(iso);
        if shown < args.max {
            shown += 1;
            report.push(&Record::Thread {
                pid: t.tgid,
                tid: t.tid,
                comm: t.stat.comm.clone(),
                uid: t.status.uid,
                kthread: t.kthread(),
                policy: t.stat.policy.short(),
                rtprio: rt.then_some(t.stat.rt_priority),
                cpu: t.stat.processor,
                state: t.stat.state.to_string(),
                cpus_allowed: t.status.cpus_allowed.clone(),
                on_isolated: iso,
                rt,
            });
        }
        if rt && !t.kthread() && !cpus.isolated.is_empty() {
            let outside = t.status.cpus_allowed.intersection(&cpus.housekeeping);
            if !outside.is_empty() {
                findings_found += 1;
                let inside = t.status.cpus_allowed.intersection(&cpus.isolated);
                report.findings.push(Finding {
                    id: "rt-on-housekeeping",
                    severity: Severity::Warn,
                    subject: Subject::Thread { tid: t.tid, comm: t.stat.comm.clone() },
                    evidence: vec![
                        Metric::new("policy", t.stat.policy.short()),
                        Metric::new("rtprio", t.stat.rt_priority),
                        Metric::new("cpus_allowed", &t.status.cpus_allowed),
                        Metric::new("housekeeping_allowed", &outside),
                    ],
                    recommendation: "an RT thread may run on a housekeeping CPU; restrict its affinity to the isolated set (or let it be, if it is meant to share them)".into(),
                    changes: if inside.is_empty() {
                        Vec::new()
                    } else {
                        vec![Change::SetAffinity { tid: t.tid, from: t.status.cpus_allowed.clone(), to: inside }]
                    },
                });
            }
        }
    }
    report.push(&Record::Summary {
        isolated_cpus: cpus.isolated,
        housekeeping_cpus: cpus.housekeeping,
        rt_threads,
        threads_on_isolated: on_isolated,
        shown,
        truncated: shown < tasks.len() || findings_found > FINDINGS_CAP,
    });
    report.findings.truncate(FINDINGS_CAP);
    finish(env, &mut report);
    Ok(report)
}
