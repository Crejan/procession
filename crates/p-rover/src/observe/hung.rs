//! `hung`: live hang triage, the running counterpart of `lastboot`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use p_roc::{Unreadable, task};
use serde::Serialize;

use crate::env::Env;
use crate::error::Error;
use crate::observe::finish;
use crate::report::{Cost, Finding, Metric, Report, Severity, Subject};

/// Sampling window.
pub const DEFAULT_DURATION: Duration = Duration::from_secs(2);
/// Shortest and longest window accepted.
pub const DURATION_RANGE: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(60));
/// Kernel stack lines shown per task.
pub const DEFAULT_STACK_LINES: usize = 14;
/// Tasks shown.
pub const DEFAULT_MAX: usize = 50;
/// This many tasks in D, or one stuck on a server for the whole window, is critical.
const CRIT_TASKS: usize = 5;

/// Arguments of `hung`.
#[derive(Clone, Debug)]
pub struct Args {
    /// Also list tasks in S whose wait is NFS or RPC.
    pub all: bool,
    /// Time between the two samples.
    pub duration: Duration,
    /// Kernel stack lines per task.
    pub stack_lines: usize,
    /// Tasks shown.
    pub max: usize,
}

impl Default for Args {
    fn default() -> Self {
        Self { all: false, duration: DEFAULT_DURATION, stack_lines: DEFAULT_STACK_LINES, max: DEFAULT_MAX }
    }
}

/// What a task waits for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitClass {
    /// An NFS or RPC server.
    NfsRpc,
    /// A local lock.
    Lock,
    /// Block I/O.
    BlockIo,
    /// Anything else.
    Other,
}

const NFS_WORDS: [&str; 6] = ["rpc_wait_bit_killable", "nfs_wait_bit_killable", "xprt", "nfs", "rpc", "fscache"];
const LOCK_WORDS: [&str; 5] = ["mutex_lock", "rwsem", "_lock", "down_read", "down_write"];
const IO_WORDS: [&str; 6] = ["io_schedule", "blk_", "bio_", "submit_bio", "wait_on_page", "folio_wait"];

/// The wait class from the wait channel and the kernel stack.
#[must_use]
pub fn classify(wchan: &str, stack: &[String]) -> WaitClass {
    let has = |words: &[&str]| words.iter().any(|w| wchan.contains(w) || stack.iter().any(|f| f.contains(w)));
    if has(&NFS_WORDS) {
        WaitClass::NfsRpc
    } else if has(&LOCK_WORDS) {
        WaitClass::Lock
    } else if has(&IO_WORDS) {
        WaitClass::BlockIo
    } else {
        WaitClass::Other
    }
}

#[derive(Serialize)]
struct Sample {
    wchan: String,
    stack: Option<Vec<String>>,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record {
    Detector {
        hung_task_timeout_secs: Option<String>,
        hung_task_warnings: Option<String>,
    },
    Task {
        pid: i32,
        tid: i32,
        comm: String,
        state: String,
        uid: u32,
        ppid: i32,
        wait_class: WaitClass,
        d_for_at_least_s: Option<u64>,
        exe: Option<String>,
        cwd: Option<String>,
        mount: Option<String>,
        samples: Vec<Sample>,
    },
    Summary {
        d_state_first: usize,
        hung: usize,
        nfs_waiters: usize,
        shown: usize,
        truncated: bool,
        by_class: BTreeMap<WaitClass, usize>,
    },
}

struct Snap {
    tgid: i32,
    comm: String,
    state: char,
    uid: u32,
    ppid: i32,
    wchan: String,
    run_ns: Option<u64>,
    stack: Option<Vec<String>>,
}

fn wchan(env: &Env, tgid: i32, tid: i32) -> String {
    let p = env.root.proc.join(tgid.to_string()).join("task").join(tid.to_string()).join("wchan");
    let w = p_roc::text::read_to_string(p).unwrap_or_default();
    let w = w.trim();
    if w == "0" { String::new() } else { w.to_string() }
}

/// The kernel stack of a task (root only), cut to `lines`.
fn stack(env: &Env, tgid: i32, tid: i32, lines: usize) -> Option<Vec<String>> {
    let p = env.root.proc.join(tgid.to_string()).join("task").join(tid.to_string()).join("stack");
    let text = p_roc::text::read_to_string(p).ok()?;
    Some(text.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).take(lines).collect())
}

fn sample(env: &Env, args: &Args, report: &mut Report) -> Result<BTreeMap<i32, Snap>, Error> {
    let scan = task::scan(&env.root, |s| s.state == 'D' || args.all)?;
    report.unreadable(scan.unreadable);
    let mut denied = 0usize;
    let mut out = BTreeMap::new();
    for t in scan.items {
        let w = wchan(env, t.tgid, t.tid);
        let wanted = t.stat.state == 'D' || NFS_WORDS.iter().any(|k| w.contains(k));
        let stack = wanted.then(|| stack(env, t.tgid, t.tid, args.stack_lines)).flatten();
        denied += usize::from(wanted && stack.is_none());
        let run_ns = task::read_counters(&env.root, t.tgid, t.tid).ok().map(|c| c.schedstat.run_ns);
        out.insert(
            t.tid,
            Snap {
                tgid: t.tgid,
                comm: t.stat.comm,
                state: t.stat.state,
                uid: t.status.uid,
                ppid: t.stat.ppid,
                wchan: w,
                run_ns,
                stack,
            },
        );
    }
    if denied > 0 {
        report.unreadable([Unreadable {
            source: "proc/<pid>/task/<tid>/stack".into(),
            reason: format!("unreadable for {denied} tasks (needs root); wait class from wchan only"),
        }]);
    }
    Ok(out)
}

/// `(mount point, fstype)` of the mounts, from `/proc/mounts`; `\040` escapes decoded.
fn mounts(env: &Env) -> Vec<(PathBuf, String)> {
    let text = p_roc::text::read_to_string(env.root.proc.join("mounts")).unwrap_or_default();
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let (_, mp, ty) = (f.next()?, f.next()?, f.next()?);
            Some((PathBuf::from(mp.replace("\\040", " ")), ty.to_string()))
        })
        .collect()
}

/// The NFS mount that holds `path`: the longest mount point that is a prefix.
fn nfs_mount(mounts: &[(PathBuf, String)], path: &Path) -> Option<String> {
    mounts
        .iter()
        .filter(|(mp, ty)| ty.starts_with("nfs") && path.starts_with(mp))
        .max_by_key(|(mp, _)| mp.components().count())
        .map(|(mp, _)| p_roc::text::from_os(mp.as_os_str()))
}

fn link(env: &Env, pid: i32, name: &str) -> Option<PathBuf> {
    std::fs::read_link(env.root.proc.join(pid.to_string()).join(name)).ok()
}

/// Runs `hung`.
///
/// # Errors
/// When the window is outside 1-60 s or the process list cannot be read.
pub fn run(env: &Env, args: &Args) -> Result<Report, Error> {
    if args.duration < DURATION_RANGE.0 || args.duration > DURATION_RANGE.1 {
        return Err(Error::Refused(format!(
            "--duration {:?} is outside {:?}..{:?}",
            args.duration, DURATION_RANGE.0, DURATION_RANGE.1
        )));
    }
    let mut report = Report::new(env, "hung", Cost::Light);
    let sysctl = |n: &str| {
        p_roc::text::read_to_string(env.root.proc.join("sys/kernel").join(n)).ok().map(|s| s.trim().to_string())
    };
    report.push(&Record::Detector {
        hung_task_timeout_secs: sysctl("hung_task_timeout_secs"),
        hung_task_warnings: sysctl("hung_task_warnings"),
    });

    let first = sample(env, args, &mut report)?;
    env.clock.pause(args.duration);
    let second = sample(env, args, &mut report)?;

    let d_first = first.values().filter(|s| s.state == 'D').count();
    let nfsish = |s: &Snap| NFS_WORDS.iter().any(|w| s.wchan.contains(w));
    // Hung: in D in both samples. With --all also the sleepers whose wait is NFS or RPC.
    let mut picked: Vec<(&i32, &Snap, Option<&Snap>)> = second
        .iter()
        .filter_map(|(tid, s)| {
            let before = first.get(tid).filter(|b| b.tgid == s.tgid);
            let hung = s.state == 'D' && before.is_some_and(|b| b.state == 'D');
            (hung || (args.all && s.state != 'D' && nfsish(s))).then_some((tid, s, before))
        })
        .collect();
    picked.sort_by_key(|(tid, ..)| **tid);

    let mounts = mounts(env);
    let (mut hung_n, mut nfs_n) = (0usize, 0usize);
    let (mut by_class, mut mounts_hit): (BTreeMap<WaitClass, usize>, BTreeSet<String>) = Default::default();
    let mut full_window_nfs = false;
    let mut shown = 0;
    for (tid, s, before) in &picked {
        let class = classify(&s.wchan, s.stack.as_deref().unwrap_or_default());
        let in_d = s.state == 'D';
        hung_n += usize::from(in_d);
        nfs_n += usize::from(class == WaitClass::NfsRpc);
        *by_class.entry(class).or_default() += usize::from(in_d);
        let continuous = before.and_then(|b| Some(b.run_ns? == s.run_ns?)).unwrap_or(false);
        let (exe, cwd) = (link(env, s.tgid, "exe"), link(env, s.tgid, "cwd"));
        let mount = (class == WaitClass::NfsRpc)
            .then(|| cwd.iter().chain(exe.iter()).find_map(|p| nfs_mount(&mounts, p)))
            .flatten();
        if in_d && class == WaitClass::NfsRpc {
            full_window_nfs |= continuous;
            mounts_hit.extend(mount.clone());
        }
        if shown < args.max {
            shown += 1;
            report.push(&Record::Task {
                pid: s.tgid,
                tid: **tid,
                comm: s.comm.clone(),
                state: s.state.to_string(),
                uid: s.uid,
                ppid: s.ppid,
                wait_class: class,
                d_for_at_least_s: (in_d && continuous).then_some(args.duration.as_secs()),
                exe: exe.map(|p| p_roc::text::from_os(p.as_os_str())),
                cwd: cwd.map(|p| p_roc::text::from_os(p.as_os_str())),
                mount,
                samples: vec![
                    Sample {
                        wchan: before.map(|b| b.wchan.clone()).unwrap_or_default(),
                        stack: before.and_then(|b| b.stack.clone()),
                    },
                    Sample { wchan: s.wchan.clone(), stack: s.stack.clone() },
                ],
            });
        }
    }
    report.push(&Record::Summary {
        d_state_first: d_first,
        hung: hung_n,
        nfs_waiters: nfs_n,
        shown,
        truncated: shown < picked.len(),
        by_class: by_class.clone(),
    });
    if hung_n > 0 {
        let crit = hung_n >= CRIT_TASKS || full_window_nfs;
        let mut evidence =
            vec![Metric::new("tasks_in_d_both_samples", hung_n), Metric::new("window_s", args.duration.as_secs())];
        evidence.extend(by_class.iter().filter(|(_, n)| **n > 0).map(|(c, n)| {
            Metric::new(
                &format!(
                    "class_{}",
                    serde_json::to_value(c).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
                ),
                n,
            )
        }));
        evidence.extend(mounts_hit.iter().map(|m| Metric::new("nfs_mount", m)));
        report.findings.push(Finding {
            id: "hung-tasks",
            severity: if crit { Severity::Crit } else { Severity::Warn },
            subject: Subject::Host,
            evidence,
            recommendation: "tasks stayed in uninterruptible sleep across both samples; NFS/RPC waits mean the server or mount is not answering, lock waits name a local holder in the stack".into(),
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
    fn wait_classes() {
        let s = |f: &str| vec![f.to_string()];
        assert_eq!(classify("rpc_wait_bit_killable", &[]), WaitClass::NfsRpc);
        assert_eq!(classify("", &s("[<0>] xprt_wait_for_buffer_space+0x1/0x2")), WaitClass::NfsRpc);
        assert_eq!(classify("", &s("[<0>] __mutex_lock+0x1/0x2")), WaitClass::Lock);
        assert_eq!(classify("rwsem_down_read_slowpath", &[]), WaitClass::Lock);
        assert_eq!(classify("io_schedule", &[]), WaitClass::BlockIo);
        assert_eq!(classify("do_wait", &[]), WaitClass::Other);
    }

    #[test]
    fn longest_nfs_mount_wins() {
        let m = vec![
            (PathBuf::from("/"), "ext4".to_string()),
            (PathBuf::from("/home"), "nfs4".to_string()),
            (PathBuf::from("/home/lab"), "nfs".to_string()),
        ];
        assert_eq!(nfs_mount(&m, Path::new("/home/lab/x")).as_deref(), Some("/home/lab"));
        assert_eq!(nfs_mount(&m, Path::new("/home/other")).as_deref(), Some("/home"));
        assert_eq!(nfs_mount(&m, Path::new("/var")), None);
        assert_eq!(nfs_mount(&m, Path::new("/homework")), None);
    }
}
