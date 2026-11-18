//! `sched`: two samples of the threads that matter, as rates.

use std::collections::BTreeMap;
use std::time::Duration;

use p_roc::{CpuSet, Policy, task};
use p_roc::Unreadable;
use serde::Serialize;

use crate::env::Env;
use crate::error::Error;
use crate::observe::{self, finish};
use crate::report::{Cost, Report, round1};

/// Sampling window.
pub const DEFAULT_DURATION: Duration = Duration::from_secs(5);
/// Shortest and longest window accepted.
pub const DURATION_RANGE: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(60));
/// Thread records shown unless `--max` says otherwise.
pub const DEFAULT_MAX: usize = 60;
/// Voluntary switches per second above which a thread is a micro-sleep poller.
pub const POLLING_PER_S: f64 = 10_000.0;
/// Run time per second above which a thread is busy (90 % of a CPU).
pub const BUSY_MS_PER_S: f64 = 900.0;

/// Arguments of `sched`.
#[derive(Clone, Debug)]
pub struct Args {
    /// CPUs to watch; the isolated set when `None`.
    pub cpus: Option<CpuSet>,
    /// Sampling window.
    pub duration: Duration,
    /// Thread records shown.
    pub max: usize,
}

impl Default for Args {
    fn default() -> Self {
        Self { cpus: None, duration: DEFAULT_DURATION, max: DEFAULT_MAX }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record {
    Thread {
        pid: i32,
        tid: i32,
        comm: String,
        kthread: bool,
        policy: String,
        rtprio: Option<u32>,
        cpu: u32,
        cpus_allowed: CpuSet,
        run_ms_per_s: f64,
        wait_ms_per_s: f64,
        slices_per_s: f64,
        switches_per_s: Option<f64>,
        voluntary_per_s: Option<f64>,
        involuntary_per_s: Option<f64>,
        migrations_per_s: Option<f64>,
        polling: bool,
        busy: bool,
    },
    Cpu {
        cpu: u32,
        threads: usize,
        run_ms_per_s: f64,
        wait_ms_per_s: f64,
    },
    Summary {
        window_s: u64,
        cpus: CpuSet,
        threads: usize,
        shown: usize,
        polling: Vec<i32>,
        busy: Vec<i32>,
        sched_debug: bool,
        degraded: Option<&'static str>,
    },
}

struct Sample {
    pid: i32,
    comm: String,
    policy: Policy,
    rtprio: u32,
    cpu: u32,
    allowed: CpuSet,
    kthread: bool,
    run_ns: u64,
    wait_ns: u64,
    slices: u64,
    switches: Option<u64>,
    voluntary: Option<u64>,
    involuntary: Option<u64>,
    migrations: Option<u64>,
    sched_debug: bool,
}

/// The threads that are realtime, run on `cpus` or may run there, with their counters.
fn sample(env: &Env, cpus: &CpuSet, report: &mut Report) -> Result<BTreeMap<i32, Sample>, Error> {
    let scan = task::scan(&env.root, |_| true)?;
    report.unreadable(scan.unreadable);
    let mut out = BTreeMap::new();
    let mut no_counters: Vec<String> = Vec::new();
    for t in scan.items {
        let rt = t.stat.policy.is_rt() || t.stat.policy == Policy::Deadline;
        if !(rt || cpus.contains(t.stat.processor) || t.status.cpus_allowed.intersects(cpus)) {
            continue;
        }
        let c = match task::read_counters(&env.root, t.tgid, t.tid) {
            Ok(c) => c,
            Err(e) if e.is_gone() => continue,
            Err(e) => {
                no_counters.push(e.to_string());
                continue;
            }
        };
        let sw = t.status.switches;
        let s = c.sched.unwrap_or_default();
        let voluntary = s.voluntary.or(sw.map(|x| x.voluntary));
        let involuntary = s.involuntary.or(sw.map(|x| x.involuntary));
        out.insert(
            t.tid,
            Sample {
                pid: t.tgid,
                comm: t.stat.comm.clone(),
                policy: t.stat.policy,
                rtprio: t.stat.rt_priority,
                cpu: t.stat.processor,
                allowed: t.status.cpus_allowed.clone(),
                kthread: t.kthread(),
                run_ns: c.schedstat.run_ns,
                wait_ns: c.schedstat.wait_ns,
                slices: c.schedstat.slices,
                switches: s.switches.or(voluntary.zip(involuntary).map(|(a, b)| a + b)),
                voluntary,
                involuntary,
                migrations: s.migrations,
                sched_debug: c.sched.is_some_and(|x| x.switches.is_some()),
            },
        );
    }
    if let Some(first) = no_counters.first() {
        report.unreadable([Unreadable {
            source: format!("proc/<pid>/task/<tid>/schedstat ({} threads)", no_counters.len()),
            reason: first.clone(),
        }]);
    }
    Ok(out)
}

fn rate(after: Option<u64>, before: Option<u64>, secs: f64, scale: f64) -> Option<f64> {
    let (a, b) = (after?, before?);
    (a >= b).then(|| round1((a - b) as f64 / scale / secs))
}

/// Runs `sched`.
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
    let mut report = Report::new(env, "sched", Cost::Light);
    let host = observe::cpus(env, &mut report);
    let watched = args.cpus.clone().unwrap_or_else(|| host.isolated.clone());
    let secs = args.duration.as_secs();
    let s = secs as f64;

    let first = sample(env, &watched, &mut report)?;
    env.clock.pause(args.duration);
    let second = sample(env, &watched, &mut report)?;

    let mut rows = Vec::new();
    for (tid, t) in &second {
        // A thread that is new, or whose tid was reused, has no rates.
        let Some(b) = first.get(tid).filter(|b| b.pid == t.pid && b.run_ns <= t.run_ns && b.slices <= t.slices) else {
            continue;
        };
        let voluntary = rate(t.voluntary, b.voluntary, s, 1.0);
        let run = round1((t.run_ns - b.run_ns) as f64 / 1e6 / s);
        rows.push(Record::Thread {
            pid: t.pid,
            tid: *tid,
            comm: t.comm.clone(),
            kthread: t.kthread,
            policy: t.policy.short(),
            rtprio: t.policy.is_rt().then_some(t.rtprio),
            cpu: t.cpu,
            cpus_allowed: t.allowed.clone(),
            run_ms_per_s: run,
            wait_ms_per_s: round1(t.wait_ns.saturating_sub(b.wait_ns) as f64 / 1e6 / s),
            slices_per_s: round1((t.slices - b.slices) as f64 / s),
            switches_per_s: rate(t.switches, b.switches, s, 1.0),
            voluntary_per_s: voluntary,
            involuntary_per_s: rate(t.involuntary, b.involuntary, s, 1.0),
            migrations_per_s: rate(t.migrations, b.migrations, s, 1.0),
            polling: voluntary.is_some_and(|v| v > POLLING_PER_S),
            busy: run >= BUSY_MS_PER_S,
        });
    }
    let run_of = |r: &Record| match r {
        Record::Thread { run_ms_per_s, tid, .. } => (std::cmp::Reverse((run_ms_per_s * 10.0) as i64), *tid),
        _ => (std::cmp::Reverse(0), 0),
    };
    rows.sort_by_key(run_of);

    let mut per_cpu: BTreeMap<u32, (usize, f64, f64)> = BTreeMap::new();
    let (mut polling, mut busy) = (Vec::new(), Vec::new());
    for r in &rows {
        if let Record::Thread { tid, cpu, run_ms_per_s, wait_ms_per_s, polling: p, busy: b, .. } = r {
            let e = per_cpu.entry(*cpu).or_default();
            e.0 += 1;
            e.1 += run_ms_per_s;
            e.2 += wait_ms_per_s;
            if *p {
                polling.push(*tid);
            }
            if *b {
                busy.push(*tid);
            }
        }
    }
    let threads = rows.len();
    let shown = threads.min(args.max);
    for r in rows.iter().take(shown) {
        report.push(r);
    }
    for (cpu, (n, run, wait)) in per_cpu {
        report.push(&Record::Cpu { cpu, threads: n, run_ms_per_s: round1(run), wait_ms_per_s: round1(wait) });
    }
    let sched_debug = second.values().any(|t| t.sched_debug);
    if !sched_debug && !second.is_empty() {
        report.unreadable([Unreadable {
            source: "proc/<pid>/task/<tid>/sched".into(),
            reason: "missing (CONFIG_SCHED_DEBUG off)".into(),
        }]);
    }
    report.push(&Record::Summary {
        window_s: secs,
        cpus: watched,
        threads,
        shown,
        polling,
        busy,
        sched_debug,
        degraded: (!sched_debug).then_some(
            "no sched file (CONFIG_SCHED_DEBUG off): migrations and total switches are null; voluntary and involuntary come from status",
        ),
    });
    finish(env, &mut report);
    Ok(report)
}
