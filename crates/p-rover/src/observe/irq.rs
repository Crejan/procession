//! `irq`: IRQ affinity, the `/proc/interrupts` delta, timer ticks and IPIs.

use std::collections::BTreeMap;
use std::time::Duration;

use p_roc::change::Change;
use p_roc::irq::{self, Interrupts, NAMED_ROWS};
use p_roc::{CpuSet, task};
use serde::Serialize;

use crate::env::Env;
use crate::error::Error;
use crate::observe::{self, finish};
use crate::report::{Cost, Finding, Metric, Report, Severity, Subject, round1};

/// Sampling window of the delta.
pub const DEFAULT_DURATION: Duration = Duration::from_secs(5);
/// Shortest and longest window accepted.
pub const DURATION_RANGE: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(60));
/// Unflagged IRQs shown, busiest first.
pub const DEFAULT_TOP: usize = 20;
/// A tick rate above this many times `CONFIG_HZ` is a thread, not the tick.
const TICK_FACTOR: f64 = 2.0;

/// Arguments of `irq`.
#[derive(Clone, Debug)]
pub struct Args {
    /// Sampling window, 1 to 60 seconds.
    pub duration: Duration,
    /// How many unflagged IRQs to show.
    pub top: usize,
}

impl Default for Args {
    fn default() -> Self {
        Self { duration: DEFAULT_DURATION, top: DEFAULT_TOP }
    }
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record {
    Policy {
        isolated_cpus: CpuSet,
        sources: p_roc::cpus::Isolation,
        workqueue_cpumask: Option<String>,
        irqbalance: bool,
    },
    Timer {
        window_s: u64,
        kernel_hz: Option<u32>,
        isolated_cpus: CpuSet,
        loc_per_s: BTreeMap<u32, f64>,
        ipi_per_s_on_isolated: BTreeMap<String, BTreeMap<u32, f64>>,
    },
    Irq {
        irq: u32,
        name: String,
        desc: String,
        affinity: Option<CpuSet>,
        effective: Option<CpuSet>,
        touches_isolated: bool,
        expected: Option<CpuSet>,
        delta: u64,
        delta_on_isolated: u64,
        flag: bool,
    },
    Summary {
        irqs: usize,
        flagged: usize,
        window_s: u64,
    },
}

/// `CONFIG_HZ` from `/boot/config-<release>`.
fn kernel_hz(env: &Env) -> Option<u32> {
    let release = std::fs::read_to_string(env.root.proc.join("sys/kernel/osrelease")).ok()?;
    let config = std::fs::read_to_string(env.boot.join(format!("config-{}", release.trim()))).ok()?;
    config.lines().find_map(|l| l.strip_prefix("CONFIG_HZ=")?.trim().parse().ok())
}

/// Per-second rates of the named rows on the isolated CPUs.
fn named_rates(before: &Interrupts, after: &Interrupts, isolated: &CpuSet, secs: f64) -> BTreeMap<String, BTreeMap<u32, f64>> {
    NAMED_ROWS
        .iter()
        .filter_map(|name| {
            let (b, a) = (before.row(name)?, after.row(name)?);
            if a.counts.len() != after.cpus.len() || b.counts.len() != a.counts.len() {
                return None;
            }
            let rates = irq::delta(&after.cpus, b, a)
                .into_iter()
                .filter(|(c, _)| isolated.contains(*c))
                .map(|(c, d)| (c, round1(d as f64 / secs)))
                .collect();
            Some(((*name).to_string(), rates))
        })
        .collect()
}

/// The names an IRQ goes by: its actions, then the device names of its row.
fn names(actions: &[String], desc: &str) -> Vec<String> {
    let mut v: Vec<String> = actions.to_vec();
    for n in desc.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        if !v.iter().any(|x| x == n) {
            v.push(n.to_string());
        }
    }
    v
}

/// Runs `irq`.
///
/// # Errors
/// When the window is outside 1-60 s, or `/proc/interrupts` or `/proc/irq` cannot be read.
pub fn run(env: &Env, args: &Args) -> Result<Report, Error> {
    if args.duration < DURATION_RANGE.0 || args.duration > DURATION_RANGE.1 {
        return Err(Error::Refused(format!(
            "--duration {:?} is outside {:?}..{:?}",
            args.duration, DURATION_RANGE.0, DURATION_RANGE.1
        )));
    }
    let expectations = env.config.irq_expectations().map_err(|detail| Error::Config { path: "config".into(), detail })?;
    let mut report = Report::new(env, "irq", Cost::Light);
    let cpus = observe::cpus(env, &mut report);
    let secs = args.duration.as_secs();

    let irqbalance = task::pids_with_comm(&env.root, "irqbalance")?;
    let workqueue_cpumask = std::fs::read_to_string(env.root.sys.join("devices/virtual/workqueue/cpumask"))
        .ok()
        .map(|s| s.trim().to_string());
    report.push(&Record::Policy {
        isolated_cpus: cpus.isolated.clone(),
        sources: cpus.sources.clone(),
        workqueue_cpumask,
        irqbalance: !irqbalance.is_empty(),
    });
    if !irqbalance.is_empty() {
        report.findings.push(Finding {
            id: "irqbalance",
            severity: Severity::Warn,
            subject: Subject::Host,
            evidence: vec![Metric::new("pids", &irqbalance)],
            recommendation: "irqbalance is running and moves IRQs at will; disable it on a realtime host and pin IRQs".into(),
            changes: Vec::new(),
        });
    }

    let before = irq::read_interrupts(&env.root)?;
    env.clock.pause(args.duration);
    let after = irq::read_interrupts(&env.root)?;
    let scan = irq::read_irqs(&env.root)?;
    report.unreadable(scan.unreadable);

    let hz = kernel_hz(env);
    let ticks = named_rates(&before, &after, &cpus.isolated, secs as f64);
    let loc = ticks.get("LOC").cloned().unwrap_or_default();
    let ipi = ticks.iter().filter(|(k, _)| k.as_str() != "LOC").map(|(k, v)| (k.clone(), v.clone())).collect();
    if let Some(hz) = hz {
        let fast: Vec<_> = loc.iter().filter(|(_, r)| **r > f64::from(hz) * TICK_FACTOR).collect();
        if !fast.is_empty() {
            report.findings.push(Finding {
                id: "tick-on-isolated",
                severity: Severity::Warn,
                subject: Subject::Host,
                evidence: std::iter::once(Metric::new("kernel_hz", hz))
                    .chain(fast.iter().map(|(c, r)| Metric::new(&format!("loc_per_s_cpu{c}"), r)))
                    .collect(),
                recommendation: "the timer-interrupt rate on an isolated CPU is far above CONFIG_HZ: a thread sleeps and wakes at that rate there; see `prover sched`".into(),
                changes: Vec::new(),
            });
        }
    }
    report.push(&Record::Timer {
        window_s: secs,
        kernel_hz: hz,
        isolated_cpus: cpus.isolated.clone(),
        loc_per_s: loc,
        ipi_per_s_on_isolated: ipi,
    });

    let mut rows = Vec::new();
    for i in &scan.items {
        let id = i.irq.to_string();
        let (b, a) = (before.row(&id), after.row(&id));
        let moved = match (b, a) {
            (Some(b), Some(a)) => irq::delta(&after.cpus, b, a),
            _ => Vec::new(),
        };
        let delta: u64 = moved.iter().map(|(_, d)| d).sum();
        let delta_on_isolated: u64 = moved.iter().filter(|(c, _)| cpus.isolated.contains(*c)).map(|(_, d)| d).sum();
        let desc = a.map(|r| r.name.clone()).unwrap_or_default();
        let all_names = names(&i.actions, &desc);
        let name = if i.actions.is_empty() { all_names.last().cloned().unwrap_or_default() } else { i.actions.join(",") };
        let effective_or_affinity = i.effective.as_ref().or(i.affinity.as_ref());
        let touches = effective_or_affinity.is_some_and(|e| e.intersects(&cpus.isolated));
        let expected = expectations
            .iter()
            .find(|e| all_names.iter().any(|n| e.matches(n)))
            .map(|e| e.cpus.clone());
        let deviates = matches!((&expected, &i.affinity), (Some(e), Some(a)) if e != a);
        let off_core = touches && delta_on_isolated > 0;
        let subject = Subject::Irq { irq: i.irq, name: name.clone() };

        if off_core {
            let to = i.affinity.as_ref().map(|a| a.difference(&cpus.isolated)).filter(|t| !t.is_empty());
            report.findings.push(Finding {
                id: "irq-on-isolated",
                severity: Severity::Warn,
                subject: subject.clone(),
                evidence: vec![
                    Metric::new("effective_affinity", effective_or_affinity),
                    Metric::new("delta_on_isolated", delta_on_isolated),
                    Metric::new("window_s", secs),
                ],
                recommendation: "the IRQ is delivered to an isolated CPU; managed IRQs and per-queue NIC IRQs may sit there legitimately, others should be moved off".into(),
                changes: match (&i.affinity, to) {
                    (Some(from), Some(to)) => vec![Change::SetIrqAffinity { irq: i.irq, from: from.clone(), to }],
                    _ => Vec::new(),
                },
            });
        }
        if let (true, Some(e), Some(a)) = (deviates, &expected, &i.affinity) {
            report.findings.push(Finding {
                id: "irq-mask-drift",
                severity: Severity::Warn,
                subject,
                evidence: vec![Metric::new("affinity", a), Metric::new("expected", e)],
                recommendation: "the IRQ's affinity differs from the configured expectation".into(),
                changes: vec![Change::SetIrqAffinity { irq: i.irq, from: a.clone(), to: e.clone() }],
            });
        }
        rows.push(Record::Irq {
            irq: i.irq,
            name,
            desc,
            affinity: i.affinity.clone(),
            effective: i.effective.clone(),
            touches_isolated: touches,
            expected,
            delta,
            delta_on_isolated,
            flag: off_core || deviates,
        });
    }

    let total = rows.len();
    let (flagged, mut rest): (Vec<_>, Vec<_>) = rows.into_iter().partition(|r| matches!(r, Record::Irq { flag: true, .. }));
    let key = |r: &Record| match r {
        Record::Irq { delta, irq, .. } => (std::cmp::Reverse(*delta), *irq),
        _ => (std::cmp::Reverse(0), 0),
    };
    rest.sort_by_key(key);
    let flagged_n = flagged.len();
    for r in &flagged {
        report.push(r);
    }
    for r in rest.iter().filter(|r| matches!(r, Record::Irq { delta, .. } if *delta > 0)).take(args.top) {
        report.push(r);
    }
    report.push(&Record::Summary { irqs: total, flagged: flagged_n, window_s: secs });
    finish(env, &mut report);
    Ok(report)
}
