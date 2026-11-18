//! `nic <if>`: link, driver, counters, rings, coalescing, offloads, queues and their IRQs;
//! with `--delta` only the counters that moved.

use std::collections::BTreeMap;
use std::time::Duration;

use globset::Glob;
use p_roc::net::{self, Interface};
use p_roc::{CpuSet, Unreadable, irq, task};
use serde::Serialize;

use crate::env::Env;
use crate::error::Error;
use crate::ethtool::{Channels, Coalesce, DriverInfo, Eee, Ring};
use crate::observe::{self, finish};
use crate::report::{Cost, Finding, Metric, Report, Severity, Subject, round2};

/// Counter names that mean errors or drops.
const TRIAGE: [&str; 10] =
    ["missed", "fifo", "crc", "no_buffer", "drop", "error", "over", "length", "timeout", "restart"];
/// Names that also count in the static view (not in the delta: pause frames move with healthy traffic).
const TRIAGE_STATIC_EXTRA: [&str; 3] = ["collision", "pause", "flow"];
/// Window limits of `--delta`.
pub const DELTA_RANGE: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(300));
/// Moved traffic counters listed after the errors.
const TRAFFIC_SHOWN: usize = 25;

/// Arguments of `nic`.
#[derive(Clone, Debug)]
pub struct Args {
    /// The interface.
    pub iface: String,
    /// Sample the counters over this window and report only what moved.
    pub delta: Option<Duration>,
    /// List every counter, not only the error and drop ones.
    pub all_stats: bool,
}

fn is_triage(name: &str, extra: bool) -> bool {
    let n = name.to_ascii_lowercase();
    TRIAGE.iter().any(|t| n.contains(t)) || (extra && TRIAGE_STATIC_EXTRA.iter().any(|t| n.contains(t)))
}

#[derive(Serialize)]
struct IrqThread {
    tid: i32,
    policy: String,
    rtprio: u32,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record {
    Link {
        #[serde(flatten)]
        interface: Interface,
    },
    Driver {
        iface: String,
        #[serde(flatten)]
        info: DriverInfo,
        kernel_driver: Option<String>,
        pci: Option<String>,
    },
    Stats {
        iface: String,
        counters: usize,
        triage: BTreeMap<String, u64>,
        nonzero_triage: BTreeMap<String, u64>,
        rx_packets: Option<u64>,
        tx_packets: Option<u64>,
    },
    Ring {
        iface: String,
        #[serde(flatten)]
        ring: Ring,
    },
    Coalesce {
        iface: String,
        #[serde(flatten)]
        coalesce: Coalesce,
    },
    Channels {
        iface: String,
        #[serde(flatten)]
        channels: Channels,
    },
    Eee {
        iface: String,
        #[serde(flatten)]
        eee: Eee,
    },
    Features {
        iface: String,
        features: BTreeMap<String, bool>,
    },
    Irq {
        iface: String,
        irq: u32,
        name: String,
        affinity: Option<CpuSet>,
        effective: Option<CpuSet>,
        touches_isolated: bool,
        thread: Option<IrqThread>,
    },
    Counter {
        iface: String,
        name: String,
        delta: u64,
        per_s: f64,
        before: Option<u64>,
        after: u64,
        triage: bool,
    },
    Summary {
        iface: String,
        window_s: u64,
        counters_moved: usize,
        error_counters_moved: usize,
        clean: bool,
    },
}

/// The findings an interface earns from its settings: coalescing, EEE, queue count.
/// The caller decides whether the interface is one of concern.
pub(crate) fn interface_findings(interface: &Interface, data: &crate::ethtool::EthtoolData) -> Vec<Finding> {
    let subject = Subject::Interface { name: interface.name.clone() };
    let mut out = Vec::new();
    if let Some(c) = data.coalesce.as_ref().filter(|c| c.rx_usecs.is_some_and(|u| u > 0)) {
        out.push(Finding {
            id: "coalescing-on",
            severity: Severity::Warn,
            subject: subject.clone(),
            evidence: vec![Metric::new("rx_usecs", c.rx_usecs), Metric::new("rx_frames", c.rx_frames)],
            recommendation: "receive interrupt coalescing delays every frame by up to rx-usecs; set rx-usecs 0 on a cyclic interface".into(),
            changes: Vec::new(),
        });
    }
    if let Some(e) = data.eee.as_ref().filter(|e| e.enabled) {
        out.push(Finding {
            id: "eee-on",
            severity: Severity::Warn,
            subject: subject.clone(),
            evidence: vec![Metric::new("eee_enabled", true), Metric::new("eee_active", e.active)],
            recommendation: "Energy-Efficient Ethernet puts the link to sleep between frames and adds wake latency; disable it on a cyclic interface".into(),
            changes: Vec::new(),
        });
    }
    if interface.rx_queues > 1 {
        out.push(Finding {
            id: "multi-queue",
            severity: Severity::Warn,
            subject,
            evidence: vec![Metric::new("rx_queues", interface.rx_queues), Metric::new("tx_queues", interface.tx_queues)],
            recommendation: "the interface has several queues, so a frame's IRQ may land on any CPU the hash picks; reduce channels to 1 for a cyclic flow".into(),
            changes: Vec::new(),
        });
    }
    out
}

fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 15 && n.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Whether the interface is one the config calls fieldbus, or none is configured.
fn of_concern(env: &Env, iface: &str) -> bool {
    let globs = &env.config.fieldbus_interfaces;
    globs.is_empty() || globs.iter().any(|g| Glob::new(g).is_ok_and(|g| g.compile_matcher().is_match(iface)))
}

/// The kernel's generic counters of an interface.
fn sysfs_counters(env: &Env, iface: &str, report: &mut Report) -> BTreeMap<String, u64> {
    match net::statistics(&env.root, iface) {
        Ok(s) => s,
        Err(e) => {
            report.unreadable([Unreadable::new(format!("sys/class/net/{iface}/statistics"), &e)]);
            BTreeMap::new()
        }
    }
}

/// All counters of an interface: the kernel's generic ones and the driver's
/// (the driver's win on a name clash).
fn counters(env: &Env, iface: &str, report: &mut Report) -> BTreeMap<String, u64> {
    let mut all = sysfs_counters(env, iface, report);
    let (data, bad) = env.ethtool.query(iface);
    report.unreadable(bad);
    all.extend(data.stats);
    all
}

/// Runs `nic`.
///
/// # Errors
/// When the interface name is invalid or the interface does not exist, or the window is outside 1-300 s.
pub fn run(env: &Env, args: &Args) -> Result<Report, Error> {
    let iface = args.iface.as_str();
    if !valid_name(iface) {
        return Err(Error::Refused(format!("bad interface name {iface:?}")));
    }
    if let Some(d) = args.delta.filter(|d| *d < DELTA_RANGE.0 || *d > DELTA_RANGE.1) {
        return Err(Error::Refused(format!("--delta {d:?} is outside {:?}..{:?}", DELTA_RANGE.0, DELTA_RANGE.1)));
    }
    let interface = net::interface(&env.root, iface).map_err(|_| Error::Refused(format!("no interface {iface}")))?;
    let mut report = Report::new(env, "nic", if args.delta.is_some() { Cost::Heavy } else { Cost::Light });

    if let Some(window) = args.delta {
        delta(env, iface, window, &mut report);
    } else {
        statics(env, args, &interface, &mut report)?;
    }
    finish(env, &mut report);
    Ok(report)
}

fn delta(env: &Env, iface: &str, window: Duration, report: &mut Report) {
    let before = counters(env, iface, report);
    env.clock.pause(window);
    let after = counters(env, iface, report);
    let secs = window.as_secs();
    type Moved<'a> = (&'a String, u64, u64);
    let moved: Vec<Moved<'_>> = after
        .iter()
        .filter_map(|(k, a)| {
            let b = before.get(k).copied().unwrap_or(0);
            (*a > b).then_some((k, a - b, b))
        })
        .collect();
    let (mut errors, mut traffic): (Vec<&Moved<'_>>, Vec<&Moved<'_>>) =
        moved.iter().partition(|(k, ..)| is_triage(k, false));
    errors.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    traffic.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    let rec = |(k, d, b): &Moved<'_>, triage: bool| Record::Counter {
        iface: iface.to_string(),
        name: (*k).clone(),
        delta: *d,
        per_s: round2(*d as f64 / secs as f64),
        before: before.get(*k).map(|_| *b),
        after: after[*k],
        triage,
    };
    for e in &errors {
        report.push(&rec(e, true));
    }
    for t in traffic.iter().take(TRAFFIC_SHOWN) {
        report.push(&rec(t, false));
    }
    report.push(&Record::Summary {
        iface: iface.to_string(),
        window_s: secs,
        counters_moved: moved.len(),
        error_counters_moved: errors.len(),
        clean: errors.is_empty(),
    });
    if !errors.is_empty() {
        report.findings.push(Finding {
            id: "nic-drops",
            severity: Severity::Warn,
            subject: Subject::Interface { name: iface.to_string() },
            evidence: errors.iter().map(|(k, d, _)| Metric::new(k, d)).chain([Metric::new("window_s", secs)]).collect(),
            recommendation: "error or drop counters moved during the window: a receive overflow or link problem in progress; check rings, interrupt coalescing and the IRQ's CPU".into(),
            changes: Vec::new(),
        });
    }
}

fn statics(env: &Env, args: &Args, interface: &Interface, report: &mut Report) -> Result<(), Error> {
    let iface = args.iface.clone();
    let concern = of_concern(env, &iface);
    let cpus = observe::cpus(env, report);
    report.push(&Record::Link { interface: interface.clone() });

    let (data, bad) = env.ethtool.query(&iface);
    report.unreadable(bad);
    report.push(&Record::Driver {
        iface: iface.clone(),
        info: data.driver.clone().unwrap_or_default(),
        kernel_driver: interface.driver.clone(),
        pci: interface.pci.clone(),
    });

    let mut all = sysfs_counters(env, &iface, report);
    all.extend(data.stats.clone());
    let listed: BTreeMap<String, u64> =
        all.iter().filter(|(k, _)| args.all_stats || is_triage(k, true)).map(|(k, v)| (k.clone(), *v)).collect();
    let nonzero = listed.iter().filter(|(_, v)| **v > 0).map(|(k, v)| (k.clone(), *v)).collect();
    report.push(&Record::Stats {
        iface: iface.clone(),
        counters: all.len(),
        triage: listed,
        nonzero_triage: nonzero,
        rx_packets: all.get("rx_packets").copied(),
        tx_packets: all.get("tx_packets").copied(),
    });
    if let Some(ring) = &data.ring {
        report.push(&Record::Ring { iface: iface.clone(), ring: ring.clone() });
    }
    if let Some(c) = &data.coalesce {
        report.push(&Record::Coalesce { iface: iface.clone(), coalesce: c.clone() });
    }
    if let Some(c) = &data.channels {
        report.push(&Record::Channels { iface: iface.clone(), channels: c.clone() });
    }
    if let Some(e) = &data.eee {
        report.push(&Record::Eee { iface: iface.clone(), eee: e.clone() });
    }
    if !data.features.is_empty() {
        report.push(&Record::Features { iface: iface.clone(), features: data.features.clone() });
    }
    if concern {
        report.findings.extend(interface_findings(interface, &data));
    }

    // IRQs: the device's MSI vectors, else the rows of /proc/interrupts that carry the interface name.
    let interrupts = irq::read_interrupts(&env.root);
    let mut irqs = interface.irqs.clone();
    if let (true, Ok(i)) = (irqs.is_empty(), &interrupts) {
        irqs = i.rows.iter().filter(|r| r.name.contains(&iface)).filter_map(|r| r.id.parse().ok()).collect();
    }
    let scan = irq::read_irqs(&env.root)?;
    report.unreadable(scan.unreadable);
    let threads = task::scan(&env.root, |s| s.comm.starts_with("irq/"))?;
    report.unreadable(threads.unreadable);
    for n in irqs {
        let info = scan.items.iter().find(|i| i.irq == n);
        let row_name = interrupts.as_ref().ok().and_then(|i| i.row(&n.to_string())).map(|r| r.name.clone());
        let effective = info.and_then(|i| i.effective.clone().or_else(|| i.affinity.clone()));
        let thread = threads
            .items
            .iter()
            .find(|t| task::irq_thread(&t.stat.comm).is_some_and(|(i, _)| i == n))
            .map(|t| IrqThread { tid: t.tid, policy: t.stat.policy.short(), rtprio: t.stat.rt_priority });
        report.push(&Record::Irq {
            iface: iface.clone(),
            irq: n,
            name: row_name.or_else(|| info.and_then(|i| i.actions.first().cloned())).unwrap_or_default(),
            affinity: info.and_then(|i| i.affinity.clone()),
            touches_isolated: effective.as_ref().is_some_and(|e| e.intersects(&cpus.isolated)),
            effective: info.and_then(|i| i.effective.clone()),
            thread,
        });
    }
    Ok(())
}
