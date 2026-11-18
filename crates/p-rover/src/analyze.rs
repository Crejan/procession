//! `analyze --pid <pid> --static`: one process explored from procfs and sysfs
//! alone. No tracing, so no thread classes, cycle chains or protocol
//! analysis; placement, memory, endpoints, interfaces, kernel-bypass
//! detection and host settings are all there.

use std::collections::BTreeMap;

use globset::Glob;
use p_roc::change::Change;
use p_roc::fd::FdKind;
use p_roc::net::{self, Interface, SocketKind};
use p_roc::pci::{self, Attached};
use p_roc::{CpuSet, Policy, Unreadable, irq, task};
use serde::Serialize;

use crate::env::Env;
use crate::error::Error;
use crate::observe::{self, finish, nic};
use crate::report::{Cost, Finding, Metric, Report, Severity, Subject};

/// Highest priority p-rover proposes for an IRQ thread: 99 is the kernel's own.
const MAX_PROPOSED_PRIO: u8 = 98;
/// Non-RT threads listed besides the RT and the declared ones.
const OTHER_THREADS_SHOWN: usize = 30;

/// Arguments of `analyze`.
#[derive(Clone, Debug, Default)]
pub struct Args {
    /// The process.
    pub pid: i32,
    /// Threads the user declares critical: always listed.
    pub tids: Vec<i32>,
    /// Procfs and sysfs only. Required until the tracing backend exists.
    pub static_only: bool,
}

#[derive(Serialize)]
struct Queue {
    index: Option<u32>,
    irq: u32,
    name: String,
    irq_affinity: Option<CpuSet>,
    irq_effective_affinity: Option<CpuSet>,
    irq_thread: Option<IrqThread>,
}

#[derive(Clone, Serialize)]
struct IrqThread {
    tid: i32,
    policy: String,
    prio: u32,
}

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Record {
    Host {
        online: Option<CpuSet>,
        isolated: CpuSet,
        nohz_full: CpuSet,
        rcu_nocbs: CpuSet,
        housekeeping: CpuSet,
        sched_rt_runtime_us: Option<String>,
        irqbalance: bool,
        governors: Vec<String>,
        cstates: Vec<CState>,
        cmdline_rt: serde_json::Map<String, serde_json::Value>,
    },
    Process {
        pid: i32,
        comm: String,
        exe: Option<String>,
        uid: u32,
        vm_rss_kb: Option<u64>,
        vm_lck_kb: Option<u64>,
        threads: usize,
    },
    Thread {
        tid: i32,
        comm: String,
        policy: String,
        rt_priority: Option<u32>,
        affinity: CpuSet,
        last_cpu: u32,
        voluntary_switches: Option<u64>,
        involuntary_switches: Option<u64>,
        utime_ticks: u64,
        stime_ticks: u64,
        syscall: Option<String>,
        declared_critical: bool,
        class: Option<&'static str>,
    },
    Endpoint {
        fd: i32,
        endpoint: &'static str,
        ifindex: Option<u32>,
        interface: Option<String>,
        proto: Option<String>,
        port: Option<u16>,
        path: Option<String>,
        pci: Option<String>,
    },
    Interface {
        #[serde(flatten)]
        interface: Interface,
        attached: Attached,
        reason: &'static str,
        queues: Vec<Queue>,
        coalesce_rx_usecs: Option<u32>,
        eee_enabled: Option<bool>,
    },
    KernelBypass {
        pci: Option<String>,
        driver: Option<String>,
        attached: Attached,
        via: &'static str,
        tied_to_process: bool,
        irqs: Vec<Queue>,
        limits: &'static str,
    },
    Summary {
        backend: &'static str,
        tracing: bool,
        threads_listed: usize,
        unresolved_packet_sockets: usize,
        not_available: &'static str,
    },
}

#[derive(Serialize)]
struct CState {
    name: String,
    disabled: bool,
}

fn first_line(p: &std::path::Path) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

/// `lan0-TxRx-3` is queue 3.
fn queue_index(name: &str) -> Option<u32> {
    name.rsplit_once('-')?.1.parse().ok()
}

/// The sleep syscalls of an architecture: `(nanosleep, clock_nanosleep)`.
fn sleep_syscalls(arch: &str) -> Option<(i64, i64)> {
    match arch {
        "x86_64" => Some((35, 230)),
        "aarch64" => Some((101, 115)),
        _ => None,
    }
}

/// `TIMER_ABSTIME` in the flags argument of `clock_nanosleep`.
const TIMER_ABSTIME: u64 = 1;

struct Ctx {
    irqs: Vec<irq::Irq>,
    interrupts: Option<irq::Interrupts>,
    irq_threads: Vec<task::Task>,
}

impl Ctx {
    fn queues(&self, irqs: &[u32]) -> Vec<Queue> {
        irqs.iter()
            .map(|n| {
                let info = self.irqs.iter().find(|i| i.irq == *n);
                let row = self.interrupts.as_ref().and_then(|i| i.row(&n.to_string()));
                let name = row
                    .map(|r| r.name.clone())
                    .or_else(|| info.and_then(|i| i.actions.first().cloned()))
                    .unwrap_or_default();
                Queue {
                    index: queue_index(&name),
                    irq: *n,
                    irq_affinity: info.and_then(|i| i.affinity.clone()),
                    irq_effective_affinity: info.and_then(|i| i.effective.clone()),
                    irq_thread: self
                        .irq_threads
                        .iter()
                        .find(|t| task::irq_thread(&t.stat.comm).is_some_and(|(i, _)| i == *n))
                        .map(|t| IrqThread { tid: t.tid, policy: t.stat.policy.short(), prio: t.stat.rt_priority }),
                    name,
                }
            })
            .collect()
    }
}

/// Runs `analyze`.
///
/// # Errors
/// When tracing is asked for (not built yet), the process or a declared thread does not exist,
/// or its threads cannot be listed.
pub fn run(env: &Env, args: &Args) -> Result<Report, Error> {
    if !args.static_only {
        return Err(Error::Refused("tracing is not built into this version: use `analyze --static`".into()));
    }
    let mut report = Report::new(env, "analyze", Cost::Light);
    let cpus = observe::cpus(env, &mut report);
    let tasks =
        task::process_tasks(&env.root, args.pid).map_err(|_| Error::Refused(format!("no process {}", args.pid)))?;
    report.unreadable(tasks.unreadable);
    let mut threads = tasks.items;
    if threads.is_empty() {
        return Err(Error::Refused(format!("no readable threads in process {}", args.pid)));
    }
    if let Some(t) = args.tids.iter().find(|t| !threads.iter().any(|x| x.tid == **t)) {
        return Err(Error::Refused(format!("thread {t} is not in process {}", args.pid)));
    }
    threads.sort_by_key(|t| t.tid);
    let critical = |t: &task::Task| args.tids.contains(&t.tid);
    let app_threads: Vec<&task::Task> = threads
        .iter()
        .filter(|t| if args.tids.is_empty() { t.stat.policy.is_rt() && !t.kthread() } else { critical(t) })
        .collect();

    // Host.
    let read_proc = |p: &str| first_line(&env.root.proc.join(p));
    let irqbalance = !task::pids_with_comm(&env.root, "irqbalance")?.is_empty();
    let cpu_dir = env.root.sys.join("devices/system/cpu");
    let mut governors: Vec<String> = (0..64)
        .filter_map(|c| first_line(&cpu_dir.join(format!("cpu{c}/cpufreq/scaling_governor"))))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    governors.dedup();
    let probe_cpu = cpus.isolated.first().or_else(|| cpus.housekeeping.first()).unwrap_or(0);
    let cstates: Vec<CState> = (0..16)
        .map_while(|n| {
            let d = cpu_dir.join(format!("cpu{probe_cpu}/cpuidle/state{n}"));
            Some(CState {
                name: first_line(&d.join("name"))?,
                disabled: first_line(&d.join("disable")).is_some_and(|v| v == "1"),
            })
        })
        .collect();
    let cmdline_rt = p_roc::cmdline::Cmdline::read(&env.root)
        .map(|c| c.rt_keys().into_iter().map(|(k, v)| (k.to_string(), v.map_or(true.into(), |v| v.into()))).collect())
        .unwrap_or_default();
    report.push(&Record::Host {
        online: p_roc::cpus::online(&env.root).ok(),
        isolated: cpus.isolated.clone(),
        nohz_full: cpus.sources.nohz_full.clone(),
        rcu_nocbs: cpus.sources.rcu_nocbs.clone(),
        housekeeping: cpus.housekeeping.clone(),
        sched_rt_runtime_us: read_proc("sys/kernel/sched_rt_runtime_us"),
        irqbalance,
        governors,
        cstates,
        cmdline_rt,
    });
    if irqbalance {
        report.findings.push(Finding {
            id: "irqbalance",
            severity: Severity::Warn,
            subject: Subject::Host,
            evidence: Vec::new(),
            recommendation: "irqbalance is running and moves IRQs at will; disable it on a realtime host and pin IRQs"
                .into(),
            changes: Vec::new(),
        });
    }

    // Process and threads.
    let status = std::fs::read_to_string(env.root.proc.join(args.pid.to_string()).join("status")).unwrap_or_default();
    let vm = task::parse_vm(&status);
    let main = threads.iter().find(|t| t.tid == args.pid).unwrap_or(&threads[0]);
    report.push(&Record::Process {
        pid: args.pid,
        comm: main.stat.comm.clone(),
        exe: task::exe(&env.root, args.pid).map(|p| p.display().to_string()),
        uid: main.status.uid,
        vm_rss_kb: vm.map(|v| v.rss_kb),
        vm_lck_kb: vm.map(|v| v.locked_kb),
        threads: threads.len(),
    });
    let sleeps = sleep_syscalls(env.arch);
    let mut syscall_denied = 0usize;
    let mut listed = 0usize;
    let mut other_shown = 0usize;
    for t in &threads {
        let rt = t.stat.policy.is_rt();
        let is_critical = critical(t);
        if !(rt || is_critical || other_shown < OTHER_THREADS_SHOWN) {
            continue;
        }
        other_shown += usize::from(!(rt || is_critical));
        listed += 1;
        let sc_path = env.root.proc.join(args.pid.to_string()).join("task").join(t.tid.to_string()).join("syscall");
        let sc = match std::fs::read_to_string(&sc_path) {
            Ok(s) => task::parse_syscall(&s),
            Err(_) => {
                syscall_denied += 1;
                None
            }
        };
        report.push(&Record::Thread {
            tid: t.tid,
            comm: t.stat.comm.clone(),
            policy: t.stat.policy.short(),
            rt_priority: rt.then_some(t.stat.rt_priority),
            affinity: t.status.cpus_allowed.clone(),
            last_cpu: t.stat.processor,
            voluntary_switches: t.status.switches.map(|s| s.voluntary),
            involuntary_switches: t.status.switches.map(|s| s.involuntary),
            utime_ticks: t.stat.utime,
            stime_ticks: t.stat.stime,
            syscall: sc.map(|s| match sleeps {
                Some((nano, _)) if s.nr == nano => "nanosleep".to_string(),
                Some((_, clock)) if s.nr == clock => {
                    format!("clock_nanosleep({})", if s.args[1] & TIMER_ABSTIME != 0 { "absolute" } else { "relative" })
                }
                _ => format!("nr {}", s.nr),
            }),
            declared_critical: is_critical,
            class: None,
        });
        if let (true, Some((nano, clock)), Some(s)) = (rt, sleeps, sc) {
            let relative = s.nr == nano || (s.nr == clock && s.args[1] & TIMER_ABSTIME == 0);
            if relative {
                report.findings.push(Finding {
                    id: "relative-sleep",
                    severity: Severity::Warn,
                    subject: Subject::Thread { tid: t.tid, comm: t.stat.comm.clone() },
                    evidence: vec![Metric::new("syscall_nr", s.nr), Metric::new("seen", "once, in a snapshot")],
                    recommendation: "the thread sleeps for a relative time, so every activation drifts by its own runtime; sleep until an absolute time (clock_nanosleep with TIMER_ABSTIME)".into(),
                    changes: Vec::new(),
                });
            }
        }
    }
    if syscall_denied > 0 {
        report.unreadable([Unreadable {
            source: "proc/<pid>/task/<tid>/syscall".into(),
            reason: format!("unreadable for {syscall_denied} threads (needs CAP_SYS_PTRACE)"),
        }]);
    }

    // Placement and memory.
    let rt_user: Vec<&task::Task> = threads.iter().filter(|t| t.stat.policy.is_rt() && !t.kthread()).collect();
    if !cpus.isolated.is_empty() {
        for t in &rt_user {
            let outside = t.status.cpus_allowed.intersection(&cpus.housekeeping);
            if !outside.is_empty() {
                let inside = t.status.cpus_allowed.intersection(&cpus.isolated);
                report.findings.push(Finding {
                    id: "rt-on-housekeeping",
                    severity: Severity::Warn,
                    subject: Subject::Thread { tid: t.tid, comm: t.stat.comm.clone() },
                    evidence: vec![
                        Metric::new("cpus_allowed", &t.status.cpus_allowed),
                        Metric::new("housekeeping_allowed", &outside),
                    ],
                    recommendation:
                        "an RT thread may run on a housekeeping CPU; restrict its affinity to the isolated set".into(),
                    changes: if inside.is_empty() {
                        Vec::new()
                    } else {
                        vec![Change::SetAffinity { tid: t.tid, from: t.status.cpus_allowed.clone(), to: inside }]
                    },
                });
            }
        }
    }
    let mut by_cpu: BTreeMap<u32, Vec<&task::Task>> = BTreeMap::new();
    for t in &rt_user {
        by_cpu.entry(t.stat.processor).or_default().push(t);
    }
    let used: CpuSet = rt_user.iter().map(|t| t.stat.processor).collect();
    let mut free = cpus.isolated.difference(&used).iter().collect::<Vec<_>>().into_iter();
    for (cpu, group) in by_cpu.iter().filter(|(_, g)| g.len() > 1) {
        // The highest priority stays; the others are candidates to move.
        let mut sorted = group.clone();
        sorted.sort_by_key(|t| std::cmp::Reverse(t.stat.rt_priority));
        for t in sorted.iter().skip(1) {
            let target = free.next();
            report.findings.push(Finding {
                id: "shared-rt-core",
                severity: Severity::Warn,
                subject: Subject::Thread { tid: t.tid, comm: t.stat.comm.clone() },
                evidence: vec![
                    Metric::new("cpu", cpu),
                    Metric::new("threads_on_cpu", group.iter().map(|g| g.tid).collect::<Vec<_>>()),
                ],
                recommendation: "two RT threads of the process run on one CPU, so one waits behind the other; give each its own isolated CPU".into(),
                changes: target
                    .filter(|c| t.status.cpus_allowed.contains(*c))
                    .map(|c| Change::SetAffinity { tid: t.tid, from: t.status.cpus_allowed.clone(), to: [c].into_iter().collect() })
                    .into_iter()
                    .collect(),
            });
        }
    }
    if let Some(v) = vm.filter(|v| v.locked_kb < v.rss_kb && !rt_user.is_empty()) {
        report.findings.push(Finding {
            id: "no-mlock",
            severity: Severity::Warn,
            subject: Subject::Host,
            evidence: vec![Metric::new("vm_lck_kb", v.locked_kb), Metric::new("vm_rss_kb", v.rss_kb)],
            recommendation: "part of the process's memory is not locked: a page fault in a cyclic activation costs far more than the period allows; call mlockall(MCL_CURRENT | MCL_FUTURE) at start".into(),
            changes: Vec::new(),
        });
    }

    // Endpoints.
    let fds = p_roc::fd::fds(&env.root, args.pid).ok();
    if fds.is_none() {
        report.unreadable([Unreadable {
            source: format!("proc/{}/fd", args.pid),
            reason: "unreadable (needs CAP_SYS_PTRACE for another user's process)".into(),
        }]);
    }
    let fds = fds.unwrap_or_default();
    let xdp_candidates: Vec<u64> =
        fds.iter().filter_map(|f| if let FdKind::Socket { inode } = f.kind { Some(inode) } else { None }).collect();
    let socks = net::sockets(&env.root, &xdp_candidates)?;
    report.unreadable(socks.unreadable);
    let sockets: BTreeMap<u64, SocketKind> = socks.items.into_iter().collect();
    let ifmap = net::ifindex_map(&env.root).unwrap_or_default();
    let pci_nics = pci::network_devices(&env.root);
    let nics = match pci_nics {
        Ok(s) => {
            report.unreadable(s.unreadable);
            s.items
        }
        Err(e) => {
            report.unreadable([Unreadable::new("sys/bus/pci/devices", &e)]);
            Vec::new()
        }
    };

    let mut ifaces: BTreeMap<String, &'static str> = BTreeMap::new();
    let mut tied_pci: Vec<(String, &'static str)> = Vec::new();
    let mut igh = false;
    let mut unresolved = 0usize;
    for f in &fds {
        let mut rec = Record::Endpoint {
            fd: f.fd,
            endpoint: "other",
            ifindex: None,
            interface: None,
            proto: None,
            port: None,
            path: None,
            pci: None,
        };
        if let Record::Endpoint { endpoint, ifindex, interface, proto, port, path, pci, .. } = &mut rec {
            match &f.kind {
                FdKind::Socket { inode } => match sockets.get(inode) {
                    Some(SocketKind::Packet { ethertype, ifindex: i }) => {
                        *endpoint = "packet";
                        *proto = Some(format!("0x{ethertype:04x}"));
                        *ifindex = Some(*i);
                        *interface = ifmap.get(i).cloned();
                        match interface {
                            Some(n) => {
                                ifaces.entry(n.clone()).or_insert("packet socket");
                            }
                            None => unresolved += 1,
                        }
                    }
                    Some(SocketKind::Udp { port: p }) => {
                        *endpoint = "udp";
                        *port = Some(*p);
                    }
                    Some(SocketKind::Tcp { port: p }) => {
                        *endpoint = "tcp";
                        *port = Some(*p);
                    }
                    Some(SocketKind::Xdp) => *endpoint = "xdp",
                    None => {}
                },
                FdKind::Vfio { group } => {
                    *endpoint = "vfio";
                    *path = Some(format!("/dev/vfio/{group}"));
                    *pci = pci::vfio_group_devices(&env.root, *group).first().cloned();
                    tied_pci.extend(pci::vfio_group_devices(&env.root, *group).into_iter().map(|a| (a, "vfio")));
                }
                FdKind::Uio { n } => {
                    *endpoint = "uio";
                    *path = Some(format!("/dev/uio{n}"));
                    *pci = pci::uio_device(&env.root, *n);
                    tied_pci.extend(pci.clone().map(|a| (a, "uio")));
                }
                FdKind::Device { path: p } => {
                    *endpoint = "device";
                    *path = Some(p.clone());
                    igh |= p.starts_with("/dev/EtherCAT");
                }
            }
        }
        report.push(&rec);
    }
    for g in &env.config.fieldbus_interfaces {
        let Ok(glob) = Glob::new(g).map(|g| g.compile_matcher()) else { continue };
        for n in net::interfaces(&env.root).unwrap_or_default().into_iter().filter(|n| glob.is_match(n)) {
            ifaces.entry(n).or_insert("fieldbus_interfaces");
        }
    }

    // Interfaces and their IRQs.
    let irq_scan = irq::read_irqs(&env.root)?;
    report.unreadable(irq_scan.unreadable);
    let threads_scan = task::scan(&env.root, |s| s.comm.starts_with("irq/"))?;
    report.unreadable(threads_scan.unreadable);
    let ctx =
        Ctx { irqs: irq_scan.items, interrupts: irq::read_interrupts(&env.root).ok(), irq_threads: threads_scan.items };
    let pinned: CpuSet = app_threads
        .iter()
        .filter(|t| t.status.cpus_allowed.len() == 1)
        .flat_map(|t| t.status.cpus_allowed.iter())
        .collect();
    let app_prio = app_threads.iter().filter(|t| t.stat.policy.is_rt()).map(|t| t.stat.rt_priority).max();
    for (name, reason) in &ifaces {
        let Ok(interface) = net::interface(&env.root, name) else { continue };
        let (data, bad) = env.ethtool.query(name);
        report.unreadable(bad);
        let queues = ctx.queues(&interface.irqs);
        for q in &queues {
            let eff = q.irq_effective_affinity.as_ref().or(q.irq_affinity.as_ref());
            if let (Some(eff), Some(aff), false) = (eff, &q.irq_affinity, pinned.is_empty())
                && !eff.intersects(&pinned)
            {
                report.findings.push(Finding {
                    id: "irq-off-core",
                        severity: Severity::Warn,
                        subject: Subject::Irq { irq: q.irq, name: q.name.clone() },
                        evidence: vec![Metric::new("interface", name), Metric::new("irq_effective", eff), Metric::new("thread_cpus", &pinned)],
                        recommendation: "the receive IRQ of the process's interface is delivered to a CPU the application thread does not run on; pin it to the thread's CPU".into(),
                        changes: pinned
                            .first()
                            .map(|c| Change::SetIrqAffinity { irq: q.irq, from: aff.clone(), to: [c].into_iter().collect() })
                            .into_iter()
                            .collect(),
                });
            }
            if let (Some(t), Some(app)) = (&q.irq_thread, app_prio)
                && t.policy == Policy::Fifo.short()
                && t.prio < app
            {
                report.findings.push(Finding {
                    id: "irq-below-app",
                        severity: Severity::Warn,
                        subject: Subject::Irq { irq: q.irq, name: q.name.clone() },
                        evidence: vec![Metric::new("interface", name), Metric::new("irq_thread_prio", t.prio), Metric::new("app_prio", app)],
                        recommendation: "the IRQ thread runs at a lower priority than the application thread it feeds and is preempted by it; raise it above".into(),
                        changes: vec![Change::SetIrqThreadPriority {
                            irq: q.irq,
                            tid: t.tid,
                            from: u8::try_from(t.prio).unwrap_or(u8::MAX),
                            to: u8::try_from(app.saturating_add(1).min(u32::from(MAX_PROPOSED_PRIO))).unwrap_or(MAX_PROPOSED_PRIO),
                        }],
                });
            }
        }
        report.findings.extend(nic::interface_findings(&interface, &data));
        report.push(&Record::Interface {
            attached: nics
                .iter()
                .find(|n| Some(&n.address) == interface.pci.as_ref())
                .map_or(Attached::Kernel, |n| n.attached),
            reason,
            queues,
            coalesce_rx_usecs: data.coalesce.as_ref().and_then(|c| c.rx_usecs),
            eee_enabled: data.eee.as_ref().map(|e| e.enabled),
            interface,
        });
    }

    // Kernel bypass.
    for nic in nics.iter().filter(|n| n.attached.is_bypass()) {
        let via = tied_pci.iter().find(|(a, _)| *a == nic.address).map(|(_, v)| *v);
        let irqs: Vec<u32> = ctx
            .interrupts
            .as_ref()
            .map(|i| {
                i.rows.iter().filter(|r| r.name.contains(&nic.address)).filter_map(|r| r.id.parse().ok()).collect()
            })
            .unwrap_or_default();
        report.push(&Record::KernelBypass {
            pci: Some(nic.address.clone()),
            driver: nic.driver.clone(),
            attached: nic.attached,
            via: via.unwrap_or("pci_binding"),
            tied_to_process: via.is_some(),
            irqs: ctx.queues(&irqs),
            limits: "no netdev, no net tracepoints, no AF_PACKET: thread classes, memory, the device's IRQ placement and host settings are reported; per-interface flow analysis is not possible",
        });
    }
    if igh {
        report.push(&Record::KernelBypass {
            pci: None,
            driver: None,
            attached: Attached::Kernel,
            via: "igh_device",
            tied_to_process: true,
            irqs: Vec::new(),
            limits: "the IgH master drives the NIC through its own kernel driver: no netdev, no net tracepoints, no AF_PACKET for that NIC",
        });
    }
    report.push(&Record::Summary {
        backend: "static",
        tracing: false,
        threads_listed: listed,
        unresolved_packet_sockets: unresolved,
        not_available: "thread classes, sleep arguments over time, cycle chain, protocol decoding, faults per activation and deadline-miss need tracing (a later phase)",
    });
    finish(env, &mut report);
    Ok(report)
}
