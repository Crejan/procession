//! The thread table: `stat`, `status`, `sched`, and the scan of RT tasks.

use std::path::PathBuf;

use crate::cpuset::CpuSet;
use crate::error::Error;
use crate::root::{Root, Scan, Unreadable, numeric_entries, read};

/// `PF_KTHREAD` from `include/linux/sched.h`.
pub const PF_KTHREAD: u32 = 0x0020_0000;

/// Scheduling policy as reported in field 41 of `/proc/<tid>/stat`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Policy {
    /// `SCHED_OTHER`.
    Other,
    /// `SCHED_FIFO`.
    Fifo,
    /// `SCHED_RR`.
    Rr,
    /// `SCHED_BATCH`.
    Batch,
    /// `SCHED_IDLE`.
    Idle,
    /// `SCHED_DEADLINE`.
    Deadline,
    /// A number this version does not know.
    Unknown(u32),
}

impl Policy {
    /// From the kernel's number.
    #[must_use]
    pub fn from_raw(v: u32) -> Self {
        match v {
            0 => Self::Other,
            1 => Self::Fifo,
            2 => Self::Rr,
            3 => Self::Batch,
            5 => Self::Idle,
            6 => Self::Deadline,
            v => Self::Unknown(v),
        }
    }

    /// `SCHED_FIFO` or `SCHED_RR`.
    #[must_use]
    pub fn is_rt(self) -> bool {
        matches!(self, Self::Fifo | Self::Rr)
    }
}

impl Policy {
    /// The short lowercase name used in JSON: `other`, `fifo`, `rr`, `batch`, `idle`, `deadline`.
    #[must_use]
    pub fn short(self) -> String {
        match self {
            Self::Other => "other".into(),
            Self::Fifo => "fifo".into(),
            Self::Rr => "rr".into(),
            Self::Batch => "batch".into(),
            Self::Idle => "idle".into(),
            Self::Deadline => "deadline".into(),
            Self::Unknown(v) => format!("unknown-{v}"),
        }
    }
}

impl serde::Serialize for Policy {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.short())
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Other => f.write_str("SCHED_OTHER"),
            Self::Fifo => f.write_str("SCHED_FIFO"),
            Self::Rr => f.write_str("SCHED_RR"),
            Self::Batch => f.write_str("SCHED_BATCH"),
            Self::Idle => f.write_str("SCHED_IDLE"),
            Self::Deadline => f.write_str("SCHED_DEADLINE"),
            Self::Unknown(v) => write!(f, "policy {v}"),
        }
    }
}

/// One task as read from `/proc/<tgid>/task/<tid>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadInfo {
    /// Thread group (process) id.
    pub tgid: i32,
    /// Thread id.
    pub tid: i32,
    /// `comm`.
    pub comm: String,
    /// Real uid: the person who started the work.
    pub uid: u32,
    /// Real primary gid.
    pub gid: u32,
    /// Supplementary groups (`Groups:`).
    pub groups: Vec<u32>,
    /// Scheduling policy.
    pub policy: Policy,
    /// Real-time priority (1-99; 0 for non-RT).
    pub rt_priority: u8,
    /// `PF_KTHREAD` set.
    pub kthread: bool,
    /// Allowed CPUs (`Cpus_allowed_list`).
    pub cpus: CpuSet,
}

/// The fields of `/proc/<pid>/stat` that are used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stat {
    /// Field 1.
    pub pid: i32,
    /// Field 2.
    pub comm: String,
    /// Field 3: `R`, `S`, `D`, `Z`, ...
    pub state: char,
    /// Field 4.
    pub ppid: i32,
    /// Field 9.
    pub flags: u32,
    /// Field 14, in clock ticks.
    pub utime: u64,
    /// Field 15, in clock ticks.
    pub stime: u64,
    /// Field 19.
    pub nice: i32,
    /// Field 39: the CPU the task last ran on.
    pub processor: u32,
    /// Field 40.
    pub rt_priority: u32,
    /// Field 41.
    pub policy: Policy,
}

fn num<T: std::str::FromStr>(what: &str, v: &str) -> Result<T, Error>
where
    T::Err: std::fmt::Display,
{
    v.parse().map_err(|e| Error::parse(what, e))
}

/// Parses `/proc/<pid>/stat`. The comm may contain spaces and parentheses, so
/// it spans from the first `(` to the last `)`.
///
/// # Errors
/// When a needed field is missing or not a number.
pub fn parse_stat(s: &str) -> Result<Stat, Error> {
    let open = s.find('(').ok_or_else(|| Error::parse("stat", "missing '('"))?;
    let close = s.rfind(')').ok_or_else(|| Error::parse("stat", "missing ')'"))?;
    let pid = num("stat: pid", s[..open].trim())?;
    let comm = s[open + 1..close].to_string();
    let rest: Vec<&str> = s[close + 1..].split_whitespace().collect();
    // rest[0] is field 3 (state), so field n (1-based, man 5 proc) is rest[n - 3].
    let field = |n: usize| -> Result<&str, Error> {
        rest.get(n - 3).copied().ok_or_else(|| Error::parse("stat", format!("missing field {n}")))
    };
    Ok(Stat {
        pid,
        comm,
        state: field(3)?.chars().next().unwrap_or('?'),
        ppid: num("stat: ppid", field(4)?)?,
        flags: num("stat: flags", field(9)?)?,
        utime: num("stat: utime", field(14)?)?,
        stime: num("stat: stime", field(15)?)?,
        nice: num("stat: nice", field(19)?)?,
        processor: num("stat: processor", field(39)?)?,
        rt_priority: num("stat: rt_priority", field(40)?)?,
        policy: Policy::from_raw(num("stat: policy", field(41)?)?),
    })
}

/// The fields of `/proc/<pid>/status` that are used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// `Tgid`.
    pub tgid: i32,
    /// `Pid`.
    pub pid: i32,
    /// Real uid (first of the four `Uid:` values).
    pub uid: u32,
    /// Real gid (first of the four `Gid:` values).
    pub gid: u32,
    /// `Groups`.
    pub groups: Vec<u32>,
    /// `Cpus_allowed_list`.
    pub cpus_allowed: CpuSet,
}

/// Parses `/proc/<pid>/status`.
///
/// # Errors
/// When a needed field is missing or malformed.
pub fn parse_status(s: &str) -> Result<Status, Error> {
    let (mut tgid, mut pid, mut uid, mut gid, mut groups, mut cpus) = (None, None, None, None, None, None);
    for line in s.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        let value = value.trim();
        let first = || value.split_whitespace().next().unwrap_or_default();
        match key {
            "Tgid" => tgid = Some(num("status: Tgid", value)?),
            "Pid" => pid = Some(num("status: Pid", value)?),
            "Uid" => uid = Some(num("status: Uid", first())?),
            "Gid" => gid = Some(num("status: Gid", first())?),
            "Groups" => {
                groups =
                    Some(value.split_whitespace().map(|g| num("status: Groups", g)).collect::<Result<Vec<u32>, _>>()?);
            }
            "Cpus_allowed_list" => {
                cpus = Some(
                    CpuSet::parse_list(value)
                        .map_err(|source| Error::Cpus { what: "status: Cpus_allowed_list".into(), source })?,
                );
            }
            _ => {}
        }
    }
    let missing = |f: &str| Error::parse(format!("status: missing {f}"), "field absent");
    Ok(Status {
        tgid: tgid.ok_or_else(|| missing("Tgid"))?,
        pid: pid.ok_or_else(|| missing("Pid"))?,
        uid: uid.ok_or_else(|| missing("Uid"))?,
        gid: gid.ok_or_else(|| missing("Gid"))?,
        groups: groups.unwrap_or_default(),
        cpus_allowed: cpus.ok_or_else(|| missing("Cpus_allowed_list"))?,
    })
}

/// The fields of `/proc/<pid>/sched` that are used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sched {
    /// `policy`.
    pub policy: Policy,
    /// Kernel-internal priority (`99 - rt_priority` for RT tasks).
    pub prio: i32,
}

/// Parses `/proc/<pid>/sched` (needs `CONFIG_SCHED_DEBUG`).
///
/// # Errors
/// When `policy` or `prio` is missing or malformed.
pub fn parse_sched(s: &str) -> Result<Sched, Error> {
    let (mut policy, mut prio) = (None, None);
    for line in s.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        match key.trim() {
            "policy" => policy = Some(Policy::from_raw(num("sched: policy", value.trim())?)),
            "prio" => prio = Some(num("sched: prio", value.trim())?),
            _ => {}
        }
    }
    Ok(Sched {
        policy: policy.ok_or_else(|| Error::parse("sched: missing policy", "field absent"))?,
        prio: prio.ok_or_else(|| Error::parse("sched: missing prio", "field absent"))?,
    })
}

/// The `exe` link of a process, `None` when it cannot be read.
#[must_use]
pub fn exe(root: &Root, tgid: i32) -> Option<PathBuf> {
    std::fs::read_link(root.proc.join(tgid.to_string()).join("exe")).ok()
}

/// Reads one task. Returns `None` for tasks that are neither RT nor
/// `SCHED_DEADLINE`, so `status` is only read for the few that matter.
///
/// # Errors
/// When the task cannot be read (see [`Error::is_gone`]) or parsed.
pub fn read_thread(root: &Root, tgid: i32, tid: i32) -> Result<Option<ThreadInfo>, Error> {
    let dir = root.proc.join(tgid.to_string()).join("task").join(tid.to_string());
    let stat = parse_stat(&read(&dir.join("stat"))?)?;
    if !stat.policy.is_rt() && stat.policy != Policy::Deadline {
        return Ok(None);
    }
    let status = parse_status(&read(&dir.join("status"))?)?;
    Ok(Some(ThreadInfo {
        tgid,
        tid,
        comm: stat.comm,
        uid: status.uid,
        gid: status.gid,
        groups: status.groups,
        policy: stat.policy,
        rt_priority: u8::try_from(stat.rt_priority).unwrap_or(u8::MAX),
        kthread: stat.flags & PF_KTHREAD != 0,
        cpus: status.cpus_allowed,
    }))
}

/// All RT and `SCHED_DEADLINE` tasks. Tasks that vanish mid-scan are
/// skipped silently; unreadable or unparsable ones are listed in
/// [`Scan::unreadable`].
///
/// # Errors
/// When the process list itself cannot be read.
pub fn rt_threads(root: &Root) -> Result<Scan<ThreadInfo>, Error> {
    let mut scan = Scan::default();
    for tgid in numeric_entries(&root.proc)? {
        let Ok(tids) = numeric_entries(&root.proc.join(tgid.to_string()).join("task")) else { continue };
        for tid in tids {
            match read_thread(root, tgid, tid) {
                Ok(Some(t)) => scan.items.push(t),
                Ok(None) => {}
                Err(e) if e.is_gone() => {}
                Err(e) => scan.unreadable.push(Unreadable::new(format!("{tgid}/{tid}"), &e)),
            }
        }
    }
    Ok(scan)
}

/// One thread as `procs` and `sched` need it: `stat` for every thread,
/// `status` only for those `keep` accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Task {
    /// Thread group id.
    pub tgid: i32,
    /// Thread id.
    pub tid: i32,
    /// What `stat` says.
    pub stat: Stat,
    /// What `status` says.
    pub status: Status,
}

impl Task {
    /// `PF_KTHREAD` set.
    #[must_use]
    pub fn kthread(&self) -> bool {
        self.stat.flags & PF_KTHREAD != 0
    }
}

/// Scans every thread of every process. `keep` sees each thread's `stat`
/// and decides whether `status` is read and the thread returned, so a scan
/// for a few threads does not read the files of thousands. Threads that exit
/// mid-scan are skipped silently; unreadable or unparsable ones are listed.
///
/// # Errors
/// When the process list itself cannot be read.
pub fn scan(root: &Root, keep: impl Fn(&Stat) -> bool) -> Result<Scan<Task>, Error> {
    let mut out = Scan::default();
    for tgid in numeric_entries(&root.proc)? {
        let Ok(tids) = numeric_entries(&root.proc.join(tgid.to_string()).join("task")) else { continue };
        for tid in tids {
            match read_task(root, tgid, tid, &keep) {
                Ok(Some(t)) => out.items.push(t),
                Ok(None) => {}
                Err(e) if e.is_gone() => {}
                Err(e) => out.unreadable.push(Unreadable::new(format!("{tgid}/{tid}"), &e)),
            }
        }
    }
    Ok(out)
}

fn read_task(root: &Root, tgid: i32, tid: i32, keep: &impl Fn(&Stat) -> bool) -> Result<Option<Task>, Error> {
    let dir = root.proc.join(tgid.to_string()).join("task").join(tid.to_string());
    let stat = parse_stat(&read(&dir.join("stat"))?)?;
    if !keep(&stat) {
        return Ok(None);
    }
    let status = parse_status(&read(&dir.join("status"))?)?;
    Ok(Some(Task { tgid, tid, stat, status }))
}

/// `schedstat` of a thread: ns on CPU, ns waiting, timeslices run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SchedStat {
    /// Time spent on the CPU, ns.
    pub run_ns: u64,
    /// Time spent waiting on a runqueue, ns.
    pub wait_ns: u64,
    /// Number of timeslices.
    pub slices: u64,
}

/// Parses `/proc/<pid>/schedstat`.
///
/// # Errors
/// When it does not hold three numbers.
pub fn parse_schedstat(s: &str) -> Result<SchedStat, Error> {
    let v: Vec<&str> = s.split_whitespace().collect();
    let [a, b, c] = v[..] else { return Err(Error::parse("schedstat", "expected three fields")) };
    Ok(SchedStat { run_ns: num("schedstat", a)?, wait_ns: num("schedstat", b)?, slices: num("schedstat", c)? })
}

/// Context switches of a thread from `status`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Switches {
    /// `voluntary_ctxt_switches`.
    pub voluntary: u64,
    /// `nonvoluntary_ctxt_switches`.
    pub involuntary: u64,
}

/// Parses the context switch counters out of `/proc/<pid>/status`.
///
/// # Errors
/// When either counter is missing or not a number.
pub fn parse_switches(s: &str) -> Result<Switches, Error> {
    let (mut v, mut n) = (None, None);
    for line in s.lines() {
        let Some((key, value)) = line.split_once(':') else { continue };
        match key {
            "voluntary_ctxt_switches" => v = Some(num("status: voluntary_ctxt_switches", value.trim())?),
            "nonvoluntary_ctxt_switches" => n = Some(num("status: nonvoluntary_ctxt_switches", value.trim())?),
            _ => {}
        }
    }
    match (v, n) {
        (Some(voluntary), Some(involuntary)) => Ok(Switches { voluntary, involuntary }),
        _ => Err(Error::parse("status: context switches", "field absent")),
    }
}

/// The IRQ number of an IRQ thread, from a comm such as `irq/125-lan0-TxRx-0`.
#[must_use]
pub fn irq_thread(comm: &str) -> Option<(u32, &str)> {
    let rest = comm.strip_prefix("irq/")?;
    let (n, name) = rest.split_once('-')?;
    Some((n.parse().ok()?, name))
}

/// The pids whose `comm` is exactly `comm` (for example `irqbalance`).
///
/// # Errors
/// When the process list cannot be read.
pub fn pids_with_comm(root: &Root, comm: &str) -> Result<Vec<i32>, Error> {
    Ok(numeric_entries(&root.proc)?
        .into_iter()
        .filter(|pid| {
            std::fs::read_to_string(root.proc.join(pid.to_string()).join("comm")).is_ok_and(|c| c.trim_end() == comm)
        })
        .collect())
}
