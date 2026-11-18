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
    /// Field 9.
    pub flags: u32,
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
        flags: num("stat: flags", field(9)?)?,
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
