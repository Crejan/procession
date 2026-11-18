//! p-usher's view on `/proc` and `/sys`: a thin wrapper over p-roc's readers
//! that keeps the `ProcFs` API (anyhow errors, warnings logged for tasks that
//! could not be parsed). The parsers themselves live in `p_roc::task`.

use std::path::{Path, PathBuf};

use anyhow::Result;
use p_roc::{Root, cpus, task};

pub use p_roc::task::{PF_KTHREAD, Sched, Stat, Status, parse_sched, parse_stat, parse_status};

use crate::cpuset::CpuSet;
use crate::model::ThreadInfo;

/// A view on `/proc` and `/sys`.
#[derive(Clone, Debug)]
pub struct ProcFs {
    root: Root,
}

impl ProcFs {
    pub fn new(proc_root: impl Into<PathBuf>, sys_root: impl Into<PathBuf>) -> Self {
        Self { root: Root::new(proc_root, sys_root, Path::new("/dev")) }
    }

    pub fn system() -> Self {
        Self { root: Root::system() }
    }

    pub fn online_cpus(&self) -> Result<CpuSet> {
        Ok(cpus::online(&self.root)?)
    }

    pub fn isolated_cpus(&self) -> Result<CpuSet> {
        Ok(cpus::sysfs_isolated(&self.root)?)
    }

    pub fn exe(&self, tgid: i32) -> Option<PathBuf> {
        task::exe(&self.root, tgid)
    }

    /// Reads one task. Returns `None` for tasks that are neither RT nor
    /// `SCHED_DEADLINE`, so `status` is only read for the few that matter.
    pub fn read_thread(&self, tgid: i32, tid: i32) -> Result<Option<ThreadInfo>> {
        Ok(task::read_thread(&self.root, tgid, tid)?)
    }

    /// All RT and `SCHED_DEADLINE` tasks. Tasks that vanish mid-scan are
    /// skipped silently; unparsable ones are logged and skipped.
    pub fn rt_threads(&self) -> Result<Vec<ThreadInfo>> {
        let scan = task::rt_threads(&self.root)?;
        for u in &scan.unreadable {
            log_warn!("skipping task {}: {}", crate::text::clean(&u.source, 128), crate::text::clean(&u.reason, crate::text::ERROR_MAX));
        }
        Ok(scan.items)
    }
}
