//! The data p-usher reasons about.

use std::fmt;
use std::path::PathBuf;
use std::time::SystemTime;

use serde::Deserialize;

use crate::cpuset::CpuSet;
pub use p_roc::task::{Policy, ThreadInfo};

/// What p-usher decided for a violating thread. The decision is the same in
/// both modes; `Intervention::enforced` tells whether it was applied.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Action {
    Restrict,
    Move,
    Failed,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Restrict => "restrict",
            Self::Move => "move",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Enforce,
    Report,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Intervention {
    pub host: String,
    pub at: SystemTime,
    pub tgid: i32,
    pub tid: i32,
    pub comm: String,
    pub exe: Option<PathBuf>,
    pub uid: u32,
    pub user: String,
    /// Primary gid plus supplementary groups; lets notifiers route on groups.
    pub gids: Vec<u32>,
    pub policy: Policy,
    pub rt_priority: u8,
    pub cpus_before: CpuSet,
    /// The target affinity; applied iff `enforced` and `action != Failed`.
    pub cpus_after: CpuSet,
    pub action: Action,
    /// False in report mode; `Failed` implies true.
    pub enforced: bool,
}
