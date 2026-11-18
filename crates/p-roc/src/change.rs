//! `Change`: what a tool does to a thread or an IRQ, carrying the value it
//! replaces so it can be checked before it is applied and reverted after.
//! The data model comes first; `apply` and the ledger arrive with the
//! writers (`Knobs`).

use serde::Serialize;

use crate::cpuset::CpuSet;
use crate::task::Policy;

/// One change, with the value it replaces.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Change {
    /// `sched_setaffinity` of a thread.
    SetAffinity {
        /// The thread.
        tid: i32,
        /// The live value.
        from: CpuSet,
        /// The wanted value.
        to: CpuSet,
    },
    /// Scheduler policy and RT priority of a thread.
    SetPolicy {
        /// The thread.
        tid: i32,
        /// The live value.
        from: (Policy, u8),
        /// The wanted value.
        to: (Policy, u8),
    },
    /// Nice value of a thread.
    SetNice {
        /// The thread.
        tid: i32,
        /// The live value.
        from: i8,
        /// The wanted value.
        to: i8,
    },
    /// `smp_affinity_list` of an IRQ.
    SetIrqAffinity {
        /// The IRQ.
        irq: u32,
        /// The live value.
        from: CpuSet,
        /// The wanted value.
        to: CpuSet,
    },
    /// RT priority of an IRQ thread.
    SetIrqThreadPriority {
        /// The IRQ.
        irq: u32,
        /// The IRQ thread.
        tid: i32,
        /// The live value.
        from: u8,
        /// The wanted value.
        to: u8,
    },
}

impl Change {
    /// The change that undoes this one: `from` and `to` swapped.
    #[must_use]
    pub fn revert(&self) -> Change {
        match self.clone() {
            Self::SetAffinity { tid, from, to } => Self::SetAffinity { tid, from: to, to: from },
            Self::SetPolicy { tid, from, to } => Self::SetPolicy { tid, from: to, to: from },
            Self::SetNice { tid, from, to } => Self::SetNice { tid, from: to, to: from },
            Self::SetIrqAffinity { irq, from, to } => Self::SetIrqAffinity { irq, from: to, to: from },
            Self::SetIrqThreadPriority { irq, tid, from, to } => {
                Self::SetIrqThreadPriority { irq, tid, from: to, to: from }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revert_swaps_and_round_trips() {
        let c = Change::SetAffinity { tid: 7, from: "0-3".parse().unwrap(), to: "2-3".parse().unwrap() };
        let r = c.revert();
        assert_eq!(r, Change::SetAffinity { tid: 7, from: "2-3".parse().unwrap(), to: "0-3".parse().unwrap() });
        assert_eq!(r.revert(), c);
    }

    #[test]
    fn serializes_tagged() {
        let c = Change::SetPolicy { tid: 1, from: (Policy::Other, 0), to: (Policy::Fifo, 50) };
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"{"kind":"set_policy","tid":1,"from":["other",0],"to":["fifo",50]}"#
        );
    }
}
