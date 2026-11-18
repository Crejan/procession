//! p-roc: reads, and where asked writes, what the kernel exposes about CPUs,
//! threads, IRQs, sockets and devices. No daemon, no CLI, no policy.
//!
//! Every reader works on a [`Root`] so tests run against fixture trees on any
//! OS. A scan returns what it read plus the sources it could not
//! ([`Unreadable`]) instead of failing as a whole.

pub mod change;
pub mod cmdline;
pub mod cpuset;
pub mod cpus;
pub mod error;
pub mod irq;
pub mod root;
pub mod sys;
pub mod task;

pub use cpuset::{CpuSet, CpuSetError, MAX_CPU};
pub use error::Error;
pub use root::{Root, Scan, Unreadable};
pub use task::{Policy, ThreadInfo};
