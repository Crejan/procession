//! The library behind p-reserve.
//!
//! Every rule a front end shows or acts on lives here once: what a run's
//! outcome is called, how old a backup may get before it is overdue or stale,
//! and which source last succeeded to which target. The CLI, the daemon and
//! the GUI read these; none of them derives its own.
//!
//! The repository itself is behind [`engine::Engine`]. No engine is
//! implemented yet; see `crates/p-reserve/SPEC.md`, "Order of work".

pub mod engine;
pub mod freshness;
pub mod health;
pub mod ledger;
pub mod outcome;
pub mod textfile;

pub use freshness::{Freshness, Thresholds};
pub use ledger::{Entry, Ledger, Pair, Run};
pub use outcome::{Level, Outcome};
