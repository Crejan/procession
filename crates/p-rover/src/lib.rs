//! p-rover: diagnoses realtime behaviour of a Linux host. One function per
//! subcommand, each taking an [`Env`] (roots, config, clock) and returning a
//! [`Report`]; the `prover` binary only parses arguments and prints.

pub mod config;
pub mod env;
pub mod error;
pub mod observe;
pub mod render;
pub mod report;

pub use config::Config;
pub use env::{Clock, Env, FakeClock, SystemClock};
pub use error::Error;
pub use report::{Cost, Finding, Metric, Report, Severity, Subject};
