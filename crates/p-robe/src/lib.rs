//! `probe`'s library: a host's diagnostics as a fixed table of rated verbs, the
//! dispatcher that runs them, and the service that offers them to agents. The
//! binary (`main.rs`) is thin: it reads the command line and calls these.
//! What both parts do is in `SPEC.md`.
//!
//! The HTTP transport that carries [`mcp::Mcp`] is not built (see
//! `proposals/REPORT.md`); everything else of the service is.

pub mod answer;
pub mod audit;
pub mod certificate;
pub mod clock;
pub mod config;
pub mod dispatch;
pub mod json;
pub mod kit;
pub mod lock;
pub mod mcp;
pub mod outcome;
pub mod pledge;
pub mod rate;
pub mod rules;
pub mod runner;
pub mod serve;
pub mod service;
#[cfg(test)]
mod service_tests;
pub mod setup;
pub mod store;
pub mod table;
#[cfg(test)]
mod testdir;
#[cfg(feature = "test-verbs")]
pub mod testverbs;
