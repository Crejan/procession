//! The library behind `pledge`.
//!
//! - [`agent`]: the SSH agent protocol and the parsers behind it (`SPEC.md`,
//!   section 10, step 1). Nothing there touches a key or a socket.
//! - [`policy`]: whether a local program may use a key (section 3).
//! - [`holder`]: the key holder, the process that holds the keys and parses
//!   nothing. [`agent_conn`], [`control`], [`serve`]: the reader process, which
//!   reads, checks, decides, asks and records (step 2, keys in files).
//! - [`record`], [`dialog`], [`mute`], [`paths`], [`peer`], [`cli`]: the rest
//!   of `pledge serve` and its command line.
//!
//! - [`approvals`], [`service_conn`], [`agents`], [`issue`], [`delegations`],
//!   [`answers`], [`config`], [`seam`]: approvals with keys in
//!   files (step 3): `service.sock`, the checks of `SPEC.md` section 4, the
//!   delegations `pledge agents start` issues, the store of answers.
//!
//! Ratings and ceilings are in `p_act::rating`; the shared exchange's codec in
//! `p_act::exchange`. The connection to the broker is not built.

pub mod agent;
pub mod agent_conn;
pub mod agents;
pub mod answers;
pub mod approvals;
pub mod broker_link;
pub mod broker_state;
pub mod certs;
pub mod cli;
pub mod config;
pub mod control;
pub mod delegations;
pub mod dialog;
pub mod error;
pub mod holder;
pub mod issue;
pub mod mute;
pub mod outside;
pub mod paths;
pub mod peer;
pub mod policy;
pub mod record;
pub mod seam;
pub mod serve;
pub mod service_conn;
pub mod shared;

#[cfg(test)]
mod approvals_tests;
#[cfg(test)]
mod broker_tests;
#[cfg(test)]
mod broker_tls_tests;
#[cfg(test)]
mod outside_tests;
#[cfg(test)]
mod testing;
