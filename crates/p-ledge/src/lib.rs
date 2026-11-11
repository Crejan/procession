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
//! Ratings and ceilings are in `p_act::rating`. Approvals (`service.sock`,
//! delegations) are step 3 and not built.

pub mod agent;
pub mod agent_conn;
pub mod cli;
pub mod control;
pub mod dialog;
pub mod error;
pub mod holder;
pub mod mute;
pub mod paths;
pub mod peer;
pub mod policy;
pub mod record;
pub mod serve;
pub mod shared;

#[cfg(test)]
mod testing;
