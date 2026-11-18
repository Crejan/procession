//! The library behind `page`, the broker of the approval system.
//!
//! - [`site`]: persons, hosts and keys, read from a file.
//! - [`register`]: the delegations the broker knows.
//! - [`core`]: the state and rules, without I/O: checks, the queue, the
//!   clearance, the standing, the log.
//! - The messages of the connections are `p_act::exchange` and `p_act::broker`.
//! - [`net`]: the two connections over any async byte stream; [`tls`]: the
//!   TLS around them.
//!
//! `doc/approval-connections.md` is the specification; `SPEC.md` the contract.

pub mod admin;
pub mod certs;
pub mod config;
pub mod core;
pub mod crypto;
pub mod log;
pub mod net;
pub mod perm;
pub mod register;
pub mod site;
#[cfg(feature = "test-support")]
pub mod testing;
pub mod tls;
