//! The library behind `page`, the broker of the approval system.
//!
//! - [`site`]: persons, hosts and keys, read from a file.
//! - [`register`]: the delegations the broker knows.
//! - [`core`]: the state and rules, without I/O: checks, the queue, the
//!   clearance, the standing, the log.
//! - [`wire`]: the messages of the connections that are the broker's own; the
//!   shared exchange is `p_act::exchange`.
//! - [`net`]: the two connections over any async byte stream; [`tls`]: the
//!   TLS around them.
//!
//! `doc/approval-connections.md` is the specification; `SPEC.md` the contract.

pub mod config;
pub mod core;
pub mod crypto;
pub mod keygen;
pub mod log;
pub mod net;
pub mod register;
pub mod site;
pub mod tls;
pub mod wire;
