//! The library behind `pledge`.
//!
//! So far it holds two decisions: [`policy`], whether a local program may
//! use a key (`SPEC.md`, section 3), and [`rating`], whether a request for
//! approval is refused, asked about or signed at once (`doc/approvals.md`,
//! R3). The agent socket, the keys themselves and approvals are not built.

pub mod policy;
pub mod rating;
