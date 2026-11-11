//! The library behind `pledge`.
//!
//! So far it holds three things: [`agent`], the SSH agent protocol and the
//! parsers behind it (`SPEC.md`, section 10, step 1); [`policy`], whether a
//! local program may use a key (section 3); and [`rating`], whether a request
//! for approval is refused, asked about or signed at once
//! (`doc/approvals.md`, R4). The SSH agent socket, the keys themselves and
//! approvals are not built.

pub mod agent;
pub mod policy;
pub mod rating;
