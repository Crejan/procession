//! The library behind `pledge`.
//!
//! So far it holds two things: [`agent`], the SSH agent protocol and the
//! parsers behind it (`SPEC.md`, section 10, step 1), and [`policy`], whether a
//! local program may use a key (section 3). Ratings and ceilings are in
//! `p_act::rating`. The SSH agent socket, the keys themselves and
//! approvals are not built.

pub mod agent;
pub mod policy;
