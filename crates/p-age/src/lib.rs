//! The library behind `page`, the broker.
//!
//! So far it holds one thing: [`register`], the delegations the broker knows
//! and whether a request under one of them may be passed on. The connections,
//! the site project's data and the clearance signature are not built; see
//! `SPEC.md`.

pub mod register;
