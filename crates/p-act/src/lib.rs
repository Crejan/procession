//! The vocabulary the approval system's programs share, and nothing else.
//!
//! `doc/approval-formats.md` is the specification; `doc/approvals.md` section 1
//! defines the terms. This crate has no policy, no sockets and no I/O beyond
//! running `ssh-keygen`.
//!
//! - [`rating`]: how bad an action can be, and the ceilings that follow.
//! - [`Call`], [`Request`], [`Clearance`]: documents that are parsed from bytes
//!   and keep those bytes. Nothing is ever re-serialised: what is signed and
//!   verified is the bytes a document was parsed from, or the bytes it was
//!   written to once.
//! - [`sign`]: signing and verifying with `ssh-keygen -Y`, one function per
//!   document type and direction, and reading the person out of a signature.
//! - [`DocumentHash`]: `sha256:<hex>` of a document's bytes.

mod error;
mod hash;
mod object;
mod request;
mod text;
mod time;

pub mod call;
pub mod clearance;
pub mod rating;
pub mod sign;

pub use call::{Call, CallContent, CallId, ServiceId};
pub use clearance::Clearance;
pub use error::ParseError;
pub use hash::{Document, DocumentHash};
pub use request::Request;
pub use time::Timestamp;
