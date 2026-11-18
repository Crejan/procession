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
//! - [`peer`]: who is on the other end of a Unix socket (the only module without the feature `formats`).

#[cfg(feature = "formats")]
mod error;
#[cfg(feature = "formats")]
mod hash;
#[cfg(feature = "formats")]
mod object;
#[cfg(feature = "formats")]
mod request;
#[cfg(feature = "formats")]
mod text;
#[cfg(feature = "formats")]
mod time;

#[cfg(feature = "formats")]
pub mod broker;
#[cfg(feature = "formats")]
pub mod call;
#[cfg(feature = "formats")]
pub mod clearance;
#[cfg(feature = "formats")]
pub mod exchange;
#[cfg(feature = "formats")]
pub mod limits;
#[cfg(feature = "pact")]
pub mod pact;
#[cfg(unix)]
pub mod peer;
#[cfg(feature = "formats")]
pub mod rating;
#[cfg(all(feature = "formats", unix))]
pub mod settings;
#[cfg(feature = "formats")]
pub mod sign;

#[cfg(feature = "formats")]
pub use call::{Call, CallContent, CallId, NotShowable, ServiceId};
#[cfg(feature = "formats")]
pub use clearance::Clearance;
#[cfg(feature = "formats")]
pub use error::ParseError;
#[cfg(feature = "formats")]
pub use hash::{Document, DocumentHash};
#[cfg(feature = "formats")]
pub use request::Request;
#[cfg(feature = "formats")]
pub use time::Timestamp;
