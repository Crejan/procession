//! The SSH agent protocol and the parsers behind it (`SPEC.md`, sections 3
//! and 10, step 1). Nothing here touches a key or a socket: it reads bytes
//! and says what they are, or why they are refused. The process that holds
//! the keys parses nothing, so this is what the reading process uses.
//!
//! - [`message`]: framing, the three messages understood, the replies.
//! - [`sign_content`]: the strict parser for what may be signed.
//! - [`binding`]: `session-bind@openssh.com` and the state of a connection.
//! - [`host_key`], [`known_hosts`]: verifying and naming the host.
//! - [`wire`], [`text`]: encodings and what may be shown.

pub mod binding;
pub mod host_key;
pub mod known_hosts;
pub mod message;
pub mod sign_content;
pub mod text;
pub mod wire;

#[cfg(test)]
mod testing;

use std::fmt;

/// Why a signing request was refused before anyone was asked. Each is
/// recorded (`SPEC.md`, section 6) under its [`label`](Refusal::label).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// SSHSIG in a namespace the approval system's own keys use.
    ReservedNamespace,
    /// Data that is neither a login nor an SSHSIG signature the SSH agent
    /// can read and show as it is.
    Unrecognised,
    /// A login without a verified host binding, while one is required.
    HostNotVerified,
    /// The connection is an agent-forwarding channel.
    Forwarded,
    /// A bind on the connection was rejected.
    BindFailed,
    /// The login is for another session or host than the binding.
    SessionMismatch,
}

impl Refusal {
    /// A short stable name, for the record and logs.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ReservedNamespace => "reserved-namespace",
            Self::Unrecognised => "unrecognised",
            Self::HostNotVerified => "host-not-verified",
            Self::Forwarded => "forwarded",
            Self::BindFailed => "bind-failed",
            Self::SessionMismatch => "session-mismatch",
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReservedNamespace => "the signature is in a namespace reserved for approvals",
            Self::Unrecognised => "the data is not a login or a signature that can be shown as it is",
            Self::HostNotVerified => "the login does not prove which host it is for",
            Self::Forwarded => "the connection is an SSH agent forwarding channel",
            Self::BindFailed => "a session binding on this connection was rejected",
            Self::SessionMismatch => "the login is for another session or host than the one bound",
        })
    }
}
