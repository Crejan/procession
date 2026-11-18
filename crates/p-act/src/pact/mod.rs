//! `pact`, the agent's signer (`proposals/pact.md`): holds the agent's key and
//! certificate, turns the model's tool calls into signed calls, and sends them.
//! Behind the cargo feature `pact`; the library the three programs use does not
//! contain any of it.
//!
//! What is here does not depend on how bytes reach a service: the
//! [`transport::Transport`] trait is the one seam, and the HTTP client is a
//! module that is added to it later.

pub mod bundle;
pub mod catalogue;
pub mod cli;
pub mod compose;
pub mod http;
pub mod mcp;
pub mod outcome;
pub mod rt;
pub mod sshsig;
pub mod transport;

#[cfg(test)]
pub(crate) mod fixture;

use std::time::Duration;

/// A service the bundle names: the only ones `pact` talks to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    /// The host's name as the site project has it.
    pub host: String,
    /// The service's name on that host.
    pub name: String,
    /// Where to send its MCP requests.
    pub url: String,
}

/// The waits `pact` signs for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// The deadline of a call that does not ask for less: 1 to 600 seconds.
    pub deadline_seconds: u32,
    /// The shortest wait `pact` will sign. A test option of the command line, never in the bundle.
    pub min_wait_seconds: u32,
}

impl Settings {
    /// The longest wait the services accept (formats section 3: ten minutes).
    pub const MAX_DEADLINE_SECONDS: u32 = crate::limits::MAX_DEADLINE_AHEAD_SECONDS as u32;
    /// The default setting.
    pub const DEFAULT_DEADLINE_SECONDS: u32 = 120;
    /// The default floor, or the setting if that is smaller.
    pub const DEFAULT_MIN_WAIT_SECONDS: u32 = 10;

    /// The floor is `min_wait_seconds` if given, else 10, and never above the setting.
    #[must_use]
    pub fn new(deadline_seconds: u32, min_wait_seconds: Option<u32>) -> Settings {
        let floor = min_wait_seconds.unwrap_or(Self::DEFAULT_MIN_WAIT_SECONDS).max(1);
        Settings { deadline_seconds, min_wait_seconds: floor.min(deadline_seconds) }
    }
}

/// While a call waits, a progress notification goes to the model's client this often (proposals/pact.md (e)).
pub const PROGRESS_INTERVAL: Duration = Duration::from_secs(15);
/// The one text of every progress notification. Nothing a service sent is ever relayed.
pub const PROGRESS_TEXT: &str = "waiting for an answer";
/// At most this many calls wait in `pact` at once, as in the service.
pub const MAX_WAITING: usize = 16;
