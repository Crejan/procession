//! How a run ended, named rather than numbered.

use serde::{Deserialize, Serialize};

/// The outcome of one operation against a repository.
///
/// Front ends match on this, never on an exit code or on a line of output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// Finished; for a backup, a snapshot was stored.
    Ok,
    /// A snapshot was stored, but some source files could not be read.
    Incomplete,
    /// Did not run because a precondition said to wait (network, power, an
    /// unreachable target). Not an attempt, and never a success.
    Deferred,
    /// The target holds no repository.
    NoRepository,
    /// Another operation holds the repository.
    Locked,
    /// The repository refused the password.
    WrongPassword,
    /// Ran past its deadline and was stopped.
    TimedOut,
    /// Could not be started at all.
    NotRun,
    /// Anything else.
    Failed,
}

impl Outcome {
    /// Whether this outcome stored a snapshot, and so resets the age of the
    /// backup. `Deferred` does not: a run that only decided to wait must not
    /// read as a success.
    pub fn stored_snapshot(self) -> bool {
        matches!(self, Outcome::Ok | Outcome::Incomplete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_runs_that_stored_a_snapshot_count_as_success() {
        assert!(Outcome::Ok.stored_snapshot());
        assert!(Outcome::Incomplete.stored_snapshot());
        for other in [
            Outcome::Deferred,
            Outcome::NoRepository,
            Outcome::Locked,
            Outcome::WrongPassword,
            Outcome::TimedOut,
            Outcome::NotRun,
            Outcome::Failed,
        ] {
            assert!(!other.stored_snapshot(), "{other:?}");
        }
    }
}
