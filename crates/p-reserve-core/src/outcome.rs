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

/// How loud a state is. The order is the exit code of `preserve health`
/// (0, 1, 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Level {
    Ok,
    /// Worth naming; not an alarm.
    Warning,
    Critical,
}

impl Level {
    /// The exit code of `preserve health`: 0, 1 or 2.
    pub fn exit_code(self) -> u8 {
        self as u8
    }
}

impl Outcome {
    /// Every outcome, best first; the order is [`Outcome::severity`].
    pub const ALL: [Outcome; 9] = [
        Outcome::Ok,
        Outcome::Deferred,
        Outcome::Incomplete,
        Outcome::Locked,
        Outcome::TimedOut,
        Outcome::NoRepository,
        Outcome::WrongPassword,
        Outcome::NotRun,
        Outcome::Failed,
    ];

    /// The kebab-case name, as written to the ledger and to JSON.
    pub fn name(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Incomplete => "incomplete",
            Outcome::Deferred => "deferred",
            Outcome::NoRepository => "no-repository",
            Outcome::Locked => "locked",
            Outcome::WrongPassword => "wrong-password",
            Outcome::TimedOut => "timed-out",
            Outcome::NotRun => "not-run",
            Outcome::Failed => "failed",
        }
    }

    /// The outcome called `name`, if there is one.
    pub fn from_name(name: &str) -> Option<Outcome> {
        Outcome::ALL.into_iter().find(|outcome| outcome.name() == name)
    }

    /// How bad this outcome is, higher is worse. Distinct per outcome, so
    /// [`Outcome::worst`] never has a tie to break. The order among the
    /// failures is a proposal; only "`ok` < `deferred` < `incomplete` < any
    /// failure" is settled.
    pub fn severity(self) -> u8 {
        Outcome::ALL.iter().position(|other| *other == self).unwrap_or(usize::MAX) as u8
    }

    /// The worst of several outcomes, which is the outcome of a run over
    /// several sources. `None` for no sources.
    pub fn worst(outcomes: impl IntoIterator<Item = Outcome>) -> Option<Outcome> {
        outcomes.into_iter().max_by_key(|outcome| outcome.severity())
    }

    /// How loud this outcome is on its own. Only `Incomplete` and the
    /// failures are warnings: a failed run keeps the last success, so the
    /// pair ages, and it is the age ([`crate::Freshness::Stale`]) that turns
    /// critical. A run is not escalated by being repeated.
    pub fn level(self) -> Level {
        match self {
            Outcome::Ok | Outcome::Deferred => Level::Ok,
            _ => Level::Warning,
        }
    }

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
    fn names_round_trip_and_match_serde() {
        for outcome in Outcome::ALL {
            assert_eq!(Outcome::from_name(outcome.name()), Some(outcome));
            let json = serde_json::to_string(&outcome).unwrap();
            assert_eq!(json, format!("\"{}\"", outcome.name()));
        }
        assert_eq!(Outcome::from_name("OK"), None);
    }

    #[test]
    fn severity_is_distinct_and_the_worst_of_a_run_wins() {
        let mut ranks: Vec<u8> = Outcome::ALL.iter().map(|o| o.severity()).collect();
        ranks.dedup();
        assert_eq!(ranks.len(), Outcome::ALL.len());
        assert_eq!(Outcome::worst([]), None);
        assert_eq!(Outcome::worst([Outcome::Ok, Outcome::Incomplete, Outcome::Ok]), Some(Outcome::Incomplete));
        assert_eq!(Outcome::worst([Outcome::Incomplete, Outcome::Failed]), Some(Outcome::Failed));
        assert_eq!(Outcome::worst([Outcome::Deferred, Outcome::Ok]), Some(Outcome::Deferred));
    }

    #[test]
    fn incomplete_is_a_warning_never_ok_and_levels_order_as_exit_codes() {
        assert_eq!(Outcome::Incomplete.level(), Level::Warning);
        assert_eq!(Outcome::Ok.level(), Level::Ok);
        assert_eq!(Outcome::Failed.level(), Level::Warning);
        assert_eq!([Level::Ok, Level::Warning, Level::Critical].map(Level::exit_code), [0, 1, 2]);
        assert!(Level::Warning < Level::Critical);
    }

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
