//! Which source last succeeded to which target, carried across runs.
//!
//! A run records every pair it reached. A pair that failed keeps its last
//! success, so it ages into an alert instead of disappearing; a pair that
//! never succeeded ages from its first attempt.

use std::collections::BTreeMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::freshness::{Freshness, Thresholds, freshness};
use crate::outcome::Outcome;

/// The rule for the name of a source or a target: `[a-z0-9][a-z0-9._-]{0,63}`: a plain word, no slash, no upper case,
/// not `.` or `..`, at most 64 bytes. It is what goes into the ledger, the metrics' labels and the socket's messages; the
/// path a name stands for stays in the configuration.
pub const NAME_RULE: &str = "[a-z0-9][a-z0-9._-]{0,63}";

/// Whether `name` is in the class [`NAME_RULE`].
pub fn is_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=64).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes.iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-'))
}

/// One source backed up to one target.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Pair {
    pub source: String,
    pub target: String,
}

impl Pair {
    pub fn new(source: impl Into<String>, target: impl Into<String>) -> Self {
        Pair { source: source.into(), target: target.into() }
    }
}

/// Why a run ended as it did, when the outcome alone does not say. Closed
/// list; the name is what is written to the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Cause {
    /// The run began and never ended: the program died, or the machine did.
    /// Found at the next start from a start marker with no end.
    Interrupted,
}

impl Cause {
    pub fn name(self) -> &'static str {
        match self {
            Cause::Interrupted => "interrupted",
        }
    }

    pub fn from_name(name: &str) -> Option<Cause> {
        [Cause::Interrupted].into_iter().find(|cause| cause.name() == name)
    }
}

/// How one run of one pair ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    pub outcome: Outcome,
    /// Bytes the run added to the target; counts only if it stored a snapshot.
    pub added_bytes: u64,
    /// How many source files could not be read; counts only if it stored a
    /// snapshot.
    pub unreadable: u64,
    pub cause: Option<Cause>,
}

impl Run {
    /// A run that stored a snapshot. A snapshot with unreadable files is
    /// `Incomplete`, never `Ok`: this is the one place that says so.
    pub fn stored(added_bytes: u64, unreadable: u64) -> Run {
        let outcome = if unreadable == 0 { Outcome::Ok } else { Outcome::Incomplete };
        Run { outcome, added_bytes, unreadable, cause: None }
    }

    /// A run that ended as `outcome` without a count of its own: a failure, a
    /// deferral, or a snapshot whose unreadable files were not counted.
    pub fn ended(outcome: Outcome) -> Run {
        Run { outcome, added_bytes: 0, unreadable: 0, cause: None }
    }

    /// A run that began and never ended: `failed`, because `interrupted`.
    pub fn interrupted() -> Run {
        Run { cause: Some(Cause::Interrupted), ..Run::ended(Outcome::Failed) }
    }

    /// The run over several sources: the worst of its sources' outcomes, with
    /// the bytes and unreadable counts summed. `None` for no sources.
    pub fn combine(runs: impl IntoIterator<Item = Run>) -> Option<Run> {
        runs.into_iter().fold(None, |sum, run| {
            Some(match sum {
                None => run,
                Some(sum) => Run {
                    outcome: Outcome::worst([sum.outcome, run.outcome]).unwrap_or(run.outcome),
                    added_bytes: sum.added_bytes.saturating_add(run.added_bytes),
                    unreadable: sum.unreadable.saturating_add(run.unreadable),
                    cause: sum.cause.or(run.cause),
                },
            })
        })
    }
}

/// What the ledger knows about one pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Entry {
    pub last_success: Option<SystemTime>,
    /// Bytes the last successful run added to the target.
    pub last_added_bytes: u64,
    /// How many files the last successful run could not read; 0 for a clean
    /// one. Kept with the success, so a later failure does not hide it.
    pub last_unreadable: u64,
    /// When a pair that never succeeded first came up for a run, tried or
    /// deferred.
    pub first_attempt: Option<SystemTime>,
    pub last_outcome: Option<Outcome>,
    /// Why the last run ended so, where the outcome does not say.
    pub last_cause: Option<Cause>,
    /// When the last run of any outcome was recorded (for a run found
    /// interrupted: when it began).
    pub last_attempt: Option<SystemTime>,
}

/// The pairs and what happened to them. Persistence is the caller's: the
/// ledger is plain data.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Ledger {
    entries: BTreeMap<Pair, Entry>,
}

impl Ledger {
    /// Record how a run of `pair` ended at `at`. The bytes and the unreadable
    /// count count only for a run that stored a snapshot.
    pub fn record(&mut self, pair: Pair, run: Run, at: SystemTime) {
        let entry = self.entries.entry(pair).or_default();
        entry.last_outcome = Some(run.outcome);
        entry.last_cause = run.cause;
        entry.last_attempt = Some(at);
        if run.outcome.stored_snapshot() {
            entry.last_success = Some(at);
            entry.last_added_bytes = run.added_bytes;
            entry.last_unreadable = run.unreadable;
            entry.first_attempt = None;
        } else if entry.last_success.is_none() {
            // A deferred run counts here too: the grace period of a pair that
            // never succeeded runs from the first time it came up, whether
            // that run was tried or put off.
            entry.first_attempt.get_or_insert(at);
        }
    }

    /// Set a pair's entry as read back from storage.
    pub fn insert(&mut self, pair: Pair, entry: Entry) {
        self.entries.insert(pair, entry);
    }

    pub fn entry(&self, pair: &Pair) -> Option<&Entry> {
        self.entries.get(pair)
    }

    /// The band of one pair; a pair the ledger has never seen is stale.
    pub fn freshness(&self, pair: &Pair, now: SystemTime, limits: &Thresholds) -> Freshness {
        let entry = self.entries.get(pair).copied().unwrap_or_default();
        freshness(now, entry.last_success, entry.first_attempt, limits)
    }

    /// Keep only the pairs `keep` accepts. For targets and sources that are
    /// no longer declared; a pair never leaves because a run failed.
    pub fn retain(&mut self, mut keep: impl FnMut(&Pair) -> bool) {
        self.entries.retain(|pair, _| keep(pair));
    }

    pub fn pairs(&self) -> impl Iterator<Item = (&Pair, &Entry)> {
        self.entries.iter()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    fn limits() -> Thresholds {
        Thresholds { fresh_within: 2 * HOUR, stale_after: 48 * HOUR, first_run_grace: HOUR }
    }

    fn t(hours: u32) -> SystemTime {
        SystemTime::UNIX_EPOCH + hours * HOUR
    }

    #[test]
    fn a_failure_keeps_the_last_success_so_the_pair_ages() {
        let pair = Pair::new("home", "offsite");
        let mut ledger = Ledger::default();
        ledger.record(pair.clone(), Run::stored(10, 0), t(0));
        ledger.record(pair.clone(), Run::ended(Outcome::Failed), t(1));

        let entry = ledger.entry(&pair).unwrap();
        assert_eq!(entry.last_success, Some(t(0)));
        assert_eq!(entry.last_added_bytes, 10);
        assert_eq!(entry.last_outcome, Some(Outcome::Failed));
        assert_eq!(ledger.freshness(&pair, t(1), &limits()), Freshness::Fresh);
        assert_eq!(ledger.freshness(&pair, t(49), &limits()), Freshness::Stale);
    }

    #[test]
    fn a_pair_that_never_succeeded_ages_from_its_first_attempt() {
        let pair = Pair::new("home", "offsite");
        let mut ledger = Ledger::default();
        ledger.record(pair.clone(), Run::ended(Outcome::Locked), t(0));
        ledger.record(pair.clone(), Run::ended(Outcome::Failed), t(5));
        assert_eq!(ledger.entry(&pair).unwrap().first_attempt, Some(t(0)));
        assert_eq!(ledger.freshness(&pair, t(5), &limits()), Freshness::Stale);
    }

    #[test]
    fn a_deferred_run_is_no_success_but_starts_the_grace_period() {
        let pair = Pair::new("home", "offsite");
        let mut ledger = Ledger::default();
        ledger.record(pair.clone(), Run::ended(Outcome::Deferred), t(0));
        let entry = ledger.entry(&pair).unwrap();
        assert_eq!(entry.last_success, None);
        assert_eq!(entry.first_attempt, Some(t(0)));
        assert_eq!(ledger.freshness(&pair, t(0), &limits()), Freshness::Pending);
        assert_eq!(ledger.freshness(&pair, t(1), &limits()), Freshness::Stale);
    }

    #[test]
    fn a_success_clears_the_first_attempt() {
        let pair = Pair::new("home", "offsite");
        let mut ledger = Ledger::default();
        ledger.record(pair.clone(), Run::ended(Outcome::Failed), t(0));
        ledger.record(pair.clone(), Run::stored(7, 2), t(1));
        let entry = ledger.entry(&pair).unwrap();
        assert_eq!(entry.first_attempt, None);
        assert_eq!(entry.last_success, Some(t(1)));
    }

    #[test]
    fn unreadable_files_make_a_snapshot_incomplete_and_the_count_survives_a_failure() {
        assert_eq!(Run::stored(5, 0).outcome, Outcome::Ok);
        assert_eq!(Run::stored(5, 3).outcome, Outcome::Incomplete);
        let pair = Pair::new("home", "offsite");
        let mut ledger = Ledger::default();
        ledger.record(pair.clone(), Run::stored(5, 3), t(0));
        assert_eq!(ledger.entry(&pair).unwrap().last_unreadable, 3);
        ledger.record(pair.clone(), Run::ended(Outcome::Failed), t(1));
        assert_eq!(ledger.entry(&pair).unwrap().last_unreadable, 3);
        // an incomplete snapshot still resets the age
        assert_eq!(ledger.freshness(&pair, t(1), &limits()), Freshness::Fresh);
        ledger.record(pair.clone(), Run::stored(5, 0), t(2));
        assert_eq!(ledger.entry(&pair).unwrap().last_unreadable, 0);
    }

    #[test]
    fn a_run_over_several_sources_is_the_worst_of_them_with_the_counts_summed() {
        let run = Run::combine([Run::stored(10, 0), Run::stored(20, 4), Run::stored(1, 1)]).unwrap();
        assert_eq!(run, Run { outcome: Outcome::Incomplete, added_bytes: 31, unreadable: 5, cause: None });
        let run = Run::combine([Run::stored(10, 2), Run::ended(Outcome::Failed)]).unwrap();
        assert_eq!(run.outcome, Outcome::Failed);
        assert_eq!(Run::combine([]), None);
    }

    #[test]
    fn an_unknown_pair_is_stale_and_retain_drops_undeclared_ones() {
        let mut ledger = Ledger::default();
        ledger.record(Pair::new("home", "old"), Run::stored(1, 0), t(0));
        ledger.record(Pair::new("home", "offsite"), Run::stored(1, 0), t(0));
        ledger.retain(|pair| pair.target != "old");
        assert_eq!(ledger.pairs().count(), 1);
        assert_eq!(ledger.freshness(&Pair::new("home", "old"), t(0), &limits()), Freshness::Stale);
    }
}
