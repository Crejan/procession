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

/// What the ledger knows about one pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Entry {
    pub last_success: Option<SystemTime>,
    /// Bytes the last successful run added to the target.
    pub last_added_bytes: u64,
    /// When a pair that never succeeded first came up for a run, tried or
    /// deferred.
    pub first_attempt: Option<SystemTime>,
    pub last_outcome: Option<Outcome>,
}

/// The pairs and what happened to them. Persistence is the caller's: the
/// ledger is plain data.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Ledger {
    entries: BTreeMap<Pair, Entry>,
}

impl Ledger {
    /// Record how a run of `pair` ended at `at`. `added_bytes` counts only
    /// for an outcome that stored a snapshot.
    pub fn record(&mut self, pair: Pair, outcome: Outcome, at: SystemTime, added_bytes: u64) {
        let entry = self.entries.entry(pair).or_default();
        entry.last_outcome = Some(outcome);
        if outcome.stored_snapshot() {
            entry.last_success = Some(at);
            entry.last_added_bytes = added_bytes;
            entry.first_attempt = None;
        } else if entry.last_success.is_none() {
            // A deferred run counts here too: the grace period of a pair that
            // never succeeded runs from the first time it came up, whether
            // that run was tried or put off.
            entry.first_attempt.get_or_insert(at);
        }
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
        ledger.record(pair.clone(), Outcome::Ok, t(0), 10);
        ledger.record(pair.clone(), Outcome::Failed, t(1), 0);

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
        ledger.record(pair.clone(), Outcome::Locked, t(0), 0);
        ledger.record(pair.clone(), Outcome::Failed, t(5), 0);
        assert_eq!(ledger.entry(&pair).unwrap().first_attempt, Some(t(0)));
        assert_eq!(ledger.freshness(&pair, t(5), &limits()), Freshness::Stale);
    }

    #[test]
    fn a_deferred_run_is_no_success_but_starts_the_grace_period() {
        let pair = Pair::new("home", "offsite");
        let mut ledger = Ledger::default();
        ledger.record(pair.clone(), Outcome::Deferred, t(0), 0);
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
        ledger.record(pair.clone(), Outcome::Failed, t(0), 0);
        ledger.record(pair.clone(), Outcome::Incomplete, t(1), 7);
        let entry = ledger.entry(&pair).unwrap();
        assert_eq!(entry.first_attempt, None);
        assert_eq!(entry.last_success, Some(t(1)));
    }

    #[test]
    fn an_unknown_pair_is_stale_and_retain_drops_undeclared_ones() {
        let mut ledger = Ledger::default();
        ledger.record(Pair::new("home", "old"), Outcome::Ok, t(0), 1);
        ledger.record(Pair::new("home", "offsite"), Outcome::Ok, t(0), 1);
        ledger.retain(|pair| pair.target != "old");
        assert_eq!(ledger.pairs().count(), 1);
        assert_eq!(ledger.freshness(&Pair::new("home", "old"), t(0), &limits()), Freshness::Stale);
    }
}
