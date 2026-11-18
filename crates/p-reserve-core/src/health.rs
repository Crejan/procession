//! The health of every declared pair, in one place.
//!
//! `preserve health`, a tray icon and a metric read [`Health`]; none of them
//! combines a freshness band and an outcome on its own.
//!
//! The rule, per pair: the level is the loudest of
//! - the freshness band: `Pending` and `Fresh` are ok, `Overdue` a warning,
//!   `Stale` critical;
//! - the outcome of the last run ([`Outcome::level`]): `Incomplete` and every
//!   failure are warnings, `Ok` and `Deferred` are ok;
//! - the files the last successful run could not read: any is a warning.
//!
//! So an `incomplete` snapshot counts for freshness and is never `ok`; a
//! failed run keeps the pair a warning until its age makes it critical; and
//! repeating a failure does not raise it.

use std::time::SystemTime;

use serde::Serialize;

use crate::freshness::{Freshness, Thresholds};
use crate::ledger::{Ledger, Pair};
use crate::outcome::{Level, Outcome};

/// Why a pair is above `ok`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    Overdue,
    Stale,
    /// The last run ended in this outcome, which is not `ok`.
    LastRun(Outcome),
    /// The last successful run could not read this many files.
    Unreadable(u64),
    /// The pair is declared but the ledger has no record of it.
    NeverRun,
}

/// One pair's health.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PairHealth {
    pub source: String,
    pub target: String,
    pub level: Level,
    pub freshness: Freshness,
    pub last_outcome: Option<Outcome>,
    /// Seconds since the Unix epoch of the last success.
    pub last_success: Option<u64>,
    pub last_added_bytes: u64,
    pub unreadable: u64,
    pub reasons: Vec<Reason>,
}

/// The health of all pairs and the worst level among them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Health {
    pub level: Level,
    pub pairs: Vec<PairHealth>,
}

impl Health {
    /// The exit code of `preserve health`: 0 ok, 1 warnings, 2 critical.
    pub fn exit_code(&self) -> u8 {
        self.level.exit_code()
    }
}

/// The health of `pairs`, which are the declared ones. A declared pair the
/// ledger has not seen is stale; a ledger pair that is not declared is not
/// reported (it is on its way out, see [`Ledger::retain`]).
pub fn assess<'a>(
    ledger: &Ledger,
    pairs: impl IntoIterator<Item = &'a Pair>,
    now: SystemTime,
    limits: &Thresholds,
) -> Health {
    let pairs: Vec<PairHealth> = pairs.into_iter().map(|pair| assess_pair(ledger, pair, now, limits)).collect();
    let level = pairs.iter().map(|pair| pair.level).max().unwrap_or(Level::Ok);
    Health { level, pairs }
}

fn assess_pair(ledger: &Ledger, pair: &Pair, now: SystemTime, limits: &Thresholds) -> PairHealth {
    let entry = ledger.entry(pair).copied();
    let known = entry.unwrap_or_default();
    let freshness = ledger.freshness(pair, now, limits);
    let mut reasons = Vec::new();
    let mut level = Level::Ok;
    let mut raise = |to: Level, reason: Reason| {
        level = level.max(to);
        reasons.push(reason);
    };
    match freshness {
        Freshness::Pending | Freshness::Fresh => {}
        Freshness::Overdue => raise(Level::Warning, Reason::Overdue),
        Freshness::Stale => raise(Level::Critical, Reason::Stale),
    }
    match known.last_outcome {
        None => raise(Level::Ok, Reason::NeverRun),
        Some(outcome) if outcome.level() > Level::Ok => raise(outcome.level(), Reason::LastRun(outcome)),
        Some(_) => {}
    }
    if known.last_unreadable > 0 {
        raise(Level::Warning, Reason::Unreadable(known.last_unreadable));
    }
    PairHealth {
        source: pair.source.clone(),
        target: pair.target.clone(),
        level,
        freshness,
        last_outcome: known.last_outcome,
        last_success: known
            .last_success
            .and_then(|at| at.duration_since(SystemTime::UNIX_EPOCH).ok())
            .map(|d| d.as_secs()),
        last_added_bytes: known.last_added_bytes,
        unreadable: known.last_unreadable,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::ledger::Run;

    const HOUR: Duration = Duration::from_secs(3600);

    fn limits() -> Thresholds {
        Thresholds { fresh_within: 2 * HOUR, stale_after: 48 * HOUR, first_run_grace: HOUR }
    }

    fn t(hours: u32) -> SystemTime {
        SystemTime::UNIX_EPOCH + hours * HOUR
    }

    fn pair() -> Pair {
        Pair::new("home", "offsite")
    }

    fn health(ledger: &Ledger, now: SystemTime) -> PairHealth {
        assess(ledger, [&pair()], now, &limits()).pairs.remove(0)
    }

    #[test]
    fn a_clean_fresh_pair_is_ok() {
        let mut ledger = Ledger::default();
        ledger.record(pair(), Run::stored(1, 0), t(0));
        let h = health(&ledger, t(1));
        assert_eq!((h.level, h.reasons.is_empty()), (Level::Ok, true));
    }

    #[test]
    fn an_incomplete_snapshot_counts_for_freshness_but_is_a_warning_with_its_count() {
        let mut ledger = Ledger::default();
        ledger.record(pair(), Run::stored(1, 12), t(0));
        let h = health(&ledger, t(1));
        assert_eq!(h.freshness, Freshness::Fresh);
        assert_eq!(h.level, Level::Warning);
        assert_eq!(h.unreadable, 12);
        assert_eq!(h.reasons, vec![Reason::LastRun(Outcome::Incomplete), Reason::Unreadable(12)]);
        let whole = assess(&ledger, [&pair()], t(1), &limits());
        assert_eq!(whole.exit_code(), 1);
    }

    #[test]
    fn a_failure_is_a_warning_until_its_age_makes_it_critical_and_repeating_does_not_raise_it() {
        let mut ledger = Ledger::default();
        ledger.record(pair(), Run::stored(1, 0), t(0));
        for hour in 1..=40 {
            ledger.record(pair(), Run::ended(Outcome::Failed), t(hour));
        }
        assert_eq!(health(&ledger, t(40)).level, Level::Warning);
        assert_eq!(health(&ledger, t(49)).level, Level::Critical);
    }

    #[test]
    fn overdue_is_a_warning_and_stale_is_critical() {
        let mut ledger = Ledger::default();
        ledger.record(pair(), Run::stored(1, 0), t(0));
        assert_eq!(health(&ledger, t(3)).level, Level::Warning);
        assert_eq!(health(&ledger, t(3)).reasons, vec![Reason::Overdue]);
        assert_eq!(health(&ledger, t(49)).level, Level::Critical);
    }

    #[test]
    fn a_declared_pair_the_ledger_never_saw_is_critical_and_an_undeclared_one_is_not_reported() {
        let mut ledger = Ledger::default();
        ledger.record(Pair::new("other", "offsite"), Run::stored(1, 0), t(0));
        let h = assess(&ledger, [&pair()], t(0), &limits());
        assert_eq!(h.pairs.len(), 1);
        assert_eq!(h.level, Level::Critical);
        assert_eq!(h.pairs[0].reasons, vec![Reason::Stale, Reason::NeverRun]);
        assert_eq!(assess(&ledger, [], t(0), &limits()).level, Level::Ok);
    }

    #[test]
    fn deferred_alone_is_not_a_problem_while_the_grace_period_runs() {
        let mut ledger = Ledger::default();
        ledger.record(pair(), Run::ended(Outcome::Deferred), t(0));
        let h = health(&ledger, t(0));
        assert_eq!((h.freshness, h.level), (Freshness::Pending, Level::Ok));
    }

    #[test]
    fn the_worst_pair_sets_the_level() {
        let mut ledger = Ledger::default();
        let (a, b) = (Pair::new("a", "x"), Pair::new("b", "x"));
        ledger.record(a.clone(), Run::stored(1, 0), t(0));
        ledger.record(b.clone(), Run::stored(1, 1), t(0));
        assert_eq!(assess(&ledger, [&a, &b], t(1), &limits()).level, Level::Warning);
    }
}
