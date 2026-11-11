//! How stale the most recent backup is.
//!
//! One function decides it. A status line, a tray icon, a CLI exit code and a
//! metric all read [`freshness`]; a second derivation is how one surface comes
//! to say "up to date" beside another's "overdue".

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// The age band of the last successful backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Freshness {
    /// No success on record, and too soon after the first attempt to call it
    /// a problem.
    Pending,
    /// Within `fresh_within`.
    Fresh,
    /// Past `fresh_within`, within `stale_after`. Worth naming, not an alarm.
    Overdue,
    /// Past `stale_after`, or never succeeded and past the grace period.
    Stale,
}

impl Freshness {
    /// Whether this band asks the user to act.
    pub fn needs_attention(self) -> bool {
        self == Freshness::Stale
    }
}

/// The limits the bands are cut at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Thresholds {
    /// A backup younger than this is fresh.
    pub fresh_within: Duration,
    /// A backup older than this is stale.
    pub stale_after: Duration,
    /// How long a source that never succeeded may take before it is stale,
    /// counted from its first attempt.
    pub first_run_grace: Duration,
}

/// The band for a source whose last success was at `last_success`.
///
/// `first_attempt` is when a source that never succeeded was first tried; it
/// is ignored once there is a success. A never-succeeded source with no
/// recorded attempt is stale: nothing says it is still on its way.
///
/// A `last_success` in the future (a clock that was set back) reads as fresh.
pub fn freshness(
    now: SystemTime,
    last_success: Option<SystemTime>,
    first_attempt: Option<SystemTime>,
    limits: &Thresholds,
) -> Freshness {
    let age = |since: SystemTime| now.duration_since(since).unwrap_or(Duration::ZERO);
    match (last_success, first_attempt) {
        (Some(at), _) => {
            let age = age(at);
            if age <= limits.fresh_within {
                Freshness::Fresh
            } else if age <= limits.stale_after {
                Freshness::Overdue
            } else {
                Freshness::Stale
            }
        }
        (None, Some(first)) if age(first) < limits.first_run_grace => Freshness::Pending,
        (None, _) => Freshness::Stale,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);
    const HOUR: Duration = Duration::from_secs(3600);

    fn limits() -> Thresholds {
        Thresholds { fresh_within: 90 * MINUTE, stale_after: 66 * HOUR, first_run_grace: 5 * MINUTE }
    }

    fn at(now: SystemTime, ago: Duration) -> Option<SystemTime> {
        Some(now - ago)
    }

    #[test]
    fn bands_are_cut_at_the_limits_inclusive() {
        let now = SystemTime::UNIX_EPOCH + 1000 * HOUR;
        let band = |ago| freshness(now, at(now, ago), None, &limits());
        assert_eq!(band(Duration::ZERO), Freshness::Fresh);
        assert_eq!(band(90 * MINUTE), Freshness::Fresh);
        assert_eq!(band(91 * MINUTE), Freshness::Overdue);
        assert_eq!(band(66 * HOUR), Freshness::Overdue);
        assert_eq!(band(66 * HOUR + MINUTE), Freshness::Stale);
    }

    #[test]
    fn a_source_that_never_succeeded_gets_a_grace_period_then_is_stale() {
        let now = SystemTime::UNIX_EPOCH + 1000 * HOUR;
        assert_eq!(freshness(now, None, at(now, MINUTE), &limits()), Freshness::Pending);
        assert_eq!(freshness(now, None, at(now, 5 * MINUTE), &limits()), Freshness::Stale);
        assert_eq!(freshness(now, None, None, &limits()), Freshness::Stale);
    }

    #[test]
    fn a_success_outranks_the_first_attempt() {
        let now = SystemTime::UNIX_EPOCH + 1000 * HOUR;
        assert_eq!(freshness(now, at(now, MINUTE), at(now, 100 * HOUR), &limits()), Freshness::Fresh);
    }

    #[test]
    fn a_success_in_the_future_is_fresh() {
        let now = SystemTime::UNIX_EPOCH + 1000 * HOUR;
        assert_eq!(freshness(now, Some(now + HOUR), None, &limits()), Freshness::Fresh);
    }

    #[test]
    fn only_stale_asks_for_attention() {
        assert!(Freshness::Stale.needs_attention());
        for quiet in [Freshness::Pending, Freshness::Fresh, Freshness::Overdue] {
            assert!(!quiet.needs_attention(), "{quiet:?}");
        }
    }
}
