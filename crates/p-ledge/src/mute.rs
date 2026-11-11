//! Muting: a local program that the person declines three times within ten
//! minutes is refused without a dialog for ten minutes (`SPEC.md`, section 5).

use std::collections::BTreeMap;

/// Declines that mute a program.
pub const DECLINES: usize = 3;
/// The window the declines must fall in, and how long the mute lasts.
pub const WINDOW_SECONDS: u64 = 600;

/// Counts declines per program. Times are Unix seconds, given by the caller.
#[derive(Debug, Default)]
pub struct Muter {
    declines: BTreeMap<String, Vec<u64>>,
    muted_until: BTreeMap<String, u64>,
}

impl Muter {
    /// Whether `program` is muted at `now`.
    #[must_use]
    pub fn is_muted(&self, program: &str, now: u64) -> bool {
        self.muted_until.get(program).is_some_and(|until| *until > now)
    }

    /// Notes that the person declined `program` at `now`. Returns `true` if
    /// this decline muted it: the person is to be told.
    pub fn declined(&mut self, program: &str, now: u64) -> bool {
        let times = self.declines.entry(program.to_owned()).or_default();
        times.retain(|then| now.saturating_sub(*then) < WINDOW_SECONDS);
        times.push(now);
        if times.len() < DECLINES {
            return false;
        }
        times.clear();
        self.muted_until.insert(program.to_owned(), now + WINDOW_SECONDS);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_third_decline_within_ten_minutes_mutes_for_ten_minutes() {
        let mut muter = Muter::default();
        assert!(!muter.declined("git", 0));
        assert!(!muter.declined("git", 100));
        assert!(!muter.is_muted("git", 150));
        assert!(muter.declined("git", 200));
        assert!(muter.is_muted("git", 200));
        assert!(muter.is_muted("git", 799));
        assert!(!muter.is_muted("git", 800));
    }

    #[test]
    fn declines_spread_over_more_than_ten_minutes_do_not_mute() {
        let mut muter = Muter::default();
        for now in [0, 400, 800, 1200, 1600] {
            assert!(!muter.declined("git", now), "{now}");
        }
    }

    #[test]
    fn programs_are_counted_apart_and_a_mute_ends_with_a_fresh_count() {
        let mut muter = Muter::default();
        muter.declined("a", 0);
        muter.declined("a", 1);
        assert!(!muter.declined("b", 2));
        assert!(muter.declined("a", 3));
        assert!(!muter.is_muted("b", 3));
        assert!(!muter.declined("a", 1000));
    }
}
