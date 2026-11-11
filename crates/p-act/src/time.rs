//! UTC times to the second, `2026-11-11T15:04:05Z`, without a time crate.

use crate::error::ParseError;
use std::fmt;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

/// A moment, in whole seconds since the Unix epoch, within years 0000 to 9999.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

const MAX_YEAR: i64 = 9999;

impl Timestamp {
    /// The current time. `None` if the clock is before 1970 or past 9999.
    #[must_use]
    pub fn now() -> Option<Timestamp> {
        let secs = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        Timestamp::from_unix(i64::try_from(secs).ok()?)
    }

    /// `None` outside years 0000 to 9999.
    #[must_use]
    pub fn from_unix(secs: i64) -> Option<Timestamp> {
        let (year, ..) = civil_from_days(secs.div_euclid(86_400));
        (0..=MAX_YEAR).contains(&year).then_some(Timestamp(secs))
    }

    #[must_use]
    pub fn unix(self) -> i64 {
        self.0
    }

    /// This time plus `secs` seconds. `None` if that leaves years 0000 to 9999.
    #[must_use]
    pub fn checked_add(self, secs: i64) -> Option<Timestamp> {
        Timestamp::from_unix(self.0.checked_add(secs)?)
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (y, mo, d) = civil_from_days(self.0.div_euclid(86_400));
        let s = self.0.rem_euclid(86_400);
        write!(f, "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z", s / 3600, s % 3600 / 60, s % 60)
    }
}

impl FromStr for Timestamp {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let bad = || ParseError::MalformedTime(s.to_owned());
        let b = s.as_bytes();
        if b.len() != 20 {
            return Err(bad());
        }
        for (i, want) in [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':'), (19, b'Z')] {
            if b[i] != want {
                return Err(bad());
            }
        }
        let num = |range: std::ops::Range<usize>| -> Result<i64, ParseError> {
            let digits = &b[range];
            if digits.iter().all(u8::is_ascii_digit) {
                Ok(digits.iter().fold(0, |n, d| n * 10 + i64::from(d - b'0')))
            } else {
                Err(bad())
            }
        };
        let (y, mo, d, h, mi, sec) = (num(0..4)?, num(5..7)?, num(8..10)?, num(11..13)?, num(14..16)?, num(17..19)?);
        if h > 23 || mi > 59 || sec > 59 || !(1..=12).contains(&mo) || d < 1 {
            return Err(bad());
        }
        let days = days_from_civil(y, mo, d);
        // A day that does not exist in its month (February 30th) does not survive the round trip.
        if civil_from_days(days) != (y, mo, d) {
            return Err(bad());
        }
        Ok(Timestamp(days * 86_400 + h * 3600 + mi * 60 + sec))
    }
}

// Howard Hinnant's civil-calendar algorithms.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_instants() {
        assert_eq!("1970-01-01T00:00:00Z".parse::<Timestamp>().unwrap().unix(), 0);
        assert_eq!("2026-11-11T15:04:05Z".parse::<Timestamp>().unwrap().unix(), 1_794_409_445);
        assert_eq!("2000-02-29T23:59:59Z".parse::<Timestamp>().unwrap().unix(), 951_868_799);
        assert_eq!("0000-01-01T00:00:00Z".parse::<Timestamp>().unwrap().unix(), -62_167_219_200);
        assert_eq!("9999-12-31T23:59:59Z".parse::<Timestamp>().unwrap().unix(), 253_402_300_799);
    }

    #[test]
    fn display_round_trips() {
        for s in [
            "1970-01-01T00:00:00Z",
            "2026-11-11T15:04:05Z",
            "2024-02-29T00:00:00Z",
            "9999-12-31T23:59:59Z",
            "0000-03-01T00:00:00Z",
        ] {
            assert_eq!(s.parse::<Timestamp>().unwrap().to_string(), s);
        }
    }

    #[test]
    fn refuses_everything_else() {
        for bad in [
            "",
            "2026-11-11T15:04:05",
            "2026-11-11 15:04:05Z",
            "2026-11-11T15:04:05z",
            "2026-11-11T15:04:05+00:00",
            "2026-11-11T15:04:05.5Z",
            "2026-13-01T00:00:00Z",
            "2026-00-01T00:00:00Z",
            "2026-02-29T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-11-00T00:00:00Z",
            "2026-11-11T24:00:00Z",
            "2026-11-11T00:60:00Z",
            "2026-11-11T00:00:60Z",
            "+026-11-11T00:00:00Z",
            "2026-11-11T00:00:0\u{661}Z",
            " 2026-11-11T00:00:00Z",
        ] {
            assert_eq!(bad.parse::<Timestamp>(), Err(ParseError::MalformedTime(bad.to_owned())), "{bad:?}");
        }
    }

    #[test]
    fn arithmetic_stays_in_range() {
        let t: Timestamp = "2026-11-11T15:04:05Z".parse().unwrap();
        assert_eq!(t.checked_add(120).unwrap().to_string(), "2026-11-11T15:06:05Z");
        assert!(Timestamp::from_unix(253_402_300_800).is_none());
        assert!(Timestamp::from_unix(-62_167_219_201).is_none());
        assert!(t.checked_add(i64::MAX).is_none());
    }
}
