//! CPU sets in the kernel's list format (`0-3,8,10-11`) and as hex masks
//! (`smp_affinity`: comma-separated 32-bit groups, most significant first).

use std::collections::BTreeSet;
use std::fmt;
use std::ops::RangeInclusive;
use std::str::FromStr;

use serde::{Serialize, Serializer};

/// Upper bound (exclusive) for a single CPU number; guards against
/// `0-4294967295` allocating a set of four billion entries.
pub const MAX_CPU: u32 = 1 << 16;

/// Why a list or mask was refused.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CpuSetError {
    /// Not a number.
    #[error("invalid CPU {value:?} in {input:?}")]
    Invalid {
        /// The offending token.
        value: String,
        /// The whole input.
        input: String,
    },
    /// A CPU number at or above [`MAX_CPU`].
    #[error("CPU {cpu} out of range in {input:?}")]
    OutOfRange {
        /// The number.
        cpu: u64,
        /// The whole input.
        input: String,
    },
    /// A range such as `3-1`.
    #[error("descending range {part:?} in {input:?}")]
    Descending {
        /// The range.
        part: String,
        /// The whole input.
        input: String,
    },
    /// A hex mask with a non-hex group.
    #[error("invalid mask group {group:?} in {input:?}")]
    BadMask {
        /// The group.
        group: String,
        /// The whole input.
        input: String,
    },
}

/// A set of CPU numbers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CpuSet(BTreeSet<u32>);

impl CpuSet {
    /// The empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Parses the list format used by sysfs and `Cpus_allowed_list`.
    ///
    /// # Errors
    /// On a non-number, a CPU at or above [`MAX_CPU`], or a descending range.
    pub fn parse_list(s: &str) -> Result<Self, CpuSetError> {
        let mut set = BTreeSet::new();
        for part in s.trim().split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let cpu = |v: &str| -> Result<u32, CpuSetError> {
                let v = v.trim();
                let n: u64 = v.parse().map_err(|_| CpuSetError::Invalid { value: v.into(), input: s.into() })?;
                match u32::try_from(n) {
                    Ok(n) if n < MAX_CPU => Ok(n),
                    _ => Err(CpuSetError::OutOfRange { cpu: n, input: s.into() }),
                }
            };
            let (lo, hi) = match part.split_once('-') {
                Some((a, b)) => (cpu(a)?, cpu(b)?),
                None => (cpu(part)?, cpu(part)?),
            };
            if lo > hi {
                return Err(CpuSetError::Descending { part: part.into(), input: s.into() });
            }
            set.extend(lo..=hi);
        }
        Ok(Self(set))
    }

    /// Parses an `smp_affinity` mask: hex groups separated by commas, the
    /// most significant group first (`00000001,0000000f` is CPUs 0-3 and 32).
    /// A group may be shorter than eight digits; a bare `ff` works too.
    ///
    /// # Errors
    /// On a non-hex group, a group wider than 32 bits, or a CPU at or above
    /// [`MAX_CPU`].
    pub fn parse_mask(s: &str) -> Result<Self, CpuSetError> {
        let groups: Vec<&str> = s.trim().split(',').map(str::trim).collect();
        let mut set = BTreeSet::new();
        for (i, group) in groups.iter().rev().enumerate() {
            let bad = || CpuSetError::BadMask { group: (*group).into(), input: s.into() };
            if group.is_empty() || group.len() > 8 {
                return Err(bad());
            }
            let bits = u32::from_str_radix(group, 16).map_err(|_| bad())?;
            for bit in (0..32).filter(|b| bits >> b & 1 == 1) {
                let cpu = i as u64 * 32 + bit;
                if cpu >= u64::from(MAX_CPU) {
                    return Err(CpuSetError::OutOfRange { cpu, input: s.into() });
                }
                set.insert(cpu as u32);
            }
        }
        Ok(Self(set))
    }

    /// The set as an `smp_affinity` mask: 32-bit groups of eight hex digits,
    /// most significant first, as wide as the highest CPU needs (`0` when
    /// empty). [`parse_mask`](Self::parse_mask) reads it back.
    #[must_use]
    pub fn to_mask(&self) -> String {
        let Some(max) = self.0.last() else { return "00000000".into() };
        let groups = max / 32 + 1;
        (0..groups)
            .rev()
            .map(|g| {
                let bits = self.0.range(g * 32..g * 32 + 32).fold(0u32, |acc, c| acc | 1 << (c % 32));
                format!("{bits:08x}")
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    /// No CPU in the set.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Number of CPUs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether `cpu` is in the set.
    #[must_use]
    pub fn contains(&self, cpu: u32) -> bool {
        self.0.contains(&cpu)
    }

    /// Lowest CPU of the set.
    #[must_use]
    pub fn first(&self) -> Option<u32> {
        self.0.first().copied()
    }

    /// Highest CPU of the set.
    #[must_use]
    pub fn last(&self) -> Option<u32> {
        self.0.last().copied()
    }

    /// The CPUs in ascending order.
    pub fn iter(&self) -> impl Iterator<Item = u32> + '_ {
        self.0.iter().copied()
    }

    /// The maximal runs of consecutive CPUs, ascending.
    #[must_use]
    pub fn ranges(&self) -> Vec<RangeInclusive<u32>> {
        let mut out: Vec<RangeInclusive<u32>> = Vec::new();
        for cpu in self.iter() {
            match out.last_mut() {
                Some(r) if *r.end() + 1 == cpu => *r = *r.start()..=cpu,
                _ => out.push(cpu..=cpu),
            }
        }
        out
    }

    /// CPUs in both sets.
    #[must_use]
    pub fn intersection(&self, other: &CpuSet) -> CpuSet {
        self.0.intersection(&other.0).copied().collect()
    }

    /// CPUs in either set.
    #[must_use]
    pub fn union(&self, other: &CpuSet) -> CpuSet {
        self.0.union(&other.0).copied().collect()
    }

    /// CPUs in `self` and not in `other`.
    #[must_use]
    pub fn difference(&self, other: &CpuSet) -> CpuSet {
        self.0.difference(&other.0).copied().collect()
    }

    /// Whether the sets share a CPU.
    #[must_use]
    pub fn intersects(&self, other: &CpuSet) -> bool {
        self.0.intersection(&other.0).next().is_some()
    }
}

impl FromIterator<u32> for CpuSet {
    fn from_iter<I: IntoIterator<Item = u32>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

impl FromStr for CpuSet {
    type Err = CpuSetError;

    fn from_str(s: &str) -> Result<Self, CpuSetError> {
        Self::parse_list(s)
    }
}

impl fmt::Display for CpuSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sep = "";
        for r in self.ranges() {
            if r.start() == r.end() {
                write!(f, "{sep}{}", r.start())?;
            } else {
                write!(f, "{sep}{}-{}", r.start(), r.end())?;
            }
            sep = ",";
        }
        Ok(())
    }
}

/// Serialized as its list format (`"0-3,8"`), which is how every report shows it.
impl Serialize for CpuSet {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_formats_lists() {
        for (input, cpus, shown) in [
            ("", vec![], ""),
            ("\n", vec![], ""),
            ("3", vec![3], "3"),
            ("0-3", vec![0, 1, 2, 3], "0-3"),
            ("0-1,4,6-7\n", vec![0, 1, 4, 6, 7], "0-1,4,6-7"),
            ("5,1,2", vec![1, 2, 5], "1-2,5"),
        ] {
            let set = CpuSet::parse_list(input).unwrap();
            assert_eq!(set, cpus.iter().copied().collect(), "{input:?}");
            assert_eq!(set.to_string(), shown, "{input:?}");
        }
    }

    #[test]
    fn rejects_garbage_and_bounds() {
        for input in ["a", "3-1", "1-", "99999999", "0-70000", "0-4294967295", "4294967296"] {
            assert!(CpuSet::parse_list(input).is_err(), "{input:?}");
        }
        assert!(CpuSet::parse_list("0-65535").is_ok());
        assert!(matches!(CpuSet::parse_list("65536"), Err(CpuSetError::OutOfRange { cpu: 65536, .. })));
    }

    #[test]
    fn masks_both_ways() {
        for (mask, list) in [
            ("1", "0"),
            ("ff", "0-7"),
            ("0000000f", "0-3"),
            ("00000001,0000000f", "0-3,32"),
            ("ffffffff,ffffffff", "0-63"),
            ("0\n", ""),
        ] {
            let set = CpuSet::parse_mask(mask).unwrap();
            assert_eq!(set.to_string(), list, "{mask:?}");
            assert_eq!(CpuSet::parse_mask(&set.to_mask()).unwrap(), set, "round trip {mask:?}");
        }
        assert_eq!(CpuSet::new().to_mask(), "00000000");
        assert_eq!("0-3,32".parse::<CpuSet>().unwrap().to_mask(), "00000001,0000000f");
        for bad in ["", "zz", "123456789", "1,,2", "1,"] {
            assert!(CpuSet::parse_mask(bad).is_err(), "{bad:?}");
        }
        // 2049 groups of 32 bits would pass MAX_CPU.
        let wide = format!("1{}", ",00000000".repeat(2048));
        assert!(matches!(CpuSet::parse_mask(&wide), Err(CpuSetError::OutOfRange { .. })));
    }

    #[test]
    fn set_operations() {
        let a: CpuSet = "0-3".parse().unwrap();
        let b: CpuSet = "2-5".parse().unwrap();
        assert_eq!(a.intersection(&b).to_string(), "2-3");
        assert_eq!(a.difference(&b).to_string(), "0-1");
        assert_eq!(a.union(&b).to_string(), "0-5");
        assert!(a.intersects(&b));
        assert!(!a.intersects(&"8".parse().unwrap()));
        assert_eq!(b.first(), Some(2));
        assert_eq!(b.last(), Some(5));
        assert_eq!("0-1,4,6-7".parse::<CpuSet>().unwrap().ranges(), vec![0..=1, 4..=4, 6..=7]);
    }

    #[test]
    fn serializes_as_list() {
        assert_eq!(serde_json::to_string(&"0-1,4".parse::<CpuSet>().unwrap()).unwrap(), "\"0-1,4\"");
    }
}
