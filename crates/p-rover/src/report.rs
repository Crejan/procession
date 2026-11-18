//! The report every subcommand returns, and the finding type they share.

use std::time::{SystemTime, UNIX_EPOCH};

use p_roc::change::Change;
use p_roc::Unreadable;
use serde::Serialize;
use serde_json::Value;

use crate::env::Env;

/// Version of the JSON layout; bumped on an incompatible change.
pub const SCHEMA_VERSION: u32 = 1;

/// How heavy a subcommand is on the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Cost {
    /// Reads files, for a moment.
    Light,
    /// Traces, or samples for a long window.
    Heavy,
}

/// `observe` reads only; `probe` loads the host or changes knobs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Reads only.
    Observe,
}

/// How serious a finding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Worth knowing.
    Info,
    /// Likely to hurt realtime behaviour.
    Warn,
    /// Breaks it.
    Crit,
}

/// What a finding is about.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Subject {
    /// A thread.
    Thread {
        /// Thread id.
        tid: i32,
        /// Its comm.
        comm: String,
    },
    /// An IRQ.
    Irq {
        /// The number.
        irq: u32,
        /// Its name.
        name: String,
    },
    /// A network interface.
    Interface {
        /// The name.
        name: String,
    },
    /// The host as a whole.
    Host,
}

/// One number a finding rests on.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Metric {
    /// What it is.
    pub name: String,
    /// Its value.
    pub value: Value,
}

impl Metric {
    /// A metric from anything JSON can hold.
    pub fn new(name: &str, value: impl Serialize) -> Self {
        Self { name: name.into(), value: serde_json::to_value(value).unwrap_or(Value::Null) }
    }
}

/// A finding: the same type in every subcommand and in `analyze`.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Finding {
    /// Stable identifier such as `irq-on-isolated`.
    pub id: &'static str,
    /// How serious.
    pub severity: Severity,
    /// What it is about.
    pub subject: Subject,
    /// The numbers it rests on.
    pub evidence: Vec<Metric>,
    /// What to do.
    pub recommendation: String,
    /// The changes that would fix it; empty when only the code can.
    pub changes: Vec<Change>,
}

/// The result of one subcommand.
#[derive(Debug, Serialize)]
pub struct Report {
    /// [`SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The subcommand.
    pub subcommand: &'static str,
    /// The host's name.
    pub host: String,
    /// When the run started, RFC 3339 UTC.
    pub started_at: String,
    /// Always `observe` for the subcommands outside `probe`.
    pub mode: Mode,
    /// Light or heavy.
    pub cost: Cost,
    /// Every source the run could not read.
    pub unreadable: Vec<Unreadable>,
    /// Flat typed records, one per observed object.
    pub records: Vec<Value>,
    /// What a probe restored; empty for observe.
    pub restored: Vec<Value>,
    /// The findings.
    pub findings: Vec<Finding>,
}

impl Report {
    /// An empty report for `subcommand`, stamped with the host and the time.
    #[must_use]
    pub fn new(env: &Env, subcommand: &'static str, cost: Cost) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            subcommand,
            host: env.host.clone(),
            started_at: rfc3339(env.clock.now()),
            mode: Mode::Observe,
            cost,
            unreadable: Vec::new(),
            records: Vec::new(),
            restored: Vec::new(),
            findings: Vec::new(),
        }
    }

    /// Appends a record (an enum tagged with `type`).
    pub fn push(&mut self, record: &impl Serialize) {
        self.records.push(serde_json::to_value(record).unwrap_or(Value::Null));
    }

    /// Appends the unreadable sources of a scan.
    pub fn unreadable(&mut self, more: impl IntoIterator<Item = Unreadable>) {
        self.unreadable.extend(more);
    }

    /// The process exit code the findings call for: 0 nothing above info, 1 warnings, 2 critical.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self.findings.iter().map(|f| f.severity).max() {
            Some(Severity::Crit) => 2,
            Some(Severity::Warn) => 1,
            _ => 0,
        }
    }
}

/// Rounds to one decimal, for rates.
#[must_use]
pub fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// `2026-11-18T09:30:00Z` from a system time (seconds, UTC).
#[must_use]
pub fn rfc3339(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = (secs / 86_400, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn dates() {
        let at = |s| rfc3339(UNIX_EPOCH + Duration::from_secs(s));
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(at(1_794_000_000), "2026-11-06T21:20:00Z");
    }
}
