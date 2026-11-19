//! The report every subcommand returns, and the finding type they share.

use std::time::{SystemTime, UNIX_EPOCH};

use p_roc::Unreadable;
use p_roc::change::Change;
use serde::Serialize;
use serde_json::Value;
use serde_json::value::RawValue;

use crate::env::Env;
use crate::sanitize;

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
    /// Records, findings and `unreadable` entries that had a string escaped (see `sanitize`).
    pub escaped_records: usize,
    /// Records and findings that had a field cut.
    pub clipped_records: usize,
    /// Every source the run could not read.
    pub unreadable: Vec<Unreadable>,
    /// Flat typed records, one per observed object; written with their fields in struct order.
    pub records: Vec<Box<RawValue>>,
    /// The same records as values, for callers and tests that inspect them (not serialized).
    #[serde(skip)]
    pub values: Vec<Value>,
    /// What a probe restored; empty for observe.
    pub restored: Vec<Value>,
    /// The findings, as the program built them (not serialized: see `findings_json`).
    #[serde(skip)]
    pub findings: Vec<Finding>,
    /// The findings as written: after the rule, with their flags. Filled by [`Report::sanitize`].
    #[serde(rename = "findings")]
    pub findings_json: Vec<Box<RawValue>>,
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
            escaped_records: 0,
            clipped_records: 0,
            unreadable: Vec::new(),
            records: Vec::new(),
            values: Vec::new(),
            restored: Vec::new(),
            findings: Vec::new(),
            findings_json: Vec::new(),
        }
    }

    /// Appends a record (an enum tagged with `type`), after the rule for strings from outside.
    pub fn push(&mut self, record: &impl Serialize) {
        let text = serde_json::to_string(record).unwrap_or_else(|_| "null".into());
        let (text, flags) = sanitize::json(sanitize::record_type(&text), &text);
        self.escaped_records += usize::from(flags.escaped);
        self.clipped_records += usize::from(!flags.clipped.is_empty());
        let value: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        self.records.push(RawValue::from_string(text).unwrap_or_else(|_| RawValue::NULL.to_owned()));
        // An odd name is information: say it, once per escaped name field.
        for (key, raw) in &flags.escaped_values {
            if let Some(subject) = odd_subject(&value, key, raw) {
                self.findings.push(Finding {
                    id: "odd-characters",
                    severity: Severity::Info,
                    subject,
                    evidence: vec![Metric::new("field", key), Metric::new("value", raw)],
                    recommendation: "this name contains characters that do not display as written (control or direction characters, or bytes that are not UTF-8); it is shown escaped".into(),
                    changes: Vec::new(),
                });
            }
        }
        self.values.push(value);
    }

    /// Applies the rule to what is not a record: the host name, the `unreadable` entries and the
    /// findings (written to `findings_json`). Called once, by `observe::finish`.
    pub fn sanitize(&mut self) {
        let host = sanitize::clean(&self.host, 255);
        self.escaped_records += usize::from(host.flagged > 0);
        self.host = host.text;
        for u in &mut self.unreadable {
            let (s, r) = (sanitize::clean(&u.source, 512), sanitize::clean(&u.reason, 512));
            self.escaped_records += usize::from(s.flagged + r.flagged > 0);
            self.clipped_records += usize::from(s.clipped.is_some() || r.clipped.is_some());
            (u.source, u.reason) = (s.text, r.text);
        }
        for f in &self.findings {
            let text = serde_json::to_string(f).unwrap_or_else(|_| "null".into());
            let (text, flags) = sanitize::json("finding", &text);
            self.escaped_records += usize::from(flags.escaped);
            self.clipped_records += usize::from(!flags.clipped.is_empty());
            self.findings_json
                .push(RawValue::from_string(sanitize::pretty(&text, 4)).unwrap_or_else(|_| RawValue::NULL.to_owned()));
        }
    }

    /// Appends the unreadable sources of a scan.
    pub fn unreadable(&mut self, more: impl IntoIterator<Item = Unreadable>) {
        for u in more {
            if !self.unreadable.contains(&u) {
                self.unreadable.push(u);
            }
        }
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

/// Rounds to two decimals, for small rates.
#[must_use]
pub fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
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

/// Who an odd name belongs to: the thread, IRQ or interface of the record it was found in.
fn odd_subject(record: &Value, key: &str, raw: &str) -> Option<Subject> {
    if !matches!(key, "comm" | "name" | "iface" | "interface") {
        return None;
    }
    if let Some(tid) = record.get("tid").and_then(Value::as_i64) {
        return Some(Subject::Thread { tid: i32::try_from(tid).ok()?, comm: raw.to_string() });
    }
    if let Some(irq) = record.get("irq").and_then(Value::as_u64) {
        return Some(Subject::Irq { irq: u32::try_from(irq).ok()?, name: raw.to_string() });
    }
    Some(Subject::Interface { name: raw.to_string() })
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
