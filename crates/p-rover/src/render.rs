//! The text form of a report: generic, so every subcommand reads alike.

use std::fmt::Write;

use serde_json::Value;

use crate::report::{Report, Severity};

fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) if s.is_empty() => "\"\"".into(),
        Value::String(s) if s.contains(' ') => format!("{s:?}"),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

/// Renders a report as lines: a header, `unreadable`, one line per record
/// (`type key=value ...`), then the findings by severity.
#[must_use]
pub fn text(r: &Report) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "{} on {} at {} (observe, cost {:?})", r.subcommand, r.host, r.started_at, r.cost);
    for u in &r.unreadable {
        let _ = writeln!(o, "unreadable {}: {}", u.source, u.reason);
    }
    for rec in &r.records {
        let Some(obj) = rec.as_object() else { continue };
        let kind = obj.get("type").and_then(Value::as_str).unwrap_or("record");
        let _ = write!(o, "{kind}");
        for (k, v) in obj.iter().filter(|(k, _)| *k != "type") {
            let _ = write!(o, " {k}={}", scalar(v));
        }
        o.push('\n');
    }
    let mut findings: Vec<_> = r.findings.iter().collect();
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    for f in findings {
        let tag = match f.severity {
            Severity::Info => "INFO",
            Severity::Warn => "WARN",
            Severity::Crit => "CRIT",
        };
        let subject = serde_json::to_value(&f.subject).unwrap_or(Value::Null);
        let _ = writeln!(o, "[{tag}] {} {} - {}", f.id, scalar(&subject), f.recommendation);
        for m in &f.evidence {
            let _ = writeln!(o, "    {} = {}", m.name, scalar(&m.value));
        }
    }
    o
}
