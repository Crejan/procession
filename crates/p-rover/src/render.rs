//! The text form of a report: generic, so every subcommand reads alike.

use std::fmt::Write;

use serde_json::Value;

use crate::report::Report;

/// One value as text. Strings are already through the rule of `sanitize` (nothing in them can
/// act on a terminal), so the only quoting left is for readability: a string with a space or a
/// quote, or an empty one, is put in double quotes with `"` as `\"`; a backslash stays as the
/// escape form wrote it.
fn scalar(v: &Value) -> String {
    match v {
        Value::String(s) if s.is_empty() || s.contains([' ', '"']) => format!("\"{}\"", s.replace('"', "\\\"")),
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
    for rec in &r.values {
        let Some(obj) = rec.as_object() else { continue };
        let kind = obj.get("type").and_then(Value::as_str).unwrap_or("record");
        let _ = write!(o, "{kind}");
        for (k, v) in obj.iter().filter(|(k, _)| *k != "type") {
            let _ = write!(o, " {k}={}", scalar(v));
        }
        o.push('\n');
    }
    // The findings as written: after the rule.
    let mut findings: Vec<Value> = r.findings_json.iter().filter_map(|f| serde_json::from_str(f.get()).ok()).collect();
    let rank = |f: &Value| match f["severity"].as_str() {
        Some("crit") => 0,
        Some("warn") => 1,
        _ => 2,
    };
    findings.sort_by_key(rank);
    for f in &findings {
        let tag = ["CRIT", "WARN", "INFO"][rank(f)];
        let id = f["id"].as_str().unwrap_or("?");
        let text = f["recommendation"].as_str().unwrap_or("");
        let _ = writeln!(o, "[{tag}] {id} {} - {text}", scalar(&f["subject"]));
        for m in f["evidence"].as_array().into_iter().flatten() {
            let _ = writeln!(o, "    {} = {}", m["name"].as_str().unwrap_or("?"), scalar(&m["value"]));
        }
    }
    o
}
