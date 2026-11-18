//! Strings that came from outside (a file another writer could have touched counts as outside) are never
//! written into JSON or text as they are. What a person is asked about is refused at entry (`agent::text`);
//! what is shown or printed as data goes through the escape form of `p-ermit`, here: visibly, reversibly,
//! bounded. A JSON writer's own escaping is not this rule (it leaves C1 controls and bidirectional marks).

use p_ermit::text::{escape, escape_clipped};
use serde_json::{Map, Value};

/// How many characters of an outside string an error or a log line may carry.
pub const MAX_ERROR_CHARS: usize = 200;

/// `text` as a visible, reversible string.
#[must_use]
pub fn text(text: &str) -> String {
    escape(text).text
}

/// `text` escaped and cut to `max_chars` characters (for errors and logs: an operator sees what it was, not all of it).
#[must_use]
pub fn bounded(text: &str, max_chars: usize) -> String {
    let clipped = escape_clipped(text, max_chars);
    if clipped.clipped { format!("{}...", clipped.text) } else { clipped.text }
}

/// `value` with every string (and every member name) escaped; an object that holds a string that had to be
/// escaped gets `"escaped": true` (absent otherwise). Numbers, booleans and structure are untouched.
#[must_use]
pub fn json(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(escape(s).text),
        Value::Array(items) => Value::Array(items.iter().map(json).collect()),
        Value::Object(members) => {
            let mut out = Map::new();
            let mut flagged = false;
            for (name, member) in members {
                let name_escaped = escape(name);
                flagged |= name_escaped.was_flagged();
                if let Value::String(s) = member {
                    let escaped = escape(s);
                    flagged |= escaped.was_flagged();
                    out.insert(name_escaped.text, Value::String(escaped.text));
                } else {
                    out.insert(name_escaped.text, json(member));
                }
            }
            if flagged {
                out.insert("escaped".into(), Value::Bool(true));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// The probe strings every output of pledge is tried with: a C1 control, a CSI, an ESC sequence, a bidirectional mark.
#[cfg(test)]
pub const PROBES: [&str; 4] = ["a\u{85}b", "a\u{9b}31mb", "a\u{1b}[31mb", "a\u{202e}b"];

/// Whether `shown` can be printed to a terminal: no control character (a line end apart) and no bidirectional mark.
#[cfg(test)]
pub fn assert_clean(shown: &str, what: &str) {
    let bad = |c: char| (c.is_control() && c != '\n') || p_ermit::text::is_bidi_mark(c);
    assert!(!shown.chars().any(bad), "{what}: not clean: {shown:?}");
}
