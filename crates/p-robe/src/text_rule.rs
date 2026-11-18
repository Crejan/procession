//! The rule for strings from outside (`README.md`, Conventions), applied at the one place every record passes: the
//! dispatcher's answer. Whatever a verb or a tool wrote, each string of each record, at any depth, is made visible with
//! `p_ermit::text` (a control character or a bidirectional mark becomes `\u{202e}`, an invalid byte `\x{ff}`, a
//! backslash `\\`), and cut at a bound of its own. Nothing is passed raw and nothing is dropped; a record that was
//! touched says so (`"escaped": true`, `"clipped": {"<field>": <full length in bytes>}`).
//!
//! The record is rewritten token by token, so the members keep their order and the strings are the only thing that
//! changes.

use p_ermit::text::escape_bytes_clipped;

/// The longest a string field is, in bytes of escaped output.
pub const FIELD_MAX: usize = 1024;

/// What a record's strings are held to: [`FIELD_MAX`], or the row's own limit for a field it declares as content.
#[derive(Debug, Clone, Copy)]
pub struct Limits<'a> {
    pub field: usize,
    pub content: &'a [(&'static str, usize)],
}

impl Limits<'_> {
    /// The usual bound for every field.
    pub const USUAL: Limits<'static> = Limits { field: FIELD_MAX, content: &[] };

    fn of(&self, field: Option<&str>) -> usize {
        field.and_then(|name| self.content.iter().find(|(n, _)| *n == name)).map_or(self.field, |(_, max)| *max)
    }
}

/// A record after the rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rewritten {
    pub line: String,
    /// Something the rule refuses was in a string.
    pub escaped: bool,
    /// The fields that were cut, with the length of the whole string in bytes.
    pub clipped: Vec<(String, usize)>,
}

/// `s` made visible and cut to at most `max_bytes` bytes of the escaped text: the text, whether anything was
/// escaped, and the full length in bytes if it was cut.
///
/// The escape form bounds characters, not bytes; the bound is made one of bytes by asking for fewer characters until
/// the text fits.
#[must_use]
pub fn visible(s: &str, max_bytes: usize) -> (String, bool, Option<usize>) {
    let mut chars = max_bytes;
    let mut done = escape_bytes_clipped(s.as_bytes(), chars);
    while done.text.len() > max_bytes && chars > 1 {
        chars = chars.saturating_sub((done.text.len() - max_bytes).div_ceil(4)).max(1);
        done = escape_bytes_clipped(s.as_bytes(), chars);
    }
    // The length of the input in bytes (p-ermit's `full_len` counts characters for valid text).
    (done.text, done.flagged > 0, done.clipped.then_some(s.len()))
}

/// Applies the rule to one record, a JSON object on one line.
///
/// A member of the record's own named `escaped` or `clipped` is the tool's claim, not ours: it is kept as
/// `tool_escaped` or `tool_clipped`, so that the flags of the dispatcher are the only ones with those names.
///
/// `None` if the line is not one JSON object of strings and values this can read: the caller does not pass it on.
#[must_use]
pub fn rewrite(line: &str, limits: &Limits<'_>) -> Option<Rewritten> {
    let bytes = line.as_bytes();
    if bytes.first() != Some(&b'{') || bytes.last() != Some(&b'}') {
        return None;
    }
    let mut out = String::with_capacity(line.len() + 32);
    let mut escaped = false;
    let mut clipped: Vec<(String, usize)> = Vec::new();
    // One entry per open container: the key of the member being read (an array keeps its parent's).
    let mut keys: Vec<Option<String>> = Vec::new();
    let mut objects: Vec<bool> = Vec::new();
    let mut i = 0;
    while i < line.len() {
        let c = line[i..].chars().next()?;
        match c {
            '"' => {
                let end = string_end(bytes, i)?;
                let decoded: String = serde_json::from_str(&line[i..=end]).ok()?;
                let is_key = objects.last() == Some(&true) && next_is_colon(bytes, end + 1);
                let field = if is_key { None } else { keys.last().and_then(|k| k.as_deref()) };
                let (text, was_escaped, full) = visible(&decoded, limits.of(field));
                escaped |= was_escaped;
                if let (Some(full), Some(name)) = (full, field.or(Some(decoded.as_str()))) {
                    clipped.push((name.to_string(), full));
                }
                let mut shown = text;
                if is_key {
                    if let Some(top) = keys.last_mut() {
                        *top = Some(decoded.clone());
                    }
                    if keys.len() == 1 && (decoded == "escaped" || decoded == "clipped") {
                        shown = format!("tool_{decoded}");
                    }
                }
                out.push_str(&serde_json::to_string(&shown).ok()?);
                i = end + 1;
                continue;
            }
            '{' | '[' => {
                let inherited = keys.last().cloned().flatten();
                keys.push(if c == '[' { inherited } else { None });
                objects.push(c == '{');
            }
            '}' | ']' => {
                keys.pop();
                objects.pop();
            }
            ',' if objects.last() == Some(&true) => {
                if let Some(top) = keys.last_mut() {
                    *top = None;
                }
            }
            _ => {}
        }
        out.push(c);
        i += c.len_utf8();
    }
    if !keys.is_empty() {
        return None;
    }
    // The flags go in before the object's closing brace.
    out.pop();
    if escaped {
        out.push_str(",\"escaped\":true");
    }
    if !clipped.is_empty() {
        out.push_str(",\"clipped\":{");
        let members: Vec<String> = clipped
            .iter()
            .map(|(field, full)| format!("{}:{full}", serde_json::Value::String(field.clone())))
            .collect();
        out.push_str(&members.join(","));
        out.push('}');
    }
    out.push('}');
    Some(Rewritten { line: out, escaped, clipped })
}

/// The index of the quote that ends the string that begins at `start`.
fn string_end(bytes: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

fn next_is_colon(bytes: &[u8], from: usize) -> bool {
    bytes[from..].iter().find(|b| !b.is_ascii_whitespace()) == Some(&b':')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rewritten(line: &str) -> Rewritten {
        rewrite(line, &Limits::USUAL).unwrap_or_else(|| panic!("{line}"))
    }

    #[test]
    fn a_record_with_nothing_to_change_is_passed_as_it_is_in_its_order() {
        let line = r#"{"type":"thread","pid":1,"comm":"cyclic","z":["a","b"],"a":{"n":null,"t":true}}"#;
        let done = rewritten(line);
        assert_eq!(done, Rewritten { line: line.to_string(), escaped: false, clipped: vec![] });
    }

    #[test]
    fn a_control_character_a_c1_one_a_bidi_mark_and_a_backslash_are_made_visible_at_any_depth() {
        // Keys too; nested objects, arrays inside objects.
        let line = "{\"type\":\"x\",\"comm\":\"a\\u0085b\",\"deep\":{\"list\":[\"\\u202eevil\",\"back\\\\slash\"],\"k\\u0007\":1}}";
        let done = rewritten(line);
        assert!(done.escaped && done.clipped.is_empty());
        assert!(done.line.ends_with(",\"escaped\":true}"), "{}", done.line);
        assert!(done.line.contains("\"comm\":\"a\\\\u{85}b\""), "{}", done.line);
        assert!(done.line.contains("\\\\u{202e}evil") && done.line.contains("back\\\\\\\\slash"), "{}", done.line);
        assert!(done.line.contains("\"k\\\\u{7}\":1"), "{}", done.line);
        // Nothing the rule refuses is left, and it is still one JSON object.
        let value: serde_json::Value = serde_json::from_str(&done.line).unwrap();
        assert!(value["deep"]["list"][0].as_str().unwrap().starts_with("\\u{202e}evil"));
        assert!(!done.line.chars().any(|c| p_ermit::text::check(&c.to_string()).is_err()), "{}", done.line);
        assert!(p_ermit::text::check(&done.line).is_ok());
    }

    #[test]
    fn a_long_string_is_cut_at_a_bound_of_bytes_with_its_full_length_and_the_name_of_the_field() {
        let long = "x".repeat(3000);
        let done =
            rewritten(&format!("{{\"type\":\"t\",\"cmd\":\"{long}\",\"in\":{{\"path\":[\"{long}\"]}},\"ok\":\"y\"}}"));
        assert_eq!(done.clipped, [("cmd".to_string(), 3000), ("path".to_string(), 3000)]);
        let value: serde_json::Value = serde_json::from_str(&done.line).unwrap();
        assert_eq!(value["cmd"].as_str().unwrap().len(), FIELD_MAX);
        assert_eq!(value["in"]["path"][0].as_str().unwrap().len(), FIELD_MAX);
        assert_eq!(value["clipped"]["cmd"], 3000);
        assert_eq!(value["ok"], "y");
        // Bytes, not characters: a string of three-byte characters and one of escapes both fit the bound.
        for unit in ["\u{20ac}", "\u{202e}", "\u{1}"] {
            let (text, _, full) = visible(&unit.repeat(2000), FIELD_MAX);
            assert!(text.len() <= FIELD_MAX && full == Some(2000 * unit.len()), "{unit:?}: {} {full:?}", text.len());
        }
    }

    #[test]
    fn a_field_the_row_declares_as_content_has_the_rows_limit() {
        let content = [("text", 4000)];
        let limits = Limits { field: FIELD_MAX, content: &content };
        let big = "q".repeat(3500);
        let done = rewrite(&format!("{{\"type\":\"file\",\"text\":\"{big}\",\"name\":\"{big}\"}}"), &limits).unwrap();
        assert_eq!(
            done.clipped,
            [("name".to_string(), 3500)],
            "the name is cut at the usual bound, the content is not"
        );
    }

    #[test]
    fn what_a_tool_says_of_its_own_escaping_is_not_taken_for_the_dispatchers() {
        let done = rewritten("{\"type\":\"t\",\"escaped\":true,\"clipped\":{\"a\":5},\"s\":\"ok\"}");
        assert!(!done.escaped);
        assert!(
            done.line.contains("\"tool_escaped\":true") && done.line.contains("\"tool_clipped\":"),
            "{}",
            done.line
        );
        assert!(!done.line.contains("\"escaped\""), "{}", done.line);
        // Only at the top of the record: a nested member of that name is data.
        let nested = rewritten("{\"type\":\"t\",\"a\":{\"escaped\":1}}");
        assert!(nested.line.contains("\"escaped\":1"));
    }

    #[test]
    fn what_is_not_one_object_is_not_passed_on() {
        for bad in ["", "[]", "{", "{\"a\":\"b}", "{\"a\":[}", "text"] {
            assert_eq!(rewrite(bad, &Limits::USUAL), None, "{bad:?}");
        }
    }
}
