//! The rule for strings from outside, applied to everything `prover` writes.
//!
//! Every string in a record, a finding, an `unreadable` entry and the header
//! passes through `p_ermit::text` before it is written, whether it came from the
//! host or is a constant of ours (a constant is clean, so it passes unchanged).
//! A control character or bidirectional mark becomes visible literal text
//! (`\u{202e}`), a backslash is doubled, a byte that is not UTF-8 (read with
//! `p_roc::text`) becomes `\x{ff}`. The escape is in the string's content: JSON
//! then carries the backslash, so no parser turns it back into the character.
//!
//! A record or finding with an escaped string gets `"escaped": true`; one with a
//! cut field gets `"clipped": {"<field>": <full length in bytes>}`. The bound of
//! a field counts **characters of the escaped text**; `full_len` is the bytes of
//! the host's string.

use std::collections::BTreeMap;

use p_ermit::text::escape_bytes_clipped;

/// A string after the rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cleaned {
    /// The escaped, possibly cut, text.
    pub text: String,
    /// How many characters the rule refused (and invalid bytes).
    pub flagged: usize,
    /// The host string's length in bytes when it was cut.
    pub clipped: Option<usize>,
}

/// Escapes `s` (which may carry `p_roc::text` stand-ins for invalid bytes) and cuts it to `max_chars`.
#[must_use]
pub fn clean(s: &str, max_chars: usize) -> Cleaned {
    let c = escape_bytes_clipped(&p_roc::text::to_bytes(s), max_chars);
    Cleaned { text: c.text, flagged: c.flagged, clipped: c.clipped.then_some(c.full_len) }
}

/// The bound, in characters of the escaped text, of the string under `key` in a record of type `rtype`.
#[must_use]
pub fn bound(rtype: &str, key: &str) -> usize {
    match rtype {
        "live" | "declared" | "grub_assignment" | "diff" => return 8192,
        "sysctl" | "detectors" | "chrony_tracking" | "chrony_source" | "driver" => return 256,
        "kernel_log" | "boot_tail" | "boots" => return 1024,
        _ => {}
    }
    match key {
        "comm" => 64,
        "name" | "iface" | "interface" | "kernel_driver" | "uart" | "tty" | "wchan" | "clock_name" | "desc"
        | "unit" => 128,
        "stack" => 256,
        _ => 4096,
    }
}

/// What the rule did to one JSON object.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Flags {
    /// Some string was escaped.
    pub escaped: bool,
    /// Cut fields and the full length of each.
    pub clipped: BTreeMap<String, usize>,
    /// `(key, host string before escaping)` of every escaped string value.
    pub escaped_values: Vec<(String, String)>,
}

impl Flags {
    /// Whether anything happened.
    #[must_use]
    pub fn any(&self) -> bool {
        self.escaped || !self.clipped.is_empty()
    }
}

/// The record type of a compact JSON object that starts `{"type":"..."`.
#[must_use]
pub fn record_type(json: &str) -> &str {
    json.strip_prefix("{\"type\":\"").and_then(|r| r.split('"').next()).unwrap_or("")
}

/// Applies the rule to every string literal of a compact JSON object, keys included, and appends the
/// flags. The order of members is kept. `rtype` selects the bounds.
#[must_use]
pub fn json(rtype: &str, text: &str) -> (String, Flags) {
    let b = text.as_bytes();
    let (mut out, mut flags) = (String::with_capacity(text.len()), Flags::default());
    let (mut i, mut last_key) = (0, String::new());
    while i < b.len() {
        if b[i] != b'"' {
            // Copy up to the next quote (all of it is JSON syntax, numbers, and literals).
            let next = text[i..].find('"').map_or(b.len(), |n| i + n);
            out.push_str(&text[i..next]);
            i = next;
            continue;
        }
        let mut j = i + 1;
        while j < b.len() && b[j] != b'"' {
            j += if b[j] == b'\\' { 2 } else { 1 };
        }
        let literal = &text[i..(j + 1).min(b.len())];
        let Ok(decoded) = serde_json::from_str::<String>(literal) else {
            out.push_str(literal);
            i = j + 1;
            continue;
        };
        let is_key = text[(j + 1).min(b.len())..].starts_with(':');
        let max = if is_key { 128 } else { bound(rtype, &last_key) };
        let c = clean(&decoded, max);
        if c.flagged > 0 {
            flags.escaped = true;
            if !is_key {
                flags.escaped_values.push((last_key.clone(), decoded.clone()));
            }
        }
        if let Some(full) = c.clipped {
            let slot = flags.clipped.entry(if is_key { "<key>".into() } else { last_key.clone() }).or_insert(0);
            *slot = (*slot).max(full);
        }
        out.push_str(&serde_json::to_string(&c.text).unwrap_or_else(|_| "\"\"".into()));
        if is_key {
            last_key = decoded;
        }
        i = j + 1;
    }
    if flags.any()
        && let Some(head) = out.strip_suffix('}').map(str::to_string)
    {
        out = head;
        if flags.escaped {
            out.push_str(",\"escaped\":true");
        }
        if !flags.clipped.is_empty() {
            out.push_str(",\"clipped\":");
            out.push_str(&serde_json::to_string(&flags.clipped).unwrap_or_else(|_| "{}".into()));
        }
        out.push('}');
    }
    (out, flags)
}

/// Re-indents a compact JSON text the way `serde_json::to_string_pretty` does (two spaces, `"k": v`),
/// as if it were nested `base` spaces deep. The text must be well-formed; strings are copied verbatim.
#[must_use]
pub fn pretty(json: &str, base: usize) -> String {
    let (mut out, mut depth, mut in_str, mut esc) = (String::with_capacity(json.len() * 2), 0usize, false, false);
    let pad = |out: &mut String, d: usize| {
        out.push('\n');
        out.extend(std::iter::repeat_n(' ', base + 2 * d));
    };
    let mut chars = json.chars().peekable();
    while let Some(c) = chars.next() {
        if in_str {
            out.push(c);
            match (esc, c) {
                (true, _) => esc = false,
                (false, '\\') => esc = true,
                (false, '"') => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => {
                in_str = true;
                out.push(c);
            }
            '{' | '[' if matches!(chars.peek(), Some('}' | ']')) => {
                out.push(c);
                out.push(chars.next().unwrap_or(c));
            }
            '{' | '[' => {
                depth += 1;
                out.push(c);
                pad(&mut out, depth);
            }
            '}' | ']' => {
                depth = depth.saturating_sub(1);
                pad(&mut out, depth);
                out.push(c);
            }
            ',' => {
                out.push(c);
                pad(&mut out, depth);
            }
            ':' => out.push_str(": "),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped_in_their_content_and_order_is_kept() {
        let src = "{\"type\":\"thread\",\"tid\":5,\"comm\":\"a\\u202eb\\u0085\\\\c\"}";
        let (out, f) = json("thread", src);
        assert_eq!(
            out,
            "{\"type\":\"thread\",\"tid\":5,\"comm\":\"a\\\\u{202e}b\\\\u{85}\\\\\\\\c\",\"escaped\":true}"
        );
        assert!(f.escaped && f.clipped.is_empty());
        assert_eq!(f.escaped_values, vec![("comm".to_string(), "a\u{202e}b\u{85}\\c".to_string())]);
        // Parsed back, the content holds the visible escapes, not the characters.
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["comm"], "a\\u{202e}b\\u{85}\\\\c");
    }

    #[test]
    fn pretty_matches_serde_jsons_layout() {
        let v =
            serde_json::json!({"id": "a", "s": {"kind": "host"}, "e": [{"n": 1}, {"n": "x,y{}"}], "c": [], "o": {}});
        let want = serde_json::to_string_pretty(&v).unwrap();
        assert_eq!(pretty(&serde_json::to_string(&v).unwrap(), 0), want);
    }

    #[test]
    fn clean_input_is_unchanged_and_unflagged() {
        let src = "{\"type\":\"x\",\"a\":[\"é\",\"ok\"],\"n\":1.5,\"m\":{\"k\":null}}";
        let (out, f) = json("x", src);
        assert_eq!(out, src);
        assert!(!f.any());
    }

    #[test]
    fn long_fields_are_cut_and_say_how_long_they_were() {
        let src = format!("{{\"type\":\"thread\",\"comm\":\"{}\"}}", "x".repeat(100));
        let (out, f) = json("thread", &src);
        assert_eq!(f.clipped["comm"], 100);
        assert!(out.ends_with("\"clipped\":{\"comm\":100}}"), "{out}");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["comm"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn invalid_bytes_show_as_hex() {
        let s = p_roc::text::from_bytes(b"ab\xff");
        let (out, f) =
            json("thread", &format!("{{\"type\":\"thread\",\"comm\":{}}}", serde_json::to_string(&s).unwrap()));
        assert!(out.contains("ab\\\\x{ff}"), "{out}");
        assert!(f.escaped);
    }
}
