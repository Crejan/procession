//! One JSON object per line, built by hand: the output has a handful of
//! shapes and needs no serialisation library. Every string is escaped here,
//! so a host name or an argument can never break a line.

use std::fmt::Write as _;

/// The version of the record shapes every verb prints.
pub const SCHEMA_VERSION: u32 = 1;

/// One record: an object with a `type` member first, and no line break.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    text: String,
}

impl Record {
    /// A record of the given type.
    #[must_use]
    pub fn new(kind: &str) -> Self {
        let mut text = String::from("{\"type\":");
        push_string(&mut text, kind);
        Self { text }
    }

    fn key(mut self, key: &str) -> Self {
        self.text.push(',');
        push_string(&mut self.text, key);
        self.text.push(':');
        self
    }

    /// A string member.
    #[must_use]
    pub fn str(self, key: &str, value: &str) -> Self {
        let mut this = self.key(key);
        push_string(&mut this.text, value);
        this
    }

    /// A string member, or `null`.
    #[must_use]
    pub fn opt_str(self, key: &str, value: Option<&str>) -> Self {
        match value {
            Some(value) => self.str(key, value),
            None => self.raw(key, "null"),
        }
    }

    /// An integer member.
    #[must_use]
    pub fn num(self, key: &str, value: u64) -> Self {
        self.raw(key, &value.to_string())
    }

    /// A boolean member.
    #[must_use]
    pub fn bool(self, key: &str, value: bool) -> Self {
        self.raw(key, if value { "true" } else { "false" })
    }

    /// An array-of-strings member.
    #[must_use]
    pub fn strs<S: AsRef<str>>(self, key: &str, values: &[S]) -> Self {
        let mut this = self.key(key);
        this.text.push('[');
        for (index, value) in values.iter().enumerate() {
            if index > 0 {
                this.text.push(',');
            }
            push_string(&mut this.text, value.as_ref());
        }
        this.text.push(']');
        this
    }

    fn raw(self, key: &str, value: &str) -> Self {
        let mut this = self.key(key);
        this.text.push_str(value);
        this
    }

    /// The record as one line, without the line break.
    #[must_use]
    pub fn line(&self) -> String {
        format!("{}}}", self.text)
    }
}

/// Quotes and escapes `value`. Controls (also U+007F to U+009F) become
/// `\u00XX`, so no byte that could end or fake a line survives.
fn push_string(into: &mut String, value: &str) {
    into.push('"');
    for c in value.chars() {
        match c {
            '"' => into.push_str("\\\""),
            '\\' => into.push_str("\\\\"),
            c if c.is_control() => {
                let _ = write!(into, "\\u{:04x}", u32::from(c));
            }
            c => into.push(c),
        }
    }
    into.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_is_one_object_on_one_line() {
        let line =
            Record::new("x").str("a", "b").num("n", 3).bool("t", true).opt_str("o", None).strs("l", &["p", "q"]).line();
        assert_eq!(line, r#"{"type":"x","a":"b","n":3,"t":true,"o":null,"l":["p","q"]}"#);
    }

    #[test]
    fn nothing_in_a_value_can_break_the_line_or_the_object() {
        let line = Record::new("x").str("a", "q\"\\\n\r\t\u{0}\u{7f}\u{85}").line();
        assert!(!line.contains(['\n', '\r', '\t', '\u{0}', '\u{7f}', '\u{85}']));
        assert_eq!(line, r#"{"type":"x","a":"q\"\\\u000a\u000d\u0009\u0000\u007f\u0085"}"#);
    }
}
