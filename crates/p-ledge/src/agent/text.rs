//! What may be shown to a person as it is (`doc/approval-formats.md`,
//! section 2; `doc/approvals.md`, R9). Text with a control character or a
//! bidirectional mark is refused, never cleaned.

/// The most characters of one field a dialog shows (`doc/approvals.md`,
/// section 7). Longer is refused.
pub const MAX_FIELD_CHARS: usize = 200;

/// Control characters: U+0000 to U+001F and U+007F to U+009F.
fn is_control(c: char) -> bool {
    matches!(c, '\u{0}'..='\u{1F}' | '\u{7F}'..='\u{9F}')
}

/// Bidirectional marks: U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to
/// U+2069.
fn is_bidi(c: char) -> bool {
    matches!(c, '\u{61C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// `text` with every control character and bidirectional mark written as
/// `\u{XXXX}`, for a reader that prints what it did not write itself (the
/// record is written clean; `pledge history` does not rely on it).
#[must_use]
pub fn escape_unshowable(text: &str) -> String {
    text.chars()
        .map(|c| if is_control(c) || is_bidi(c) { format!("\\u{{{:04X}}}", u32::from(c)) } else { c.to_string() })
        .collect()
}

/// Whether `text` holds no control character and no bidirectional mark (its length is
/// the caller's limit, which differs by field).
#[must_use]
pub fn is_clean(text: &str) -> bool {
    !text.chars().any(|c| is_control(c) || is_bidi(c))
}

/// Whether `text` can be shown as it is: at most [`MAX_FIELD_CHARS`]
/// characters, none a control character or a bidirectional mark.
#[must_use]
pub fn is_showable(text: &str) -> bool {
    text.chars().count() <= MAX_FIELD_CHARS && !text.chars().any(|c| is_control(c) || is_bidi(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_text_is_showable() {
        assert!(is_showable("jan"));
        assert!(is_showable("git"));
        assert!(is_showable("Ünïcode ✓"));
        assert!(is_showable(""));
    }

    #[test]
    fn controls_are_not() {
        for text in ["a\nb", "a\tb", "a\u{0}b", "a\u{7F}b", "a\u{85}b", "a\u{9F}b", "\u{1B}[31m"] {
            assert!(!is_showable(text), "{text:?}");
        }
    }

    #[test]
    fn bidirectional_marks_are_not() {
        for c in ['\u{61C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202E}', '\u{2066}', '\u{2069}'] {
            assert!(!is_showable(&format!("ja{c}n")), "{c:?}");
        }
    }

    #[test]
    fn escaping_makes_everything_printable() {
        assert_eq!(escape_unshowable("a\u{1B}[31m\u{202E}b"), "a\\u{001B}[31m\\u{202E}b");
        assert_eq!(escape_unshowable("plain ✓"), "plain ✓");
    }

    #[test]
    fn length_counts_characters_not_bytes() {
        assert!(is_showable(&"é".repeat(MAX_FIELD_CHARS)));
        assert!(!is_showable(&"é".repeat(MAX_FIELD_CHARS + 1)));
    }
}
