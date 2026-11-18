//! The workspace's rule for anything that is shown to a person or written to a log: **no control characters and no
//! bidirectional marks**. A control character can rewrite a terminal or a log line; a bidirectional mark can make
//! text read as something else than it is. One definition, so that every program refuses the same set.

use std::fmt;

/// Which kind of character was refused. It never holds the character itself, so that an error that is logged or shown
/// cannot carry what it refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// A control character: U+0000 to U+001F, U+007F to U+009F.
    Control,
    /// A bidirectional mark: U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069.
    Bidi,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Refused::Control => "a control character",
            Refused::Bidi => "a bidirectional mark",
        })
    }
}

impl std::error::Error for Refused {}

/// Whether `c` is a bidirectional mark.
#[must_use]
pub fn is_bidi_mark(c: char) -> bool {
    matches!(c, '\u{061C}' | '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}')
}

/// `Ok` if `s` has no control character and no bidirectional mark; else the kind of the first one found. The
/// character is not in the error.
pub fn check(s: &str) -> Result<(), Refused> {
    for c in s.chars() {
        if c.is_control() {
            return Err(Refused::Control);
        }
        if is_bidi_mark(c) {
            return Err(Refused::Bidi);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn controls_and_bidi_marks_are_told_apart_and_never_echoed() {
        for c in ['\0', '\u{1f}', '\u{7f}', '\u{85}', '\u{9f}', '\n', '\t', '\r', '\u{1b}'] {
            assert_eq!(check(&format!("a{c}b")), Err(Refused::Control), "{c:?}");
        }
        for c in ['\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202D}', '\u{202E}', '\u{2066}', '\u{2069}'] {
            assert_eq!(check(&format!("a{c}b")), Err(Refused::Bidi), "{c:?}");
        }
        assert_eq!(check("ordinary \u{e9} \u{65e5}\u{672c} \u{2713} \u{1f600}"), Ok(()));
        assert_eq!(check(""), Ok(()));
        // The boundaries: just outside the ranges is fine, and so are separators that are not control characters
        // (U+2029 is a paragraph separator, category Zp; the rule is the formats', which is Cc and the marks above).
        for c in ['\u{a0}', '\u{2065}', '\u{206a}', '\u{202f}', '\u{2029}', '\u{200d}'] {
            assert_eq!(check(&c.to_string()), Ok(()), "{c:?}");
        }
        assert_eq!(Refused::Control.to_string(), "a control character");
        assert!(!Refused::Bidi.to_string().contains('\u{202e}'));
    }
}
