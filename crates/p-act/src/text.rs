//! Rules for strings (formats section 2).

use crate::error::ParseError;

/// Control characters (U+0000 to U+001F, U+007F to U+009F) and bidirectional
/// marks (U+061C, U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069) are
/// refused.
pub(crate) fn check(member: &str, s: &str) -> Result<(), ParseError> {
    p_ermit::text::check(s).map_err(|refused| match refused {
        p_ermit::text::Refused::Control => ParseError::ControlCharacter(member.to_owned()),
        p_ermit::text::Refused::Bidi => ParseError::BidiMark(member.to_owned()),
    })
}

/// A name that can safely stand in an allowed-signers principal: it contains
/// nothing that `ssh-keygen` would read as a separator, pattern or quote.
pub(crate) fn is_name(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// `[a-z][a-z0-9-]*`
pub(crate) fn is_service_name(s: &str) -> bool {
    let mut bytes = s.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// Lower-case words separated by single spaces; a word is `[a-z][a-z0-9-]*`.
pub(crate) fn is_action(s: &str) -> bool {
    s.split(' ').all(is_service_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_controls_and_bidi_marks_with_distinct_errors() {
        for c in ['\0', '\u{1f}', '\u{7f}', '\u{85}', '\u{9f}', '\n', '\t'] {
            assert_eq!(check("m", &format!("a{c}b")), Err(ParseError::ControlCharacter("m".into())), "{c:?}");
        }
        for c in ['\u{061C}', '\u{200E}', '\u{200F}', '\u{202A}', '\u{202E}', '\u{2066}', '\u{2069}'] {
            assert_eq!(check("m", &format!("a{c}b")), Err(ParseError::BidiMark("m".into())), "{c:?}");
        }
        assert_eq!(check("m", "ordinary ü 日本 ✓"), Ok(()));
    }

    #[test]
    fn names_actions() {
        assert!(is_action("rt procs") && is_action("run command") && is_action("x"));
        for bad in ["", " a", "a ", "a  b", "A b", "a_b", "1a", "a\nb"] {
            assert!(!is_action(bad), "{bad:?}");
        }
        assert!(is_service_name("probe") && is_service_name("p-1"));
        assert!(!is_service_name("") && !is_service_name("-p") && !is_service_name("P"));
        assert!(is_name(&"a".repeat(64)) && !is_name(&"a".repeat(65)));
        assert!(is_name("a.example") && is_name("alice") && is_name("host-1_x"));
        for bad in ["", "a b", "a@b", "a,b", "a*", "a\"b", "a:b", "!a"] {
            assert!(!is_name(bad), "{bad:?}");
        }
    }
}
