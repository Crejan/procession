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

// --- Escaping: for data that came from elsewhere and is shown or passed on, not refused -------------------------

/// Text escaped by [`escape`], [`escape_bytes`]: every character [`check`] refuses, and every byte that is not UTF-8,
/// is visible literal text, and a literal backslash is doubled, so the form is unambiguous and [`unescape`] undoes it.
///
/// - a control character or a bidirectional mark is `\u{202e}` (lower-case hex, no leading zeros);
/// - a byte that is not part of valid UTF-8 is `\x{ff}` (two lower-case hex digits);
/// - a backslash is `\\`.
///
/// The result has no character [`check`] refuses, so it can be put in JSON, a log or a terminal as it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Escaped {
    /// The escaped text.
    pub text: String,
    /// How many control characters, bidirectional marks and invalid bytes were escaped (a doubled backslash is not
    /// one of them): non-zero is what a caller flags a record with.
    pub flagged: usize,
}

impl Escaped {
    /// Whether anything the rule refuses was in the input.
    #[must_use]
    pub fn was_flagged(&self) -> bool {
        self.flagged > 0
    }
}

impl fmt::Display for Escaped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// [`escape_clipped`]'s result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clipped {
    /// The escaped text, at most the given number of characters, cut between escapes and never inside one.
    pub text: String,
    /// As [`Escaped::flagged`], **of what is in `text`**.
    pub flagged: usize,
    /// Whether text was dropped from the end.
    pub clipped: bool,
    /// The length of the whole input: characters for a `&str`, bytes for `&[u8]`.
    pub full_len: usize,
}

/// One unit of the escaped form: its text, whether it is flagged, and how long the input it stands for was.
struct Piece {
    text: String,
    flagged: bool,
    input_len: usize,
}

fn char_piece(c: char) -> Piece {
    let (text, flagged) = if c == '\\' {
        ("\\\\".to_owned(), false)
    } else if c.is_control() || is_bidi_mark(c) {
        (format!("\\u{{{:x}}}", u32::from(c)), true)
    } else {
        (c.to_string(), false)
    };
    Piece { text, flagged, input_len: 1 }
}

fn pieces_of_bytes(bytes: &[u8]) -> Vec<Piece> {
    let mut pieces = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                pieces.extend(text.chars().map(char_piece));
                break;
            }
            Err(error) => {
                let (valid, after) = rest.split_at(error.valid_up_to());
                // `valid` is valid UTF-8 by `valid_up_to`.
                pieces.extend(String::from_utf8_lossy(valid).chars().map(char_piece));
                let bad = error.error_len().unwrap_or(after.len()).min(after.len());
                pieces.extend(after[..bad].iter().map(|b| Piece {
                    text: format!("\\x{{{b:02x}}}"),
                    flagged: true,
                    input_len: 1,
                }));
                rest = &after[bad..];
            }
        }
    }
    pieces
}

fn escaped(pieces: Vec<Piece>) -> Escaped {
    Escaped { flagged: pieces.iter().filter(|p| p.flagged).count(), text: pieces.into_iter().map(|p| p.text).collect() }
}

fn clipped(pieces: Vec<Piece>, max_chars: usize) -> Clipped {
    let full_len = pieces.iter().map(|p| p.input_len).sum();
    let (mut text, mut flagged, mut used, mut clipped) = (String::new(), 0, 0, false);
    for piece in pieces {
        let n = piece.text.chars().count();
        if used + n > max_chars {
            clipped = true;
            break;
        }
        used += n;
        flagged += usize::from(piece.flagged);
        text.push_str(&piece.text);
    }
    Clipped { text, flagged, clipped, full_len }
}

/// `s` with every character [`check`] refuses made visible, as [`Escaped`] says. For diagnostic data that is shown or
/// passed on rather than refused.
#[must_use]
pub fn escape(s: &str) -> Escaped {
    escaped(s.chars().map(char_piece).collect())
}

/// As [`escape`] for bytes: what is not valid UTF-8 is `\x{..}` byte by byte, never replaced, so two different byte
/// strings never show alike.
#[must_use]
pub fn escape_bytes(bytes: &[u8]) -> Escaped {
    escaped(pieces_of_bytes(bytes))
}

/// [`escape`], then cut to at most `max_chars` characters of the escaped text, between escapes. Clipping is for data
/// that is shown; something a person approves by is refused, not cut.
#[must_use]
pub fn escape_clipped(s: &str, max_chars: usize) -> Clipped {
    clipped(s.chars().map(char_piece).collect(), max_chars)
}

/// [`escape_bytes`], then cut as [`escape_clipped`] does.
#[must_use]
pub fn escape_bytes_clipped(bytes: &[u8], max_chars: usize) -> Clipped {
    clipped(pieces_of_bytes(bytes), max_chars)
}

/// The bytes an escaped text stands for, or `None` if it is not in the form (a backslash that begins nothing known, an
/// escape that is not closed, a number that is not hex or not a character, a `\x` above `ff`). For tests and for a
/// person who needs the exact bytes.
#[must_use]
pub fn unescape_bytes(escaped: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(escaped.len());
    let mut chars = escaped.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            let mut buf = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            continue;
        }
        match chars.next()? {
            '\\' => out.push(b'\\'),
            kind @ ('u' | 'x') => {
                if chars.next()? != '{' {
                    return None;
                }
                let mut hex = String::new();
                loop {
                    match chars.next()? {
                        '}' => break,
                        h if h.is_ascii_hexdigit() && hex.len() < 8 => hex.push(h),
                        _ => return None,
                    }
                }
                let n = u32::from_str_radix(&hex, 16).ok()?;
                if kind == 'x' {
                    out.push(u8::try_from(n).ok()?);
                } else {
                    let mut buf = [0u8; 4];
                    out.extend_from_slice(char::from_u32(n)?.encode_utf8(&mut buf).as_bytes());
                }
            }
            _ => return None,
        }
    }
    Some(out)
}

/// As [`unescape_bytes`], and the result must be UTF-8 (it is, for anything [`escape`] made).
#[must_use]
pub fn unescape(escaped: &str) -> Option<String> {
    String::from_utf8(unescape_bytes(escaped)?).ok()
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

#[cfg(test)]
mod escape_tests {
    use super::*;

    const ALPHABET: [char; 12] =
        ['a', ' ', '\\', '\n', '\0', '\u{7f}', '\u{85}', '\u{202e}', '\u{2066}', '\u{e9}', '\u{1f600}', 'u'];

    #[test]
    fn the_forms() {
        let e = escape("a\u{202e}b\x07c\\d\u{1b}[31m");
        assert_eq!(e.text, "a\\u{202e}b\\u{7}c\\\\d\\u{1b}[31m");
        assert_eq!(e.flagged, 3, "the backslash is escaped but not flagged");
        assert_eq!(escape("plain \u{e9} \u{65e5}").flagged, 0);
        assert!(!escape("plain").was_flagged() && escape("\n").was_flagged());
        assert_eq!(escape_bytes(b"ab\xffc\xc3").text, "ab\\x{ff}c\\x{c3}");
        assert_eq!(escape_bytes(b"ab\xffc\xc3").flagged, 2);
        assert_eq!(escape_bytes("\u{e9}".as_bytes()).text, "\u{e9}");
        // A truncated sequence and a stray continuation byte; every invalid byte on its own.
        assert_eq!(escape_bytes(&[0xe6, 0x97]).text, "\\x{e6}\\x{97}");
        assert_eq!(escape_bytes(&[0x80, 0x80]).text, "\\x{80}\\x{80}");
        // A literal `\u{202e}` in the input is not the escape of the mark.
        assert_ne!(escape("\\u{202e}").text, escape("\u{202e}").text);
        assert_eq!(escape("\\u{202e}").text, "\\\\u{202e}");
        assert_eq!(e.to_string(), e.text);
    }

    #[test]
    fn it_is_reversible_and_the_result_passes_the_rule_for_everything_short_over_a_hard_alphabet() {
        let mut inputs = vec![String::new()];
        for _ in 0..4 {
            let longer: Vec<String> =
                inputs.iter().flat_map(|s| ALPHABET.iter().map(move |c| format!("{s}{c}"))).collect();
            inputs.extend(longer);
            inputs.truncate(40_000);
        }
        for s in inputs {
            let e = escape(&s);
            assert_eq!(unescape(&e.text).as_deref(), Some(s.as_str()), "{s:?}");
            assert_eq!(check(&e.text), Ok(()), "{s:?}");
            assert_eq!(e.flagged > 0, check(&s).is_err(), "{s:?}");
            assert!(e.text.chars().all(|c| !c.is_control() && !is_bidi_mark(c)));
        }
    }

    #[test]
    fn bytes_are_reversible_and_never_alike() {
        // A small deterministic generator: no dependency.
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let mut seen = std::collections::HashMap::new();
        for _ in 0..20_000 {
            let len = usize::try_from(next() % 9).unwrap();
            // Biased to bytes that matter: UTF-8 lead and continuation bytes, controls, backslash, `u`, `x`, `{`.
            let bytes: Vec<u8> = (0..len)
                .map(|_| match next() % 6 {
                    0 => [0xe2, 0x80, 0xae, 0xc3, 0xa9, 0xf0, 0x9f, 0x98][usize::try_from(next() % 8).unwrap()],
                    1 => b"\\ux{}"[usize::try_from(next() % 5).unwrap()],
                    2 => u8::try_from(next() % 0x20).unwrap(),
                    _ => u8::try_from(next() & 0xff).unwrap(),
                })
                .collect();
            let e = escape_bytes(&bytes);
            assert_eq!(unescape_bytes(&e.text).as_deref(), Some(bytes.as_slice()), "{bytes:?}");
            assert_eq!(check(&e.text), Ok(()), "{bytes:?}");
            if let Some(other) = seen.insert(e.text.clone(), bytes.clone()) {
                assert_eq!(other, bytes, "two byte strings showed alike: {}", e.text);
            }
        }
    }

    #[test]
    fn unescape_refuses_what_is_not_the_form() {
        for bad in [
            "\\",
            "\\q",
            "\\u",
            "\\u{",
            "\\u{202e",
            "\\u{zz}",
            "\\u{}",
            "\\x{100}",
            "\\u{d800}",
            "\\u{110000}",
            "\\u202e",
            "\\u{123456789}",
        ] {
            assert_eq!(unescape_bytes(bad), None, "{bad}");
        }
        assert_eq!(unescape("\\x{ff}"), None, "not UTF-8");
        assert_eq!(unescape_bytes("\\x{ff}"), Some(vec![0xff]));
    }

    #[test]
    fn clipping_is_between_escapes_and_says_so() {
        let s = "ab\u{202e}cd";
        // a b \u{202e} c d: 1 + 1 + 8 + 1 + 1 characters of escaped text.
        let full = escape_clipped(s, 100);
        assert_eq!((full.text.as_str(), full.clipped, full.full_len, full.flagged), ("ab\\u{202e}cd", false, 5, 1));
        for max in 0..14 {
            let c = escape_clipped(s, max);
            assert!(c.text.chars().count() <= max, "{max}");
            assert!(unescape(&c.text).is_some_and(|t| s.starts_with(&t)), "{max}: {}", c.text);
            assert_eq!(c.clipped, max < 12, "{max}");
            assert_eq!(c.full_len, 5);
        }
        // Just before the escape ends: the escape is dropped whole.
        assert_eq!(escape_clipped(s, 9).text, "ab");
        assert_eq!(escape_clipped(s, 10).text, "ab\\u{202e}");
        assert_eq!(escape_clipped(s, 10).flagged, 1);
        assert_eq!(escape_clipped(s, 9).flagged, 0, "of what is in the text");
        assert_eq!(escape_clipped("", 0), Clipped { text: String::new(), flagged: 0, clipped: false, full_len: 0 });
        let b = escape_bytes_clipped(&[b'a', 0xff, b'b'], 6);
        assert_eq!((b.text.as_str(), b.clipped, b.full_len), ("a", true, 3));
        let b = escape_bytes_clipped(&[b'a', 0xff, b'b'], 8);
        assert_eq!((b.text.as_str(), b.clipped, b.flagged), ("a\\x{ff}b", false, 1));
        // Multi-byte characters count once.
        assert_eq!(escape_clipped("\u{1f600}\u{1f600}\u{1f600}", 2).text, "\u{1f600}\u{1f600}");
    }
}
