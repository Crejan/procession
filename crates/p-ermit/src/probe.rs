//! For the tests of every program that must show or log text from elsewhere (feature `test-support`): strings that carry
//! what the rule refuses, and a check that a program's output has none of it raw.
//!
//! The probes are a C1 control character (U+0085 and U+009B, the single-byte CSI), a bidirectional mark (U+202E) and an
//! ordinary C0 control (ESC). A test feeds them through every output a program has and calls [`assert_clean`] on what
//! comes out.

use crate::text::{check, escape};

/// A C1 control character, the next-line mark.
pub const C1_NEL: &str = "\u{85}";
/// A C1 control character, the single-byte control sequence introducer: a terminal may act on it.
pub const C1_CSI: &str = "\u{9b}";
/// A bidirectional mark: the right-to-left override.
pub const BIDI_RLO: &str = "\u{202e}";
/// A C0 control character: escape.
pub const C0_ESC: &str = "\u{1b}";

/// All of them, each on its own.
pub const PROBES: [&str; 4] = [C1_NEL, C1_CSI, BIDI_RLO, C0_ESC];

/// One string that has every probe in it, between ordinary letters: `a<NEL>b<CSI>c<RLO>d<ESC>e`.
pub const PROBE_ALL: &str = "a\u{85}b\u{9b}c\u{202e}d\u{1b}e";

/// Panics, saying where and what (the text **escaped**, so that the failure message is clean too), if `output` holds a
/// control character or a bidirectional mark. `what` names the output being checked.
#[track_caller]
pub fn assert_clean_in(what: &str, output: &str) {
    if let Err(kind) = check(output) {
        panic!("{what} has {kind} in it, raw: {}", escape(output).text);
    }
}

/// [`assert_clean_in`] without a name. A newline at the end of a line of output is the caller's to remove first.
#[track_caller]
pub fn assert_clean(output: &str) {
    assert_clean_in("the output", output);
}

/// Whether `output` shows any probe raw (the same as `check(output).is_err()`, for a test that asserts the opposite).
#[must_use]
pub fn is_dirty(output: &str) -> bool {
    check(output).is_err()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_probes_are_refused_by_the_rule_and_clean_text_passes() {
        for p in PROBES.iter().chain(std::iter::once(&PROBE_ALL)) {
            assert!(is_dirty(p), "{p:?}");
            assert_clean(&escape(p).text);
        }
        assert_clean("plain \u{e9} text");
    }

    #[test]
    #[should_panic(expected = "a control character in it, raw: a\\u{85}b")]
    fn a_dirty_output_fails_and_the_failure_message_is_itself_clean() {
        assert_clean(PROBE_ALL);
    }
}
