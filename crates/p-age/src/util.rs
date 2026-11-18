//! How the broker shows a string that came from outside (the workspace's rule, `README.md`, "Strings from outside"):
//! text a certificate, a file, a program or a peer could have shaped is **escaped and bounded** where it is only shown
//! (an error, a line on standard error), and **validated and refused** where the broker acts on it.
//!
//! A JSON writer's own escaping is not the rule: `serde_json` escapes control characters and writes bidirectional marks
//! raw. What reaches the log and the JSON status is validated before it gets there (`site::valid_name`, the parsers of
//! `p-act`); `tests/outputs.rs` pins that.

use std::fmt::Display;

use p_ermit::text::{check, escape_clipped};

/// The most characters of an outside string that an error or a line shows.
pub const SHOWN_CHARS: usize = 200;

/// `s` escaped (`\u{202e}`, `\x{ff}`, `\\`) and cut at [`SHOWN_CHARS`], with the full length when it was cut.
#[must_use]
pub fn shown(s: &str) -> String {
    let c = escape_clipped(s, SHOWN_CHARS);
    if c.clipped { format!("{}… ({} characters in all)", c.text, c.full_len) } else { c.text }
}

/// The text of an error that was built from outside data (a certificate, `ssh-keygen`'s stderr, a parser), shown.
#[must_use]
pub fn shown_error(e: &dyn Display) -> String {
    shown(&e.to_string())
}

/// Whether `s` has no control character and no bidirectional mark.
#[must_use]
pub fn is_clean(s: &str) -> bool {
    check(s).is_ok()
}
