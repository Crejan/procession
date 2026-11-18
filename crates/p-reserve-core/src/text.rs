//! Strings from outside are shown through `p_ermit::text`, the workspace's rule: a control character, a bidirectional
//! mark or a byte that is not UTF-8 becomes visible literal text (`\u{202e}`, `\x{ff}`), reversibly, and the record
//! that held one is flagged. This module only names the two uses that recur here.

pub use p_ermit::text::{Clipped, Escaped, escape, escape_bytes, escape_bytes_clipped, escape_clipped};

/// The longest text of an error's `detail`, in characters of the escaped form.
pub const MAX_DETAIL: usize = 512;

/// `text` escaped and bounded: for a log, and for the words of a program or library that was run (rustic's own
/// messages quote paths and repository data). Never for a machine reader.
pub fn for_log(text: &str) -> String {
    escape_clipped(text, MAX_DETAIL).text
}

/// `text` escaped, for an argument or a name echoed in an error.
pub fn shown(text: &str) -> String {
    escape(text).text
}
