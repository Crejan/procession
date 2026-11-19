//! The rule for strings from outside (`p_ermit::text`), for what p-usher writes: its log, its
//! e-mails and its metrics file. A thread name, a path, a user name, the host name and the text of an
//! error that came from a relay are not ours; they are escaped and bounded before they are shown.

use std::path::{Path, PathBuf};

use p_ermit::text::escape_bytes_clipped;

/// A thread name, at most this many characters of the escaped text.
pub const COMM_MAX: usize = 64;
/// A user or host name.
pub const NAME_MAX: usize = 255;
/// A path.
pub const PATH_MAX: usize = 4096;
/// The text of an error that may carry words from elsewhere (a mail relay, a file).
pub const ERROR_MAX: usize = 512;

/// `s` (as `p_roc::text` hands out host strings) made safe to show: refused characters and bytes that
/// are not UTF-8 become visible text, a backslash is doubled, and the result is cut to `max` characters.
#[must_use]
pub fn clean(s: &str, max: usize) -> String {
    escape_bytes_clipped(&p_roc::text::to_bytes(s), max).text
}

/// [`clean`] for a path read from the host.
#[must_use]
pub fn clean_path(p: &Path) -> PathBuf {
    PathBuf::from(clean(&p_roc::text::from_os(p.as_os_str()), PATH_MAX))
}

/// [`clean`] for an error to be logged.
#[must_use]
pub fn clean_error(e: &anyhow::Error) -> String {
    clean(&format!("{e:#}"), ERROR_MAX)
}

#[cfg(test)]
mod tests {
    use p_ermit::probe::{PROBE_ALL, assert_clean};

    use super::*;

    #[test]
    fn probes_are_made_visible_and_text_is_bounded() {
        assert_clean(&clean(PROBE_ALL, COMM_MAX));
        assert_eq!(clean("plain é", COMM_MAX), "plain é");
        assert_eq!(clean(&"x".repeat(100), 10).chars().count(), 10);
        assert_eq!(clean(&p_roc::text::from_bytes(b"a\xff"), 64), "a\\x{ff}");
    }
}
