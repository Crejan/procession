//! The audit line: one line in syslog before a call runs and one after, and
//! a call whose first line cannot be written does not run.
//!
//! The line is `event=<name> key=value ...`. Every value passes [`quote`],
//! which keeps a caller's bytes from adding a field or a line.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The tag in syslog.
pub const TAG: &str = "probe";
/// The facility and level in syslog.
pub const PRIORITY: &str = "auth.info";
/// A wedged syslog socket must not hold the verb that reports on the host.
const TIMEOUT: Duration = Duration::from_secs(10);
/// Where `logger` is looked for. Not `PATH`: this runs under sudo, and the
/// program that writes the record of a call is not the caller's to choose.
const LOGGER_PATHS: [&str; 2] = ["/usr/bin/logger", "/bin/logger"];
/// The longest value a refusal line copies from a caller.
pub const CLIP: usize = 200;

/// Where audit lines go.
pub trait Audit {
    /// Writes one line.
    ///
    /// # Errors
    /// Why it could not be written. The call then does not run.
    fn write(&self, line: &str) -> Result<(), String>;

    /// Where the lines go, in words, for `sys kit`.
    fn describe(&self) -> String;
}

/// Syslog, through `logger(1)` run by absolute path with an empty
/// environment. Same mechanism as `diag-tools`; no library, and the same on
/// Linux and macOS (only Linux is a target).
#[derive(Debug)]
pub struct Syslog {
    logger: Option<PathBuf>,
}

impl Syslog {
    /// Finds `logger` among [`LOGGER_PATHS`].
    #[must_use]
    pub fn new() -> Self {
        Self { logger: LOGGER_PATHS.iter().map(PathBuf::from).find(|path| path.is_file()) }
    }

    /// The command line for one line (tested without running it).
    fn argv(line: &str) -> Vec<String> {
        ["-t", TAG, "-p", PRIORITY, "--", line].map(String::from).to_vec()
    }
}

impl Default for Syslog {
    fn default() -> Self {
        Self::new()
    }
}

impl Audit for Syslog {
    fn write(&self, line: &str) -> Result<(), String> {
        let logger = self.logger.as_ref().ok_or("no logger found in /usr/bin or /bin")?;
        let mut child = Command::new(logger)
            .args(Self::argv(line))
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("cannot start logger: {error}"))?;
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) if status.success() => return Ok(()),
                Ok(Some(status)) => return Err(format!("logger failed: {status}")),
                Ok(None) if started.elapsed() > TIMEOUT => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("logger timed out".into());
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(5)),
                Err(error) => return Err(format!("logger: {error}")),
            }
        }
    }

    fn describe(&self) -> String {
        match &self.logger {
            Some(path) => format!("syslog via {}", path.display()),
            None => "syslog: logger not found".into(),
        }
    }
}

/// Appends lines to a file. For the tests only.
#[cfg(any(test, feature = "test-verbs"))]
#[derive(Debug)]
pub struct FileAudit(pub PathBuf);

#[cfg(any(test, feature = "test-verbs"))]
impl Audit for FileAudit {
    fn write(&self, line: &str) -> Result<(), String> {
        use std::io::Write as _;
        let mut file =
            std::fs::OpenOptions::new().append(true).create(true).open(&self.0).map_err(|e| e.to_string())?;
        writeln!(file, "{line}").map_err(|e| e.to_string())
    }

    fn describe(&self) -> String {
        format!("file {}", self.0.display())
    }
}

/// `value` as one word of an audit line. Plain words stay as they are;
/// anything else is single-quoted, with `'` as `'\''`, `\` as `\\`, and every
/// control or non-ASCII character as an escape, so the result is one printable
/// ASCII word on one line.
#[must_use]
pub fn quote(value: &str) -> String {
    let plain = |c: char| c.is_ascii_alphanumeric() || "_.,:/=+@%-".contains(c);
    if !value.is_empty() && value.chars().all(plain) {
        return value.to_string();
    }
    let mut out = String::from("'");
    for c in value.chars() {
        match c {
            '\'' => out.push_str("'\\''"),
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(c),
            c => out.extend(c.escape_unicode()),
        }
    }
    out.push('\'');
    out
}

/// At most `max` bytes of `value`, cut at a character boundary, with `...`
/// where something was left out.
#[must_use]
pub fn clip(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let mut end = max;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &value[..end])
}

/// `event=<event> k=v ...`, every value quoted.
#[must_use]
pub fn line(event: &str, fields: &[(&str, &str)]) -> String {
    let mut text = format!("event={event}");
    for (key, value) in fields {
        text.push(' ');
        text.push_str(key);
        text.push('=');
        text.push_str(&quote(value));
    }
    text
}

/// An audit sink that remembers, or refuses. For the tests only.
#[cfg(test)]
pub mod fake {
    use super::Audit;
    use std::cell::RefCell;

    #[derive(Debug, Default)]
    pub struct Memory {
        pub lines: RefCell<Vec<String>>,
        /// Refuse every line after this many were written.
        pub fail_after: Option<usize>,
    }

    impl Audit for Memory {
        fn write(&self, line: &str) -> Result<(), String> {
            if self.fail_after.is_some_and(|n| self.lines.borrow().len() >= n) {
                return Err("the sink is down".into());
            }
            self.lines.borrow_mut().push(line.to_string());
            Ok(())
        }

        fn describe(&self) -> String {
            "memory".into()
        }
    }
}

/// Where the state of the dispatcher is kept: the directory with the locks.
#[must_use]
pub fn default_lock_dir() -> &'static Path {
    Path::new("/var/lib/probe/locks")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_words_stay_and_others_are_one_printable_ascii_word() {
        assert_eq!(quote("pid=4711"), "pid=4711");
        assert_eq!(quote(""), "''");
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's"), "'it'\\''s'");
        assert_eq!(quote("a\nevent=done"), "'a\\u{a}event=done'");
        assert_eq!(quote("a\\b"), "'a\\\\b'");
        assert_eq!(quote("é\u{202e}"), "'\\u{e9}\\u{202e}'");
        for hostile in ["x\ny", "x\r\ny", "\u{0}", "x\u{85}y", "x\u{2028}y"] {
            assert!(quote(hostile).chars().all(|c| (' '..='~').contains(&c)), "{hostile:?}");
        }
    }

    #[test]
    fn a_value_cannot_add_a_field_or_a_line() {
        let text = line("refused", &[("reason", "x\nevent=done rc=0"), ("cmd", "a b")]);
        assert_eq!(text, "event=refused reason='x\\u{a}event=done rc=0' cmd='a b'");
        assert!(!text.contains('\n'));
    }

    #[test]
    fn clip_keeps_characters_whole() {
        assert_eq!(clip("abc", 5), "abc");
        assert_eq!(clip("abcdef", 3), "abc...");
        assert_eq!(clip("aéb", 2), "a...");
    }

    #[test]
    fn syslog_is_written_with_tag_and_priority_and_the_line_after_two_dashes() {
        assert_eq!(Syslog::argv("event=start"), ["-t", "probe", "-p", "auth.info", "--", "event=start"]);
    }

    #[test]
    fn a_file_sink_appends_and_a_broken_one_refuses() {
        let dir = crate::testdir::new("audit");
        let sink = FileAudit(dir.join("audit.log"));
        sink.write("one").unwrap();
        sink.write("two").unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("audit.log")).unwrap(), "one\ntwo\n");
        std::fs::create_dir(dir.join("dir")).unwrap();
        assert!(FileAudit(dir.join("dir")).write("x").is_err());
    }
}
