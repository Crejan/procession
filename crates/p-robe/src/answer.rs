//! What a verb writes: records, one per line, capped.

use std::io::Write;

use crate::json::{Record, SCHEMA_VERSION};

/// Every answer is capped, so that no verb fills an agent's context or a
/// terminal. 1 MiB is the figure `doc/approvals.md` section 7 gives a command's
/// output; the same for every verb until one needs another.
pub const ANSWER_CAP: usize = 1 << 20;

/// What the last record has to leave room for: `{"type":"truncated",...}`.
const TRUNCATED_ROOM: usize = 96;

/// The answer is full (or its reader has gone): the verb stops writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Full;

/// The writer of one verb's answer.
pub struct Answer<'a> {
    out: &'a mut dyn Write,
    cap: usize,
    written: usize,
    full: bool,
    lost: bool,
    failure: Option<String>,
}

impl<'a> Answer<'a> {
    /// An answer of at most `cap` bytes.
    pub fn new(out: &'a mut dyn Write, cap: usize) -> Self {
        Self { out, cap, written: 0, full: false, lost: false, failure: None }
    }

    /// Writes one record. When it would not fit, writes a final `truncated`
    /// record instead, and every later call fails with [`Full`].
    ///
    /// # Errors
    /// [`Full`] when the cap is reached or the reader has gone.
    pub fn record(&mut self, record: &Record) -> Result<(), Full> {
        self.record_line(&record.line())
    }

    /// As [`Answer::record`], for a line that is already one JSON object (a record the tool wrote).
    ///
    /// # Errors
    /// [`Full`] when the cap is reached or the reader has gone.
    pub fn record_line(&mut self, line: &str) -> Result<(), Full> {
        if self.full {
            return Err(Full);
        }
        if self.written + line.len() + 1 + TRUNCATED_ROOM > self.cap {
            let note = Record::new("truncated").num("limit_bytes", self.cap as u64).line();
            self.lost |= writeln!(self.out, "{note}").is_err();
            self.full = true;
            return Err(Full);
        }
        if writeln!(self.out, "{line}").is_err() {
            self.full = true;
            self.lost = true;
            return Err(Full);
        }
        self.written += line.len() + 1;
        Ok(())
    }

    /// Whether the cap cut the answer.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.full
    }

    /// Says that the verb was started and gave no usable result, and why: the dispatcher ends the call as
    /// failed with this cause. The first cause stays.
    pub fn fail(&mut self, cause: &str) {
        self.failure.get_or_insert_with(|| cause.to_string());
    }

    /// The cause the verb gave with [`Answer::fail`], if it did.
    #[must_use]
    pub fn failure(&self) -> Option<&str> {
        self.failure.as_deref()
    }

    /// Whether the reader went away: the answer did not get out, and not even as a clean cut.
    #[must_use]
    pub fn lost(&self) -> bool {
        self.lost
    }

    /// Bytes written.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.written
    }
}

/// The first record of every verb's answer.
#[must_use]
pub fn header(noun: &str, verb: &str, host: &str, ts: &str) -> Record {
    Record::new("header")
        .num("schema_version", u64::from(SCHEMA_VERSION))
        .str("noun", noun)
        .str("verb", verb)
        .str("host", host)
        .str("ts", ts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_are_written_one_per_line() {
        let mut out = Vec::new();
        let mut answer = Answer::new(&mut out, 1000);
        answer.record(&Record::new("a")).unwrap();
        answer.record(&Record::new("b")).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "{\"type\":\"a\"}\n{\"type\":\"b\"}\n");
    }

    #[test]
    fn at_the_cap_the_answer_ends_with_a_truncated_record_and_nothing_more() {
        let mut out = Vec::new();
        let mut answer = Answer::new(&mut out, 400);
        let big = Record::new("x").str("pad", &"a".repeat(100));
        let mut stopped_at = None;
        for index in 0..20 {
            if answer.record(&big).is_err() {
                stopped_at = Some(index);
                break;
            }
        }
        assert!(stopped_at.is_some());
        assert!(answer.truncated());
        assert_eq!(answer.record(&Record::new("late")), Err(Full));
        let text = String::from_utf8(out).unwrap();
        assert!(text.len() <= 400, "{}", text.len());
        assert!(text.lines().last().unwrap().starts_with("{\"type\":\"truncated\""));
        assert!(!text.contains("late"));
    }

    #[test]
    fn a_reader_that_has_gone_stops_the_verb() {
        struct Gone;
        impl Write for Gone {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut gone = Gone;
        let mut answer = Answer::new(&mut gone, 1000);
        assert_eq!(answer.record(&Record::new("a")), Err(Full));
    }
}
