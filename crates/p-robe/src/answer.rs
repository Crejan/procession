//! What a verb writes: records, one per line, capped.

use std::collections::BTreeMap;
use std::io::Write;

use crate::json::{Record, SCHEMA_VERSION};
use crate::text_rule::{self, Limits};

/// Every answer is capped, so that no verb fills an agent's context or a
/// terminal. 1 MiB is the figure `doc/approvals.md` section 7 gives a command's
/// output; the same for every verb until one needs another.
pub const ANSWER_CAP: usize = 1 << 20;

/// What is kept back out of the cap for the `truncated` record: it says how much was dropped, by type.
pub const TRUNCATED_MAX: usize = 1024;

/// What is kept back out of the cap for the closing record (a verb's trailer or summary): a small fixed
/// bound, so that a cut answer still ends with its code, its result and the full counts.
pub const CLOSING_MAX: usize = 2048;

/// The most types the `truncated` record names; the rest are counted together as `others`.
const DROPPED_TYPES_NAMED: usize = 8;

/// The longest type name the `truncated` record repeats (a tool's own words are clipped).
const TYPE_NAME_MAX: usize = 40;

/// The answer's reader has gone: the verb may stop writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Full;

/// The writer of one verb's answer.
///
/// The cap applies to everything before the closing record. A record that would pass it, and every
/// record after, is not written but counted (lines, bytes, by `type`); [`Answer::close`] then writes the
/// `truncated` record that says how much was dropped, and after it the closing record, which is never
/// left out: it carries what the verb found in full, not what was sent. A verb goes on after the cut (its
/// writes succeed), so the counts are complete.
pub struct Answer<'a> {
    out: &'a mut dyn Write,
    cap: usize,
    written: usize,
    full: bool,
    closed: bool,
    /// The `truncated` record has been written.
    noted: bool,
    lost: bool,
    failure: Option<String>,
    dropped_lines: u64,
    dropped_bytes: u64,
    dropped: BTreeMap<String, u64>,
    /// The fields a row declares as content, which have limits of their own.
    content: &'a [(&'static str, usize)],
    /// Records in which the dispatcher escaped something, and records in which it cut a field (every record the
    /// verb wrote, also the ones the cap dropped).
    escaped_records: u64,
    clipped_records: u64,
}

/// What the closing record may say of the answer before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Closing {
    /// The cap dropped lines.
    pub truncated: bool,
    /// Records before the closing one in which the dispatcher itself escaped a string: what the verb or its tool
    /// did not.
    pub escaped_records: u64,
    /// Records before the closing one in which the dispatcher cut a field.
    pub clipped_records: u64,
}

impl<'a> Answer<'a> {
    /// An answer of at most `cap` bytes, the closing record and the `truncated` record included.
    pub fn new(out: &'a mut dyn Write, cap: usize) -> Self {
        Self {
            out,
            cap,
            written: 0,
            full: false,
            closed: false,
            noted: false,
            lost: false,
            failure: None,
            dropped_lines: 0,
            dropped_bytes: 0,
            dropped: BTreeMap::new(),
            content: &[],
            escaped_records: 0,
            clipped_records: 0,
        }
    }

    /// Names the fields of this verb's records that are content (a file's bytes), not names: they have their
    /// own limit instead of the usual one.
    pub fn set_content(&mut self, content: &'a [(&'static str, usize)]) {
        self.content = content;
    }

    /// The rule for strings from outside, applied to one record; `None` if it cannot be read as one (it is then not
    /// passed on, and the call has failed).
    fn ruled(&mut self, line: &str) -> Option<String> {
        let limits = Limits { field: text_rule::FIELD_MAX, content: self.content };
        let done = text_rule::rewrite(line, &limits);
        match done {
            Some(done) => {
                self.escaped_records += u64::from(done.escaped);
                self.clipped_records += u64::from(!done.clipped.is_empty());
                Some(done.line)
            }
            None => {
                self.fail("unreadable-record");
                None
            }
        }
    }

    /// Writes one record, or, past the cap, counts it as dropped.
    ///
    /// # Errors
    /// [`Full`] when the reader has gone.
    pub fn record(&mut self, record: &Record) -> Result<(), Full> {
        self.record_line(&record.line())
    }

    /// As [`Answer::record`], for a line that is already one JSON object (a record the tool wrote).
    ///
    /// # Errors
    /// [`Full`] when the reader has gone.
    pub fn record_line(&mut self, line: &str) -> Result<(), Full> {
        if self.closed {
            return Ok(());
        }
        let Some(line) = self.ruled(line) else { return Ok(()) };
        let line = line.as_str();
        if !self.full && self.written + line.len() + 1 + TRUNCATED_MAX + CLOSING_MAX > self.cap {
            self.full = true;
        }
        if self.full {
            self.dropped_lines += 1;
            self.dropped_bytes += line.len() as u64 + 1;
            *self.dropped.entry(type_of(line)).or_default() += 1;
            return Ok(());
        }
        self.put(line)
    }

    fn put(&mut self, line: &str) -> Result<(), Full> {
        if writeln!(self.out, "{line}").is_err() {
            self.lost = true;
            return Err(Full);
        }
        self.written += line.len() + 1;
        Ok(())
    }

    /// The `truncated` record, if the cap cut the answer: how much was dropped and of which types.
    fn truncated_line(&self) -> Option<String> {
        if !self.full {
            return None;
        }
        let mut by_type: Vec<(&String, &u64)> = self.dropped.iter().collect();
        by_type.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let others: u64 = by_type.iter().skip(DROPPED_TYPES_NAMED).map(|(_, n)| **n).sum();
        let named: Vec<String> = by_type
            .iter()
            .take(DROPPED_TYPES_NAMED)
            .map(|(kind, n)| format!("{}:{n}", serde_json::Value::String((*kind).clone())))
            .collect();
        Some(format!(
            "{{\"type\":\"truncated\",\"limit_bytes\":{},\"dropped_lines\":{},\"dropped_bytes\":{},\"dropped\":{{{}}},\"others\":{others}}}",
            self.cap,
            self.dropped_lines,
            self.dropped_bytes,
            named.join(",")
        ))
    }

    /// Ends the answer: the `truncated` record if it was cut, then the closing record, which `make`
    /// builds knowing whether it was cut. Always written, whatever the cap said.
    ///
    /// # Errors
    /// [`Full`] when the reader has gone.
    pub fn close(&mut self, make: impl FnOnce(&Closing) -> Record) -> Result<(), Full> {
        if self.closed {
            return Ok(());
        }
        let closing = Closing {
            truncated: self.full,
            escaped_records: self.escaped_records,
            clipped_records: self.clipped_records,
        };
        let line = make(&closing).line();
        // The closing record's own strings are held to the rule too (`sys kit` reports strings from files).
        let line = self.ruled(&line).unwrap_or(line);
        let result = self.finish().and_then(|()| self.put(&line));
        self.closed = true;
        result
    }

    /// Writes the `truncated` record if the answer was cut and it has not been written; for a verb that
    /// has no closing record.
    ///
    /// # Errors
    /// [`Full`] when the reader has gone.
    pub fn finish(&mut self) -> Result<(), Full> {
        if self.closed {
            return Ok(());
        }
        match self.truncated_line() {
            Some(line) if !self.noted => {
                self.noted = true;
                self.put(&line)
            }
            _ => Ok(()),
        }
    }

    /// Whether the cap cut the answer.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.full
    }

    /// Lines dropped by the cap.
    #[must_use]
    pub fn dropped_lines(&self) -> u64 {
        self.dropped_lines
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

/// The `type` of a record line, clipped; `?` if it has none.
fn type_of(line: &str) -> String {
    line.strip_prefix("{\"type\":\"")
        .and_then(|rest| rest.split('"').next())
        .map_or_else(|| "?".to_string(), |kind| kind.chars().take(TYPE_NAME_MAX).collect())
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

    const ROOM: usize = TRUNCATED_MAX + CLOSING_MAX;

    fn trailer(closing: &Closing) -> Record {
        Record::new("trailer")
            .num("rc", 1)
            .str("result", "warnings")
            .num("records", 20)
            .bool("truncated", closing.truncated)
    }

    #[test]
    fn records_are_written_one_per_line() {
        let mut out = Vec::new();
        let mut answer = Answer::new(&mut out, ROOM + 1000);
        answer.record(&Record::new("a")).unwrap();
        answer.record(&Record::new("b")).unwrap();
        assert_eq!(String::from_utf8(out).unwrap(), "{\"type\":\"a\"}\n{\"type\":\"b\"}\n");
    }

    #[test]
    fn a_cut_answer_says_what_was_dropped_and_still_ends_with_its_closing_record() {
        let mut out = Vec::new();
        let cap = ROOM + 400;
        let mut answer = Answer::new(&mut out, cap);
        let big = Record::new("x").str("pad", &"a".repeat(100));
        for _ in 0..20 {
            // The verb is not stopped: its writes succeed, and are counted.
            assert_eq!(answer.record(&big), Ok(()));
        }
        assert_eq!(answer.record(&Record::new("y")), Ok(()));
        assert!(answer.truncated());
        answer.close(trailer).unwrap();
        assert_eq!(answer.record(&Record::new("late")), Ok(()), "after the end nothing is written");
        let text = String::from_utf8(out).unwrap();
        assert!(text.len() <= cap, "{} > {cap}", text.len());
        let lines: Vec<&str> = text.lines().collect();
        let kept = lines.len() - 2;
        assert!((1..20).contains(&kept), "{lines:?}");
        let cut: serde_json::Value = serde_json::from_str(lines[kept]).unwrap();
        assert_eq!(cut["type"], "truncated");
        assert_eq!(cut["dropped_lines"].as_u64(), Some(21 - kept as u64));
        assert_eq!(cut["dropped"]["x"].as_u64(), Some(20 - kept as u64));
        assert_eq!(cut["dropped"]["y"], 1);
        let (big_len, y_len) = (big.line().len() as u64 + 1, Record::new("y").line().len() as u64 + 1);
        assert_eq!(cut["dropped_bytes"].as_u64(), Some((20 - kept as u64) * big_len + y_len));
        let last: serde_json::Value = serde_json::from_str(lines[kept + 1]).unwrap();
        assert_eq!(
            (last["type"].as_str(), last["truncated"].as_bool(), last["rc"].as_i64()),
            (Some("trailer"), Some(true), Some(1))
        );
        assert!(lines[kept + 1].len() < CLOSING_MAX);
        assert!(!text.contains("late"));
    }

    #[test]
    fn an_answer_that_fits_is_not_marked_and_has_no_truncated_record() {
        let mut out = Vec::new();
        let mut answer = Answer::new(&mut out, ROOM + 1000);
        answer.record(&Record::new("a")).unwrap();
        answer.close(trailer).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(!text.contains("truncated\":\"") && text.contains("\"truncated\":false"), "{text}");
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn the_truncated_record_stays_within_its_bound_whatever_the_types_are() {
        let mut out = Vec::new();
        let mut answer = Answer::new(&mut out, ROOM);
        for index in 0..300 {
            let kind = format!("{index}-{}", "t".repeat(200));
            answer.record(&Record::new(&kind)).unwrap();
        }
        answer.finish().unwrap();
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.len() <= TRUNCATED_MAX, "{}", text.len());
        let cut: serde_json::Value = serde_json::from_str(text.trim_end()).unwrap();
        assert_eq!(cut["dropped_lines"], 300);
        let named: u64 = cut["dropped"].as_object().unwrap().values().map(|n| n.as_u64().unwrap()).sum();
        assert_eq!(named + cut["others"].as_u64().unwrap(), 300, "every dropped line is counted");
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
        let mut answer = Answer::new(&mut gone, ROOM + 1000);
        assert_eq!(answer.record(&Record::new("a")), Err(Full));
        assert!(answer.lost());
    }
}
