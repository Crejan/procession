//! The record (`proposals/record.md`, `SPEC.md` section 6): a file of JSON
//! lines, each entry carrying the hash of the line before it.
//!
//! The hash of an entry is SHA-256 over the bytes of its line as they are in
//! the file, without the `\n`; nothing is re-serialised. `pledge serve` holds
//! an exclusive lock on the file and is its only writer. An entry is flushed
//! (`fdatasync`) before the signature it describes is handed over.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use p_act::Timestamp;
use ring::digest;
use serde_json::{Map, Value};

use crate::error::{Error, Result};

/// How long entries are kept: a year.
pub const KEEP_SECONDS: i64 = 365 * 24 * 3600;

/// `sha256:<hex>` of `bytes`.
#[must_use]
pub fn hash_line(bytes: &[u8]) -> String {
    let mut text = String::from("sha256:");
    for byte in digest::digest(&digest::SHA256, bytes).as_ref() {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

/// What opening the record found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Opened {
    /// Bytes of an unfinished last line that were cut off.
    pub repaired_bytes: Option<u64>,
    /// Entries removed from the start for being older than a year.
    pub trimmed: Option<Trimmed>,
}

/// Entries removed from the start.
#[derive(Debug, PartialEq, Eq)]
pub struct Trimmed {
    /// How many.
    pub count: u64,
    /// The `seq` of the last one removed.
    pub through_seq: u64,
    /// The `time` of the last one removed.
    pub through_time: String,
}

/// The record, open for appending.
pub struct Record {
    path: PathBuf,
    file: Box<dyn Sink>,
    seq: u64,
    last_hash: Option<String>,
}

/// Where entries are written: a file, or in a test something that fails.
trait Sink: Send {
    /// Writes `bytes` and flushes them to disk.
    fn write_durably(&mut self, bytes: &[u8]) -> std::io::Result<()>;
}

impl Sink for File {
    fn write_durably(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.write_all(bytes)?;
        self.sync_data()
    }
}

/// How long opening waits for the lock before it says another `pledge serve` has it.
///
/// A lock (`flock`) belongs to the open file, not to a process: a child started
/// with `fork` (every `ssh-keygen` pledge runs) holds it too until it execs, and
/// so does one started just before a stop. Waiting a moment lets those go; a real
/// second `pledge serve` holds it for as long as it runs and is refused after the wait.
pub const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

fn lock(file: &File, path: &Path, wait: std::time::Duration) -> Result<()> {
    let until = std::time::Instant::now() + wait;
    loop {
        // SAFETY: the descriptor is open for the lifetime of `file`.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        if std::time::Instant::now() >= until {
            return Err(Error::Locked(path.to_owned()));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

fn open_locked(path: &Path, wait: std::time::Duration) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .open(path)
        .map_err(Error::io(format!("opening {}", path.display())))?;
    lock(&file, path, wait)?;
    Ok(file)
}

fn field(line: &[u8], name: &str) -> Option<Value> {
    serde_json::from_slice::<Map<String, Value>>(line).ok()?.remove(name)
}

impl Record {
    /// Opens (creating it, mode 0600) and locks the record at `path`; cuts
    /// off an unfinished last line; removes entries older than a year before
    /// `now` from the start. Appends nothing: the caller records `repaired`
    /// and `trimmed` events from what is returned.
    ///
    /// # Errors
    ///
    /// [`Error::Locked`] if another process holds it, [`Error::Io`].
    pub fn open(path: &Path, now: Timestamp) -> Result<(Self, Opened)> {
        Self::open_waiting(path, now, LOCK_WAIT)
    }

    /// As [`open`](Self::open), waiting at most `wait` for the lock.
    ///
    /// # Errors
    ///
    /// As [`open`](Self::open).
    pub fn open_waiting(path: &Path, now: Timestamp, wait: std::time::Duration) -> Result<(Self, Opened)> {
        let mut file = open_locked(path, wait)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(Error::io(format!("reading {}", path.display())))?;
        let mut opened = Opened::default();
        if !bytes.is_empty() && !bytes.ends_with(b"\n") {
            let keep = bytes.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
            opened.repaired_bytes = Some((bytes.len() - keep) as u64);
            file.set_len(keep as u64).map_err(Error::io(format!("repairing {}", path.display())))?;
            bytes.truncate(keep);
        }
        let mut lines: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
        lines.pop(); // after the final newline
        let cutoff = now.unix() - KEEP_SECONDS;
        let old = lines
            .iter()
            .take_while(|line| {
                field(line, "time")
                    .and_then(|t| t.as_str().and_then(|t| t.parse::<Timestamp>().ok()))
                    .is_some_and(|t| t.unix() < cutoff)
            })
            .count();
        if old > 0 {
            let last_removed = lines[old - 1];
            opened.trimmed = Some(Trimmed {
                count: old as u64,
                through_seq: field(last_removed, "seq").and_then(|v| v.as_u64()).unwrap_or(0),
                through_time: field(last_removed, "time")
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default(),
            });
            let temp = path.with_extension("jsonl.new");
            let mut out = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp)
                .map_err(Error::io(format!("creating {}", temp.display())))?;
            for line in &lines[old..] {
                out.write_all(line).and_then(|()| out.write_all(b"\n")).map_err(Error::io("trimming the record"))?;
            }
            out.sync_all().map_err(Error::io("trimming the record"))?;
            fs::rename(&temp, path).map_err(Error::io("trimming the record"))?;
            file = open_locked(path, wait)?;
            lines.drain(..old);
        }
        let (seq, last_hash) = match lines.last() {
            Some(last) => {
                let seq = field(last, "seq").and_then(|v| v.as_u64()).unwrap_or(lines.len() as u64);
                (seq, Some(hash_line(last)))
            }
            None => (0, None),
        };
        Ok((Self { path: path.to_owned(), file: Box::new(file), seq, last_hash }, opened))
    }

    /// A record whose writes always fail, to test what happens then.
    #[cfg(test)]
    pub(crate) fn failing() -> Self {
        struct Broken;
        impl Sink for Broken {
            fn write_durably(&mut self, _: &[u8]) -> std::io::Result<()> {
                Err(std::io::Error::other("disk full"))
            }
        }
        Self { path: PathBuf::from("/nonexistent"), file: Box::new(Broken), seq: 0, last_hash: None }
    }

    /// Appends one entry and flushes it to disk. `entry` holds the members
    /// of its `type` (and the type itself as `type`); `schema_version`,
    /// `seq`, `time` and `prev` are added here.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if the entry could not be written and flushed. Nothing
    /// may then be signed for it.
    pub fn append(&mut self, now: Timestamp, entry: Value) -> Result<()> {
        let Value::Object(mut members) = entry else {
            return Err(Error::Refused("a record entry is an object".into()));
        };
        members.insert("schema_version".into(), 1.into());
        members.insert("seq".into(), (self.seq + 1).into());
        members.insert("time".into(), now.to_string().into());
        members.insert("prev".into(), self.last_hash.clone().map_or(Value::Null, Value::String));
        let line = serde_json::to_vec(&Value::Object(members)).map_err(|e| Error::Refused(e.to_string()))?;
        let mut data = line.clone();
        data.push(b'\n');
        self.file.write_durably(&data).map_err(Error::io(format!("writing {}", self.path.display())))?;
        self.seq += 1;
        self.last_hash = Some(hash_line(&line));
        Ok(())
    }
}

/// A place where the chain does not hold.
#[derive(Debug, PartialEq, Eq)]
pub struct Break {
    /// The 1-based line.
    pub line: usize,
    /// What is wrong with it.
    pub problem: String,
}

/// What reading the record found.
#[derive(Debug, Default)]
pub struct Report {
    /// The entries that are valid JSON objects, in order.
    pub entries: Vec<Value>,
    /// Where the chain does not hold.
    pub breaks: Vec<Break>,
    /// `Some(seq)` if earlier entries were removed (the first `seq` is above 1).
    pub starts_at: Option<u64>,
}

/// Reads and verifies the record without needing `pledge serve`. Reading goes
/// on after a break so that one break does not hide the rest. An unfinished
/// last line is ignored.
///
/// # Errors
///
/// [`Error::Io`] if the file cannot be read.
pub fn read_and_verify(path: &Path) -> Result<Report> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(Error::io(format!("reading {}", path.display()))(e)),
    };
    let mut report = Report::default();
    let mut previous: Option<(u64, String, Option<Timestamp>)> = None;
    let mut lines: Vec<&[u8]> = bytes.split(|b| *b == b'\n').collect();
    lines.pop(); // empty, or an unfinished line
    for (index, line) in lines.iter().enumerate() {
        let number = index + 1;
        let mut note = |problem: &str| report.breaks.push(Break { line: number, problem: problem.to_owned() });
        let Ok(Value::Object(members)) = serde_json::from_slice::<Value>(line) else {
            note("not a JSON object");
            previous = None;
            continue;
        };
        let seq = members.get("seq").and_then(Value::as_u64);
        let time = members.get("time").and_then(Value::as_str).and_then(|t| t.parse::<Timestamp>().ok());
        let prev = members.get("prev");
        match (&previous, seq) {
            (None, Some(seq)) if report.entries.is_empty() => {
                if seq > 1 {
                    report.starts_at = Some(seq);
                }
            }
            (Some((last_seq, last_hash, last_time)), Some(seq)) => {
                if seq != last_seq + 1 {
                    note("seq does not follow the one before");
                }
                if prev.and_then(Value::as_str) != Some(last_hash.as_str()) {
                    note("prev does not match the hash of the line before");
                }
                if let (Some(then), Some(now)) = (last_time, time) {
                    if now < *then {
                        note("time is earlier than the entry before");
                    }
                }
            }
            (_, None) => note("no seq"),
            (None, Some(_)) => note("follows a line that could not be read"),
        }
        previous = seq.map(|seq| (seq, hash_line(line), time));
        report.entries.push(Value::Object(members));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::testing::TestDir;

    fn at(secs: i64) -> Timestamp {
        Timestamp::from_unix(secs).expect("time")
    }

    const NOW: i64 = 1_800_000_000;

    fn entries(path: &Path) -> Report {
        read_and_verify(path).expect("reads")
    }

    #[test]
    fn entries_form_a_chain_over_their_own_bytes() {
        let dir = TestDir::new("record-chain");
        let path = dir.path().join("record.jsonl");
        let (mut record, opened) = Record::open(&path, at(NOW)).expect("open");
        assert_eq!(opened, Opened::default());
        record.append(at(NOW), json!({"type":"event","event":"started"})).expect("append");
        record.append(at(NOW + 1), json!({"type":"signing-request","result":"approved"})).expect("append");
        let text = fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2);
        let first: Value = serde_json::from_str(lines[0]).expect("json");
        let second: Value = serde_json::from_str(lines[1]).expect("json");
        assert_eq!((first["seq"].as_u64(), first["prev"].is_null()), (Some(1), true));
        assert_eq!(second["prev"], hash_line(lines[0].as_bytes()));
        assert_eq!(second["time"], at(NOW + 1).to_string());
        assert_eq!(second["schema_version"], 1);
        let report = entries(&path);
        assert!(report.breaks.is_empty(), "{:?}", report.breaks);
        assert_eq!(report.entries.len(), 2);
        assert_eq!(report.starts_at, None);
    }

    #[test]
    fn a_changed_removed_or_swapped_line_breaks_the_chain() {
        let dir = TestDir::new("record-break");
        let path = dir.path().join("record.jsonl");
        let (mut record, _) = Record::open(&path, at(NOW)).expect("open");
        for i in 0..4 {
            record.append(at(NOW + i), json!({"type":"event","n":i})).expect("append");
        }
        drop(record);
        let text = fs::read_to_string(&path).expect("read");
        let lines: Vec<&str> = text.lines().collect();
        let write = |lines: &[String]| {
            fs::write(&path, lines.join("\n") + "\n").expect("write");
            entries(&path).breaks
        };
        let mut changed: Vec<String> = lines.iter().map(|s| (*s).to_owned()).collect();
        changed[1] = changed[1].replace("\"n\":1", "\"n\":9");
        assert_eq!(write(&changed).iter().map(|b| b.line).collect::<Vec<_>>(), [3], "the line after a changed one");
        let mut removed: Vec<String> = lines.iter().map(|s| (*s).to_owned()).collect();
        removed.remove(1);
        assert!(!write(&removed).is_empty());
        let mut swapped: Vec<String> = lines.iter().map(|s| (*s).to_owned()).collect();
        swapped.swap(1, 2);
        assert!(!write(&swapped).is_empty());
        let mut garbage: Vec<String> = lines.iter().map(|s| (*s).to_owned()).collect();
        garbage[2] = "not json".into();
        let breaks = write(&garbage);
        assert!(breaks.iter().any(|b| b.line == 3 && b.problem == "not a JSON object"));
        assert!(breaks.iter().any(|b| b.line == 4), "reading goes on after a break");
    }

    #[test]
    fn a_second_writer_is_refused_and_reopening_continues_the_chain() {
        let dir = TestDir::new("record-lock");
        let path = dir.path().join("record.jsonl");
        let (mut record, _) = Record::open(&path, at(NOW)).expect("open");
        record.append(at(NOW), json!({"type":"event"})).expect("append");
        assert!(matches!(Record::open_waiting(&path, at(NOW), std::time::Duration::ZERO), Err(Error::Locked(_))));
        drop(record);
        let (mut again, _) = Record::open(&path, at(NOW)).expect("reopen");
        again.append(at(NOW + 5), json!({"type":"event"})).expect("append");
        let report = entries(&path);
        assert!(report.breaks.is_empty());
        assert_eq!(report.entries[1]["seq"], 2);
    }

    #[test]
    fn an_unfinished_last_line_is_cut_off_and_reported() {
        let dir = TestDir::new("record-torn");
        let path = dir.path().join("record.jsonl");
        let (mut record, _) = Record::open(&path, at(NOW)).expect("open");
        record.append(at(NOW), json!({"type":"event"})).expect("append");
        drop(record);
        let mut file = OpenOptions::new().append(true).open(&path).expect("open");
        file.write_all(b"{\"seq\":2,\"tim").expect("write");
        drop(file);
        assert!(entries(&path).breaks.is_empty(), "a reader ignores it");
        let (mut record, opened) = Record::open(&path, at(NOW)).expect("open");
        assert_eq!(opened.repaired_bytes, Some(13));
        record.append(at(NOW + 1), json!({"type":"event","event":"repaired"})).expect("append");
        let report = entries(&path);
        assert!(report.breaks.is_empty(), "{:?}", report.breaks);
        assert_eq!(report.entries.len(), 2);
    }

    #[test]
    fn entries_older_than_a_year_go_from_the_start_without_rehashing() {
        let dir = TestDir::new("record-trim");
        let path = dir.path().join("record.jsonl");
        let (mut record, _) = Record::open(&path, at(NOW - 2 * KEEP_SECONDS)).expect("open");
        record.append(at(NOW - 2 * KEEP_SECONDS), json!({"type":"event"})).expect("append");
        record.append(at(NOW - KEEP_SECONDS - 10), json!({"type":"event"})).expect("append");
        record.append(at(NOW - 100), json!({"type":"event"})).expect("append");
        record.append(at(NOW - 50), json!({"type":"event"})).expect("append");
        drop(record);
        let before: Vec<String> = fs::read_to_string(&path).expect("read").lines().map(str::to_owned).collect();
        let (mut record, opened) = Record::open(&path, at(NOW)).expect("open");
        assert_eq!(
            opened.trimmed,
            Some(Trimmed { count: 2, through_seq: 2, through_time: at(NOW - KEEP_SECONDS - 10).to_string() })
        );
        let after: Vec<String> = fs::read_to_string(&path).expect("read").lines().map(str::to_owned).collect();
        assert_eq!(after, before[2..], "the lines kept are the lines they were");
        record.append(at(NOW), json!({"type":"event","event":"trimmed"})).expect("append");
        let report = entries(&path);
        assert!(report.breaks.is_empty(), "{:?}", report.breaks);
        assert_eq!(report.starts_at, Some(3));
        assert_eq!(report.entries.len(), 3);
        assert!(
            matches!(Record::open_waiting(&path, at(NOW), std::time::Duration::ZERO), Err(Error::Locked(_))),
            "the new file is locked"
        );
    }

    #[test]
    fn a_missing_record_reads_as_empty() {
        let dir = TestDir::new("record-none");
        let report = entries(&dir.path().join("none.jsonl"));
        assert!(report.entries.is_empty() && report.breaks.is_empty());
    }
}
