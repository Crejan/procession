//! The store of answers (`doc/approval-connections.md`, 3.7): pledge's answer
//! to a request is final until the call's deadline. The same bytes submitted
//! again get the same answer again, from this store, which is on disk so that
//! a restart does not forget it.
//!
//! Two kinds of entry, one line each in `answers.jsonl`:
//!
//! - `used`: a call's identifier, with the hash of the request it was used for.
//!   Set before an approval is signed, and when the person declines. A
//!   different request under a used identifier is refused `call-used`.
//! - `answer`: the answer for a request's hash, until the call's deadline.
//!
//! Entries are forgotten at their expiry. Nothing is rewritten while pledge
//! runs; the file is compacted when it opens.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// An answer pledge keeps, in the words of the exchange.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "lowercase", deny_unknown_fields)]
pub enum Stored {
    /// The approval, as its armoured bytes in base64.
    Approved {
        /// Base64 of the armoured SSHSIG.
        approval: String,
    },
    /// The person said no.
    Declined,
    /// A verdict.
    Refused {
        /// The reason's wire word.
        reason: String,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "entry", rename_all = "lowercase", deny_unknown_fields)]
enum Line {
    Used { call: String, request: String, expires: i64 },
    Answer { request: String, expires: i64, answer: Stored },
}

#[derive(Default)]
struct Memory {
    used: HashMap<String, (String, i64)>,
    answers: HashMap<String, (Stored, i64)>,
}

/// The store.
pub struct Answers {
    file: Mutex<File>,
    memory: Mutex<Memory>,
}

impl Answers {
    /// Opens `path`, forgetting what expired before `now`, and rewrites the
    /// file without it.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupt`] if a line does not parse; [`Error::Io`].
    pub fn open(path: &PathBuf, now: i64) -> Result<Self> {
        let mut memory = Memory::default();
        match fs::read_to_string(path) {
            Ok(text) => {
                for (number, line) in text.lines().enumerate() {
                    let entry: Line = serde_json::from_str(line).map_err(|e| Error::Corrupt {
                        path: path.clone(),
                        problem: format!("line {}: {e}", number + 1),
                    })?;
                    match entry {
                        Line::Used { call, request, expires } if expires > now => {
                            memory.used.insert(call, (request, expires));
                        }
                        Line::Answer { request, expires, answer } if expires > now => {
                            memory.answers.insert(request, (answer, expires));
                        }
                        _ => {}
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io(format!("reading {}", path.display()))(e)),
        }
        let temp = path.with_extension("jsonl.new");
        let context = format!("writing {}", path.display());
        let mut out = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)
            .map_err(Error::io(context.clone()))?;
        for (call, (request, expires)) in &memory.used {
            let line =
                serde_json::to_string(&Line::Used { call: call.clone(), request: request.clone(), expires: *expires })
                    .map_err(|e| Error::Refused(e.to_string()))?;
            writeln!(out, "{line}").map_err(Error::io(context.clone()))?;
        }
        for (request, (answer, expires)) in &memory.answers {
            let line = serde_json::to_string(&Line::Answer {
                request: request.clone(),
                expires: *expires,
                answer: answer.clone(),
            })
            .map_err(|e| Error::Refused(e.to_string()))?;
            writeln!(out, "{line}").map_err(Error::io(context.clone()))?;
        }
        out.sync_all().map_err(Error::io(context.clone()))?;
        fs::rename(&temp, path).map_err(Error::io(context.clone()))?;
        let file = OpenOptions::new().append(true).mode(0o600).open(path).map_err(Error::io(context))?;
        Ok(Self { file: Mutex::new(file), memory: Mutex::new(memory) })
    }

    fn append(&self, line: &Line) -> Result<()> {
        let mut text = serde_json::to_vec(line).map_err(|e| Error::Refused(e.to_string()))?;
        text.push(b'\n');
        let mut file = self.file.lock().map_err(|_| Error::Refused("the store's lock is poisoned".into()))?;
        file.write_all(&text).and_then(|()| file.sync_data()).map_err(Error::io("writing the store of answers"))
    }

    /// The answer kept for this request's hash, if it has not expired.
    #[must_use]
    pub fn answer(&self, request: &str, now: i64) -> Option<Stored> {
        let memory = self.memory.lock().ok()?;
        memory.answers.get(request).filter(|(_, expires)| *expires > now).map(|(answer, _)| answer.clone())
    }

    /// The hash of the request a call's identifier was used for, if it still is.
    #[must_use]
    pub fn used_for(&self, call: &str, now: i64) -> Option<String> {
        let memory = self.memory.lock().ok()?;
        memory.used.get(call).filter(|(_, expires)| *expires > now).map(|(request, _)| request.clone())
    }

    /// Marks a call's identifier used for a request, until `expires`. Durable
    /// before it returns.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if it cannot be written; then nothing may be signed.
    pub fn mark_used(&self, call: &str, request: &str, expires: i64) -> Result<()> {
        self.append(&Line::Used { call: call.to_owned(), request: request.to_owned(), expires })?;
        self.memory
            .lock()
            .map_err(|_| Error::Refused("poisoned".into()))?
            .used
            .insert(call.to_owned(), (request.to_owned(), expires));
        Ok(())
    }

    /// Keeps the answer for a request's hash until `expires`. Durable before it returns.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if it cannot be written.
    pub fn keep(&self, request: &str, answer: Stored, expires: i64) -> Result<()> {
        self.append(&Line::Answer { request: request.to_owned(), expires, answer: answer.clone() })?;
        self.memory
            .lock()
            .map_err(|_| Error::Refused("poisoned".into()))?
            .answers
            .insert(request.to_owned(), (answer, expires));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestDir;

    #[test]
    fn answers_and_used_identifiers_are_kept_until_their_expiry_and_survive_a_restart() {
        let dir = TestDir::new("answers");
        let path = dir.path().join("answers.jsonl");
        let store = Answers::open(&path, 100).expect("open");
        store.mark_used("call-1", "sha256:a", 200).expect("used");
        store.keep("sha256:a", Stored::Approved { approval: "QUJD".into() }, 200).expect("keep");
        store.keep("sha256:b", Stored::Refused { reason: "ceiling".into() }, 150).expect("keep");
        store.keep("sha256:c", Stored::Declined, 300).expect("keep");
        assert_eq!(store.answer("sha256:a", 150), Some(Stored::Approved { approval: "QUJD".into() }));
        assert_eq!(store.used_for("call-1", 150).as_deref(), Some("sha256:a"));
        assert_eq!(store.answer("sha256:b", 150), None, "expired at 150");
        drop(store);
        let again = Answers::open(&path, 160).expect("reopen");
        assert_eq!(again.answer("sha256:a", 160), Some(Stored::Approved { approval: "QUJD".into() }));
        assert_eq!(again.answer("sha256:b", 160), None);
        assert_eq!(again.answer("sha256:c", 160), Some(Stored::Declined));
        assert_eq!(again.used_for("call-1", 160).as_deref(), Some("sha256:a"));
        assert_eq!(again.used_for("call-1", 200), None);
        assert_eq!(again.answer("sha256:zzz", 160), None);
        drop(again);
        let compacted = Answers::open(&path, 250).expect("reopen late");
        assert_eq!(compacted.answer("sha256:c", 250), Some(Stored::Declined));
        assert_eq!(fs::read_to_string(&path).expect("read").lines().count(), 1, "the expired are gone from the file");
    }

    #[test]
    fn a_corrupt_store_is_an_error_not_an_empty_one() {
        let dir = TestDir::new("answers-bad");
        let path = dir.path().join("answers.jsonl");
        fs::write(&path, "garbage\n").expect("write");
        assert!(matches!(Answers::open(&path, 0), Err(Error::Corrupt { .. })));
    }
}
