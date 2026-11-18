//! The log: one line for every request, when it ended and what became of it.
//! Never the parameters of the action, never a claim, never a `detail`: only
//! the names of host and service, the person, the request's hash and a code.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use p_act::{DocumentHash, Timestamp};

/// One request's end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub at: Timestamp,
    pub host: String,
    pub service: String,
    /// `None` when the request was refused before a person was known.
    pub person: Option<String>,
    /// The request's hash; `None` for an entry about a delegation, not a request.
    pub request: Option<DocumentHash>,
    /// The delegation an entry is about (a withdrawal an honest pledge would not send), if it is about one.
    pub delegation: Option<String>,
    /// `approval-returned`, `declined`, `expired`, `cancelled`, or `refused:<code>`. The broker never
    /// writes "approved": that word is the service's to say.
    pub result: String,
}

/// Where the log goes.
pub trait LogSink: Send {
    fn write(&mut self, entry: &LogEntry);
}

/// A JSON line per entry, appended to a file.
#[derive(Debug)]
pub struct FileLog(File);

impl FileLog {
    pub fn open(path: &Path) -> std::io::Result<FileLog> {
        OpenOptions::new().create(true).append(true).open(path).map(FileLog)
    }
}

impl LogSink for FileLog {
    fn write(&mut self, e: &LogEntry) {
        let line = serde_json::json!({
            "at": e.at.to_string(), "host": e.host, "service": e.service, "person": e.person,
            "request": e.request.map(|h| h.to_string()), "delegation": e.delegation, "result": e.result,
        });
        // A log that cannot be written must not stop the broker: say so on standard error.
        if let Err(err) = writeln!(self.0, "{line}") {
            eprintln!("page: cannot write the log: {err}");
        }
    }
}

/// Entries kept in memory, for tests.
#[derive(Debug, Clone, Default)]
pub struct MemoryLog(pub Arc<Mutex<Vec<LogEntry>>>);

impl LogSink for MemoryLog {
    fn write(&mut self, entry: &LogEntry) {
        if let Ok(mut v) = self.0.lock() {
            v.push(entry.clone());
        }
    }
}

impl MemoryLog {
    #[must_use]
    pub fn entries(&self) -> Vec<LogEntry> {
        self.0.lock().map(|v| v.clone()).unwrap_or_default()
    }
}
