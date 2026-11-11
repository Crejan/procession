//! The identifiers of calls the service has taken, on disk until their
//! deadlines. An identifier is recorded when the call is submitted, before
//! anything is sent: a call is spent from then on, whatever becomes of it, and
//! a restart does not forget it (`SPEC.md`, "What the service does with a call").

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use p_act::{CallId, Timestamp};

/// Why an identifier could not be recorded.
#[derive(Debug, PartialEq, Eq)]
pub enum StoreError {
    /// Taken before.
    Used,
    /// The store cannot be written: no record, no call.
    Io(String),
}

/// One file per identifier, `<dir>/<uuid>`, holding the deadline.
#[derive(Debug)]
pub struct UsedStore {
    dir: PathBuf,
}

impl UsedStore {
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Creates the directory (mode 0700) if it is missing.
    ///
    /// # Errors
    /// The I/O error, in words.
    pub fn ensure(&self) -> Result<(), String> {
        std::fs::create_dir_all(&self.dir).map_err(|e| e.to_string())?;
        std::fs::set_permissions(&self.dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
            .map_err(|e| e.to_string())
    }

    /// Records `id` until `deadline`: created exclusively and flushed, with the
    /// directory, so that a crash cannot lose what was reported as recorded.
    ///
    /// # Errors
    /// [`StoreError::Used`] if it is there, [`StoreError::Io`] if it cannot be written.
    pub fn record(&self, id: &CallId, deadline: Timestamp) -> Result<(), StoreError> {
        let path = self.dir.join(id.as_str());
        let mut file = match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Err(StoreError::Used),
            Err(e) => return Err(StoreError::Io(e.to_string())),
        };
        let io = |e: std::io::Error| StoreError::Io(e.to_string());
        writeln!(file, "{}", deadline.unix()).map_err(io)?;
        file.sync_all().map_err(io)?;
        std::fs::File::open(&self.dir).and_then(|dir| dir.sync_all()).map_err(io)
    }

    /// Forgets what is past its deadline: no call with that identifier can be
    /// taken any more, so nothing is lost. Returns how many were forgotten.
    pub fn purge(&self, now: Timestamp) -> usize {
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return 0 };
        let mut forgotten = 0;
        for entry in entries.flatten() {
            let past = std::fs::read_to_string(entry.path())
                .ok()
                .and_then(|text| text.trim().parse::<i64>().ok())
                .is_some_and(|deadline| deadline < now.unix());
            if past && std::fs::remove_file(entry.path()).is_ok() {
                forgotten += 1;
            }
        }
        forgotten
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ID: &str = "3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11";

    fn at(secs: i64) -> Timestamp {
        Timestamp::from_unix(secs).unwrap()
    }

    #[test]
    fn an_identifier_is_taken_once_and_a_new_store_on_the_same_directory_remembers() {
        let dir = crate::testdir::new("used");
        let id = CallId::parse(ID).unwrap();
        UsedStore::new(&dir).record(&id, at(2_000_000_000)).unwrap();
        assert_eq!(UsedStore::new(&dir).record(&id, at(2_000_000_000)), Err(StoreError::Used), "a restart");
        assert!(
            UsedStore::new(&dir).record(&CallId::parse("00000000-0000-4000-8000-000000000000").unwrap(), at(1)).is_ok()
        );
    }

    #[test]
    fn what_is_past_its_deadline_is_forgotten_and_the_rest_kept() {
        let dir = crate::testdir::new("used");
        let store = UsedStore::new(&dir);
        let (old, new) = (CallId::parse(ID).unwrap(), CallId::parse("00000000-0000-4000-8000-000000000000").unwrap());
        store.record(&old, at(1_000)).unwrap();
        store.record(&new, at(3_000)).unwrap();
        assert_eq!(store.purge(at(2_000)), 1);
        assert!(store.record(&old, at(1_000)).is_ok(), "forgotten");
        assert_eq!(store.record(&new, at(3_000)), Err(StoreError::Used), "kept");
    }

    #[test]
    fn a_store_that_cannot_be_written_says_so() {
        let dir = crate::testdir::new("used").join("absent");
        let store = UsedStore::new(&dir);
        assert!(matches!(store.record(&CallId::parse(ID).unwrap(), at(1)), Err(StoreError::Io(_))));
        store.ensure().unwrap();
        assert!(store.record(&CallId::parse(ID).unwrap(), at(1)).is_ok());
    }
}
