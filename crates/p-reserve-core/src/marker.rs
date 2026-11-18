//! The start marker of a writing job: the one thing about a job that is
//! persisted.
//!
//! Before a job that writes to a repository (backup, prune, check,
//! reprovision) starts, whoever runs it, the daemon or a one-shot `preserve`,
//! calls [`MarkerDir::begin`]. That writes a small file naming the job and its
//! pairs and holds an exclusive lock (`flock`) on it for the life of the job.
//! When the job ends, the ledger is saved and then the marker removed
//! ([`Marker::complete`]): the marker goes with the ledger entry.
//!
//! At the next start, [`MarkerDir::recover`] finds the markers nobody holds
//! any more: those jobs began and did not end. Each pair of such a marker
//! becomes a ledger entry with outcome `failed` and cause `interrupted`, unless
//! the ledger already records a run of that pair at or after the marker's start
//! (the program died between saving the ledger and removing the marker). A
//! marker whose lock is held belongs to a job that is still running, in
//! another process, and is left alone. Recovery is idempotent: it saves the
//! ledger before it removes a marker, so a crash in the middle repeats safely.
//!
//! The marker files are 0600, in a directory of mode 0700 that nobody else
//! may write to.

use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ledger::{Ledger, Pair, Run};
use crate::textfile::{Textfile, TextfileError};

const SCHEMA_VERSION: u32 = 1;
const EXTENSION: &str = "marker";
const MAX_MARKER_BYTES: u64 = 64 * 1024;

/// The jobs that write to a repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum JobKind {
    Backup,
    Prune,
    Check,
    Reprovision,
}

/// A writing job about to start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Unique among jobs: letters, digits, `.`, `_`, `-`, at most 64.
    pub id: String,
    pub kind: JobKind,
    /// The (source, target) pairs the job will record.
    pub pairs: Vec<Pair>,
    pub started: SystemTime,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stored {
    schema_version: u32,
    job: String,
    kind: JobKind,
    /// Milliseconds since the epoch.
    started: u64,
    pairs: Vec<Pair>,
}

#[derive(Debug, Error)]
pub enum MarkerError {
    #[error("{0} is not a job identifier (letters, digits, . _ -, at most 64)")]
    BadId(String),
    #[error("the marker directory {0} must be a directory that only its owner may write")]
    UntrustedDir(String),
    #[error("a marker for job {0} exists already")]
    Exists(String),
    #[error("{what}: {source}")]
    Io { what: String, source: io::Error },
    #[error(transparent)]
    Ledger(#[from] TextfileError),
}

fn io_err(what: impl Into<String>) -> impl FnOnce(io::Error) -> MarkerError {
    let what = what.into();
    move |source| MarkerError::Io { what, source }
}

fn millis(at: SystemTime) -> u64 {
    at.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The directory the markers live in.
#[derive(Debug, Clone)]
pub struct MarkerDir {
    dir: PathBuf,
}

/// A job that has begun. Hold it for the life of the job (it holds the lock);
/// end it with [`Marker::complete`] after the ledger entry is decided. Dropping
/// it without that leaves the marker behind, which is what a crash does.
#[must_use = "a marker that is dropped looks like an interrupted job"]
#[derive(Debug)]
pub struct Marker {
    file: File,
    path: PathBuf,
}

/// A job found interrupted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Recovered {
    pub job: String,
    pub kind: JobKind,
    /// The pairs that were given an `interrupted` entry.
    pub pairs: Vec<Pair>,
}

impl MarkerDir {
    pub fn new(dir: impl Into<PathBuf>) -> MarkerDir {
        MarkerDir { dir: dir.into() }
    }

    fn check_dir(&self) -> Result<(), MarkerError> {
        let shown = self.dir.display().to_string();
        let meta = fs::symlink_metadata(&self.dir).map_err(io_err(format!("cannot look at {shown}")))?;
        if !meta.is_dir() || meta.permissions().mode() & 0o022 != 0 {
            return Err(MarkerError::UntrustedDir(shown));
        }
        Ok(())
    }

    /// Record that `job` is starting: write its marker and lock it.
    pub fn begin(&self, job: &Job) -> Result<Marker, MarkerError> {
        if !valid_id(&job.id) {
            return Err(MarkerError::BadId(job.id.clone()));
        }
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&self.dir)
            .map_err(io_err(format!("cannot create {}", self.dir.display())))?;
        self.check_dir()?;
        let path = self.dir.join(format!("{}.{EXTENSION}", job.id));
        let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path).map_err(|e| {
            if e.kind() == io::ErrorKind::AlreadyExists {
                MarkerError::Exists(job.id.clone())
            } else {
                MarkerError::Io { what: format!("cannot create {}", path.display()), source: e }
            }
        })?;
        let written = (|| {
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
            // Locked before anything is written: a recovery that finds the file empty and unlocked knows
            // its writer died before it began.
            file.try_lock().map_err(|e| match e {
                TryLockError::Error(e) => e,
                TryLockError::WouldBlock => io::Error::new(io::ErrorKind::WouldBlock, "the new marker is locked"),
            })?;
            let stored = Stored {
                schema_version: SCHEMA_VERSION,
                job: job.id.clone(),
                kind: job.kind,
                started: millis(job.started),
                pairs: job.pairs.clone(),
            };
            let mut bytes = serde_json::to_vec(&stored).map_err(io::Error::from)?;
            bytes.push(b'\n');
            file.write_all(&bytes)?;
            file.sync_all()?;
            File::open(&self.dir)?.sync_all()
        })();
        if let Err(e) = written {
            let _ = fs::remove_file(&path);
            return Err(MarkerError::Io { what: format!("cannot write {}", path.display()), source: e });
        }
        Ok(Marker { file, path })
    }

    /// Find the jobs that began and did not end, give each of their pairs an
    /// `interrupted` entry in `ledger`, save the ledger to `store`, then remove
    /// those markers. Markers whose job is still running are left alone, and
    /// a marker that is not a marker (an empty or damaged file nobody holds) is
    /// removed without a ledger entry: that job never began.
    pub fn recover(&self, ledger: &mut Ledger, store: &Textfile) -> Result<Vec<Recovered>, MarkerError> {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(MarkerError::Io { what: format!("cannot read {}", self.dir.display()), source: e }),
        };
        self.check_dir()?;
        let mut found = Vec::new();
        let mut to_remove = Vec::new();
        let mut names: Vec<_> = entries.filter_map(Result::ok).map(|e| e.path()).collect();
        names.sort();
        for path in names {
            if path.extension().and_then(|e| e.to_str()) != Some(EXTENSION) {
                continue;
            }
            let Some((file, stored)) = open_orphan(&path)? else { continue };
            // the lock is held until `file` drops, at the end of this iteration
            match stored {
                None => to_remove.push(path),
                Some(stored) => {
                    let started = SystemTime::UNIX_EPOCH + Duration::from_millis(stored.started);
                    let mut pairs = Vec::new();
                    for pair in stored.pairs {
                        let recorded = ledger.entry(&pair).and_then(|e| e.last_attempt).is_some_and(|at| at >= started);
                        if !recorded {
                            ledger.record(pair.clone(), Run::interrupted(), started);
                            pairs.push(pair);
                        }
                    }
                    if !pairs.is_empty() {
                        found.push(Recovered { job: stored.job, kind: stored.kind, pairs });
                    }
                    to_remove.push(path);
                }
            }
            drop(file);
        }
        if !found.is_empty() {
            store.save(ledger)?;
        }
        for path in to_remove {
            fs::remove_file(&path).map_err(io_err(format!("cannot remove {}", path.display())))?;
        }
        Ok(found)
    }
}

/// Open a marker nobody holds: `None` if its job is still running, otherwise
/// the open (locked) file and what it says, `None` inside if it says nothing
/// usable.
type Orphan = Option<(File, Option<Stored>)>;

fn open_orphan(path: &Path) -> Result<Orphan, MarkerError> {
    let what = format!("cannot read {}", path.display());
    let mut file = File::open(path).map_err(io_err(what.clone()))?;
    let meta = file.metadata().map_err(io_err(what.clone()))?;
    if !meta.is_file() || meta.uid() != own_uid() {
        return Ok(None);
    }
    match file.try_lock_shared() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => return Ok(None),
        Err(TryLockError::Error(e)) => return Err(MarkerError::Io { what, source: e }),
    }
    let mut bytes = Vec::new();
    (&mut file).take(MAX_MARKER_BYTES + 1).read_to_end(&mut bytes).map_err(io_err(what))?;
    let stored = if bytes.len() as u64 > MAX_MARKER_BYTES {
        None
    } else {
        serde_json::from_slice::<Stored>(&bytes).ok().filter(|s| {
            s.schema_version == SCHEMA_VERSION
                && valid_id(&s.job)
                && s.pairs
                    .iter()
                    .all(|p| p_ermit::text::check(&p.source).is_ok() && p_ermit::text::check(&p.target).is_ok())
        })
    };
    Ok(Some((file, stored)))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && !id.starts_with('.')
}

fn own_uid() -> u32 {
    // SAFETY: `geteuid` has no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

impl Marker {
    /// The job ended and its ledger entry is decided: save `ledger` to
    /// `store`, then remove the marker. If saving fails the marker stays, so
    /// that the next start finds the job unfinished.
    pub fn complete(self, store: &Textfile, ledger: &Ledger) -> Result<(), MarkerError> {
        store.save(ledger)?;
        self.end()
    }

    /// Remove the marker without saving anything: for a job that wrote no
    /// ledger entry (a cancelled one, which never touches the ledger).
    pub fn end(self) -> Result<(), MarkerError> {
        fs::remove_file(&self.path).map_err(io_err(format!("cannot remove {}", self.path.display())))?;
        drop(self.file);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;
    use crate::freshness::Thresholds;
    use crate::health::{Reason, assess};
    use crate::outcome::{Level, Outcome};
    use crate::textfile::DEFAULT_PREFIX;

    fn t(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn job(id: &str, pairs: &[(&str, &str)], started: u64) -> Job {
        Job {
            id: id.to_owned(),
            kind: JobKind::Backup,
            pairs: pairs.iter().map(|(s, d)| Pair::new(*s, *d)).collect(),
            started: t(started),
        }
    }

    struct Env {
        _dir: tempfile::TempDir,
        markers: MarkerDir,
        store: Textfile,
        marker_path: PathBuf,
    }

    fn env() -> Env {
        let dir = tempfile::tempdir().unwrap();
        let markers_path = dir.path().join("markers");
        let store = Textfile::new(dir.path().join("ledger.prom"), DEFAULT_PREFIX).unwrap();
        Env { markers: MarkerDir::new(&markers_path), store, marker_path: markers_path, _dir: dir }
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> =
            fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    #[test]
    fn a_job_that_ends_leaves_no_marker_and_the_ledger_is_saved_first() {
        let e = env();
        let marker = e.markers.begin(&job("j-1", &[("home", "off")], 100)).unwrap();
        assert_eq!(files(&e.marker_path), vec!["j-1.marker"]);
        let mut ledger = Ledger::default();
        ledger.record(Pair::new("home", "off"), Run::stored(5, 0), t(160));
        marker.complete(&e.store, &ledger).unwrap();
        assert!(files(&e.marker_path).is_empty());
        assert_eq!(e.store.load().unwrap(), ledger);
        let mut loaded = e.store.load().unwrap();
        assert!(e.markers.recover(&mut loaded, &e.store).unwrap().is_empty());
    }

    #[test]
    fn a_marker_left_behind_becomes_a_failed_interrupted_entry_that_keeps_the_last_success() {
        let e = env();
        let mut ledger = Ledger::default();
        ledger.record(Pair::new("home", "off"), Run::stored(5, 0), t(50));
        e.store.save(&ledger).unwrap();
        // the crash: the job began, its marker was never ended (the handle just goes away)
        drop(e.markers.begin(&job("j-2", &[("home", "off"), ("docs", "off")], 100)).unwrap());
        assert_eq!(files(&e.marker_path), vec!["j-2.marker"]);

        let mut ledger = e.store.load().unwrap();
        let found = e.markers.recover(&mut ledger, &e.store).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].job.as_str(), found[0].kind, found[0].pairs.len()), ("j-2", JobKind::Backup, 2));
        assert!(files(&e.marker_path).is_empty());

        let home = ledger.entry(&Pair::new("home", "off")).unwrap();
        assert_eq!((home.last_outcome, home.last_cause), (Some(Outcome::Failed), Some(crate::Cause::Interrupted)));
        assert_eq!((home.last_success, home.last_attempt), (Some(t(50)), Some(t(100))));
        let docs = ledger.entry(&Pair::new("docs", "off")).unwrap();
        assert_eq!((docs.last_success, docs.first_attempt), (None, Some(t(100))));
        // it is on disk, and health says so
        assert_eq!(e.store.load().unwrap(), ledger);
        let limits = Thresholds {
            fresh_within: Duration::from_secs(1000),
            stale_after: Duration::from_secs(100_000),
            first_run_grace: Duration::from_secs(10_000),
        };
        let pair = Pair::new("home", "off");
        let health = assess(&ledger, [(&pair, &limits)], t(200));
        assert_eq!(health.level, Level::Warning);
        assert!(health.pairs[0].reasons.contains(&Reason::Interrupted));
        assert!(health.pairs[0].reasons.contains(&Reason::LastRun(Outcome::Failed)));
    }

    #[test]
    fn recovery_is_idempotent_and_survives_a_crash_between_saving_and_removing() {
        let e = env();
        drop(e.markers.begin(&job("j-3", &[("home", "off")], 100)).unwrap());
        let mut ledger = Ledger::default();
        e.markers.recover(&mut ledger, &e.store).unwrap();
        let after_first = ledger.clone();
        // as if the marker had not been removed: put it back
        drop(e.markers.begin(&job("j-3", &[("home", "off")], 100)).unwrap());
        let mut again = e.store.load().unwrap();
        assert!(e.markers.recover(&mut again, &e.store).unwrap().is_empty());
        assert_eq!(again, after_first);
        assert!(files(&e.marker_path).is_empty());
    }

    #[test]
    fn a_job_that_saved_its_ledger_and_died_before_removing_the_marker_is_not_called_interrupted() {
        let e = env();
        drop(e.markers.begin(&job("j-4", &[("home", "off")], 100)).unwrap());
        let mut ledger = Ledger::default();
        ledger.record(Pair::new("home", "off"), Run::stored(5, 0), t(120));
        e.store.save(&ledger).unwrap();
        let mut loaded = e.store.load().unwrap();
        assert!(e.markers.recover(&mut loaded, &e.store).unwrap().is_empty());
        assert_eq!(loaded.entry(&Pair::new("home", "off")).unwrap().last_outcome, Some(Outcome::Ok));
        assert!(files(&e.marker_path).is_empty());
    }

    #[test]
    fn a_marker_of_a_job_still_running_is_left_alone() {
        let e = env();
        let live = e.markers.begin(&job("j-5", &[("home", "off")], 100)).unwrap();
        let mut ledger = Ledger::default();
        assert!(e.markers.recover(&mut ledger, &e.store).unwrap().is_empty());
        assert_eq!(files(&e.marker_path), vec!["j-5.marker"]);
        assert_eq!(ledger, Ledger::default());
        live.end().unwrap();
    }

    #[test]
    fn something_that_is_not_a_marker_is_removed_or_ignored_without_a_ledger_entry() {
        let e = env();
        e.markers.begin(&job("j-6", &[("a", "b")], 1)).unwrap().end().unwrap(); // makes the directory
        fs::write(e.marker_path.join("empty.marker"), "").unwrap();
        fs::write(e.marker_path.join("junk.marker"), "not json").unwrap();
        fs::write(e.marker_path.join("notes.txt"), "keep").unwrap();
        fs::create_dir(e.marker_path.join("dir.marker")).unwrap();
        let mut ledger = Ledger::default();
        assert!(e.markers.recover(&mut ledger, &e.store).unwrap().is_empty());
        assert_eq!(files(&e.marker_path), vec!["dir.marker", "notes.txt"]);
        assert_eq!(ledger, Ledger::default());
    }

    #[test]
    fn a_marker_holding_a_name_with_a_control_character_or_a_bad_job_id_is_discarded_without_an_entry() {
        let e = env();
        e.markers.begin(&job("j-11", &[("a", "b")], 1)).unwrap().end().unwrap(); // makes the directory
        let marker = |id: &str, source: &str| {
            format!(
                "{{\"schema_version\":1,\"job\":\"{id}\",\"kind\":\"backup\",\"started\":1000,\"pairs\":[{{\"source\":\"{source}\",\"target\":\"t\"}}]}}\n"
            )
        };
        fs::write(e.marker_path.join("a.marker"), marker("ok", "x\\u0085y")).unwrap();
        fs::write(e.marker_path.join("b.marker"), marker("ok", "x\\u202ey")).unwrap();
        fs::write(e.marker_path.join("c.marker"), marker("../evil", "x")).unwrap();
        let mut ledger = Ledger::default();
        assert!(e.markers.recover(&mut ledger, &e.store).unwrap().is_empty());
        assert_eq!(ledger, Ledger::default());
        assert!(files(&e.marker_path).is_empty());
    }

    #[test]
    fn begin_refuses_a_bad_id_a_second_marker_for_one_job_and_an_unsafe_directory() {
        let e = env();
        for bad in ["", ".hidden", "a/b", "a b", &"x".repeat(65)] {
            assert!(matches!(e.markers.begin(&job(bad, &[], 1)), Err(MarkerError::BadId(_))), "{bad:?}");
        }
        let first = e.markers.begin(&job("j-7", &[("a", "b")], 1)).unwrap();
        assert!(matches!(e.markers.begin(&job("j-7", &[("a", "b")], 1)), Err(MarkerError::Exists(_))));
        first.end().unwrap();
        fs::set_permissions(&e.marker_path, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(matches!(e.markers.begin(&job("j-8", &[("a", "b")], 1)), Err(MarkerError::UntrustedDir(_))));
        assert!(matches!(e.markers.recover(&mut Ledger::default(), &e.store), Err(MarkerError::UntrustedDir(_))));
    }

    #[test]
    fn modes_are_explicit_whatever_the_umask() {
        for mask in [0o002, 0o022, 0o077, 0o000] {
            let e = env();
            let marker = crate::umask::with(mask, || e.markers.begin(&job("j-9", &[("a", "b")], 1)).unwrap());
            let file = fs::metadata(e.marker_path.join("j-9.marker")).unwrap();
            assert_eq!(file.mode() & 0o7777, 0o600, "umask {mask:04o}");
            assert_eq!(fs::metadata(&e.marker_path).unwrap().mode() & 0o7777, 0o700, "umask {mask:04o}");
            marker.end().unwrap();
        }
    }

    #[test]
    fn a_ledger_that_cannot_be_saved_keeps_the_marker() {
        let e = env();
        let marker = e.markers.begin(&job("j-10", &[("a", "b")], 1)).unwrap();
        let blocked = Textfile::new(e.marker_path.join("no/such/dir/ledger.prom"), DEFAULT_PREFIX).unwrap();
        assert!(matches!(marker.complete(&blocked, &Ledger::default()), Err(MarkerError::Ledger(_))));
        assert_eq!(files(&e.marker_path), vec!["j-10.marker"]);
    }
}
