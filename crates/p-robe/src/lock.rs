//! One call per identity at a time: an exclusive `flock` on
//! `<dir>/<identity>.lock`, held until the call is done.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

/// Why no lock was taken.
#[derive(Debug, PartialEq, Eq)]
pub enum Fault {
    /// Another call of this identity runs.
    Busy,
    /// The lock cannot be used: a symlink, or it cannot be opened.
    Refused(String),
}

/// What [`take`] found.
#[derive(Debug)]
pub enum Taken {
    /// The lock, held while the `File` lives.
    Held(File),
    /// There is no lock directory; the call runs unlocked, and says so.
    NoDirectory,
}

/// Takes the lock of `identity`.
///
/// # Errors
/// [`Fault::Busy`] when another call holds it, [`Fault::Refused`] when the
/// lock file is a symlink or cannot be opened.
pub fn take(dir: &Path, identity: &str) -> Result<Taken, Fault> {
    if !dir.is_dir() {
        return Ok(Taken::NoDirectory);
    }
    let path = dir.join(format!("{identity}.lock"));
    if path.symlink_metadata().is_ok_and(|meta| meta.file_type().is_symlink()) {
        return Err(Fault::Refused("lock file is a symlink".into()));
    }
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o644)
        .open(&path)
        .map_err(|error| Fault::Refused(format!("cannot open lock: {error}")))?;
    // SAFETY: `flock` on a descriptor this function owns, with constant flags.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        Ok(Taken::Held(file))
    } else {
        Err(Fault::Busy)
    }
}

/// Why a directory or file that root executes from is not safe, or `None`:
/// not owned by root, or writable by group or others.
#[must_use]
pub fn loose(uid: u32, mode: u32) -> Option<String> {
    if uid != 0 {
        Some(format!("owned by uid {uid}"))
    } else if mode & 0o022 != 0 {
        Some(format!("mode {:04o}", mode & 0o7777))
    } else {
        None
    }
}

/// The state of the lock directory, in words, for `sys kit`: `None` if fine.
#[must_use]
pub fn directory_problem(dir: &Path) -> Option<String> {
    match dir.symlink_metadata() {
        Err(_) => Some("missing: calls run unlocked".into()),
        Ok(meta) if !meta.is_dir() => Some("not a directory: calls run unlocked".into()),
        Ok(meta) => loose(meta.uid(), meta.mode()).map(|why| format!("not safe: {why}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_second_call_of_the_same_identity_is_busy_until_the_first_is_done() {
        let dir = crate::testdir::new("lock");
        let first = take(&dir, "jan").unwrap();
        assert!(matches!(first, Taken::Held(_)));
        assert_eq!(take(&dir, "jan").unwrap_err(), Fault::Busy);
        drop(first);
        // A process another test forks while the lock is held keeps a copy of the descriptor until it has exec'd.
        let started = std::time::Instant::now();
        loop {
            match take(&dir, "jan") {
                Ok(Taken::Held(_)) => break,
                other => assert!(started.elapsed() < std::time::Duration::from_secs(3), "{other:?}"),
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn another_identity_is_not_held_up() {
        let dir = crate::testdir::new("lock");
        let _jan = take(&dir, "jan").unwrap();
        assert!(matches!(take(&dir, "eva").unwrap(), Taken::Held(_)));
    }

    #[test]
    fn a_missing_directory_means_no_lock() {
        let dir = crate::testdir::new("lock").join("absent");
        assert!(matches!(take(&dir, "jan").unwrap(), Taken::NoDirectory));
        assert_eq!(directory_problem(&dir).unwrap(), "missing: calls run unlocked");
    }

    #[test]
    fn a_symlinked_lock_file_is_refused() {
        let dir = crate::testdir::new("lock");
        let target = dir.join("elsewhere");
        std::fs::write(&target, "").unwrap();
        std::os::unix::fs::symlink(&target, dir.join("jan.lock")).unwrap();
        assert_eq!(take(&dir, "jan").unwrap_err(), Fault::Refused("lock file is a symlink".into()));
    }

    #[test]
    fn what_root_executes_from_must_belong_to_root_and_be_closed() {
        assert_eq!(loose(0, 0o755), None);
        assert_eq!(loose(0, 0o700), None);
        assert_eq!(loose(1000, 0o755).unwrap(), "owned by uid 1000");
        assert_eq!(loose(0, 0o775).unwrap(), "mode 0775");
        assert_eq!(loose(0, 0o757).unwrap(), "mode 0757");
    }
}
