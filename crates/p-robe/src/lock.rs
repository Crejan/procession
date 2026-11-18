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

/// As [`take`], but a lock that is held is waited for, up to `max`, asking again every 20 ms (a `flock`
/// that blocks cannot be given up on without a thread). `max` of zero is [`take`].
///
/// # Errors
/// As [`take`]; [`Fault::Busy`] only after `max` has passed.
pub fn take_waiting(dir: &Path, identity: &str, max: std::time::Duration) -> Result<Taken, Fault> {
    let started = std::time::Instant::now();
    loop {
        match take(dir, identity) {
            Err(Fault::Busy) if started.elapsed() < max => {
                std::thread::sleep(std::time::Duration::from_millis(20).min(max - started.elapsed()));
            }
            other => return other,
        }
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
    fn a_lock_that_is_held_is_waited_for_until_it_is_free_or_the_time_is_up() {
        use std::time::{Duration, Instant};
        let dir = crate::testdir::new("lock");
        let held = take(&dir, "jan").unwrap();
        // Time up: busy, after about the time asked.
        let started = Instant::now();
        assert_eq!(take_waiting(&dir, "jan", Duration::from_millis(300)).unwrap_err(), Fault::Busy);
        assert!(started.elapsed() >= Duration::from_millis(300) && started.elapsed() < Duration::from_secs(2));
        // Zero is no wait.
        let started = Instant::now();
        assert_eq!(take_waiting(&dir, "jan", Duration::ZERO).unwrap_err(), Fault::Busy);
        assert!(started.elapsed() < Duration::from_millis(100));
        // Freed during the wait: taken.
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(200));
            drop(held);
        });
        let started = Instant::now();
        assert!(matches!(take_waiting(&dir, "jan", Duration::from_secs(5)).unwrap(), Taken::Held(_)));
        assert!(started.elapsed() >= Duration::from_millis(150) && started.elapsed() < Duration::from_secs(3));
        releaser.join().unwrap();
        // What is not a wait's business is refused at once: a symlink, no directory.
        std::os::unix::fs::symlink(dir.join("x"), dir.join("eva.lock")).unwrap();
        let started = Instant::now();
        assert!(matches!(take_waiting(&dir, "eva", Duration::from_secs(5)), Err(Fault::Refused(_))));
        assert!(started.elapsed() < Duration::from_millis(200));
        assert!(matches!(take_waiting(&dir.join("absent"), "jan", Duration::from_secs(5)), Ok(Taken::NoDirectory)));
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
