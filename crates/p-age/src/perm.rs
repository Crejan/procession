//! Who may write what the broker reads and keeps. A configuration the wrong
//! person can change is a broker the wrong person controls, so such a file is
//! refused, not warned about.

use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use thiserror::Error;

/// Why a file or directory was refused.
#[derive(Debug, Error)]
pub enum PermError {
    #[error("cannot look at {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("{path} can be written by someone who is neither its owner nor root (mode {mode:o})")]
    WritableByOthers { path: String, mode: u32 },
    #[error("{path} belongs to user {uid}, who is neither root nor the user running the broker")]
    OtherOwner { path: String, uid: u32 },
    #[error("{path} can be read or written by someone but its owner (mode {mode:o}); it must be {wanted:o}")]
    NotPrivate { path: String, mode: u32, wanted: u32 },
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> PermError + '_ {
    move |source| PermError::Io { path: path.display().to_string(), source }
}

/// The user id the broker runs as: that of a file it has just made.
fn my_uid() -> Result<u32, PermError> {
    let file =
        tempfile::NamedTempFile::new().map_err(|source| PermError::Io { path: "a temporary file".into(), source })?;
    Ok(file.as_file().metadata().map_err(|source| PermError::Io { path: "a temporary file".into(), source })?.uid())
}

/// A file the broker is configured from: nobody but its owner (or root) can write it, and its owner is root or
/// the user the broker runs as.
pub fn check_config_file(path: &Path) -> Result<(), PermError> {
    let meta = std::fs::metadata(path).map_err(io(path))?;
    let shown = path.display().to_string();
    if meta.mode() & 0o022 != 0 {
        return Err(PermError::WritableByOthers { path: shown, mode: meta.mode() & 0o7777 });
    }
    let uid = meta.uid();
    if uid != 0 && uid != my_uid()? {
        return Err(PermError::OtherOwner { path: shown, uid });
    }
    Ok(())
}

/// A file only its owner may read or write (0600).
pub fn check_private_file(path: &Path) -> Result<(), PermError> {
    let mode = std::fs::metadata(path).map_err(io(path))?.mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(PermError::NotPrivate { path: path.display().to_string(), mode, wanted: 0o600 });
    }
    Ok(())
}

/// A directory only its owner may enter (0700); made if it is not there.
pub fn ensure_private_dir(path: &Path) -> Result<(), PermError> {
    if !path.exists() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path).map_err(io(path))?;
    }
    let mode = std::fs::metadata(path).map_err(io(path))?.mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(PermError::NotPrivate { path: path.display().to_string(), mode, wanted: 0o700 });
    }
    Ok(())
}

/// Replace `path` with `bytes`: a new file (0600) is written and flushed, then renamed over the old one, so a
/// reader sees the old file or the new, never half of one.
pub fn replace_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}
