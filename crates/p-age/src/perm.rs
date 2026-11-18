//! Who may read and write what the broker keeps: its register and the directory it is in. (The
//! configuration and the site file are read with `p_act::settings`.)

use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::Path;

use thiserror::Error;

/// Why a file or directory was refused.
#[derive(Debug, Error)]
pub enum PermError {
    #[error("cannot look at {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("{path} can be read or written by someone but its owner (mode {mode:o}); it must be {wanted:o}")]
    NotPrivate { path: String, mode: u32, wanted: u32 },
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> PermError + '_ {
    move |source| PermError::Io { path: path.display().to_string(), source }
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
