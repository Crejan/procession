//! The roots readers work on, and the shape of a partial result.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::error::Error;

/// Where `/proc`, `/sys` and `/dev` live. The default is the real ones;
/// tests point it at fixture trees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Root {
    /// `/proc`.
    pub proc: PathBuf,
    /// `/sys`.
    pub sys: PathBuf,
    /// `/dev`.
    pub dev: PathBuf,
}

impl Root {
    /// A root from three directories.
    pub fn new(proc: impl Into<PathBuf>, sys: impl Into<PathBuf>, dev: impl Into<PathBuf>) -> Self {
        Self { proc: proc.into(), sys: sys.into(), dev: dev.into() }
    }

    /// The live system.
    #[must_use]
    pub fn system() -> Self {
        Self::new("/proc", "/sys", "/dev")
    }
}

impl Default for Root {
    fn default() -> Self {
        Self::system()
    }
}

/// A source a scan could not read, and why (permission, missing file,
/// missing kernel option).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Unreadable {
    /// The path, or a name for a non-file source.
    pub source: String,
    /// The reason, as text.
    pub reason: String,
}

impl Unreadable {
    /// Records `error` against `source`.
    pub fn new(source: impl Into<String>, error: &dyn std::error::Error) -> Self {
        Self { source: source.into(), reason: error.to_string() }
    }
}

/// What a scan read, plus what it could not.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scan<T> {
    /// What was read.
    pub items: Vec<T>,
    /// What was not.
    pub unreadable: Vec<Unreadable>,
}

impl<T> Default for Scan<T> {
    fn default() -> Self {
        Self { items: Vec::new(), unreadable: Vec::new() }
    }
}

pub(crate) fn read(path: &Path) -> Result<String, Error> {
    fs::read_to_string(path).map_err(|e| Error::io(path, e))
}

/// Numeric directory entries (pids, tids), sorted.
pub(crate) fn numeric_entries(dir: &Path) -> Result<Vec<i32>, Error> {
    let rd = fs::read_dir(dir).map_err(|e| Error::io(dir, e))?;
    let mut ids: Vec<i32> = rd.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok()).collect();
    ids.sort_unstable();
    Ok(ids)
}
