//! The error type of the readers.

use std::io;
use std::path::PathBuf;

use crate::cpuset::CpuSetError;

/// What went wrong reading or parsing a kernel file.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file or directory could not be read.
    #[error("reading {}: {source}", path.display())]
    Io {
        /// The path that failed.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: io::Error,
    },
    /// A file was read but does not have the expected shape.
    #[error("{what}: {detail}")]
    Parse {
        /// The file or field.
        what: String,
        /// What is wrong with it.
        detail: String,
    },
    /// A CPU list or mask inside a file is malformed.
    #[error("{what}: {source}")]
    Cpus {
        /// The file or field.
        what: String,
        /// The underlying error.
        #[source]
        source: CpuSetError,
    },
}

impl Error {
    pub(crate) fn io(path: impl Into<PathBuf>, source: io::Error) -> Self {
        Self::Io { path: path.into(), source }
    }

    pub(crate) fn parse(what: impl Into<String>, detail: impl ToString) -> Self {
        Self::Parse { what: what.into(), detail: detail.to_string() }
    }

    /// The thing read no longer exists: a task that exited between listing
    /// and reading (`ENOENT`, `ESRCH`). Scans skip these silently.
    #[must_use]
    pub fn is_gone(&self) -> bool {
        matches!(self, Self::Io { source, .. }
            if source.kind() == io::ErrorKind::NotFound || source.raw_os_error() == Some(libc::ESRCH))
    }
}
