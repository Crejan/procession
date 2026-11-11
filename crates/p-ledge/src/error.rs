//! The errors of `pledge`.

use std::io;
use std::path::PathBuf;

/// What can go wrong outside the pure parsers. Each says what was being done.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file or socket operation failed.
    #[error("{context}: {source}")]
    Io {
        /// What was being done, with the path.
        context: String,
        /// The operating system's error.
        #[source]
        source: io::Error,
    },
    /// A directory a socket or a key lives in is not private to the person.
    #[error("{path}: {problem}")]
    Unsafe {
        /// The directory or file.
        path: PathBuf,
        /// Why it is not acceptable.
        problem: &'static str,
    },
    /// Another `pledge serve` holds the record.
    #[error("{0} is in use by another pledge serve")]
    Locked(PathBuf),
    /// A file pledge wrote does not have the shape it should.
    #[error("{path}: {problem}")]
    Corrupt {
        /// The file.
        path: PathBuf,
        /// What is wrong.
        problem: String,
    },
    /// The key holder failed or answered nonsense.
    #[error("key holder: {0}")]
    Holder(String),
    /// A request for the person, which cannot be met.
    #[error("{0}")]
    Refused(String),
}

impl Error {
    /// An [`Error::Io`] with its context.
    pub fn io(context: impl Into<String>) -> impl FnOnce(io::Error) -> Self {
        let context = context.into();
        move |source| Self::Io { context, source }
    }
}

/// The result type of this crate.
pub type Result<T> = std::result::Result<T, Error>;
