//! The seam to the repository.
//!
//! A front end never talks to a backup program. It asks an [`Engine`], which
//! is opened once and then answers many questions: the cost of opening a
//! repository (connecting, loading its index) is paid per session, not per
//! question. That is the point of holding it behind a trait object in a
//! long-running process rather than spawning a tool per call.
//!
//! The engine on `rustic_core` is [`crate::rustic::RusticEngine`]; see
//! `crates/p-reserve/SPEC.md`.

use std::io::Write;
use std::path::Path;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::outcome::Outcome;

/// A snapshot in the repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    pub id: String,
    pub time: SystemTime,
    pub host: String,
    pub paths: Vec<String>,
    pub tags: Vec<String>,
}

/// What a directory entry in a snapshot is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NodeKind {
    File,
    Dir,
    Symlink,
    Other,
}

/// One entry of a directory in a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// The name as the bytes the source file system held. Show it through `text::escape_bytes`, never lossily.
    pub name: Vec<u8>,
    pub kind: NodeKind,
    pub size: u64,
    pub mtime: Option<SystemTime>,
}

/// An operation that did not produce its answer: the named outcome, and the
/// engine's own words for a log or an error line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineError {
    pub outcome: Outcome,
    pub detail: String,
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.outcome, self.detail)
    }
}

impl std::error::Error for EngineError {}

/// What a restore wrote.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RestoreSummary {
    /// Files restored (written or already identical).
    pub files: u64,
    /// Bytes of those files.
    pub bytes: u64,
}

/// An opened repository.
///
/// Reading and restoring is all there is so far; backup, forget, prune and
/// check join it as the engine behind them is built. A snapshot is named by
/// its id, an unambiguous prefix of it, or `latest`.
pub trait Engine {
    /// The snapshots, oldest first.
    fn snapshots(&self) -> Result<Vec<Snapshot>, EngineError>;

    /// The direct children of `dir` in `snapshot`. `dir` is absolute within
    /// the snapshot; "/" is its root.
    fn list(&self, snapshot: &str, dir: &str) -> Result<Vec<Node>, EngineError>;

    /// The content of the file `path` of `snapshot`, written to `out`.
    /// Returns the number of bytes written. `path` must be a regular file.
    fn dump(&self, snapshot: &str, path: &str, out: &mut dyn Write) -> Result<u64, EngineError>;

    /// Restore `path` of `snapshot` to `destination` on this machine.
    ///
    /// A directory is restored as the contents of `destination` (which must
    /// not exist or be an empty directory); a file is restored as the file
    /// `destination` (which must not exist). `destination` must be absolute.
    /// Nothing existing is overwritten or deleted.
    fn restore(&self, snapshot: &str, path: &str, destination: &Path) -> Result<RestoreSummary, EngineError>;
}
