//! The seam to the repository.
//!
//! A front end never talks to a backup program. It asks an [`Engine`], which
//! is opened once and then answers many questions: the cost of opening a
//! repository (connecting, loading its index) is paid per session, not per
//! question. That is the point of holding it behind a trait object in a
//! long-running process rather than spawning a tool per call.
//!
//! No engine is implemented yet. The first is planned on `rustic_core`; see
//! `crates/p-reserve/SPEC.md`.

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
    pub name: String,
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

/// An opened repository.
///
/// Reading is all there is so far; backup, forget, prune, check and restore
/// join it as the engine behind them is built.
pub trait Engine {
    /// The snapshots, oldest first.
    fn snapshots(&self) -> Result<Vec<Snapshot>, EngineError>;

    /// The direct children of `dir` in `snapshot`. `dir` is absolute within
    /// the snapshot; "/" is its root.
    fn list(&self, snapshot: &str, dir: &str) -> Result<Vec<Node>, EngineError>;
}
