//! The engine on `rustic_core`: one opened repository, answering many
//! questions from the index it loaded once.
//!
//! Nothing here writes to a repository. Opening takes the repository's
//! location (a local path, or a `rustic_backend` scheme with its options) and
//! the password, which the caller reads from a 0600 file or the key store;
//! this module never sees where it came from.

use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use rustic_backend::BackendOptions;
use rustic_core::repofile::{Node as RepoNode, NodeType};
use rustic_core::{
    Credentials, IndexedFullStatus, LocalDestination, LsOptions, Repository, RepositoryOptions, RestoreOptions,
    RusticError,
};

use crate::engine::{Engine, EngineError, Node, NodeKind, RestoreSummary, Snapshot};
use crate::outcome::Outcome;

/// Where a repository is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Location {
    /// A local path, or `opendal:sftp`, `rest:https://...` and so on.
    pub repository: String,
    /// The backend's options (for `opendal:sftp`: `endpoint`, `root`, `user`,
    /// `key`, `known_hosts_strategy`).
    pub options: BTreeMap<String, String>,
}

impl Location {
    pub fn local(path: impl Into<String>) -> Location {
        Location { repository: path.into(), options: BTreeMap::new() }
    }
}

/// An open repository with its index in memory.
pub struct RusticEngine {
    repo: Repository<IndexedFullStatus>,
}

impl std::fmt::Debug for RusticEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RusticEngine").finish_non_exhaustive()
    }
}

fn fail(outcome: Outcome, detail: impl AsRef<str>) -> EngineError {
    EngineError { outcome, detail: crate::text::for_log(detail.as_ref()) }
}

/// What a rustic error is called. Only the kinds that mean something to a
/// front end get their own name; the rest is `failed`, with rustic's words.
fn named(error: &RusticError) -> EngineError {
    let outcome = if error.is_incorrect_password() { Outcome::WrongPassword } else { Outcome::Failed };
    fail(outcome, error.to_string())
}

impl RusticEngine {
    /// Open the repository at `location` with `password` and load its index.
    /// A location with no repository is `no-repository`; a refused password
    /// is `wrong-password`.
    pub fn open(location: &Location, password: &str) -> Result<RusticEngine, EngineError> {
        let mut options = BackendOptions::default().repository(location.repository.as_str());
        options.options = location.options.clone();
        let backends = options.to_backends().map_err(|e| named(&e))?;
        let repo = Repository::new(&RepositoryOptions::default(), &backends).map_err(|e| named(&e))?;
        match repo.config_id() {
            Ok(Some(_)) => {}
            Ok(None) => return Err(fail(Outcome::NoRepository, "the location holds no repository")),
            Err(e) => return Err(named(&e)),
        }
        let repo =
            repo.open(&Credentials::password(password)).map_err(|e| named(&e))?.to_indexed().map_err(|e| named(&e))?;
        Ok(RusticEngine { repo })
    }

    /// `snapshot` and `path` as rustic's `id:path`, with `path` made relative
    /// to the snapshot root.
    fn spec(snapshot: &str, path: &str) -> Result<String, EngineError> {
        if snapshot.is_empty() || snapshot.contains(':') {
            return Err(fail(Outcome::Failed, "a snapshot is `latest`, an id or a prefix of one"));
        }
        let relative: PathBuf = Path::new(path).components().filter(|c| matches!(c, Component::Normal(_))).collect();
        if Path::new(path).components().any(|c| matches!(c, Component::ParentDir)) {
            return Err(fail(Outcome::Failed, "a path inside a snapshot has no `..`"));
        }
        Ok(format!("{snapshot}:{}", relative.display()))
    }

    fn node(&self, snapshot: &str, path: &str) -> Result<RepoNode, EngineError> {
        self.repo.node_from_snapshot_path(&Self::spec(snapshot, path)?, |_| true).map_err(|e| named(&e))
    }
}

fn system_time(ts: rustic_core::jiff::Timestamp) -> SystemTime {
    SystemTime::from(ts)
}

fn kind(node: &RepoNode) -> NodeKind {
    match node.node_type {
        NodeType::File => NodeKind::File,
        NodeType::Dir => NodeKind::Dir,
        NodeType::Symlink { .. } => NodeKind::Symlink,
        _ => NodeKind::Other,
    }
}

impl Engine for RusticEngine {
    fn snapshots(&self) -> Result<Vec<Snapshot>, EngineError> {
        let mut all = self.repo.get_all_snapshots().map_err(|e| named(&e))?;
        all.sort_by_key(|s| s.time.timestamp());
        Ok(all
            .into_iter()
            .map(|s| Snapshot {
                id: s.id.to_hex().to_string(),
                time: SystemTime::from(s.time.timestamp()),
                host: s.hostname.clone(),
                paths: s.paths.iter().map(ToString::to_string).collect(),
                tags: s.tags.iter().map(ToString::to_string).collect(),
            })
            .collect())
    }

    fn list(&self, snapshot: &str, dir: &str) -> Result<Vec<Node>, EngineError> {
        let node = self.node(snapshot, dir)?;
        let Some(tree_id) = node.subtree else {
            return Err(fail(Outcome::Failed, "not a directory"));
        };
        let tree = self.repo.get_tree(&tree_id).map_err(|e| named(&e))?;
        Ok(tree
            .nodes
            .iter()
            .map(|n| Node {
                name: n.name().as_bytes().to_vec(),
                kind: kind(n),
                size: n.meta.size,
                mtime: n.meta.mtime.map(system_time),
            })
            .collect())
    }

    fn dump(&self, snapshot: &str, path: &str, out: &mut dyn Write) -> Result<u64, EngineError> {
        let node = self.node(snapshot, path)?;
        if !node.is_file() {
            return Err(fail(Outcome::Failed, "not a regular file"));
        }
        let mut counted = Counting { inner: out, bytes: 0 };
        self.repo.dump(&node, &mut counted).map_err(|e| named(&e))?;
        Ok(counted.bytes)
    }

    fn restore(&self, snapshot: &str, path: &str, destination: &Path) -> Result<RestoreSummary, EngineError> {
        check_destination(destination)?;
        let node = self.node(snapshot, path)?;
        let dest = destination.to_str().ok_or_else(|| fail(Outcome::Failed, "the destination is not UTF-8"))?;
        let ls = self.repo.ls(&node, &LsOptions::default()).map_err(|e| named(&e))?;
        let local = LocalDestination::new(dest, true, !node.is_dir()).map_err(|e| named(&e))?;
        let options = RestoreOptions::default();
        let plan = self.repo.prepare_restore(&options, ls.clone(), &local, false).map_err(|e| named(&e))?;
        let summary = RestoreSummary { files: plan.stats.files.restore, bytes: plan.restore_size };
        self.repo.restore(plan, &options, ls, &local).map_err(|e| named(&e))?;
        Ok(summary)
    }
}

/// A destination is absolute, and either does not exist or is an empty
/// directory: a restore never overwrites or deletes anything.
fn check_destination(destination: &Path) -> Result<(), EngineError> {
    if !destination.is_absolute() || destination.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(fail(Outcome::Failed, "the destination must be an absolute path without `..`"));
    }
    match std::fs::symlink_metadata(destination) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(fail(Outcome::Failed, format!("cannot look at the destination: {e}"))),
        Ok(meta) if meta.is_dir() => {
            let empty = std::fs::read_dir(destination).is_ok_and(|mut entries| entries.next().is_none());
            if empty { Ok(()) } else { Err(fail(Outcome::Failed, "the destination directory is not empty")) }
        }
        Ok(_) => Err(fail(Outcome::Failed, "the destination exists")),
    }
}

struct Counting<'a> {
    inner: &'a mut dyn Write,
    bytes: u64,
}

impl Write for Counting<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::testing::make_repository;

    const PASSWORD: &str = "test-password";

    /// The fixture is made and opened once for all read-only tests: in a debug build, deriving the key
    /// and building the index costs seconds each time. Tests write only to their own scratch directory.
    struct Fixture {
        _dir: tempfile::TempDir,
        repo: PathBuf,
        source: PathBuf,
        big: Vec<u8>,
        engine: RusticEngine,
        scratch_root: PathBuf,
    }

    impl Fixture {
        /// A fresh empty directory of this test's own.
        fn scratch(&self, name: &str) -> PathBuf {
            let dir = self.scratch_root.join(name);
            fs::create_dir(&dir).unwrap();
            dir
        }
    }

    /// A tree of three files (one of a few chunks) in a throwaway repository.
    fn fixture() -> &'static Fixture {
        static FIXTURE: std::sync::OnceLock<Fixture> = std::sync::OnceLock::new();
        FIXTURE.get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().canonicalize().unwrap();
            let source = root.join("src");
            fs::create_dir_all(source.join("d/e")).unwrap();
            fs::write(source.join("a.txt"), "hello\n").unwrap();
            fs::write(source.join("d/b.txt"), "b").unwrap();
            // not compressible, several chunks: a simple xorshift stream
            let mut x: u64 = 0x2545_f491_4f6c_dd1d;
            let big: Vec<u8> = (0..2 * 1024 * 1024)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    (x >> 24) as u8
                })
                .collect();
            fs::write(source.join("d/e/big.bin"), &big).unwrap();
            let repo = root.join("repo");
            let t = std::time::Instant::now();
            make_repository(&repo, PASSWORD, &source);
            eprintln!("fixture: init and backup took {:?}", t.elapsed());
            let scratch_root = root.join("scratch");
            fs::create_dir(&scratch_root).unwrap();
            let t = std::time::Instant::now();
            let engine = RusticEngine::open(&Location::local(repo.to_str().unwrap()), PASSWORD).unwrap();
            eprintln!("fixture: open and index took {:?}", t.elapsed());
            Fixture { _dir: dir, repo, source, big, engine, scratch_root }
        })
    }

    fn inside(f: &Fixture, rel: &str) -> String {
        f.source.join(rel).to_str().unwrap().to_owned()
    }

    #[test]
    fn snapshots_lists_the_one_snapshot_with_its_paths_and_a_recent_time() {
        let f = fixture();
        let snapshots = f.engine.snapshots().unwrap();
        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].paths, vec![f.source.to_str().unwrap().to_owned()]);
        assert_eq!(snapshots[0].id.len(), 64);
        let age = SystemTime::now().duration_since(snapshots[0].time).unwrap();
        assert!(age < std::time::Duration::from_secs(600), "{age:?}");
    }

    #[test]
    fn list_gives_the_direct_children_with_kind_size_and_mtime() {
        let f = fixture();
        let engine = &f.engine;
        let mut top = engine.list("latest", &inside(f, "")).unwrap();
        top.sort_by(|a, b| a.name.cmp(&b.name));
        let names: Vec<_> = top.iter().map(|n| (std::str::from_utf8(&n.name).unwrap(), n.kind)).collect();
        assert_eq!(names, vec![("a.txt", NodeKind::File), ("d", NodeKind::Dir)]);
        assert_eq!(top[0].size, 6);
        assert!(top[0].mtime.is_some());
        let sub = engine.list("latest", &inside(f, "d")).unwrap();
        assert_eq!(sub.len(), 2);
        assert!(sub.iter().any(|n| n.name == b"e" && n.kind == NodeKind::Dir));
        // a snapshot's id (and a prefix of it) names it as well as `latest`
        let id = engine.snapshots().unwrap().remove(0).id;
        assert_eq!(engine.list(&id, &inside(f, "")).unwrap().len(), 2);
        assert_eq!(engine.list(&id[..8], &inside(f, "")).unwrap().len(), 2);
    }

    #[test]
    fn dump_writes_the_file_and_counts_the_bytes() {
        let f = fixture();
        let engine = &f.engine;
        let mut out = Vec::new();
        assert_eq!(engine.dump("latest", &inside(f, "a.txt"), &mut out).unwrap(), 6);
        assert_eq!(out, b"hello\n");
        let mut big = Vec::new();
        engine.dump("latest", &inside(f, "d/e/big.bin"), &mut big).unwrap();
        assert!(big == f.big, "a file of several chunks comes back byte for byte");
    }

    #[test]
    fn a_missing_path_a_directory_a_bad_snapshot_and_dotdot_are_failures_not_panics() {
        let f = fixture();
        let engine = &f.engine;
        let mut out = Vec::new();
        for (snapshot, path) in [
            ("latest", inside(f, "nope")),
            ("latest", inside(f, "d")),
            ("zzzzzzzz", inside(f, "")),
            ("la:test", inside(f, "")),
            ("latest", format!("{}/../x", f.source.display())),
        ] {
            let err = engine.dump(snapshot, &path, &mut out).unwrap_err();
            assert_eq!(err.outcome, Outcome::Failed, "{snapshot} {path}");
        }
        assert!(out.is_empty());
        assert_eq!(engine.list("latest", &inside(f, "a.txt")).unwrap_err().outcome, Outcome::Failed);
    }

    #[test]
    fn restore_of_a_directory_gives_back_the_tree_and_a_file_the_file() {
        let f = fixture();
        let scratch = f.scratch("restore_of_a_directory_gives_back_the_tr");
        let engine = &f.engine;
        let dest = scratch.join("tree");
        let summary = engine.restore("latest", &inside(f, ""), &dest).unwrap();
        assert_eq!(summary.files, 3);
        assert_eq!(summary.bytes, 6 + 1 + f.big.len() as u64);
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"hello\n");
        assert_eq!(fs::read(dest.join("d/b.txt")).unwrap(), b"b");
        assert!(fs::read(dest.join("d/e/big.bin")).unwrap() == f.big);

        let file = scratch.join("one.txt");
        let summary = engine.restore("latest", &inside(f, "a.txt"), &file).unwrap();
        assert_eq!(summary.files, 1);
        assert_eq!(fs::read(&file).unwrap(), b"hello\n");
    }

    #[test]
    fn restore_never_overwrites_and_wants_an_absolute_destination() {
        let f = fixture();
        let scratch = f.scratch("restore_never_overwrites_and_wants_an_ab");
        let engine = &f.engine;
        let existing = scratch.join("exists.txt");
        fs::write(&existing, "mine").unwrap();
        assert_eq!(engine.restore("latest", &inside(f, "a.txt"), &existing).unwrap_err().outcome, Outcome::Failed);
        assert_eq!(fs::read(&existing).unwrap(), b"mine");
        let full = scratch.join("full");
        fs::create_dir(&full).unwrap();
        fs::write(full.join("x"), "mine").unwrap();
        assert!(engine.restore("latest", &inside(f, ""), &full).is_err());
        assert_eq!(fs::read(full.join("x")).unwrap(), b"mine");
        assert!(!full.join("a.txt").exists());
        for bad in ["rel/dir", "/tmp/../etc/x"] {
            assert!(engine.restore("latest", &inside(f, ""), Path::new(bad)).is_err(), "{bad}");
        }
        // an empty directory is fine
        let empty = scratch.join("empty");
        fs::create_dir(&empty).unwrap();
        engine.restore("latest", &inside(f, ""), &empty).unwrap();
        assert!(empty.join("a.txt").exists());
    }

    #[test]
    fn a_wrong_password_and_a_location_without_a_repository_have_their_own_names() {
        let f = fixture();
        let scratch = f.scratch("a_wrong_password_and_a_location_without_");
        let err = RusticEngine::open(&Location::local(f.repo.to_str().unwrap()), "not the password").unwrap_err();
        assert_eq!(err.outcome, Outcome::WrongPassword, "{err}");
        let empty = scratch.join("empty-dir");
        fs::create_dir(&empty).unwrap();
        let err = RusticEngine::open(&Location::local(empty.to_str().unwrap()), PASSWORD).unwrap_err();
        assert_eq!(err.outcome, Outcome::NoRepository, "{err}");
        let err =
            RusticEngine::open(&Location::local(scratch.join("missing").to_str().unwrap()), PASSWORD).unwrap_err();
        assert!(matches!(err.outcome, Outcome::NoRepository | Outcome::Failed), "{err}");
    }

    #[test]
    fn opening_reads_only_the_repository_is_byte_for_byte_unchanged() {
        let f = fixture();
        let scratch = f.scratch("opening_reads_only_the_repository_is_byt");
        let before = tree_listing(&f.repo);
        let engine = RusticEngine::open(&Location::local(f.repo.to_str().unwrap()), PASSWORD).unwrap();
        let _ = engine.snapshots().unwrap();
        let _ = engine.list("latest", &inside(f, "")).unwrap();
        engine.dump("latest", &inside(f, "a.txt"), &mut Vec::new()).unwrap();
        engine.restore("latest", &inside(f, ""), &scratch.join("r")).unwrap();
        drop(engine);
        assert_eq!(tree_listing(&f.repo), before);
    }

    /// Every file under `dir` with its length and content, sorted.
    fn tree_listing(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
        let mut out = Vec::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(path) = stack.pop() {
            for entry in fs::read_dir(&path).unwrap() {
                let p = entry.unwrap().path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.push((p.clone(), fs::read(&p).unwrap()));
                }
            }
        }
        out.sort();
        out
    }
}
