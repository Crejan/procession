#![cfg(feature = "testing")]
//! The engine against real repositories: one written by `rustic_core` and one written by `restic`. Not part of the
//! default test run (it needs the `engine-rustic` feature and the `restic` binary, and a debug build derives keys and
//! loads indexes slowly):
//!
//! `cargo test -p p-reserve-core --features testing --offline --test engine`
//!
//! The SHA-256 test is fundament's restore test: every file of a source tree is restored from a snapshot and its
//! SHA-256 compared with the source file's. The restic tests make a local repository in a temporary directory with the
//! `restic` binary on the path (no network). If `restic` is not there those tests say SKIPPED and count as not run.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use p_reserve_core::Outcome;
use p_reserve_core::engine::{Engine, NodeKind};
use p_reserve_core::rustic::{Location, RusticEngine};
use p_reserve_core::testing::make_repository;
use sha2::{Digest, Sha256};

const PASSWORD: &str = "engine-test-password";

fn sha256(path: &Path) -> String {
    let mut hasher = Sha256::new();
    std::io::copy(&mut fs::File::open(path).unwrap(), &mut hasher).unwrap();
    hasher.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

/// Relative path to SHA-256 of every regular file under `root`, symlinks as their target text.
fn digests(root: &Path) -> BTreeMap<PathBuf, String> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let rel = path.strip_prefix(root).unwrap().to_path_buf();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_symlink() {
                out.insert(rel, format!("-> {}", fs::read_link(&path).unwrap().display()));
            } else {
                out.insert(rel, sha256(&path));
            }
        }
    }
    out
}

/// File names a source file system can hold and a terminal, a log or a front end must not meet raw: a C1 control
/// (U+0085, U+009B), a bidirectional mark (U+202E), an ESC sequence and a newline.
const WEIRD: [&str; 5] = ["c1\u{85}next", "csi\u{9b}31m", "rtl\u{202e}txt.exe", "esc\x1b[2Jclear", "two\nlines"];

/// A source tree: small files, an empty file, a symlink, a nested directory, a file of several chunks that does not
/// compress and one that does.
fn make_source(root: &Path) -> PathBuf {
    let source = root.join("src");
    fs::create_dir_all(source.join("deep/er/still")).unwrap();
    fs::write(source.join("a.txt"), "hello\n").unwrap();
    fs::write(source.join("empty"), "").unwrap();
    fs::write(source.join("deep/er/still/z.txt"), "z").unwrap();
    std::os::unix::fs::symlink("a.txt", source.join("link")).unwrap();
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let noise: Vec<u8> = (0..3 * 1024 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect();
    fs::write(source.join("deep/noise.bin"), noise).unwrap();
    fs::create_dir(source.join("weird")).unwrap();
    for (i, name) in WEIRD.iter().enumerate() {
        fs::write(source.join("weird").join(name), format!("content {i}")).unwrap();
    }
    fs::write(source.join("deep/er/zeros.bin"), vec![0u8; 2 * 1024 * 1024]).unwrap();
    source
}

fn restic_available() -> bool {
    Command::new("restic").arg("version").output().is_ok_and(|o| o.status.success())
}

fn restic(repo: &Path, args: &[&str]) -> std::process::Output {
    let out = Command::new("restic")
        .args(["--quiet", "--no-cache", "-r"])
        .arg(repo)
        .args(args)
        .env("RESTIC_PASSWORD", PASSWORD)
        .output()
        .unwrap();
    assert!(out.status.success(), "restic {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    out
}

struct Written {
    _dir: tempfile::TempDir,
    repo: PathBuf,
    source: PathBuf,
    scratch: PathBuf,
    engine: RusticEngine,
}

impl Written {
    fn path_in_snapshot(&self, rel: &str) -> String {
        self.source.join(rel).to_str().unwrap().to_owned()
    }

    fn scratch(&self, name: &str) -> PathBuf {
        let dir = self.scratch.join(name);
        fs::create_dir(&dir).unwrap();
        dir
    }
}

fn open(repo: &Path) -> RusticEngine {
    RusticEngine::open(&Location::local(repo.to_str().unwrap()), PASSWORD).unwrap()
}

/// A repository `rustic_core` wrote.
fn by_rustic() -> &'static Written {
    static F: OnceLock<Written> = OnceLock::new();
    F.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let source = make_source(&root);
        make_repository(&root.join("repo"), PASSWORD, &source);
        let scratch = root.join("scratch");
        fs::create_dir(&scratch).unwrap();
        let engine = open(&root.join("repo"));
        Written { repo: root.join("repo"), _dir: dir, source, scratch, engine }
    })
}

/// A repository `restic` wrote (None, with SKIPPED printed, if there is no `restic`).
fn by_restic() -> Option<&'static Written> {
    static F: OnceLock<Option<Written>> = OnceLock::new();
    F.get_or_init(|| {
        if !restic_available() {
            return None;
        }
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let source = make_source(&root);
        let repo = root.join("repo");
        restic(&repo, &["init"]);
        restic(&repo, &["backup", source.to_str().unwrap()]);
        let scratch = root.join("scratch");
        fs::create_dir(&scratch).unwrap();
        let engine = open(&repo);
        Some(Written { repo, _dir: dir, source, scratch, engine })
    })
    .as_ref()
}

fn skipped() {
    eprintln!("SKIPPED: no `restic` binary on the path; this test did not run");
}

fn assert_restores_with_matching_sha256(w: &Written, name: &str) {
    let dest = w.scratch(name);
    let summary = w.engine.restore("latest", &w.path_in_snapshot(""), &dest).unwrap();
    let (want, got) = (digests(&w.source), digests(&dest));
    assert_eq!(want.keys().collect::<Vec<_>>(), got.keys().collect::<Vec<_>>(), "the same files");
    for (path, sha) in &want {
        assert_eq!(&got[path], sha, "SHA-256 of {}", path.display());
    }
    assert_eq!(summary.files as usize, want.values().filter(|v| !v.starts_with("->")).count());
    // each file one by one, as fundament's restore test does, to a path of its own
    for (path, sha) in want.iter().filter(|(_, v)| !v.starts_with("->")) {
        let one = w.scratch(&format!("{name}-one")).join("f");
        w.engine.restore("latest", &w.path_in_snapshot(path.to_str().unwrap()), &one).unwrap();
        assert_eq!(&sha256(&one), sha, "single file {}", path.display());
        fs::remove_dir_all(one.parent().unwrap()).unwrap();
    }
}

#[test]
fn a_restore_from_a_repository_rustic_wrote_matches_the_source_by_sha256() {
    assert_restores_with_matching_sha256(by_rustic(), "rustic-sha");
}

#[test]
fn a_restore_from_a_repository_restic_wrote_matches_the_source_by_sha256() {
    let Some(w) = by_restic() else { return skipped() };
    assert_restores_with_matching_sha256(w, "restic-sha");
}

#[test]
fn the_engine_lists_and_reads_what_restic_wrote() {
    let Some(w) = by_restic() else { return skipped() };
    let snapshots = w.engine.snapshots().unwrap();
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].paths, vec![w.source.to_str().unwrap().to_owned()]);
    assert!(!snapshots[0].host.is_empty());
    let mut top: Vec<_> = w
        .engine
        .list("latest", &w.path_in_snapshot(""))
        .unwrap()
        .into_iter()
        .map(|n| (String::from_utf8(n.name).unwrap(), n.kind))
        .collect();
    top.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        top,
        vec![
            ("a.txt".to_owned(), NodeKind::File),
            ("deep".to_owned(), NodeKind::Dir),
            ("empty".to_owned(), NodeKind::File),
            ("link".to_owned(), NodeKind::Symlink),
            ("weird".to_owned(), NodeKind::Dir),
        ]
    );
    let mut out = Vec::new();
    assert_eq!(w.engine.dump("latest", &w.path_in_snapshot("a.txt"), &mut out).unwrap(), 6);
    assert_eq!(out, b"hello\n");
    let mut noise = Vec::new();
    w.engine.dump("latest", &w.path_in_snapshot("deep/noise.bin"), &mut noise).unwrap();
    assert_eq!(noise, fs::read(w.source.join("deep/noise.bin")).unwrap());
}

#[test]
fn opening_and_reading_changes_nothing_in_a_repository_restic_wrote_and_takes_no_lock() {
    let Some(w) = by_restic() else { return skipped() };
    let listing = |dir: &str| -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(w.repo.join(dir))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    let before = (listing("locks"), listing("snapshots"), listing("index"), listing("keys"));
    let fresh = open(&w.repo);
    let _ = fresh.snapshots().unwrap();
    let _ = fresh.list("latest", &w.path_in_snapshot("")).unwrap();
    assert_eq!((listing("locks"), listing("snapshots"), listing("index"), listing("keys")), before);
    assert!(before.0.is_empty(), "no lock at rest");
}

/// `restic backup --stdin` holds its lock until its input is closed: a restic that is writing.
fn spawn_writing_restic(repo: &Path) -> Child {
    Command::new("restic")
        .args(["--quiet", "--no-cache", "-r"])
        .arg(repo)
        .args(["backup", "--stdin", "--stdin-filename", "late.txt"])
        .env("RESTIC_PASSWORD", PASSWORD)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

#[test]
fn a_repository_restic_is_writing_to_can_be_read_and_data_written_after_the_open_needs_a_reopen() {
    if !restic_available() {
        return skipped();
    }
    // a repository of its own: this test writes to it
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let source = make_source(&root);
    let repo = root.join("repo");
    restic(&repo, &["init"]);
    restic(&repo, &["backup", source.to_str().unwrap()]);

    let mut writer = spawn_writing_restic(&repo);
    let locks = repo.join("locks");
    let lock_count = || fs::read_dir(&locks).unwrap().count();
    let deadline = Instant::now() + Duration::from_secs(60);
    while lock_count() == 0 {
        assert!(Instant::now() < deadline, "restic took no lock");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(lock_count(), 1);

    // opened while restic holds its lock and is mid-backup: rustic neither waits nor refuses, takes no lock of its own
    let engine = open(&repo);
    assert_eq!(lock_count(), 1, "the engine took no lock");
    assert_eq!(engine.snapshots().unwrap().len(), 1);
    let mut out = Vec::new();
    engine.dump("latest", &source.join("a.txt").to_string_lossy(), &mut out).unwrap();
    assert_eq!(out, b"hello\n");

    // restic finishes and writes a second snapshot
    writer.stdin.take().unwrap().write_all(b"written later\n").unwrap();
    let status = writer.wait().unwrap();
    assert!(status.success());
    assert_eq!(lock_count(), 0, "restic released its lock");

    // the list of snapshots is read from the repository each time: the new one is there at once
    let snapshots = engine.snapshots().unwrap();
    assert_eq!(snapshots.len(), 2);
    // its data is not in the index this engine loaded: reading it fails, it does not panic and does not return wrong bytes
    let late = &snapshots[1].id;
    let mut stale = Vec::new();
    let attempt = engine.dump(late, "/late.txt", &mut stale);
    eprintln!("observed: dump of data written after the open: {attempt:?}");
    if let Err(e) = &attempt {
        assert_eq!(e.outcome, Outcome::Failed);
    }
    assert!(attempt.is_err() || stale == b"written later\n", "never wrong bytes");
    // a new open sees it
    let mut fresh = Vec::new();
    open(&repo).dump(late, "/late.txt", &mut fresh).unwrap();
    assert_eq!(fresh, b"written later\n");
}

fn assert_weird_names_are_listed_read_and_restored_under_their_real_names(w: &Written, name: &str) {
    use std::os::unix::ffi::OsStrExt;
    let dir = w.path_in_snapshot("weird");
    // listed, never refused: the names come back as the bytes the file system held
    let mut listed: Vec<Vec<u8>> = w.engine.list("latest", &dir).unwrap().into_iter().map(|n| n.name).collect();
    listed.sort();
    let mut want: Vec<Vec<u8>> = WEIRD.iter().map(|n| n.as_bytes().to_vec()).collect();
    want.sort();
    assert_eq!(listed, want);
    // read: the bytes of each, by its real path
    for (i, weird) in WEIRD.iter().enumerate() {
        let mut out = Vec::new();
        w.engine.dump("latest", &format!("{dir}/{weird}"), &mut out).unwrap();
        assert_eq!(out, format!("content {i}").as_bytes(), "{weird:?}");
    }
    // restored under the real names, and nothing else
    let dest = w.scratch(name);
    w.engine.restore("latest", &dir, &dest).unwrap();
    let mut on_disk: Vec<Vec<u8>> =
        fs::read_dir(&dest).unwrap().map(|e| e.unwrap().file_name().as_bytes().to_vec()).collect();
    on_disk.sort();
    assert_eq!(on_disk, want);
    for (i, weird) in WEIRD.iter().enumerate() {
        assert_eq!(fs::read(dest.join(weird)).unwrap(), format!("content {i}").as_bytes());
    }
}

#[test]
fn names_with_c1_controls_and_a_bidi_mark_are_listed_read_and_restored_under_their_real_names_from_a_rustic_repository() {
    assert_weird_names_are_listed_read_and_restored_under_their_real_names(by_rustic(), "weird-rustic");
}

#[test]
fn names_with_c1_controls_and_a_bidi_mark_are_listed_read_and_restored_under_their_real_names_from_a_restic_repository() {
    let Some(w) = by_restic() else { return skipped() };
    assert_weird_names_are_listed_read_and_restored_under_their_real_names(w, "weird-restic");
}
