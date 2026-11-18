//! Fixture trees and golden files for the subcommand tests.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use p_rover::{Config, Env, FakeClock, Report};
use p_roc::Root;
use tempfile::TempDir;

pub fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        let kind = e.file_type().unwrap();
        if kind.is_symlink() {
            std::os::unix::fs::symlink(fs::read_link(e.path()).unwrap(), dest).unwrap();
        } else if kind.is_dir() {
            copy_dir(&e.path(), &dest);
        } else {
            fs::copy(e.path(), dest).unwrap();
        }
    }
}

/// A writable copy of a fixture host, so a test can change it between samples.
pub struct Host {
    pub dir: TempDir,
}

impl Host {
    pub fn new(name: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        copy_dir(&fixtures().join(name), dir.path());
        Self { dir }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    /// An environment on this host; `on_pause` runs instead of waiting.
    pub fn env(&self, on_pause: impl FnMut(std::time::Duration) + Send + 'static) -> Env {
        let cfg = self.path("config.toml");
        let config = if cfg.exists() { Config::load(Some(&cfg)).unwrap() } else { Config::default() };
        Env {
            root: Root::new(self.path("proc"), self.path("sys"), self.path("dev")),
            etc: self.path("etc"),
            boot: self.path("boot"),
            config,
            host: "testhost".into(),
            clock: Box::new(FakeClock::new(1_794_000_000, on_pause)),
            ethtool: Box::new(p_rover::ethtool::Fixed::default()),
        }
    }
}

/// Compares the report's JSON with `tests/golden/<name>.json`. With
/// `UPDATE_GOLDEN=1` the file is rewritten instead.
pub fn golden(name: &str, report: &Report) {
    let mut got = serde_json::to_string_pretty(report).unwrap();
    got.push('\n');
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(format!("{name}.json"));
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        fs::write(&path, &got).unwrap();
        return;
    }
    let want = fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing golden {}; run with UPDATE_GOLDEN=1", path.display()));
    assert_eq!(got, want, "golden {name} differs; rerun with UPDATE_GOLDEN=1 to accept");
}
