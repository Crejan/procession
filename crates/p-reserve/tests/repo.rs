//! `preserve snapshots`, `ls` and `restore` as processes, against a
//! throwaway repository in a temporary directory. The repository is made once
//! for the whole file (a debug build derives its key slowly); every test reads
//! it and writes only to its own directory.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use p_reserve_core::testing::make_repository;

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    source: PathBuf,
    config: PathBuf,
}

fn write_mode(path: &Path, text: &str, mode: u32) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let source = root.join("src");
        fs::create_dir_all(source.join("d")).unwrap();
        fs::write(source.join("a.txt"), "hello\n").unwrap();
        fs::write(source.join("d/b.txt"), "b").unwrap();
        make_repository(&root.join("repo"), "pw-for-the-test", &source);
        write_mode(&root.join("good.pw"), "pw-for-the-test\n", 0o600);
        write_mode(&root.join("bad.pw"), "another password\n", 0o600);
        write_mode(&root.join("open.pw"), "pw-for-the-test\n", 0o644);
        let config = root.join("p-reserve.toml");
        let target = |name: &str, pw: &str, repo: &str| {
            format!(
                "[[target]]\nname = \"{name}\"\nrepository = \"{}\"\npassword_file = \"{}\"\n",
                root.join(repo).display(),
                root.join(pw).display()
            )
        };
        let text = [
            target("good", "good.pw", "repo"),
            target("wrongpw", "bad.pw", "repo"),
            target("openpw", "open.pw", "repo"),
            target("norepo", "good.pw", "nowhere"),
        ]
        .concat();
        write_mode(&config, &text, 0o644);
        Fixture { _dir: dir, root, source, config }
    })
}

fn preserve(args: &[&str]) -> Output {
    let f = fixture();
    Command::new(env!("CARGO_BIN_EXE_preserve"))
        .args(args)
        .args(["--config", f.config.to_str().unwrap()])
        .output()
        .unwrap()
}

fn json(out: &Output) -> serde_json::Value {
    serde_json::from_slice(&out.stdout).unwrap_or_else(|e| panic!("{e}: {out:?}"))
}

#[test]
fn snapshots_lists_the_snapshot_as_text_and_as_json() {
    let f = fixture();
    let out = preserve(&["snapshots", "good", "--format", "json"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let j = json(&out);
    assert_eq!(
        (j["schema_version"].clone(), j["type"].clone(), j["target"].clone()),
        (1.into(), "snapshots".into(), "good".into())
    );
    assert_eq!(j["snapshots"].as_array().unwrap().len(), 1);
    assert_eq!(j["snapshots"][0]["paths"][0], f.source.to_str().unwrap());
    assert_eq!(j["snapshots"][0]["id"].as_str().unwrap().len(), 64);
    assert!(j["snapshots"][0]["time"].as_u64().unwrap() > 1_700_000_000);
    let out = preserve(&["snapshots", "good"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains(f.source.to_str().unwrap()));
}

#[test]
fn ls_lists_a_directory_and_restore_gives_the_files_back() {
    let f = fixture();
    let out = preserve(&["ls", "good", "latest", f.source.to_str().unwrap(), "--format", "json"]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let j = json(&out);
    let mut names: Vec<_> = j["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["name"].as_str().unwrap().to_owned(), e["kind"].as_str().unwrap().to_owned()))
        .collect();
    names.sort();
    assert_eq!(names, vec![("a.txt".to_owned(), "file".to_owned()), ("d".to_owned(), "dir".to_owned())]);

    let dest = f.root.join("restored");
    let out = preserve(&[
        "restore",
        "good",
        "latest",
        f.source.to_str().unwrap(),
        "--to",
        dest.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let j = json(&out);
    assert_eq!((j["type"].clone(), j["files"].clone(), j["bytes"].clone()), ("restore".into(), 2.into(), 7.into()));
    assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"hello\n");
    assert_eq!(fs::read(dest.join("d/b.txt")).unwrap(), b"b");

    // a second restore to the same place overwrites nothing and fails with the outcome named
    let out = preserve(&[
        "restore",
        "good",
        "latest",
        f.source.to_str().unwrap(),
        "--to",
        dest.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!((json(&out)["type"].clone(), json(&out)["outcome"].clone()), ("error".into(), "failed".into()));
}

#[test]
fn a_wrong_password_and_a_missing_repository_are_named() {
    let out = preserve(&["snapshots", "wrongpw", "--format", "json"]);
    assert_eq!(out.status.code(), Some(3));
    assert_eq!(json(&out)["outcome"], "wrong-password");
    let out = preserve(&["snapshots", "norepo"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no-repository"), "{out:?}");
}

#[test]
fn a_password_file_others_can_read_an_unknown_target_and_bad_usage_stop_before_opening() {
    let out = preserve(&["snapshots", "openpw"]);
    assert_eq!(out.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not-run") && stderr.contains("chmod 600") && !stderr.contains("pw-for-the-test"),
        "{stderr}"
    );
    let out = preserve(&["snapshots", "nosuch"]);
    assert_eq!(out.status.code(), Some(3));
    for args in [
        &["snapshots"][..],
        &["ls", "good"],
        &["restore", "good", "latest", "/x"],
        &["snapshots", "good", "--bogus"],
        &["snapshots", "good", "--format", "xml"],
        &["restore", "good", "latest", "/x", "--to"],
    ] {
        assert_eq!(preserve(args).status.code(), Some(4), "{args:?}");
    }
}

#[test]
fn restore_refuses_a_relative_destination_and_writes_nothing() {
    let f = fixture();
    let out = preserve(&["restore", "good", "latest", f.source.to_str().unwrap(), "--to", "relative/out"]);
    assert_eq!(out.status.code(), Some(3));
    assert!(!Path::new("relative/out").exists());
}
