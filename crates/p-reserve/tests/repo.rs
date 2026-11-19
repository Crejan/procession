#![cfg(feature = "engine-rustic")]
//! Built only with the engine: `cargo test -p p-reserve --features engine-rustic`.
//!
//! `preserve snapshots`, `ls` and `restore` as processes, against a
//! throwaway repository in a temporary directory. The repository is made once
//! for the whole file (a debug build derives its key slowly); every test reads
//! it and writes only to its own directory.

use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;

use p_reserve_core::testing::make_repository;

/// Names a source file system can hold: a C1 control (U+0085, U+009B), a bidirectional mark (U+202E), ESC, a newline.
const WEIRD: [&str; 5] = ["c1\u{85}next", "csi\u{9b}31m", "rtl\u{202e}txt.exe", "esc\x1b[2Jclear", "two\nlines"];

const BAD_A: &[u8] = b"bad\xff\xfename";
const BAD_B: &[u8] = b"bad\xfe\xffname";

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
        fs::create_dir(source.join("bad")).unwrap();
        for (i, bad) in [BAD_A, BAD_B].iter().enumerate() {
            // best effort: a file system that needs valid UTF-8 names (APFS) cannot hold them
            let _ = fs::write(source.join("bad").join(std::ffi::OsStr::from_bytes(bad)), format!("bad {i}"));
        }
        fs::create_dir(source.join("weird")).unwrap();
        for (i, name) in WEIRD.iter().enumerate() {
            fs::write(source.join("weird").join(name), format!("content {i}")).unwrap();
        }
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
    assert_eq!(
        names,
        vec![
            ("a.txt".to_owned(), "file".to_owned()),
            ("bad".to_owned(), "dir".to_owned()),
            ("d".to_owned(), "dir".to_owned()),
            ("weird".to_owned(), "dir".to_owned())
        ]
    );

    // two more files, of 5 bytes, where the file system can hold names that are not UTF-8
    let bad =
        [BAD_A, BAD_B].iter().filter(|b| f.source.join("bad").join(std::ffi::OsStr::from_bytes(b)).exists()).count()
            as u64;
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
    assert_eq!(
        (j["type"].clone(), j["files"].clone(), j["bytes"].clone()),
        ("restore".into(), (7 + bad).into(), (7 + 5 * 9 + 5 * bad).into())
    );
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

/// The bytes a terminal or a log must never get from preserve: ESC, C1 controls, bidirectional marks (as UTF-8).
fn raw_refused(bytes: &[u8]) -> bool {
    let text = String::from_utf8_lossy(bytes);
    text.chars().any(|c| (c.is_control() && c != '\n') || p_ermit::text::is_bidi_mark(c)) || text.contains('\u{fffd}')
}

#[test]
fn names_with_c1_controls_a_bidi_mark_esc_and_a_newline_are_listed_escaped_and_restored_under_their_real_names() {
    let f = fixture();
    let dir = f.source.join("weird");
    // text: every name is there, as what it is, none raw, and the lines are not split by the newline
    let out = preserve(&["ls", "good", "latest", dir.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(!raw_refused(&out.stdout), "raw refused characters on stdout: {:?}", out.stdout);
    let text = String::from_utf8(out.stdout).unwrap();
    assert_eq!(text.lines().count(), WEIRD.len(), "{text}");
    for shown in ["c1\\u{85}next", "csi\\u{9b}31m", "rtl\\u{202e}txt.exe", "esc\\u{1b}[2Jclear", "two\\u{a}lines"] {
        assert!(text.contains(shown), "{shown} in {text}");
    }
    // JSON: valid, one entry per name, flagged
    let out = preserve(&["ls", "good", "latest", dir.to_str().unwrap(), "--format", "json"]);
    assert!(!raw_refused(&out.stdout), "{:?}", out.stdout);
    let j = json(&out);
    let entries = j["entries"].as_array().unwrap();
    assert_eq!(entries.len(), WEIRD.len());
    assert!(entries.iter().all(|e| e["escaped"] == true), "{j}");
    let names: Vec<String> = entries.iter().map(|e| e["name"].as_str().unwrap().to_owned()).collect();
    for weird in WEIRD {
        let shown = p_ermit::text::escape(weird).text;
        assert!(names.contains(&shown), "{shown} in {names:?}");
        // reversible: the shown name stands for exactly the real one
        assert_eq!(p_ermit::text::unescape(&shown).as_deref(), Some(weird));
    }
    // an ordinary name is not flagged
    let out = preserve(&["ls", "good", "latest", f.source.to_str().unwrap(), "--format", "json"]);
    assert!(json(&out)["entries"].as_array().unwrap().iter().all(|e| e["escaped"] == false));

    // restore: the real names on disk, only the output escaped
    let dest = f.root.join("weird-restored");
    let out = preserve(&["restore", "good", "latest", dir.to_str().unwrap(), "--to", dest.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(!raw_refused(&out.stdout) && !raw_refused(&out.stderr));
    let mut on_disk: Vec<Vec<u8>> =
        fs::read_dir(&dest).unwrap().map(|e| e.unwrap().file_name().as_bytes().to_vec()).collect();
    on_disk.sort();
    let mut want: Vec<Vec<u8>> = WEIRD.iter().map(|n| n.as_bytes().to_vec()).collect();
    want.sort();
    assert_eq!(on_disk, want);
    for (i, name) in WEIRD.iter().enumerate() {
        assert_eq!(fs::read(dest.join(name)).unwrap(), format!("content {i}").as_bytes());
    }
}

#[test]
fn an_error_about_a_weird_path_does_not_repeat_it_raw() {
    let f = fixture();
    let missing = f.source.join("weird").join("nope\u{202e}\u{85}");
    for args in [
        &["restore", "good", "latest", missing.to_str().unwrap(), "--to", "/tmp/never-written-x"][..],
        &["ls", "good", "latest", missing.to_str().unwrap()],
    ] {
        let out = preserve(args);
        assert_eq!(out.status.code(), Some(3), "{args:?}");
        assert!(!raw_refused(&out.stderr) && !raw_refused(&out.stdout), "{:?}", out.stderr);
        let json = preserve(&[args, &["--format", "json"]].concat());
        assert!(!raw_refused(&json.stdout), "{:?}", json.stdout);
        let j = serde_json::from_slice::<serde_json::Value>(&json.stdout).unwrap();
        assert!(j.get("detail").is_none(), "the engine's words are not forwarded to a machine reader: {j}");
    }
}

#[test]
fn names_that_are_not_utf8_are_shown_with_x_escapes_apart_and_restored_with_the_real_bytes() {
    let f = fixture();
    let dir = f.source.join("bad");
    if !dir.join(std::ffi::OsStr::from_bytes(BAD_A)).exists() || !dir.join(std::ffi::OsStr::from_bytes(BAD_B)).exists()
    {
        assert!(
            std::env::var_os("PRESERVE_TESTS_STRICT").is_none(),
            "SKIPPED in strict mode: no non-UTF-8 file names here"
        );
        eprintln!(
            "SKIPPED: this file system cannot hold file names that are not UTF-8 (APFS cannot; run it on Linux); this test did not run"
        );
        return;
    }
    let out = preserve(&["ls", "good", "latest", dir.to_str().unwrap(), "--format", "json"]);
    assert!(!raw_refused(&out.stdout), "{:?}", out.stdout);
    let j = json(&out);
    let names: Vec<&str> = j["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"bad\\x{ff}\\x{fe}name") && names.contains(&"bad\\x{fe}\\x{ff}name"), "{names:?}");
    assert!(j["entries"].as_array().unwrap().iter().all(|e| e["escaped"] == true));
    let text = preserve(&["ls", "good", "latest", dir.to_str().unwrap()]);
    assert!(!raw_refused(&text.stdout));
    let dest = f.root.join("bad-restored");
    let out = preserve(&["restore", "good", "latest", dir.to_str().unwrap(), "--to", dest.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert_eq!(fs::read(dest.join(std::ffi::OsStr::from_bytes(BAD_A))).unwrap(), b"bad 0");
    assert_eq!(fs::read(dest.join(std::ffi::OsStr::from_bytes(BAD_B))).unwrap(), b"bad 1");
}
