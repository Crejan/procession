#![cfg(not(feature = "engine-rustic"))]
//! A build without the repository engine says so plainly: a named outcome and
//! exit code 3, never a panic, and the catalog does not claim the verbs.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn write_mode(path: &std::path::Path, text: &str, mode: u32) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn the_repository_verbs_say_this_build_has_no_engine() {
    let dir = tempfile::tempdir().unwrap();
    let pw = dir.path().join("pw");
    write_mode(&pw, "secret\n", 0o600);
    let config = dir.path().join("p-reserve.toml");
    write_mode(
        &config,
        &format!("[[target]]\nname = \"t\"\nrepository = \"/nowhere\"\npassword_file = \"{}\"\n", pw.display()),
        0o644,
    );
    for args in [&["snapshots", "t"][..], &["ls", "t", "latest"], &["restore", "t", "latest", "/a", "--to", "/tmp/x"]] {
        let out = Command::new(env!("CARGO_BIN_EXE_preserve"))
            .args(args)
            .args(["--config", config.to_str().unwrap()])
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(3), "{args:?}");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("not-run") && stderr.contains("no repository engine"), "{stderr}");
        let json = Command::new(env!("CARGO_BIN_EXE_preserve"))
            .args(args)
            .args(["--format", "json", "--config", config.to_str().unwrap()])
            .output()
            .unwrap();
        let j: serde_json::Value = serde_json::from_slice(&json.stdout).unwrap();
        assert_eq!((j["type"].clone(), j["outcome"].clone()), ("error".into(), "not-run".into()));
    }
}

#[test]
fn the_catalog_does_not_claim_verbs_this_build_cannot_run() {
    let out = Command::new(env!("CARGO_BIN_EXE_preserve")).args(["catalog", "--format", "json"]).output().unwrap();
    let j: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    for verb in j["verbs"].as_array().unwrap() {
        let engine_verb = ["snapshots", "ls", "restore"].contains(&verb["name"].as_str().unwrap());
        if engine_verb {
            assert_eq!(verb["implemented"], false, "{verb}");
        }
    }
}
