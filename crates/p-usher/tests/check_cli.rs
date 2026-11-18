//! `p-usher --check` as an operator runs it before an upgrade.

use std::os::unix::fs::PermissionsExt;
use std::process::Command;

fn check(mode: u32, text: &str) -> (Option<i32>, String) {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("p-usher.toml");
    std::fs::write(&p, text).unwrap();
    std::fs::set_permissions(&p, PermissionsExt::from_mode(mode)).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_p-usher")).args(["--check", "--config"]).arg(&p).output().unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn a_good_file_is_ok_and_exits_zero() {
    let (code, out) = check(0o644, "");
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("configuration ok"));
}

#[test]
fn a_refused_file_is_named_with_its_fix_and_exits_non_zero() {
    let (code, out) = check(0o664, "");
    assert_ne!(code, Some(0));
    assert!(out.starts_with("refused: ") && out.contains("chmod 600"), "{out}");
}
