//! `preserve health` as a process: the ledger file in, the exit code and the
//! report out. Time is fixed with `--now`.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use p_reserve_core::textfile::{DEFAULT_PREFIX, Textfile};
use p_reserve_core::{Ledger, Outcome, Pair, Run};
use std::time::{Duration, SystemTime};

const HOUR: u64 = 3600;
const START: u64 = 1_700_000_000;

fn at(secs: u64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
}

fn write_ledger(dir: &Path, build: impl FnOnce(&mut Ledger)) -> std::path::PathBuf {
    let mut ledger = Ledger::default();
    build(&mut ledger);
    let path = dir.join("ledger.prom");
    Textfile::new(&path, DEFAULT_PREFIX).unwrap().save(&ledger).unwrap();
    path
}

fn health(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_preserve")).arg("health").args(args).output().unwrap()
}

fn run_at(ledger: &Path, hours: u64, extra: &[&str]) -> Output {
    let now = (START + hours * HOUR).to_string();
    let mut args = vec!["--ledger", ledger.to_str().unwrap(), "--now", &now];
    args.extend_from_slice(extra);
    health(&args)
}

#[test]
fn a_fresh_clean_pair_exits_0() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = write_ledger(dir.path(), |l| l.record(Pair::new("home", "offsite"), Run::stored(1, 0), at(START)));
    let out = run_at(&ledger, 1, &[]);
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("ok\n"));
}

#[test]
fn an_incomplete_snapshot_exits_1_and_says_how_many_files() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = write_ledger(dir.path(), |l| l.record(Pair::new("home", "offsite"), Run::stored(1, 12), at(START)));
    let out = run_at(&ledger, 1, &[]);
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("warning\n") && text.contains("12 files could not be read"), "{text}");
}

#[test]
fn a_stale_pair_exits_2_and_json_carries_the_schema_version_and_the_exit_code() {
    let dir = tempfile::tempdir().unwrap();
    let ledger = write_ledger(dir.path(), |l| {
        l.record(Pair::new("home", "offsite"), Run::stored(1, 0), at(START));
        l.record(Pair::new("home", "offsite"), Run::ended(Outcome::Failed), at(START + 10 * HOUR));
    });
    let out = run_at(&ledger, 100, &["--format", "json"]);
    assert_eq!(out.status.code(), Some(2));
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["schema_version"], 1);
    assert_eq!(json["type"], "health");
    assert_eq!(json["level"], "critical");
    assert_eq!(json["exit_code"], 2);
    assert_eq!(json["pairs"][0]["freshness"], "stale");
    assert_eq!(json["pairs"][0]["last_outcome"], "failed");
}

#[test]
fn a_declared_pair_without_a_record_is_critical_and_without_a_ledger_file_too() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("p-reserve.toml");
    fs::write(&config, "[[pair]]\nsource = \"home\"\ntarget = \"offsite\"\n").unwrap();
    let missing = dir.path().join("none.prom");
    let out = run_at(&missing, 0, &["--config", config.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "{out:?}");
}

#[test]
fn an_unreadable_or_corrupt_ledger_exits_3_never_reads_as_healthy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ledger.prom");
    fs::write(&path, "preserve_backup_last_added_bytes{source=\"a\"} 1\n").unwrap();
    let out = run_at(&path, 0, &[]);
    assert_eq!(out.status.code(), Some(3));
    assert!(String::from_utf8_lossy(&out.stderr).contains("line 1"));
    let out = health(&["--config", dir.path().join("absent.toml").to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(3));
}

#[test]
fn bad_usage_exits_4() {
    for args in [&["--format", "xml"][..], &["--bogus"], &["--now", "yesterday"], &["--ledger"]] {
        assert_eq!(health(args).status.code(), Some(4), "{args:?}");
    }
}

#[test]
fn the_catalog_marks_health_as_implemented_and_forget_is_not_a_verb() {
    let out = Command::new(env!("CARGO_BIN_EXE_preserve")).args(["catalog", "--format", "json"]).output().unwrap();
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let verbs = json["verbs"].as_array().unwrap();
    let find = |name: &str| verbs.iter().find(|v| v["name"] == name);
    assert_eq!(find("health").unwrap()["implemented"], true);
    assert_eq!(find("run").unwrap()["implemented"], false);
    assert!(find("reprovision").is_some());
    for gone in ["forget", "unlock", "mount", "unmount"] {
        assert!(find(gone).is_none(), "{gone}");
    }
}
