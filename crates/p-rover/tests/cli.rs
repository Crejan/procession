//! The `prover` binary against the fixture tree: arguments, JSON on stdout, exit codes.

mod common;

use std::process::{Command, Output};

use common::fixtures;

fn prover(args: &[&str]) -> Output {
    let host = fixtures().join("host1");
    let mut c = Command::new(env!("CARGO_BIN_EXE_prover"));
    c.args(["--proc-root", host.join("proc").to_str().unwrap()])
        .args(["--sys-root", host.join("sys").to_str().unwrap()])
        .args(["--boot-root", host.join("boot").to_str().unwrap()])
        .args(["--config", host.join("config.toml").to_str().unwrap()])
        .args(args);
    c.output().unwrap()
}

#[test]
fn procs_json_on_stdout_with_exit_code_for_warnings() {
    let out = prover(&["procs", "--format", "json"]);
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["subcommand"], "procs");
    assert_eq!(v["schema_version"], 1);
    assert_eq!(v["mode"], "observe");
    assert_eq!(v["findings"][0]["id"], "rt-on-housekeeping");
}

#[test]
fn text_is_the_default_and_format_may_come_first() {
    let out = prover(&["procs"]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("procs on "), "{text}");
    assert!(text.contains("[WARN] rt-on-housekeeping"), "{text}");
    let json = prover(&["--format", "json", "procs"]);
    assert!(serde_json::from_slice::<serde_json::Value>(&json.stdout).is_ok());
}

#[test]
fn irq_runs_the_shortest_window() {
    let out = prover(&["irq", "--duration", "1s", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["subcommand"], "irq");
    assert_eq!(v["records"][1]["window_s"], 1);
}

#[test]
fn refusals_and_usage_errors_exit_4() {
    assert_eq!(prover(&["irq", "--duration", "5m"]).status.code(), Some(4));
    assert_eq!(prover(&["nosuch"]).status.code(), Some(4));
    assert_eq!(prover(&["--help"]).status.code(), Some(0));
}

#[test]
fn output_file_is_written_and_stdout_stays_empty() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("out.json");
    let out = prover(&["procs", "--format", "json", "--output", f.to_str().unwrap()]);
    assert!(out.stdout.is_empty());
    assert!(serde_json::from_str::<serde_json::Value>(&std::fs::read_to_string(f).unwrap()).is_ok());
}
