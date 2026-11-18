//! The rows that run `prover`, with the real `prover` binary of this workspace on its fixture host
//! (`crates/p-rover/tests/fixtures/host1`), in a build with `--features test-verbs`.
//!
//! The row's command has no option for another `/proc` or `/sys`, and must not have: so the test build
//! (never for root) takes a `PROBE_TEST_PROVER`, here a script that runs the real binary with the fixture's
//! roots in front of the row's words. The wrapper around it, the limit, the checks and the lines are the
//! production ones. What the dispatcher does with a tool that fails or lies is in `src/prover.rs` (fakes).

#![cfg(feature = "test-verbs")]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const PROBE: &str = env!("CARGO_BIN_EXE_probe");

/// The `prover` binary, built if it is not there yet (the tests of this package do not build it).
fn prover_binary() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let profile_dir = exe.parent().unwrap().parent().unwrap();
    let binary = profile_dir.join("prover");
    if !binary.exists() {
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
        let mut build = Command::new(cargo);
        build.args(["build", "-p", "p-rover", "--bin", "prover"]).current_dir(env!("CARGO_MANIFEST_DIR"));
        if profile_dir.file_name().is_some_and(|n| n == "release") {
            build.arg("--release");
        }
        assert!(build.status().unwrap().success(), "cannot build prover");
    }
    assert!(binary.exists(), "{}", binary.display());
    binary
}

/// A directory with the audit sink's place, a copy of the fixture's config and the wrapper script.
fn setup(name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("probe-prover-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("locks")).unwrap();
    let host = Path::new(env!("CARGO_MANIFEST_DIR")).join("../p-rover/tests/fixtures/host1");
    // The tool's settings reader refuses a file others can write: the mode is set, not left to the umask.
    let config = dir.join("config.toml");
    std::fs::copy(host.join("config.toml"), &config).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
    let wrapper = dir.join("prover");
    std::fs::write(
        &wrapper,
        format!(
            "#!/bin/sh\nexec '{}' --proc-root '{}' --sys-root '{}' --boot-root '{}' --config '{}' \"$@\"\n",
            prover_binary().display(),
            host.join("proc").display(),
            host.join("sys").display(),
            host.join("boot").display(),
            config.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o755)).unwrap();
    (dir, wrapper)
}

fn probe(dir: &Path, prover: &Path, args: &[&str]) -> Output {
    Command::new(PROBE)
        .args(args)
        .env_clear()
        .env("SUDO_USER", "jan")
        .env("PROBE_TEST_SANDBOX", dir)
        .env("PROBE_TEST_PROVER", prover)
        .output()
        .unwrap()
}

fn lines(out: &Output) -> Vec<serde_json::Value> {
    String::from_utf8(out.stdout.clone())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{l}: {e}")))
        .collect()
}

fn audit(dir: &Path) -> String {
    std::fs::read_to_string(dir.join("audit.log")).unwrap_or_default()
}

#[test]
fn rt_procs_is_the_real_tools_answer_in_the_conventions_lines() {
    let (dir, wrapper) = setup("procs");
    let out = probe(&dir, &wrapper, &["rt", "procs"]);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let all = lines(&out);
    assert_eq!(
        (all[0]["type"].as_str(), all[0]["noun"].as_str(), all[0]["verb"].as_str()),
        (Some("header"), Some("rt"), Some("procs"))
    );
    assert_eq!(all[0]["subcommand"], "procs");
    assert!(all.iter().any(|l| l["type"] == "thread"), "{all:?}");
    assert!(all.iter().any(|l| l["type"] == "summary"), "{all:?}");
    let finding = all.iter().find(|l| l["type"] == "finding").expect("a finding");
    assert_eq!(finding["id"], "rt-on-housekeeping");
    // The fixture's host has a warning: the tool exits 1, and that is the trailer's rc, not probe's.
    let trailer = all.last().unwrap();
    assert_eq!(
        (trailer["type"].as_str(), trailer["rc"].as_i64(), trailer["result"].as_str()),
        (Some("trailer"), Some(1), Some("warnings"))
    );
    let log = audit(&dir);
    assert!(log.contains("event=start") && log.contains("event=done") && !log.contains("cause="), "{log}");
}

#[test]
fn the_parameters_reach_the_tool_as_the_flags_the_row_chose() {
    let (dir, wrapper) = setup("params");
    let out = probe(&dir, &wrapper, &["rt", "procs", "max=1"]);
    assert_eq!(out.status.code(), Some(0));
    let threads = lines(&out).iter().filter(|l| l["type"] == "thread").count();
    assert_eq!(threads, 1, "max=1 reached the tool as --max 1");
    let out = probe(&dir, &wrapper, &["rt", "irq", "duration=1", "top=1"]);
    assert_eq!(out.status.code(), Some(0), "{}", String::from_utf8_lossy(&out.stderr));
    let all = lines(&out);
    assert_eq!(all[0]["subcommand"], "irq");
    assert!(all.iter().any(|l| l["type"] == "irq") && all.iter().any(|l| l["type"] == "timer"), "{all:?}");
    let summary = all.iter().find(|l| l["type"] == "summary").unwrap();
    assert_eq!(summary["window_s"], 1, "duration=1 became --duration 1s");
}

#[test]
fn a_tool_that_is_not_there_is_a_failed_call_not_an_empty_answer() {
    let (dir, _) = setup("missing");
    let out = probe(&dir, &dir.join("no-prover"), &["rt", "irq"]);
    assert_eq!(out.status.code(), Some(70));
    assert!(audit(&dir).contains("cause='tool-unusable:not found'"), "{}", audit(&dir));
}
