//! The `probe` binary, end to end, in a build with `--features test-verbs`
//! (the test hook that moves the audit and the locks into a directory of the
//! test's own exists only there). Without the feature the tests that need it
//! are not compiled; the last one checks what a production build does.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const PROBE: &str = env!("CARGO_BIN_EXE_probe");

fn sandbox(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("probe-cli-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("locks")).unwrap();
    dir
}

fn probe(args: &[&str], sandbox: Option<&Path>) -> Output {
    let mut command = Command::new(PROBE);
    command.args(args).env_clear().env("SUDO_USER", "jan");
    if let Some(dir) = sandbox {
        command.env("PROBE_TEST_SANDBOX", dir);
    }
    command.output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
fn the_catalogue_needs_no_sudo_and_lists_every_verb_with_its_status() {
    let out = probe(&["catalog"], None);
    assert!(out.status.success());
    let table = text(&out.stdout);
    for expected in ["sys  kit", "rt   irq", "run  command", "service-only", "unavailable"] {
        assert!(table.contains(expected), "{expected}\n{table}");
    }
    let json = probe(&["catalog", "--format", "json"], None);
    assert!(text(&json.stdout).lines().all(|l| l.starts_with("{\"type\":")));
    assert_eq!(text(&probe(&["rt"], None).stdout).lines().count(), 4);
}

#[test]
fn a_production_build_does_not_know_the_test_hook() {
    if cfg!(feature = "test-verbs") {
        return;
    }
    // Not root, so the entrance refuses, whatever PROBE_TEST_SANDBOX says.
    let dir = sandbox("prod");
    let out = probe(&["sys", "kit"], Some(&dir));
    if text(&Command::new("id").arg("-u").output().unwrap().stdout).trim() != "0" {
        assert!(matches!(out.status.code(), Some(3 | 64)), "{:?}", out.status);
        assert!(text(&out.stdout).is_empty());
    }
}

#[cfg(feature = "test-verbs")]
mod with_test_verbs {
    use super::*;

    fn audit(dir: &Path) -> Vec<String> {
        std::fs::read_to_string(dir.join("audit.log"))
            .map(|s| s.lines().map(String::from).collect())
            .unwrap_or_default()
    }

    #[test]
    fn the_harmless_test_verb_runs_between_two_audit_lines() {
        let dir = sandbox("echo");
        let out = probe(&["test", "echo", "a=1"], Some(&dir));
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let lines: Vec<String> = text(&out.stdout).lines().map(String::from).collect();
        assert!(lines[0].starts_with("{\"type\":\"header\""));
        assert_eq!(lines[1], "{\"type\":\"echo\",\"identity\":\"jan\",\"args\":[\"a=1\"]}");
        let log = audit(&dir);
        assert_eq!(log.len(), 2, "{log:?}");
        assert!(log[0].starts_with("event=start noun=test verb=echo args=a=1 identity=jan"));
        assert!(log[1].starts_with("event=done ") && log[1].contains("rc=0"));
    }

    #[test]
    fn the_catalogue_of_a_test_build_lists_the_test_verbs_and_the_top_rating() {
        let out = text(&probe(&["catalog", "--format", "json"], None).stdout);
        assert!(out.contains("\"noun\":\"test\",\"verb\":\"echo\""));
        assert!(out.contains("\"noun\":\"test\",\"verb\":\"peak\",\"runs\":\"probe\",\"exposure\":\"open\",\"damage\":\"none\",\"disruption\":\"outage\",\"needs_confirmation\":true"));
        assert!(out.contains("\"verb\":\"echo\",\"runs\":\"probe\",\"exposure\":\"open\",\"damage\":\"none\",\"disruption\":\"none\",\"needs_confirmation\":false"));
    }

    #[test]
    fn a_refusal_is_exit_64_with_a_line_in_the_audit_and_no_answer() {
        let dir = sandbox("refuse");
        for argv in [&["test", "echo", "-x"][..], &["run", "command"], &["nope", "x"], &["test", "echo", "a b"]] {
            let out = probe(argv, Some(&dir));
            assert_eq!(out.status.code(), Some(64), "{argv:?}");
            assert!(out.stdout.is_empty());
        }
        let log = audit(&dir);
        assert_eq!(log.len(), 4);
        assert!(log.iter().all(|l| l.starts_with("event=refused ")));
    }

    #[test]
    fn no_audit_no_run() {
        let dir = sandbox("noaudit");
        std::fs::create_dir(dir.join("audit.log")).unwrap(); // a directory: no line can be written
        let out = probe(&["test", "echo"], Some(&dir));
        assert_eq!(out.status.code(), Some(3));
        assert!(out.stdout.is_empty());
        assert!(text(&out.stderr).contains("cannot write the audit line"));
    }

    #[test]
    fn a_verb_that_cannot_run_here_exits_3() {
        let dir = sandbox("unavail");
        let out = probe(&["rt", "irq"], Some(&dir));
        assert_eq!(out.status.code(), Some(3));
        assert!(text(&out.stderr).contains("prover"));
    }

    #[test]
    fn sys_kit_answers_and_warns_of_a_test_build() {
        let dir = sandbox("kit");
        let out = probe(&["sys", "kit"], Some(&dir));
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        let answer = text(&out.stdout);
        assert!(answer.contains("\"test_verbs\":true"));
        assert!(answer.contains("test-verbs feature"));
    }

    #[test]
    fn a_second_call_of_one_identity_while_the_first_runs_is_busy() {
        use std::os::fd::AsRawFd;
        let dir = sandbox("busy");
        let held = std::fs::OpenOptions::new().append(true).create(true).open(dir.join("locks/jan.lock")).unwrap();
        // SAFETY: flock on a descriptor of this test, constant flags.
        assert_eq!(unsafe { libc::flock(held.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }, 0);
        let out = probe(&["test", "echo"], Some(&dir));
        assert_eq!(out.status.code(), Some(75));
        assert!(out.stdout.is_empty());
        assert!(audit(&dir)[0].starts_with("event=busy "));
        drop(held);
        assert_eq!(probe(&["test", "echo"], Some(&dir)).status.code(), Some(0));
    }

    #[test]
    fn the_caller_does_not_choose_the_identity_by_arguments() {
        let dir = sandbox("ident");
        let out = probe(&["test", "echo", "identity=eva"], Some(&dir));
        assert!(text(&out.stdout).contains("\"identity\":\"jan\""));
    }
}
