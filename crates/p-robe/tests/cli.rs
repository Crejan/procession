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
fn serve_says_what_is_wrong_with_its_settings() {
    let missing = probe(&["serve", "--config", "/nonexistent/probe.json"], None);
    assert_eq!(missing.status.code(), Some(64));
    assert!(text(&missing.stderr).contains("/nonexistent/probe.json"), "{}", text(&missing.stderr));
    assert_eq!(probe(&["serve", "--bogus"], None).status.code(), Some(64));
    assert_eq!(probe(&["setup", "--bogus"], None).status.code(), Some(64));
    let dir = std::env::temp_dir().join(format!("probe-cli-serve-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("probe.json");
    std::fs::write(&file, r#"{"person":"jan"}"#).unwrap();
    let out = probe(&["serve", "--config", file.to_str().unwrap()], None);
    assert_eq!(out.status.code(), Some(64));
    assert!(text(&out.stderr).contains("missing field `confirmed_key`"), "{}", text(&out.stderr));
    // Writable by others: refused before it is read.
    std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o666)).unwrap();
    let out = probe(&["serve", "--config", file.to_str().unwrap()], None);
    assert_eq!(out.status.code(), Some(64));
    assert!(text(&out.stderr).contains("can be written by someone other than its owner"), "{}", text(&out.stderr));
}

#[test]
fn setup_if_due_is_a_no_op_while_the_certificate_is_fresh_and_by_hand_it_renews_always() {
    let dir = std::env::temp_dir().join(format!("probe-cli-setup-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let host = dir.join("host");
    let made =
        Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-C", "", "-f"]).arg(&host).output().unwrap();
    assert!(made.status.success());
    let out = dir.join("out");
    let setup = |extra: &[&str]| {
        let mut args = vec!["setup"];
        args.extend_from_slice(extra);
        args.extend(["--host-key", host.to_str().unwrap(), "--host", "a.example", "--out", out.to_str().unwrap()]);
        probe(&args, None)
    };
    let first = setup(&["--if-due"]);
    assert_eq!(first.status.code(), Some(0), "{}", text(&first.stderr));
    assert!(text(&first.stdout).starts_with("Due ("), "{}", text(&first.stdout));
    let cert = std::fs::read(out.join("service-key-cert.pub")).unwrap();
    let second = setup(&["--if-due"]);
    assert_eq!(second.status.code(), Some(0));
    assert!(text(&second.stdout).starts_with("Not due: "), "{}", text(&second.stdout));
    assert_eq!(std::fs::read(out.join("service-key-cert.pub")).unwrap(), cert, "nothing was touched");
    // By hand, without the flag: renews always.
    let renewed = setup(&[]);
    assert_eq!(renewed.status.code(), Some(0));
    assert!(text(&renewed.stdout).starts_with("Kept the service's key"), "{}", text(&renewed.stdout));
    assert_ne!(std::fs::read(out.join("service-key-cert.pub")).unwrap(), cert);
    // A failed renewal is a non-zero exit.
    std::fs::remove_file(out.join("service-key-cert.pub")).unwrap();
    let failed = probe(
        &[
            "setup",
            "--if-due",
            "--host-key",
            "/nonexistent/host",
            "--host",
            "a.example",
            "--out",
            out.to_str().unwrap(),
        ],
        None,
    );
    assert_eq!(failed.status.code(), Some(1), "{}", text(&failed.stderr));
    assert_eq!(probe(&["setup", "--if-due", "--bogus"], None).status.code(), Some(64));
    let _ = std::fs::remove_dir_all(&dir);
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

    // -- rating by path, end to end ------------------------------------------

    use std::os::unix::fs::{PermissionsExt, symlink};

    /// A sandbox with `open/` (rated harmless by the test verb) and `private/`.
    fn place(name: &str) -> PathBuf {
        let dir = sandbox(name);
        for sub in ["open", "private"] {
            std::fs::create_dir(dir.join(sub)).unwrap();
            std::fs::set_permissions(dir.join(sub), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(dir.join("open/a"), "hello").unwrap();
        std::fs::write(dir.join("private/s"), "secret").unwrap();
        dir
    }

    fn read(dir: &Path, within: Option<&str>, path: &Path) -> Output {
        let path = path.display().to_string();
        match within {
            Some(rating) => probe(&["--within", rating, "test", "read", &path], Some(dir)),
            None => probe(&["test", "read", &path], Some(dir)),
        }
    }

    fn refused_above(out: &Output) {
        assert_eq!(out.status.code(), Some(64), "{}", text(&out.stderr));
        assert!(out.stdout.is_empty(), "nothing ran");
        assert!(text(&out.stderr).contains("above-approved"), "{}", text(&out.stderr));
    }

    #[test]
    fn a_file_in_the_open_place_runs_at_the_harmless_rating_and_is_read_from_the_open_file() {
        let dir = place("read");
        let out = read(&dir, Some("open,none,none"), &dir.join("open/a"));
        assert_eq!(out.status.code(), Some(0), "{}", text(&out.stderr));
        assert!(text(&out.stdout).contains("\"text\":\"hello\""), "{}", text(&out.stdout));
    }

    #[test]
    fn a_file_elsewhere_is_rated_secret_and_runs_only_if_the_approved_rating_allows() {
        let dir = place("elsewhere");
        let secret = dir.join("private/s");
        refused_above(&read(&dir, Some("open,none,none"), &secret));
        refused_above(&read(&dir, Some("internal,none,none"), &secret));
        assert_eq!(read(&dir, Some("secret,none,none"), &secret).status.code(), Some(0));
        // A person at the dispatcher passes no flag and needs no approval.
        assert_eq!(read(&dir, None, &secret).status.code(), Some(0));
        let log = audit(&dir);
        assert!(log[0].starts_with("event=refused ") && log[0].contains("above-approved"), "{log:?}");
    }

    #[test]
    fn a_link_planted_between_the_approval_and_the_opening_is_refused() {
        let dir = place("planted");
        let link = dir.join("open/link");
        symlink(dir.join("open/a"), &link).unwrap();
        // The service rates the name (harmless) and passes that as --within.
        assert_eq!(read(&dir, Some("open,none,none"), &link).status.code(), Some(0));
        // Before the same call reaches the dispatcher, the link is replaced.
        std::fs::remove_file(&link).unwrap();
        symlink(dir.join("private/s"), &link).unwrap();
        let before = audit(&dir).len();
        refused_above(&read(&dir, Some("open,none,none"), &link));
        let log = audit(&dir);
        assert_eq!(log.len(), before + 1);
        assert!(log.last().unwrap().starts_with("event=refused "));
        assert!(!log.last().unwrap().contains("event=start"));
    }

    #[test]
    fn a_directory_that_others_can_write_keeps_the_worst_rating() {
        let dir = place("loose");
        let loose = dir.join("open/loose");
        std::fs::create_dir(&loose).unwrap();
        std::fs::write(loose.join("f"), "x").unwrap();
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o777)).unwrap();
        refused_above(&read(&dir, Some("open,none,none"), &loose.join("f")));
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(read(&dir, Some("open,none,none"), &loose.join("f")).status.code(), Some(0));
        std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o775)).unwrap();
        refused_above(&read(&dir, Some("open,none,none"), &loose.join("f")));
    }

    #[test]
    fn dot_dot_does_not_get_out_of_the_open_place_unrated() {
        let dir = place("dotdot");
        refused_above(&read(&dir, Some("open,none,none"), &dir.join("open/../private/s")));
    }

    #[test]
    fn a_fifo_a_missing_file_and_a_relative_path() {
        let dir = place("odd");
        let fifo = dir.join("open/fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        let out = read(&dir, Some("secret,none,none"), &fifo);
        assert_eq!(out.status.code(), Some(64));
        assert!(text(&out.stderr).contains("not a regular file"));
        // A file that is not there cannot be rated: the worst, and then the verb fails.
        refused_above(&read(&dir, Some("open,none,none"), &dir.join("open/absent")));
        assert_eq!(read(&dir, Some("secret,none,none"), &dir.join("open/absent")).status.code(), Some(1));
        let out = probe(&["--within", "secret,none,none", "test", "read", "open/a"], Some(&dir));
        assert_eq!(out.status.code(), Some(64));
    }

    #[test]
    fn a_malformed_within_is_refused_and_the_catalogue_shows_the_rule() {
        let dir = place("flag");
        for bad in ["open,none", "OPEN,none,none", "open,none,huge", ""] {
            let out = probe(&["--within", bad, "test", "echo"], Some(&dir));
            assert_eq!(out.status.code(), Some(64), "{bad:?}");
        }
        let out = probe(&["test", "echo", "--within", "open,none,none"], Some(&dir));
        assert_eq!(out.status.code(), Some(64), "an argument may not start with -");
        let catalogue = text(&probe(&["catalog", "--format", "json"], Some(&dir)).stdout);
        assert!(
            catalogue.contains("\"type\":\"param\",\"noun\":\"test\",\"verb\":\"read\",\"name\":\"path\""),
            "{catalogue}"
        );
    }
}
