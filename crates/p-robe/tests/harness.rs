//! The harness's own failure message: when `pledge serve` does not come up, the panic carries everything it
//! wrote and how it ended (the owner's first Linux run ended with "agent.sock does not answer" and nothing else).
#![allow(unused_imports)]

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;

use common::*;

#[test]
#[should_panic(expected = "can be written by someone other than its owner")]
fn a_pledge_that_does_not_start_is_heard_in_the_panic() {
    let dir = dir_for("harness");
    let (state, sockets) = (dir.join("state"), dir.join("run"));
    fs::create_dir_all(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    // A configuration that others can write: pledge refuses it, before it binds a socket.
    fs::write(state.join("config.json"), "{}").unwrap();
    fs::set_permissions(state.join("config.json"), fs::Permissions::from_mode(0o666)).unwrap();
    let _ = Pledge::spawn(&pledge_binary(), &dir, &state, &sockets);
}

#[test]
fn the_message_says_how_the_process_ended_and_what_it_wrote() {
    let dir = dir_for("harness-message");
    let (state, sockets) = (dir.join("state"), dir.join("run"));
    fs::create_dir_all(&state).unwrap();
    fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
    fs::write(state.join("config.json"), "{}").unwrap();
    fs::set_permissions(state.join("config.json"), fs::Permissions::from_mode(0o666)).unwrap();
    let panic = std::panic::catch_unwind(|| Pledge::spawn(&pledge_binary(), &dir, &state, &sockets)).unwrap_err();
    let text = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(text.contains("the process: exited:"), "{text}");
    assert!(text.contains("what it wrote (") && text.contains("err: pledge:"), "{text}");
    assert!(text.contains("agent.sock does not answer"), "{text}");
}

// ---- the umask ---------------------------------------------------------------------------------------------

/// Run only by the test below, in a child process whose umask is 0002 (the umask of an account with a group of
/// its own name, Debian's default, which is what the owner's container had): the harness starts pledge, which
/// refuses a configuration that its group could write.
#[test]
#[ignore = "run by the test below in a child process with umask 0002"]
fn child_starts_pledge_under_umask_002() {
    if std::env::var("HARNESS_UMASK_CHILD").as_deref() != Ok("1") {
        return;
    }
    // SAFETY: umask has no preconditions; this process is the child made for it.
    let before = unsafe { libc::umask(0o002) };
    assert_eq!(before, 0o002, "the child was not started with umask 0002");
    let dir = dir_for("umask");
    keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", dir.join("host").to_str().unwrap()]);
    // Directories made here follow the umask (0775): the harness must not lean on it for anything pledge judges.
    let mut pledge = Pledge::start(&dir);
    assert_eq!(fs::metadata(pledge.state.join("config.json")).unwrap().permissions().mode() & 0o777, 0o600);
    pledge.answer("y\n");
    let _ = pledge.ok(&["keys", "create", "delegation"]);
}

#[test]
fn the_harness_starts_pledge_under_a_umask_of_0002() {
    use std::os::unix::process::CommandExt;
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", "child_starts_pledge_under_umask_002", "--ignored", "--nocapture", "--test-threads=1"])
        .env("HARNESS_UMASK_CHILD", "1");
    // SAFETY: only `umask`, which is async-signal-safe, runs between fork and exec.
    unsafe {
        command.pre_exec(|| {
            libc::umask(0o002);
            Ok(())
        });
    }
    let out = command.output().unwrap();
    assert!(
        out.status.success(),
        "under umask 0002: {}\n{}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed"), "{}", String::from_utf8_lossy(&out.stdout));
}

#[test]
fn a_binary_built_from_another_commit_than_the_one_expected_is_refused() {
    assert_eq!(build_matches(Some("abc123"), Some("abc123")), Ok(()));
    assert_eq!(build_matches(Some("abc123"), None), Ok(()), "no expectation: nothing to compare");
    assert_eq!(build_matches(None, None), Ok(()));
    let stale = build_matches(Some("967b64c"), Some("2a38839")).unwrap_err();
    assert!(stale.contains("stale") && stale.contains("967b64c") && stale.contains("2a38839"), "{stale}");
    // A binary that was built without saying what from cannot be shown to be the right one.
    assert!(build_matches(None, Some("2a38839")).unwrap_err().contains("unknown commit"));
    assert!(build_matches(Some("2a38839-dirty"), Some("2a38839")).is_err(), "a dirty tree is not the commit");
}

#[test]
fn a_program_named_by_the_run_is_taken_as_given_and_only_if_it_is_there() {
    let dir = dir_for("named");
    let (named, classic) = (dir.join("named"), dir.join("classic"));
    fs::write(&named, "").unwrap();
    let said = |given: Option<&std::path::Path>, classic: &std::path::Path| {
        resolve_binary(given.map(|p| p.as_os_str().to_owned()), classic.to_path_buf(), "PROBE_X_BIN")
    };
    // What the run named wins, even where the classic place has another file.
    fs::write(&classic, "").unwrap();
    assert_eq!(said(Some(&named), &classic), Ok(named.clone()));
    // Without a name: the classic place, if it is there; if not, words that say what to do.
    assert_eq!(said(None, &classic), Ok(classic.clone()));
    let why = said(None, &dir.join("absent")).unwrap_err();
    assert!(why.contains("PROBE_X_BIN") && why.contains("cargo build"), "{why}");
    // A name that is not a file is not quietly replaced by the classic place.
    assert!(said(Some(&dir.join("nothing")), &classic).unwrap_err().contains("not a file"));
}

#[test]
fn the_default_place_of_a_workspace_program_is_the_directory_of_probe_not_the_place_of_this_test() {
    // `pledge` is built (the stage-1 tests need it too); where this test executable is does not matter.
    let found = workspace_binary("PROBE_TEST_NOT_SET_ANYWHERE", "pledge");
    let probe = std::path::Path::new(env!("CARGO_BIN_EXE_probe"));
    assert_eq!(found, probe.parent().unwrap().join("pledge"));
    assert!(!found.starts_with(std::env::current_exe().unwrap().parent().unwrap()) || found.parent() == probe.parent());
}

#[test]
fn a_build_in_a_checkout_says_which_commit_without_being_told() {
    let built = BUILT_FROM.expect("build.rs sets it");
    let in_git = std::process::Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .is_ok_and(|o| o.status.success());
    if in_git {
        assert!(built != "unknown" && built.len() >= 12, "{built}");
    }
    assert!(!built.contains(char::is_whitespace));
}
