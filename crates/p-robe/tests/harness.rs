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
