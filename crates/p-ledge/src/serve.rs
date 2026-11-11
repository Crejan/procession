//! `pledge serve`: the reader process, with its sockets.
//!
//! Starts the key holder as a child, opens the record, binds `agent.sock` and
//! `control.sock` in a directory only the person can enter, and serves them.
//! `service.sock` is step 3.

use std::fs;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use serde_json::json;

use crate::agent::known_hosts::KnownHosts;
use crate::dialog::Dialogs;
use crate::error::{Error, Result};
use crate::holder::ChildHolder;
use crate::paths::{Paths, ensure_private_dir};
use crate::peer::{self, own_uid};
use crate::record::Record;
use crate::shared::{Parts, Shared, system_clock};
use crate::{agent_conn, control};

/// What `pledge serve` needs to start.
pub struct Config {
    /// Where state and sockets are.
    pub paths: Paths,
    /// The program that is started as the key holder (`pledge` itself).
    pub holder_program: PathBuf,
    /// The `known_hosts` files that name verified hosts.
    pub known_hosts: Vec<PathBuf>,
    /// How the person is asked.
    pub dialogs: Arc<dyn Dialogs>,
}

/// The warning printed at start: this form protects nothing.
pub const WARNING: &str = "pledge: development form: the keys are in files under the state directory and a program is \
identified by the path of its process. This protects nothing against anything that runs as your user, \
and a presence check is a question on this terminal.";

/// Binds `path` as a Unix socket, mode 0600, replacing a stale one. A socket
/// that something still listens on is an error.
///
/// # Errors
///
/// [`Error::Io`], or [`Error::Locked`] if another pledge serve answers there.
pub fn bind_socket(path: &Path) -> Result<UnixListener> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() {
            return Err(Error::Unsafe { path: path.to_owned(), problem: "exists and is not a socket" });
        }
        if UnixStream::connect(path).is_ok() {
            return Err(Error::Locked(path.to_owned()));
        }
        fs::remove_file(path).map_err(Error::io(format!("removing the stale {}", path.display())))?;
    }
    let listener = UnixListener::bind(path).map_err(Error::io(format!("binding {}", path.display())))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(Error::io(format!("protecting {}", path.display())))?;
    Ok(listener)
}

/// Runs until killed.
///
/// # Errors
///
/// Whatever stops it from starting: a directory that is not private, a
/// record another pledge serve holds, a key that cannot be loaded.
pub fn run(config: Config) -> Result<()> {
    eprintln!("{WARNING}");
    ensure_private_dir(&config.paths.state)?;
    ensure_private_dir(&config.paths.sockets)?;
    let (record, opened) = Record::open(&config.paths.record(), system_clock())?;
    let holder = ChildHolder::spawn(&config.holder_program, &config.paths.keys())?;
    let shared = Arc::new(Shared::new(Parts {
        holder: Box::new(holder),
        record,
        dialogs: config.dialogs,
        programs_file: config.paths.programs(),
        known_hosts: config.known_hosts,
    })?);
    shared.event("started", json!({"form": "files", "version": env!("CARGO_PKG_VERSION")}));
    if let Some(bytes) = opened.repaired_bytes {
        shared.event("repaired", json!({"dropped_bytes": bytes}));
    }
    if let Some(trimmed) = opened.trimmed {
        shared.event(
            "trimmed",
            json!({"count": trimmed.count, "through_seq": trimmed.through_seq, "through_time": trimmed.through_time}),
        );
    }
    let agent = bind_socket(&config.paths.agent_socket())?;
    let control_listener = bind_socket(&config.paths.control_socket())?;
    eprintln!(
        "pledge: serving. SSH agent socket: {path}\npledge: use it with: export SSH_AUTH_SOCK={path}",
        path = config.paths.agent_socket().display()
    );
    let for_control = Arc::clone(&shared);
    thread::spawn(move || accept_control(&for_control, &control_listener));
    accept_agent(&shared, &agent);
    Ok(())
}

/// Whether the peer of `stream` is this user.
fn is_own(stream: &UnixStream) -> Option<peer::Peer> {
    peer::peer(stream).ok().filter(|peer| peer.uid == own_uid())
}

fn accept_agent(shared: &Arc<Shared>, listener: &UnixListener) {
    for stream in listener.incoming().flatten() {
        let Some(peer) = is_own(&stream) else { continue };
        let shared = Arc::clone(shared);
        thread::spawn(move || {
            let program = peer.pid.and_then(peer::program_path);
            agent_conn::serve(&shared, stream, program.as_deref());
        });
    }
}

fn accept_control(shared: &Arc<Shared>, listener: &UnixListener) {
    for stream in listener.incoming().flatten() {
        if is_own(&stream).is_none() {
            continue;
        }
        let shared = Arc::clone(shared);
        thread::spawn(move || control::serve(&shared, stream));
    }
}

/// The `known_hosts` files of the person running pledge.
#[must_use]
pub fn default_known_hosts() -> Vec<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).map_or_else(Vec::new, |home| KnownHosts::default_paths(&home))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestDir;

    #[test]
    fn a_socket_is_bound_private_and_a_live_one_is_not_replaced() {
        let dir = TestDir::new("serve-bind");
        let path = dir.path().join("agent.sock");
        let listener = bind_socket(&path).expect("bound");
        assert_eq!(fs::metadata(&path).expect("meta").permissions().mode() & 0o777, 0o600);
        assert!(matches!(bind_socket(&path), Err(Error::Locked(_))));
        drop(listener);
        let _again = bind_socket(&path).expect("a stale socket is replaced");
    }

    #[test]
    fn a_file_that_is_not_a_socket_is_left_alone() {
        let dir = TestDir::new("serve-file");
        let path = dir.path().join("agent.sock");
        fs::write(&path, "x").expect("write");
        assert!(matches!(bind_socket(&path), Err(Error::Unsafe { .. })));
        assert!(path.exists());
    }
}
