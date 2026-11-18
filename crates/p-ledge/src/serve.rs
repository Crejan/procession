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
use crate::config::Config as Settings;
use crate::dialog::Dialogs;
use crate::error::{Error, Result};
use crate::holder::ChildHolder;
use crate::paths::{Paths, ensure_private_dir, ensure_socket_dir};
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
    let settings = Settings::load(&config.paths.state.join("config.json"))?;
    ensure_socket_dir(&config.paths.sockets, settings.service_group.is_some())?;
    let (record, opened) = Record::open(&config.paths.record(), system_clock())?;
    let holder = ChildHolder::spawn(&config.holder_program, &config.paths.keys())?;
    let shared = Arc::new(Shared::new(Parts {
        holder: Box::new(holder),
        record,
        dialogs: config.dialogs,
        programs_file: config.paths.programs(),
        known_hosts: config.known_hosts,
        state_dir: config.paths.state.clone(),
        work_dir: config.paths.sockets.clone(),
    })?);
    shared.settle_lost();
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
    let service = bind_service_socket(&config.paths, settings.service_group.as_deref())?;
    let for_service = Arc::clone(&shared);
    thread::spawn(move || accept_service(&for_service, &service));
    eprintln!(
        "pledge: serving. SSH agent socket: {path}\npledge: use it with: export SSH_AUTH_SOCK={path}",
        path = config.paths.agent_socket().display()
    );
    let for_control = Arc::clone(&shared);
    thread::spawn(move || accept_control(&for_control, &control_listener));
    accept_agent(&shared, &agent);
    Ok(())
}

/// Binds `service.sock`. Without a group: socket 0600 in a directory 0700.
/// With one: the directory 0710 and the socket 0660, both of that group.
fn bind_service_socket(paths: &Paths, group: Option<&str>) -> Result<UnixListener> {
    let listener = bind_socket(&paths.service_socket())?;
    let Some(group) = group else { return Ok(listener) };
    let name = std::ffi::CString::new(group).map_err(|_| Error::Refused("service_group is not a name".into()))?;
    // SAFETY: `name` is a valid C string; the result is read at once, at startup, on one thread.
    let gid = unsafe { libc::getgrnam(name.as_ptr()).as_ref().map(|entry| entry.gr_gid) }
        .ok_or_else(|| Error::Refused(format!("there is no group {group}")))?;
    for (path, mode) in [(paths.sockets.as_path(), 0o710), (paths.service_socket().as_path(), 0o660)] {
        let c_path =
            std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| Error::Refused("path".into()))?;
        // SAFETY: `c_path` is a valid C string; a uid of -1 (u32::MAX) leaves the owner as it is.
        if unsafe { libc::chown(c_path.as_ptr(), u32::MAX, gid) } != 0 {
            return Err(Error::io(format!("giving {} to the group {group}", path.display()))(
                std::io::Error::last_os_error(),
            ));
        }
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .map_err(Error::io(format!("protecting {}", path.display())))?;
    }
    Ok(listener)
}

fn accept_service(shared: &Arc<Shared>, listener: &UnixListener) {
    for stream in listener.incoming().flatten() {
        // The door is the file mode; who connects is information, not a decision.
        let peer = match peer::peer(&stream) {
            Ok(p) => Some((p.uid, p.pid)),
            Err(e) => {
                eprintln!(
                    "pledge: service socket: could not read the peer's credentials ({e}): the request is handled without them"
                );
                None
            }
        };
        let shared = Arc::clone(shared);
        thread::spawn(move || crate::service_conn::serve(&shared, stream, peer));
    }
}

/// Whether the peer of `socket` is this user. `Err` says why not, for a line on stderr; the peer is
/// told nothing. This is not a record entry: it is not a request, and anything that can connect
/// (only this user can: the directory is 0700) could otherwise fill the record with them.
fn check_peer<S: std::os::unix::io::AsRawFd>(socket: &S, which: &str) -> std::result::Result<peer::Peer, String> {
    match peer::peer(socket) {
        Ok(peer) if peer.uid == own_uid() => Ok(peer),
        Ok(peer) => Err(format!("{which}: a connection from user {} (not this user) was dropped", peer.uid)),
        Err(e) => Err(format!("{which}: could not read the peer's credentials ({e}): the connection was dropped")),
    }
}

/// The peer of `stream` if it is this user; otherwise one line on stderr and `None`.
fn is_own(stream: &UnixStream, which: &str) -> Option<peer::Peer> {
    check_peer(stream, which).map_err(|why| eprintln!("pledge: {why}")).ok()
}

fn accept_agent(shared: &Arc<Shared>, listener: &UnixListener) {
    for stream in listener.incoming().flatten() {
        let Some(peer) = is_own(&stream, "SSH agent socket") else { continue };
        let shared = Arc::clone(shared);
        thread::spawn(move || {
            let program = peer.pid.and_then(peer::program_path);
            agent_conn::serve(&shared, stream, program.as_deref());
        });
    }
}

fn accept_control(shared: &Arc<Shared>, listener: &UnixListener) {
    for stream in listener.incoming().flatten() {
        if is_own(&stream, "control socket").is_none() {
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
    use crate::paths::ensure_socket_dir;
    use crate::testing::TestDir;

    #[test]
    fn a_socket_is_bound_private_and_a_live_one_is_not_replaced() {
        let dir = TestDir::new("serve-bind");
        let path = dir.path().join("agent.sock");
        let listener = bind_socket(&path).expect("bound");
        assert_eq!(fs::metadata(&path).expect("meta").permissions().mode() & 0o777, 0o600);
        assert!(matches!(bind_socket(&path), Err(Error::Locked(_))));
        drop(listener);
        // Closing a socket takes a moment on some systems: a stale one is replaced once it refuses.
        let mut replaced = None;
        for _ in 0..40 {
            match bind_socket(&path) {
                Ok(listener) => {
                    replaced = Some(listener);
                    break;
                }
                Err(Error::Locked(_)) => std::thread::sleep(std::time::Duration::from_millis(50)),
                Err(e) => panic!("{e}"),
            }
        }
        assert!(replaced.is_some(), "a stale socket is replaced");
    }

    fn own_group_name() -> String {
        // SAFETY: getgid has no preconditions; the name is copied at once, on one thread.
        let name = unsafe {
            libc::getgrgid(libc::getgid())
                .as_ref()
                .map(|entry| std::ffi::CStr::from_ptr(entry.gr_name).to_string_lossy().into_owned())
        };
        name.expect("the user's group has a name")
    }

    #[test]
    fn service_sock_is_0600_in_0700_without_a_group_and_0660_in_0710_with_one() {
        let dir = TestDir::new("serve-door");
        let paths = Paths { state: dir.path().join("state"), sockets: dir.path().join("run") };
        ensure_socket_dir(&paths.sockets, false).expect("dir");
        let _plain = bind_service_socket(&paths, None).expect("bound");
        let mode = |path: &Path| fs::metadata(path).expect("meta").permissions().mode() & 0o777;
        assert_eq!((mode(&paths.sockets), mode(&paths.service_socket())), (0o700, 0o600));
        drop(_plain);

        let grouped = Paths { state: dir.path().join("state"), sockets: dir.path().join("run2") };
        ensure_socket_dir(&grouped.sockets, true).expect("dir");
        let _listener = bind_service_socket(&grouped, Some(&own_group_name())).expect("bound with a group");
        assert_eq!((mode(&grouped.sockets), mode(&grouped.service_socket())), (0o710, 0o660));
        ensure_socket_dir(&grouped.sockets, true).expect("0710 is accepted when a group is set (a restart)");
        assert!(ensure_socket_dir(&grouped.sockets, false).is_err(), "and not when none is");
        assert!(matches!(
            bind_service_socket(&grouped, Some("no-such-group-here")),
            Err(Error::Locked(_) | Error::Refused(_))
        ));
    }

    #[test]
    fn a_peer_that_cannot_be_read_is_reported_and_not_accepted() {
        // A regular file is not a socket: asking it for peer credentials fails.
        let dir = TestDir::new("serve-peer");
        let file = fs::File::create(dir.path().join("not-a-socket")).expect("file");
        let why = check_peer(&file, "SSH agent socket").expect_err("not readable");
        assert!(why.starts_with("SSH agent socket: could not read the peer's credentials"), "{why}");
        assert!(why.ends_with("the connection was dropped"), "{why}");
        // A socket pair's peer is this very process: accepted.
        let (a, _b) = UnixStream::pair().expect("pair");
        assert!(check_peer(&a, "control socket").is_ok());
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
