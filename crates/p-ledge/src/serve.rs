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
use std::time::Duration;

use serde_json::json;

use crate::agent::known_hosts::KnownHosts;
use crate::config::Config as Settings;
use crate::dialog::Dialogs;
use crate::error::{Error, Result};
use crate::holder::ChildHolder;
use crate::paths::{Paths, ensure_private_dir, ensure_socket_dir};
use crate::record::Record;
use crate::shared::{Parts, Shared, system_clock};
use crate::{agent_conn, control};
use p_act::peer::{Peer, Policy, Throttle};

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
    if let Some(broker) = settings.broker.as_ref() {
        start_broker_link(&shared, broker)?;
    }
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

/// Starts the connection to the broker, in stage 2 (a `broker` member in `config.json`).
fn start_broker_link(shared: &Arc<Shared>, broker: &crate::config::BrokerEntry) -> Result<()> {
    use crate::broker_link::{self, SessionConfig, TlsTransport};
    let person =
        shared.approvals.config.person.clone().ok_or_else(|| {
            Error::Refused("a broker is configured but no person is: set `person` in config.json".into())
        })?;
    if shared.key_with_purpose("connection").is_none() {
        return Err(Error::Refused("a broker is configured but there is no connection key: run `pledge keys create connection` and give its public part to an administrator".into()));
    }
    let site_ca = p_act::sign::PublicKey::parse(&broker.site_ca).map_err(|e| Error::Refused(e.to_string()))?;
    let tls = broker_link::client_config(&broker.tls_root).map_err(Error::Refused)?;
    let name = rustls::pki_types::ServerName::try_from(broker.name().to_owned())
        .map_err(|e| Error::Refused(format!("broker.server_name: {e}")))?;
    let address = broker.address.clone();
    let connect = Box::new(move || -> std::io::Result<Box<dyn broker_link::DynTransport>> {
        use std::net::ToSocketAddrs as _;
        let mut last = std::io::Error::other("the broker's address has no address");
        for candidate in address.to_socket_addrs()? {
            match std::net::TcpStream::connect_timeout(&candidate, std::time::Duration::from_secs(10)) {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    let transport = TlsTransport::connect(
                        Arc::clone(&tls),
                        name.clone(),
                        stream,
                        std::time::Duration::from_secs(10),
                    )?;
                    return Ok(Box::new(transport));
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    });
    let link = broker_link::start(shared, SessionConfig { person, site_ca }, connect);
    let _ = shared.link.set(link);
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

/// At most one such line per ten seconds per socket.
pub const LOG_INTERVAL: Duration = p_act::peer::LOG_INTERVAL;

/// The throttle of one socket: lines for dropped connections start with `pledge: `. Not the record.
fn throttle() -> Throttle {
    Throttle::new("pledge", LOG_INTERVAL)
}

fn to_stderr(line: &str) {
    eprintln!("{line}");
}

/// The peer of `socket` if it may connect under `policy`; otherwise one (throttled) line on stderr and
/// `None`, and the peer is told nothing. This is not a record entry: it is not a request, and anything that
/// can connect could otherwise fill the record with them.
fn admitted<S: std::os::unix::io::AsRawFd>(
    socket: &S,
    policy: &Policy<'_>,
    which: &str,
    throttle: &mut Throttle,
) -> Option<Peer> {
    p_act::peer::accept(socket, policy, which, throttle, &mut to_stderr)
}

/// `service.sock`: who connects is the file mode's business (a service may run under another account),
/// but a connection whose peer credentials cannot be read is dropped, as on the other two sockets: no
/// request is handled for it and the peer is told nothing (the connection just ends).
fn accept_service(shared: &Arc<Shared>, listener: &UnixListener) {
    let mut throttle = throttle();
    for stream in listener.incoming().flatten() {
        let Some(peer) = admitted(&stream, &Policy::AnyReadable, "service socket", &mut throttle) else { continue };
        let shared = Arc::clone(shared);
        thread::spawn(move || crate::service_conn::serve(&shared, stream, Some(crate::peer::Seen::of(&peer))));
    }
}

fn accept_agent(shared: &Arc<Shared>, listener: &UnixListener) {
    let mut throttle = throttle();
    for stream in listener.incoming().flatten() {
        let Some(peer) = admitted(&stream, &Policy::OwnUser, "SSH agent socket", &mut throttle) else { continue };
        let shared = Arc::clone(shared);
        thread::spawn(move || agent_conn::serve(&shared, stream, peer.program()));
    }
}

fn accept_control(shared: &Arc<Shared>, listener: &UnixListener) {
    let mut throttle = throttle();
    for stream in listener.incoming().flatten() {
        if admitted(&stream, &Policy::OwnUser, "control socket", &mut throttle).is_none() {
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
    use p_act::peer::own_uid;

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
    fn service_sock_drops_a_connection_whose_peer_cannot_be_read_and_takes_any_other_user_that_can() {
        let dir = TestDir::new("serve-service-peer");
        let file = fs::File::create(dir.path().join("not-a-socket")).expect("file");
        let mut throttle = throttle();
        assert!(
            admitted(&file, &Policy::AnyReadable, "service socket", &mut throttle).is_none(),
            "no request is handled"
        );
        let (a, _b) = UnixStream::pair().expect("pair");
        let peer =
            admitted(&a, &Policy::AnyReadable, "service socket", &mut throttle).expect("a readable peer is taken");
        assert_eq!(
            peer.uid(),
            own_uid(),
            "a service under another account would be taken too: the door is the file mode"
        );
    }

    #[test]
    fn a_peer_that_cannot_be_read_is_reported_and_not_accepted() {
        // A regular file is not a socket: asking it for peer credentials fails.
        let dir = TestDir::new("serve-peer");
        let file = fs::File::create(dir.path().join("not-a-socket")).expect("file");
        let why = p_act::peer::admit(&file, &Policy::OwnUser).expect_err("not readable").message("SSH agent socket");
        assert!(why.starts_with("SSH agent socket: could not read the peer's credentials"), "{why}");
        assert!(why.ends_with("the connection was dropped"), "{why}");
        // A socket pair's peer is this very process: accepted.
        let (a, _b) = UnixStream::pair().expect("pair");
        assert!(p_act::peer::admit(&a, &Policy::OwnUser).is_ok());
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
