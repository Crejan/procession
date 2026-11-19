//! The administrator's verbs and how they reach the running broker
//! (`proposals/admin-socket.md`): a Unix socket `admin.sock` in the state
//! directory, one JSON line in, one JSON line out.
//!
//! The rules of the register (a restricting command is in force at once and
//! says whether it is stored; a permitting one is refused while the register
//! cannot be written) live in the running broker, which is why the verbs are
//! its clients and never edit `register.json` themselves.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream as StdStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crate::register::Actor;
use p_act::peer::{self, Throttle};
use p_act::sign::Fingerprint;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};

use crate::core::{BrokerCertificateStatus, CertificateStatus, Status, Stored};
use crate::net::{Broker, Lines};
use crate::site::valid_name;

/// The socket's name in the state directory.
pub const SOCKET_NAME: &str = "admin.sock";
/// A command is at most this long.
const MAX_COMMAND_BYTES: usize = 4096;
/// A command must arrive, and an answer must be read, within this long.
const WAIT: Duration = Duration::from_secs(10);

/// What a command is about: a person or one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Person(String),
    Key(Fingerprint),
}

/// A command to the running broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Status,
    Block(Target),
    Unblock(Target),
    Withdraw(Fingerprint),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommandWire {
    schema_version: u32,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    person: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delegation: Option<String>,
}

impl Command {
    /// The line to write, with its `\n`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut wire =
            CommandWire { schema_version: 1, kind: String::new(), person: None, key: None, delegation: None };
        let target = |wire: &mut CommandWire, t: &Target| match t {
            Target::Person(p) => wire.person = Some(p.clone()),
            Target::Key(k) => wire.key = Some(k.to_string()),
        };
        match self {
            Command::Status => "status".clone_into(&mut wire.kind),
            Command::Block(t) => {
                "block".clone_into(&mut wire.kind);
                target(&mut wire, t);
            }
            Command::Unblock(t) => {
                "unblock".clone_into(&mut wire.kind);
                target(&mut wire, t);
            }
            Command::Withdraw(fp) => {
                "withdraw".clone_into(&mut wire.kind);
                wire.delegation = Some(fp.to_string());
            }
        }
        let mut line = serde_json::to_vec(&wire).unwrap_or_default();
        line.push(b'\n');
        line
    }

    /// Read a command line. `None` for anything that is not exactly one command.
    #[must_use]
    pub fn parse(line: &[u8]) -> Option<Command> {
        let wire: CommandWire = serde_json::from_slice(line).ok()?;
        if wire.schema_version != 1 {
            return None;
        }
        let target = |wire: &CommandWire| match (&wire.person, &wire.key, &wire.delegation) {
            (Some(p), None, None) if valid_name(p) => Some(Target::Person(p.clone())),
            (None, Some(k), None) => k.parse().ok().map(Target::Key),
            _ => None,
        };
        match wire.kind.as_str() {
            "status" if wire.person.is_none() && wire.key.is_none() && wire.delegation.is_none() => {
                Some(Command::Status)
            }
            "block" => target(&wire).map(Command::Block),
            "unblock" => target(&wire).map(Command::Unblock),
            "withdraw" => match (&wire.person, &wire.key, &wire.delegation) {
                (None, None, Some(d)) => d.parse().ok().map(Command::Withdraw),
                _ => None,
            },
            _ => None,
        }
    }
}

/// Why a command was refused. A closed list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    UnknownPerson,
    UnknownKey,
    UnknownDelegation,
    /// A permitting command while the register cannot be written.
    Unavailable,
    /// The command is not understood.
    Malformed,
}

impl Refusal {
    #[must_use]
    pub fn wire(self) -> &'static str {
        match self {
            Refusal::UnknownPerson => "unknown-person",
            Refusal::UnknownKey => "unknown-key",
            Refusal::UnknownDelegation => "unknown-delegation",
            Refusal::Unavailable => "unavailable",
            Refusal::Malformed => "malformed",
        }
    }

    fn from_wire(word: &str) -> Option<Refusal> {
        [
            Refusal::UnknownPerson,
            Refusal::UnknownKey,
            Refusal::UnknownDelegation,
            Refusal::Unavailable,
            Refusal::Malformed,
        ]
        .into_iter()
        .find(|r| r.wire() == word)
    }
}

/// The reasons the register could not be written; a closed list. Anything else is read as `io`.
const WHY: [&str; 4] = ["permission-denied", "read-only", "no-space", "io"];

/// The reasons the broker's certificate may be not valid; a closed list. Anything else is read as `refused`.
fn known_failure(word: &str) -> &'static str {
    ["missing", "not-yet-valid", "expired", "refused"].into_iter().find(|w| *w == word).unwrap_or("refused")
}

fn known_why(word: &str) -> &'static str {
    WHY.into_iter().find(|w| *w == word).unwrap_or("io")
}

/// The broker's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    /// A restricting command is in force. `Err(why)` when it is not stored.
    Done(Result<(), &'static str>),
    /// Nothing was done. `why` accompanies `Unavailable`.
    Refused(Refusal, Option<&'static str>),
    Status(Box<Status>),
}

#[derive(Debug, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct ReplyWire {
    schema_version: u32,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    stored: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    why: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    degraded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pledges: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    held: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    delegations: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    withdrawn: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blocked_persons: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blocked_keys: Option<Vec<String>>,
    /// The certificate input, present only if one is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    certificates_carried: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    certificates_not_carried: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    certificates_directory_refused: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    uncovered: Option<Vec<String>>,
    /// The broker's own certificate, present only if it is checked.
    /// Why `ssh-keygen` cannot be used, when it cannot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    keygen_unusable: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    administrators_group: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    administrators_gid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    broker_certificate_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    broker_certificate_valid: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    broker_certificate_days: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    broker_certificate_failure: Option<String>,
}

impl Reply {
    /// The line to write, with its `\n`.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut w = ReplyWire { schema_version: 1, ..ReplyWire::default() };
        match self {
            Reply::Done(stored) => {
                "done".clone_into(&mut w.kind);
                w.stored = Some(stored.is_ok());
                w.why = stored.err().map(str::to_owned);
            }
            Reply::Refused(reason, why) => {
                "refused".clone_into(&mut w.kind);
                w.reason = Some(reason.wire().to_owned());
                w.why = why.map(str::to_owned);
            }
            Reply::Status(s) => {
                "status".clone_into(&mut w.kind);
                w.degraded = Some(s.degraded.is_some());
                w.why = s.degraded.map(str::to_owned);
                (w.pledges, w.held, w.delegations, w.withdrawn) =
                    (Some(s.pledges), Some(s.held), Some(s.delegations), Some(s.withdrawn));
                (w.blocked_persons, w.blocked_keys) = (Some(s.blocked_persons.clone()), Some(s.blocked_keys.clone()));
                w.keygen_unusable = s.keygen_unusable.clone();
                w.administrators_group = s.administrators.as_ref().map(|g| g.name.clone());
                w.administrators_gid = s.administrators.as_ref().map(|g| g.gid);
                let b = &s.broker_certificate;
                w.broker_certificate_path = Some(b.path.clone());
                w.broker_certificate_valid = Some(b.valid);
                w.broker_certificate_days = b.days_left;
                w.broker_certificate_failure = b.failure.map(str::to_owned);
                if let Some(c) = &s.certificates {
                    w.certificates_carried = Some(c.carried);
                    w.certificates_not_carried = Some(c.not_carried);
                    w.certificates_directory_refused = Some(c.directory_refused);
                    w.uncovered = Some(c.uncovered.clone());
                }
            }
        }
        let mut line = serde_json::to_vec(&w).unwrap_or_default();
        line.push(b'\n');
        line
    }

    /// Read an answer line. `None` for anything that is not exactly one answer.
    #[must_use]
    pub fn parse(line: &[u8]) -> Option<Reply> {
        let w: ReplyWire = serde_json::from_slice(line).ok()?;
        if w.schema_version != 1 {
            return None;
        }
        match w.kind.as_str() {
            "done" => {
                Some(Reply::Done(if w.stored? { Ok(()) } else { Err(known_why(w.why.as_deref().unwrap_or("io"))) }))
            }
            "refused" => {
                let reason = Refusal::from_wire(&w.reason?)?;
                Some(Reply::Refused(reason, w.why.as_deref().map(known_why)))
            }
            "status" => {
                // What the socket sends is read as strictly as everything else: a list that breaks the rule is not
                // printed, the answer is refused whole (the verb says it got no answer).
                let clean = |l: &Option<Vec<String>>| l.iter().flatten().all(|x| crate::util::is_clean(x));
                let names = w.blocked_persons.iter().flatten().all(|n| crate::site::valid_name(n));
                let keys = w.blocked_keys.iter().flatten().all(|k| k.parse::<Fingerprint>().is_ok());
                let texts = [
                    &w.keygen_unusable,
                    &w.administrators_group,
                    &w.broker_certificate_path,
                    &w.broker_certificate_failure,
                ]
                .iter()
                .all(|t| t.as_deref().is_none_or(crate::util::is_clean));
                if !(names && keys && clean(&w.uncovered) && texts) {
                    return None;
                }
                Some(Reply::Status(Box::new(Status {
                    degraded: if w.degraded? { Some(known_why(w.why.as_deref().unwrap_or("io"))) } else { None },
                    pledges: w.pledges?,
                    held: w.held?,
                    delegations: w.delegations?,
                    withdrawn: w.withdrawn?,
                    blocked_persons: w.blocked_persons?,
                    blocked_keys: w.blocked_keys?,
                    keygen_unusable: w.keygen_unusable,
                    administrators: match (w.administrators_group, w.administrators_gid) {
                        (Some(name), Some(gid)) => Some(AdminGroup { name, gid }),
                        (None, None) => None,
                        _ => return None,
                    },
                    broker_certificate: BrokerCertificateStatus {
                        path: w.broker_certificate_path?,
                        valid: w.broker_certificate_valid?,
                        days_left: w.broker_certificate_days,
                        failure: w.broker_certificate_failure.as_deref().map(known_failure),
                    },
                    certificates: match w.certificates_carried {
                        None => None,
                        Some(carried) => Some(CertificateStatus {
                            carried,
                            not_carried: w.certificates_not_carried?,
                            directory_refused: w.certificates_directory_refused?,
                            uncovered: w.uncovered?,
                        }),
                    },
                })))
            }
            _ => None,
        }
    }
}

fn done(stored: Stored) -> Reply {
    Reply::Done(match stored {
        Stored::Yes => Ok(()),
        Stored::No(e) => Err(e.code),
    })
}

/// Carry out one command on the running broker, for a caller that is this process's own user (a test's, or the
/// broker's own).
pub async fn execute(broker: &Arc<Broker>, command: Command) -> Reply {
    execute_as(broker, command, p_act::peer::own_uid()).await
}

/// Carry out one command for the administrator whose user id the peer lookup read. A block or a withdrawal records
/// that uid and nothing else about the caller (not `SUDO_USER`, nothing the caller could set); through `sudo` it is
/// 0. The account's name is looked up **after** the answer is made, on a thread of its own, and added if it comes.
pub async fn execute_as(broker: &Arc<Broker>, command: Command, uid: u32) -> Reply {
    let by = || Actor::Administrator { uid, account: None };
    let records = matches!(command, Command::Block(_) | Command::Withdraw(_));
    let reply = execute_command(broker, command, by).await;
    if records && matches!(reply, Reply::Done(_)) {
        broker.name_administrator_later(uid);
    }
    reply
}

async fn execute_command(broker: &Arc<Broker>, command: Command, by: impl Fn() -> Actor) -> Reply {
    let refused = |r| Reply::Refused(r, None);
    match command {
        Command::Status => match broker.with_core(|c, now| (c.status(now), Vec::new())).await {
            Some(status) => Reply::Status(Box::new(status)),
            None => refused(Refusal::Malformed),
        },
        Command::Block(Target::Person(p)) => {
            let name = p.clone();
            if !broker.with_core(move |c, _| (c.knows_person(&name), Vec::new())).await.unwrap_or(false) {
                return refused(Refusal::UnknownPerson);
            }
            done(broker.block_person(p, by()).await)
        }
        Command::Block(Target::Key(k)) => {
            let fp = k.to_string();
            if !broker.with_core(move |c, _| (c.knows_key(&fp), Vec::new())).await.unwrap_or(false) {
                return refused(Refusal::UnknownKey);
            }
            done(broker.block_key(k.to_string(), by()).await)
        }
        Command::Unblock(Target::Person(p)) => {
            let name = p.clone();
            let known = broker.with_core(move |c, _| (c.knows_person(&name) || c.signin_blocked(&name), Vec::new()));
            if !known.await.unwrap_or(false) {
                return refused(Refusal::UnknownPerson);
            }
            match broker.unblock_person(p).await {
                Ok(()) => Reply::Done(Ok(())),
                Err(e) => Reply::Refused(Refusal::Unavailable, Some(e.code)),
            }
        }
        Command::Unblock(Target::Key(k)) => {
            let fp = k.to_string();
            let known = broker.with_core(move |c, _| (c.knows_key(&fp) || c.key_is_blocked(&fp), Vec::new()));
            if !known.await.unwrap_or(false) {
                return refused(Refusal::UnknownKey);
            }
            match broker.unblock_key(k.to_string()).await {
                Ok(()) => Reply::Done(Ok(())),
                Err(e) => Reply::Refused(Refusal::Unavailable, Some(e.code)),
            }
        }
        Command::Withdraw(d) => {
            let fp = d.to_string();
            if !broker.with_core(move |c, _| (c.knows_delegation(&fp), Vec::new())).await.unwrap_or(false) {
                return refused(Refusal::UnknownDelegation);
            }
            done(broker.admin_withdraw(d, by()).await)
        }
    }
}

/// Why the socket could not be made.
#[derive(Debug, Error)]
pub enum BindError {
    #[error("another broker answers on {0}")]
    InUse(String),
    #[error("cannot make {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("{0}")]
    Group(String),
}

/// The group whose members may use `admin.sock` besides root: the config member `administrators_group`, resolved to
/// a gid once, at start. **Who is in the group is the operating system's matter**; the broker reads membership from
/// the kernel, per connection, and never from the name service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminGroup {
    pub name: String,
    pub gid: u32,
}

/// Why `administrators_group` cannot be used: the start is refused, naming the member.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GroupError {
    #[error("`administrators_group`: not supported here (the kernel's list of a peer's groups is read on Linux only)")]
    Unsupported,
    #[error("`administrators_group`: not a group name")]
    BadName,
    #[error("`administrators_group`: the group could not be looked up: {0}")]
    Lookup(String),
    #[error("`administrators_group`: there is no such group")]
    Unknown,
    #[error("`administrators_group`: it is group 0, which is root's")]
    Root,
    #[error(
        "`administrators_group`: it is the broker's own primary group, which would admit every process of its user"
    )]
    OwnPrimary,
}

/// Resolve the member to a gid, with the lookups given (so that every refusal is testable anywhere).
pub fn resolve_group_with(
    name: &str,
    supported: bool,
    lookup: impl FnOnce(&str) -> Result<Option<u32>, String>,
    own_gid: u32,
) -> Result<AdminGroup, GroupError> {
    if !supported {
        return Err(GroupError::Unsupported);
    }
    if name.is_empty() || name.chars().count() > 256 || !crate::util::is_clean(name) {
        return Err(GroupError::BadName);
    }
    let gid = lookup(name).map_err(GroupError::Lookup)?.ok_or(GroupError::Unknown)?;
    if gid == 0 {
        return Err(GroupError::Root);
    }
    if gid == own_gid {
        return Err(GroupError::OwnPrimary);
    }
    Ok(AdminGroup { name: name.to_owned(), gid })
}

/// Resolve `administrators_group` with the system's lookups (start only: the lookup may block).
pub fn resolve_group(name: &str) -> Result<AdminGroup, GroupError> {
    resolve_group_with(
        name,
        peer::groups_supported(),
        |n| peer::group_id(n).map_err(|e| e.to_string()),
        peer::own_gid(),
    )
}

/// The rule when no administrators' group is configured: the user the broker runs as, or root.
pub const POLICY: peer::Policy<'static> = peer::Policy::OwnUserOrRoot;

/// What `page` says on standard error when it runs as root while an administrators' group is configured: the
/// register will say uid 0 and not who it was.
pub const ROOT_NOTICE: &str = "page: recorded as root; run without sudo to be recorded by name";

/// Whether `page` run by user `uid` says [`ROOT_NOTICE`].
#[must_use]
pub fn recorded_as_root(group_configured: bool, uid: u32) -> bool {
    group_configured && uid == 0
}

/// Whether a peer may use the socket, from what the kernel said of it. Without a group: root and the broker's own
/// user. With one: root, or a member of the group by primary group or by supplementary groups; **the broker's own
/// user is refused** although it is in the group. `supplementary` is read only when it is needed, and an error from it
/// is a refusal, never an admission.
pub fn admits<E>(
    group: Option<&AdminGroup>,
    (uid, gid): (u32, u32),
    own_uid: u32,
    supplementary: impl FnOnce() -> Result<Vec<u32>, E>,
) -> bool {
    match group {
        None => uid == 0 || uid == own_uid,
        Some(_) if uid == 0 => true,
        Some(_) if uid == own_uid => false,
        Some(g) => gid == g.gid || supplementary().is_ok_and(|groups| groups.contains(&g.gid)),
    }
}

/// Make `admin.sock` in `state_dir`: 0600 set explicitly after `bind`, whatever the umask. A socket that is
/// there is removed only if nothing answers on it.
pub fn bind(state_dir: &Path) -> Result<UnixListener, BindError> {
    bind_for(state_dir, None)
}

/// As [`bind`]. With an administrators' group the directory is given to it for traversal (group, 0710) and the
/// socket is group `gid` mode 0660, each **checked afterwards**; a broker that cannot do that does not start. The
/// umask is 077 while the socket is made, so it is never open for an instant.
pub fn bind_for(state_dir: &Path, group: Option<&AdminGroup>) -> Result<UnixListener, BindError> {
    let path = state_dir.join(SOCKET_NAME);
    let shown = path.display().to_string();
    let io = |source| BindError::Io { path: shown.clone(), source };
    if path.exists() {
        if StdStream::connect(&path).is_ok() {
            return Err(BindError::InUse(shown));
        }
        std::fs::remove_file(&path).map_err(io)?;
    }
    let listener = UnixListener::bind(&path).map_err(io)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).map_err(io)?;
    if let Some(g) = group {
        crate::perm::open_socket_to_group(&path, g.gid)
            .and_then(|()| crate::perm::open_dir_to_group(state_dir, g.gid))
            .map_err(|e| BindError::Group(e.to_string()))?;
    }
    Ok(listener)
}

/// The admitted peer's user id, or `None` and one throttled line. Read or drop: credentials that cannot be read, a
/// user the rule refuses, and groups that cannot be read are all a dropped connection, told nothing.
pub fn admitted_uid_for<S: AsRawFd>(
    socket: &S,
    group: Option<&AdminGroup>,
    throttle: &mut Throttle,
    sink: &mut dyn FnMut(&str),
) -> Option<u32> {
    let drop_with = |throttle: &mut Throttle, text: String, sink: &mut dyn FnMut(&str)| {
        throttle.report(&text, sink);
        None
    };
    let peer = match peer::Peer::read_credentials(socket) {
        Ok(p) => p,
        Err(e) => {
            return drop_with(
                throttle,
                format!("admin socket: could not read the peer's credentials ({e}): dropped"),
                sink,
            );
        }
    };
    if admits(group, (peer.uid(), peer.gid()), peer::own_uid(), || peer::peer_groups(socket)) {
        Some(peer.uid())
    } else {
        drop_with(throttle, format!("admin socket: a connection from user {} was dropped", peer.uid()), sink)
    }
}

/// Whether to serve this peer under the broker's own rule (root and the broker's user): the credentials are read
/// and checked; anyone else is dropped and told nothing; the refusal is one throttled line on `sink`.
pub fn admit_peer<S: AsRawFd>(socket: &S, throttle: &mut Throttle, sink: &mut dyn FnMut(&str)) -> bool {
    admitted_uid_for(socket, None, throttle, sink).is_some()
}

/// Serve commands for ever.
pub async fn serve(listener: UnixListener, broker: Arc<Broker>) {
    let mut throttle = Throttle::new("page", peer::LOG_INTERVAL);
    let group = broker.administrators();
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let Some(uid) = admitted_uid_for(&stream, group.as_ref(), &mut throttle, &mut |line| eprintln!("{line}"))
        else {
            continue;
        };
        let broker = Arc::clone(&broker);
        tokio::spawn(serve_one(stream, broker, uid));
    }
}

/// One command, one answer, and the end.
pub async fn serve_one(stream: UnixStream, broker: Arc<Broker>, uid: u32) {
    let (rd, mut wr) = tokio::io::split(stream);
    let mut lines = Lines::with_limit(rd, WAIT, MAX_COMMAND_BYTES);
    let reply = match lines.read(Some(WAIT)).await {
        Ok(Some(line)) => match Command::parse(&line) {
            Some(command) => execute_as(&broker, command, uid).await,
            None => Reply::Refused(Refusal::Malformed, None),
        },
        _ => return,
    };
    let _ = wr.write_all(&reply.encode()).await;
    let _ = wr.shutdown().await;
}

// ---------------------------------------------------------------------------
// The verbs, as clients
// ---------------------------------------------------------------------------

/// Why a command could not be put to the broker.
#[derive(Debug, Error)]
pub enum ClientError {
    #[error("no broker answers at {0}")]
    NoBroker(String),
    #[error("the broker's answer was not understood")]
    BadAnswer,
}

/// Put a command to the broker whose socket is `socket`, and read its answer.
pub fn ask(socket: &Path, command: &Command) -> Result<Reply, ClientError> {
    let shown = socket.display().to_string();
    let mut stream = StdStream::connect(socket).map_err(|_| ClientError::NoBroker(shown.clone()))?;
    stream.set_read_timeout(Some(WAIT)).map_err(|_| ClientError::NoBroker(shown.clone()))?;
    stream.write_all(&command.encode()).map_err(|_| ClientError::NoBroker(shown))?;
    let mut line = Vec::new();
    BufReader::new(stream.take(64 * 1024)).read_until(b'\n', &mut line).map_err(|_| ClientError::BadAnswer)?;
    if line.pop() != Some(b'\n') {
        return Err(ClientError::BadAnswer);
    }
    Reply::parse(&line).ok_or(ClientError::BadAnswer)
}

/// Where the socket is, for a state directory.
#[must_use]
pub fn socket_path(state_dir: &Path) -> PathBuf {
    state_dir.join(SOCKET_NAME)
}

/// The exit codes of the verbs, one meaning each (`SPEC.md`).
pub const EXIT_TABLE: &str = "exit codes:\n  0  done (and stored, where something is stored)\n  1  refused\n  2  usage\n  3  no broker answers\n  4  in force but NOT stored (block, withdraw)\n  5  the broker is degraded (`status` only)\n  6  an enabled person has no valid certificate for a purpose (`status` only)\n  7  the broker has no valid certificate of its own: it issues no clearances (`status` only)\nThe exit code of `status` is the gravest condition that holds, in the order 7, 5, 6; its lines are the complete list\nof the conditions that hold (`status --format json` gives the same list as an array).";

/// Done.
pub const EXIT_DONE: u8 = 0;
/// Refused.
pub const EXIT_REFUSED: u8 = 1;
/// Usage.
pub const EXIT_USAGE: u8 = 2;
/// No broker answers.
pub const EXIT_NO_BROKER: u8 = 3;
/// In force, but not stored.
pub const EXIT_NOT_STORED: u8 = 4;
/// The broker is degraded; only `status` returns it.
pub const EXIT_DEGRADED: u8 = 5;
/// An enabled person has no valid certificate for a purpose; only `status` returns it.
pub const EXIT_UNCOVERED: u8 = 6;
/// The broker has no valid certificate of its own and issues no clearances; only `status` returns it, and before 5 and 6.
pub const EXIT_NO_BROKER_CERTIFICATE: u8 = 7;

/// What a verb prints and exits with for an answer (`proposals/admin-socket.md`, section 3; [`EXIT_TABLE`]).
#[must_use]
pub fn render(command: &Command, reply: &Reply) -> (String, u8) {
    let (verb, past) = match command {
        Command::Status => ("status", ""),
        Command::Block(_) => ("block", "blocked"),
        Command::Unblock(_) => ("unblock", "unblocked"),
        Command::Withdraw(_) => ("withdraw", "withdrawn"),
    };
    let what = match command {
        Command::Block(Target::Person(p)) | Command::Unblock(Target::Person(p)) => p.clone(),
        Command::Block(Target::Key(k)) | Command::Unblock(Target::Key(k)) | Command::Withdraw(k) => k.to_string(),
        Command::Status => String::new(),
    };
    match reply {
        Reply::Done(Ok(())) => (format!("{past} and stored: {what}"), EXIT_DONE),
        Reply::Done(Err(why)) => {
            (format!("{past}, NOT stored: {why} ({what} is in force in the broker's memory)"), EXIT_NOT_STORED)
        }
        Reply::Refused(Refusal::Unavailable, why) => {
            (format!("{verb} refused: the register cannot be written ({})", why.unwrap_or("io")), EXIT_REFUSED)
        }
        Reply::Refused(reason, _) => (format!("{verb} refused: {}", reason.wire()), EXIT_REFUSED),
        Reply::Status(s) => {
            let conditions = conditions(s);
            let mut out = if conditions.is_empty() {
                "conditions: none\n".to_owned()
            } else {
                // The exit code is the gravest of these, in the order 7, 5, 6; this is the complete list.
                let mut o = String::from("conditions (the exit code is the gravest; this is the complete list):\n");
                for c in &conditions {
                    o.push_str(&format!("  {}  {}\n", c.code, c.text));
                }
                o
            };
            out.push_str(&format!(
                "pledges connected: {}\nrequests held: {}\ndelegations: {} ({} withdrawn)\n",
                s.pledges, s.held, s.delegations, s.withdrawn
            ));
            out.push_str(&format!("blocked persons: {}\n", list(&s.blocked_persons)));
            out.push_str(&format!("blocked keys: {}\n", list(&s.blocked_keys)));
            out.push_str(&match &s.administrators {
                Some(g) => format!("administrators: group {} (gid {})", crate::util::shown(&g.name), g.gid),
                None => "administrators: root only".to_owned(),
            });
            let b = &s.broker_certificate;
            match (b.valid, b.days_left) {
                (true, Some(days)) => {
                    out.push_str(&format!("\nbroker certificate ({}): valid, {days} days left", b.path));
                }
                _ => out.push_str(&format!("\nbroker certificate ({}): NOT valid", b.path)),
            }
            if let Some(c) = &s.certificates {
                out.push_str(&format!(
                    "\ncertificates carried: {} ({} not carried{})\npersons without a valid certificate: {}",
                    c.carried,
                    c.not_carried,
                    if c.directory_refused { "; the directory is refused whole" } else { "" },
                    list(&c.uncovered)
                ));
            }
            (out, conditions.first().map_or(EXIT_DONE, |c| c.code))
        }
    }
}

/// A condition `page status` reports: a code (the exit code if it is the gravest), a name and a detail for a machine,
/// and a line for a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Condition {
    pub code: u8,
    pub name: &'static str,
    pub detail: String,
    pub text: String,
}

/// Every condition that holds, the gravest first: 7 (no valid certificate of the broker's own), 5 (degraded), 6 (an
/// enabled person without a valid certificate for a purpose, or a certificates directory refused whole).
#[must_use]
pub fn conditions(s: &Status) -> Vec<Condition> {
    let mut list = Vec::new();
    // Without a usable ssh-keygen the broker can verify and sign nothing: the same meaning as 7, so the same code, and
    // a line of its own that says why.
    if let Some(why) = &s.keygen_unusable {
        list.push(Condition {
            code: EXIT_NO_BROKER_CERTIFICATE,
            name: "ssh-keygen-unusable",
            detail: why.clone(),
            text: format!("ssh-keygen cannot be used ({why}): the broker can verify and sign nothing"),
        });
    }
    let b = &s.broker_certificate;
    if !b.valid {
        let why = b.failure.unwrap_or("refused");
        list.push(Condition {
            code: EXIT_NO_BROKER_CERTIFICATE,
            name: "no-broker-certificate",
            detail: why.to_owned(),
            text: format!(
                "the broker has no valid certificate of its own ({}): {why}; it issues no clearances and no standings",
                b.path
            ),
        });
    }
    if let Some(why) = s.degraded {
        list.push(Condition {
            code: EXIT_DEGRADED,
            name: "degraded",
            detail: why.to_owned(),
            text: format!("the broker is degraded ({why}): the register cannot be stored; going on from memory"),
        });
    }
    if let Some(c) = &s.certificates {
        if c.directory_refused {
            list.push(Condition {
                code: EXIT_UNCOVERED,
                name: "certificates-directory-refused",
                detail: String::new(),
                text: "the certificates directory is refused whole: no certificate is carried".to_owned(),
            });
        } else if !c.uncovered.is_empty() {
            list.push(Condition {
                code: EXIT_UNCOVERED,
                name: "no-valid-certificate",
                detail: c.uncovered.join(","),
                text: format!("no valid certificate for: {}", c.uncovered.join(", ")),
            });
        }
    }
    list
}

/// The conditions as a JSON array, one object per condition (`status --format json`); `[]` when none holds.
#[must_use]
pub fn conditions_json(s: &Status) -> String {
    let items: Vec<serde_json::Value> = conditions(s)
        .into_iter()
        .map(|c| serde_json::json!({"code": c.code, "condition": c.name, "detail": c.detail}))
        .collect();
    serde_json::Value::Array(items).to_string()
}

fn list(items: &[String]) -> String {
    if items.is_empty() { "none".to_owned() } else { items.join(", ") }
}
