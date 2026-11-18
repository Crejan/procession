//! The administrator's verbs and how they reach the running broker
//! (`proposals/admin-socket.md`): a Unix socket `admin.sock` in the state
//! directory, one JSON line in, one JSON line out.
//!
//! The rules of the register (a restricting command is in force at once and
//! says whether it is stored; a permitting one is refused while the register
//! cannot be written) live in the running broker, which is why the verbs are
//! its clients and never edit `register.json` themselves.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use p_act::sign::Fingerprint;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};

use crate::core::{Status, Stored};
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
    Status(Status),
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
            "status" => Some(Reply::Status(Status {
                degraded: if w.degraded? { Some(known_why(w.why.as_deref().unwrap_or("io"))) } else { None },
                pledges: w.pledges?,
                held: w.held?,
                delegations: w.delegations?,
                withdrawn: w.withdrawn?,
                blocked_persons: w.blocked_persons?,
                blocked_keys: w.blocked_keys?,
            })),
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

/// Carry out one command on the running broker.
pub async fn execute(broker: &Arc<Broker>, command: Command) -> Reply {
    let refused = |r| Reply::Refused(r, None);
    match command {
        Command::Status => match broker.with_core(|c, _| (c.status(), Vec::new())).await {
            Some(status) => Reply::Status(status),
            None => refused(Refusal::Malformed),
        },
        Command::Block(Target::Person(p)) => {
            let name = p.clone();
            if !broker.with_core(move |c, _| (c.knows_person(&name), Vec::new())).await.unwrap_or(false) {
                return refused(Refusal::UnknownPerson);
            }
            done(broker.block_person(p).await)
        }
        Command::Block(Target::Key(k)) => {
            let fp = k.to_string();
            if !broker.with_core(move |c, _| (c.knows_key(&fp), Vec::new())).await.unwrap_or(false) {
                return refused(Refusal::UnknownKey);
            }
            done(broker.block_key(k.to_string()).await)
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
            done(broker.admin_withdraw(d).await)
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
}

/// Make `admin.sock` in `state_dir`: 0600 set explicitly after `bind`, whatever the umask. A socket that is
/// there is removed only if nothing answers on it. Returns the listener and the user id the broker runs as (the
/// owner of the socket it has just made), the one user besides root a peer may be.
pub fn bind(state_dir: &Path) -> Result<(UnixListener, u32), BindError> {
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
    let uid = std::fs::metadata(&path).map_err(io)?.uid();
    Ok((listener, uid))
}

/// Serve commands for ever. A peer that is neither root nor `broker_uid` is closed without a word.
pub async fn serve(listener: UnixListener, broker: Arc<Broker>, broker_uid: u32) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let broker = Arc::clone(&broker);
        tokio::spawn(async move {
            let Ok(cred) = stream.peer_cred() else { return };
            if cred.uid() != 0 && cred.uid() != broker_uid {
                return;
            }
            serve_one(stream, broker).await;
        });
    }
}

/// One command, one answer, and the end.
pub async fn serve_one(stream: UnixStream, broker: Arc<Broker>) {
    let (rd, mut wr) = tokio::io::split(stream);
    let mut lines = Lines::with_limit(rd, WAIT, MAX_COMMAND_BYTES);
    let reply = match lines.read(Some(WAIT)).await {
        Ok(Some(line)) => match Command::parse(&line) {
            Some(command) => execute(&broker, command).await,
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

/// What a verb prints and exits with for an answer (`proposals/admin-socket.md`, section 3). A restricting verb
/// whose change is not stored, and any refusal, exit 1.
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
        Reply::Done(Ok(())) => (format!("{past} and stored: {what}"), 0),
        Reply::Done(Err(why)) => (format!("{past}, NOT stored: {why} ({what} is in force in the broker's memory)"), 1),
        Reply::Refused(Refusal::Unavailable, why) => {
            (format!("{verb} refused: the register cannot be written ({})", why.unwrap_or("io")), 1)
        }
        Reply::Refused(reason, _) => (format!("{verb} refused: {}", reason.wire()), 1),
        Reply::Status(s) => {
            let mut out = match s.degraded {
                Some(why) => format!("degraded: yes ({why}): the register cannot be stored; going on from memory\n"),
                None => "degraded: no\n".to_owned(),
            };
            out.push_str(&format!(
                "pledges connected: {}\nrequests held: {}\ndelegations: {} ({} withdrawn)\n",
                s.pledges, s.held, s.delegations, s.withdrawn
            ));
            out.push_str(&format!("blocked persons: {}\n", list(&s.blocked_persons)));
            out.push_str(&format!("blocked keys: {}", list(&s.blocked_keys)));
            (out, u8::from(s.degraded.is_some()))
        }
    }
}

fn list(items: &[String]) -> String {
    if items.is_empty() { "none".to_owned() } else { items.join(", ") }
}
