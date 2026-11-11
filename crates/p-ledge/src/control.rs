//! `control.sock`: what a person tells their pledge (`proposals/control-sock.md`).
//!
//! One JSON object per line, `schema_version` and `type` on every message.
//! The client sends a `command` with a `ref`, the server answers with a
//! `reply`; replies may come in any order. A line that is not a valid message
//! is answered with one `error` and the connection is closed. This is the
//! framing of `service.sock` too (the shared exchange's: 96 KiB per line, ten
//! seconds from the first byte).

use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::agent::text::is_showable;
use crate::agents;
use crate::dialog::{Outcome, Wait};
use crate::holder::KeyType;
use crate::policy::{Admission, Standing};
use crate::shared::{KeyInfo, KeyMeta, Shared};

/// The longest line, on every transport.
pub const MAX_LINE: usize = 96 * 1024;
/// How long a line may take from its first byte.
pub const LINE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a command waits for the person.
pub const PRESENCE_TIMEOUT: Duration = Duration::from_secs(60);
/// The `schema_version` of these messages.
pub const SCHEMA_VERSION: u32 = 1;

/// Why a line could not be read.
#[derive(Debug)]
pub enum LineError {
    /// Longer than [`MAX_LINE`].
    TooLong,
    /// Did not end within [`LINE_TIMEOUT`] of its first byte.
    Timeout,
    /// The connection failed or ended inside a line.
    Io(io::Error),
}

/// Reads lines from a Unix socket with the limits of the shared exchange.
pub struct LineReader {
    reader: BufReader<UnixStream>,
    socket: UnixStream,
    timeout: Duration,
}

impl LineReader {
    /// A reader over `socket`.
    ///
    /// # Errors
    ///
    /// The operating system's error if the socket cannot be cloned.
    pub fn new(socket: &UnixStream) -> io::Result<Self> {
        Ok(Self { reader: BufReader::new(socket.try_clone()?), socket: socket.try_clone()?, timeout: LINE_TIMEOUT })
    }

    /// The next line without its `\n`; `Ok(None)` if the connection ended
    /// between lines.
    ///
    /// # Errors
    ///
    /// [`LineError`] for a line that is too long, too slow, or cut off.
    pub fn next_line(&mut self) -> Result<Option<Vec<u8>>, LineError> {
        let mut line = Vec::new();
        let mut started: Option<Instant> = None;
        loop {
            let timeout = match started {
                None => None,
                Some(at) => Some(
                    self.timeout.checked_sub(at.elapsed()).filter(|left| !left.is_zero()).ok_or(LineError::Timeout)?,
                ),
            };
            // macOS refuses to set a timeout on a socket whose peer has gone
            // (EINVAL); the read then ends at once, so the error is not needed.
            let _ = self.socket.set_read_timeout(timeout);
            let buffer = match self.reader.fill_buf() {
                Ok(buffer) => buffer,
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                    return Err(LineError::Timeout);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(LineError::Io(e)),
            };
            if buffer.is_empty() {
                return if line.is_empty() {
                    Ok(None)
                } else {
                    Err(LineError::Io(io::ErrorKind::UnexpectedEof.into()))
                };
            }
            started.get_or_insert_with(Instant::now);
            let (taken, done) = match buffer.iter().position(|b| *b == b'\n') {
                Some(end) => (end + 1, true),
                None => (buffer.len(), false),
            };
            line.extend_from_slice(&buffer[..taken - usize::from(done)]);
            self.reader.consume(taken);
            if line.len() > MAX_LINE {
                return Err(LineError::TooLong);
            }
            if done {
                return Ok(Some(line));
            }
        }
    }
}

fn write_line(stream: &mut UnixStream, message: &Value) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(message).map_err(io::Error::other)?;
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()
}

/// A command, as the client sends it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Command {
    schema_version: u32,
    #[serde(rename = "type")]
    message_type: String,
    #[serde(rename = "ref")]
    reference: String,
    name: String,
    #[serde(default)]
    args: Value,
}

fn valid_reference(reference: &str) -> bool {
    (1..=64).contains(&reference.len())
        && reference.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The error codes of a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Code {
    /// No such command.
    UnknownCommand,
    /// The arguments do not fit the command.
    BadArguments,
    /// What was named does not exist.
    NotFound,
    /// What was asked for exists already.
    AlreadyExists,
    /// A rule says no.
    Refused,
    /// The presence check failed or the person said no.
    PresenceDenied,
    /// No terminal, no key holder, or the record could not be written.
    Unavailable,
}

impl Code {
    /// The code as it is sent.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownCommand => "unknown-command",
            Self::BadArguments => "bad-arguments",
            Self::NotFound => "not-found",
            Self::AlreadyExists => "already-exists",
            Self::Refused => "refused",
            Self::PresenceDenied => "presence-denied",
            Self::Unavailable => "unavailable",
        }
    }
}

/// Serves one connection until it ends. The caller has checked that the peer
/// is the person's own user.
pub fn serve(shared: &Shared, stream: UnixStream) {
    // Delegations started on this connection whose bundle was not reported
    // written: if the connection ends first, they are withdrawn.
    let mut pending: Vec<String> = Vec::new();
    serve_commands(shared, stream, &mut pending);
    for id in pending {
        if agents::withdraw(shared, &id, "delivery-failed").is_ok() {
            eprintln!("pledge: the bundle of {id} was not reported written: the delegation is withdrawn");
        }
    }
}

fn serve_commands(shared: &Shared, mut stream: UnixStream, pending: &mut Vec<String>) {
    let Ok(mut lines) = LineReader::new(&stream) else { return };
    let protocol_error = |stream: &mut UnixStream, error: &str| {
        let _ = write_line(stream, &json!({"schema_version": SCHEMA_VERSION, "type": "error", "error": error}));
    };
    loop {
        let line = match lines.next_line() {
            Ok(Some(line)) => line,
            Ok(None) | Err(LineError::Io(_) | LineError::Timeout) => return,
            Err(LineError::TooLong) => return protocol_error(&mut stream, "line-too-long"),
        };
        let command: Command = match serde_json::from_slice(&line) {
            Ok(command) => command,
            Err(_) => return protocol_error(&mut stream, "malformed-line"),
        };
        if command.schema_version != SCHEMA_VERSION {
            return protocol_error(&mut stream, "unsupported-version");
        }
        if command.message_type != "command" || !valid_reference(&command.reference) {
            return protocol_error(&mut stream, "unknown-type");
        }
        let reply = match dispatch(shared, &command.name, command.args, pending) {
            Ok(data) => {
                json!({"schema_version": SCHEMA_VERSION, "type": "reply", "ref": command.reference, "result": "ok", "data": data})
            }
            Err(code) => {
                json!({"schema_version": SCHEMA_VERSION, "type": "reply", "ref": command.reference, "result": "error", "error": code.as_str()})
            }
        };
        if write_line(&mut stream, &reply).is_err() {
            return;
        }
    }
}

fn arguments<T: for<'de> Deserialize<'de>>(args: Value) -> Result<T, Code> {
    serde_json::from_value(if args.is_null() { Value::Object(Map::new()) } else { args })
        .map_err(|_| Code::BadArguments)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoArgs {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateArgs {
    purpose: String,
    #[serde(default)]
    key_type: Option<String>,
    program: Option<String>,
    user: Option<String>,
    host: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FingerprintArgs {
    fingerprint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProgramArgs {
    program: String,
    #[serde(default)]
    scope: Option<String>,
}

fn dispatch(shared: &Shared, name: &str, args: Value, pending: &mut Vec<String>) -> Result<Value, Code> {
    match name {
        "status" => arguments::<NoArgs>(args).map(|_| status(shared)),
        "keys.list" => arguments::<NoArgs>(args).and_then(|_| keys_list(shared)),
        "keys.create" => keys_create(shared, arguments(args)?),
        "keys.retire" => keys_retire(shared, &arguments::<FingerprintArgs>(args)?.fingerprint),
        "programs.list" => arguments::<NoArgs>(args).and_then(|_| programs_list(shared)),
        "programs.admit" => {
            let args: ProgramArgs = arguments(args)?;
            if args.scope.as_deref().is_some_and(|scope| scope != "generally") {
                return Err(Code::BadArguments);
            }
            program_decision(shared, &args.program, Some(Admission::AdmitGenerally), "program-admitted")
        }
        "programs.block" => program_decision(
            shared,
            &arguments::<ProgramArgs>(args)?.program,
            Some(Admission::Block),
            "program-blocked",
        ),
        "programs.forget" => {
            program_decision(shared, &arguments::<ProgramArgs>(args)?.program, None, "program-forgotten")
        }
        "agents.start" => {
            let (data, id) = agents::start(shared, arguments(args)?)?;
            pending.push(id);
            Ok(data)
        }
        "agents.delivered" => {
            let id = arguments::<DelegationArgs>(args)?.delegation;
            let done = agents::delivered(shared, &id)?;
            pending.retain(|p| *p != id);
            Ok(done)
        }
        "agents.failed" => {
            let id = arguments::<DelegationArgs>(args)?.delegation;
            pending.retain(|p| *p != id);
            agents::withdraw(shared, &id, "delivery-failed")
        }
        "agents.list" => arguments::<NoArgs>(args).map(|_| agents::list(shared)),
        "agents.withdraw" => agents::withdraw(shared, &arguments::<DelegationArgs>(args)?.delegation, "person"),
        _ => Err(Code::UnknownCommand),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationArgs {
    delegation: String,
}

fn status(shared: &Shared) -> Value {
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "form": "files",
        "protects_nothing": "keys are in files and the person is identified by the program's path",
        "keys": shared.keys.read().map_or(0, |keys| keys.len()),
        "programs": shared.policy.lock().map_or(0, |policy| policy.programs().count()),
    })
}

fn key_json(key: &KeyInfo) -> Value {
    let meta = key.meta.as_ref();
    json!({
        "purpose": meta.map_or("unknown", |m| m.purpose.as_str()),
        "fingerprint": key.fingerprint,
        "public": key.public_line(),
        "created": meta.map_or("", |m| m.created.as_str()),
        "program": meta.and_then(|m| m.program.clone()),
        "use": meta.and_then(|m| m.use_.clone()),
    })
}

fn keys_list(shared: &Shared) -> Result<Value, Code> {
    let keys = shared.keys.read().map_err(|_| Code::Unavailable)?;
    Ok(json!({"keys": keys.iter().map(key_json).collect::<Vec<_>>()}))
}

fn presence(shared: &Shared, question: &str) -> Result<(), Code> {
    match shared.dialogs.confirm(question, &Wait::up_to(PRESENCE_TIMEOUT)) {
        Outcome::Answer(true) => Ok(()),
        Outcome::Answer(false) | Outcome::Timeout => Err(Code::PresenceDenied),
        Outcome::Unavailable | Outcome::Cancelled => Err(Code::Unavailable),
    }
}

/// A word of a bound key's description: shown as it is, so it must be
/// showable, and it cannot hold a space or `@` that would make `user@host`
/// ambiguous.
fn plain(word: Option<&str>) -> Result<&str, Code> {
    word.filter(|w| !w.is_empty() && is_showable(w) && !w.contains([' ', '@'])).ok_or(Code::BadArguments)
}

fn keys_create(shared: &Shared, args: CreateArgs) -> Result<Value, Code> {
    let key_type = match args.key_type.as_deref() {
        None => KeyType::Ed25519,
        Some(name) => KeyType::from_name(name).ok_or(Code::BadArguments)?,
    };
    let (meta, question) = match args.purpose.as_str() {
        "shared" => {
            if args.program.is_some() || args.user.is_some() || args.host.is_some() {
                return Err(Code::BadArguments);
            }
            (
                KeyMeta {
                    purpose: "shared".into(),
                    program: None,
                    use_: None,
                    comment: "pledge shared".into(),
                    key_type: String::new(),
                    created: String::new(),
                },
                format!("make a shared {} key", key_type.name()),
            )
        }
        "bound" => {
            let program =
                args.program.as_deref().filter(|p| !p.is_empty() && is_showable(p)).ok_or(Code::BadArguments)?;
            let (user, host) = (plain(args.user.as_deref())?, plain(args.host.as_deref())?);
            (
                KeyMeta {
                    purpose: "bound".into(),
                    program: Some(program.to_owned()),
                    use_: Some(format!("login {user}@{host}")),
                    comment: format!("pledge bound {user}@{host}"),
                    key_type: String::new(),
                    created: String::new(),
                },
                format!("make a {} key for the program {program} to log in as {user} on {host}", key_type.name()),
            )
        }
        purpose @ ("confirmed" | "automatic" | "delegation") => {
            if args.program.is_some() || args.user.is_some() || args.host.is_some() {
                return Err(Code::BadArguments);
            }
            if shared.key_with_purpose(purpose).is_some() {
                return Err(Code::AlreadyExists);
            }
            let what = match purpose {
                "confirmed" => "approvals the person was asked for",
                "automatic" => "approvals in mode automatic",
                _ => "an agent's certificate",
            };
            (
                KeyMeta {
                    purpose: purpose.into(),
                    program: None,
                    use_: None,
                    comment: format!("pledge {purpose}"),
                    key_type: String::new(),
                    created: String::new(),
                },
                format!("make the {purpose} key, for {what} (never offered on the SSH agent socket)"),
            )
        }
        _ => return Err(Code::BadArguments),
    };
    presence(shared, &question)?;
    let key = shared.create_key(key_type, meta).map_err(|_| Code::Unavailable)?;
    shared.event("key-created", json!({"purpose": args.purpose, "key_fingerprint": key.fingerprint}));
    Ok(key_json(&key))
}

fn keys_retire(shared: &Shared, fingerprint: &str) -> Result<Value, Code> {
    let key = shared
        .keys
        .read()
        .map_err(|_| Code::Unavailable)?
        .iter()
        .find(|k| k.fingerprint == fingerprint)
        .cloned()
        .ok_or(Code::NotFound)?;
    presence(shared, &format!("retire the key {} (it is deleted)", key.fingerprint))?;
    shared.retire_key(fingerprint).map_err(|_| Code::Unavailable)?;
    shared.event(
        "key-retired",
        json!({"purpose": key.meta.as_ref().map(|m| m.purpose.clone()), "key_fingerprint": key.fingerprint}),
    );
    Ok(json!({}))
}

fn programs_list(shared: &Shared) -> Result<Value, Code> {
    let policy = shared.policy.lock().map_err(|_| Code::Unavailable)?;
    let programs: Vec<Value> = policy
        .programs()
        .map(|(program, standing)| json!({"program": program, "state": if standing == Standing::Admitted { "admitted" } else { "blocked" }}))
        .collect();
    Ok(json!({"programs": programs}))
}

fn program_decision(shared: &Shared, program: &str, answer: Option<Admission>, event: &str) -> Result<Value, Code> {
    if program.is_empty() || !is_showable(program) {
        return Err(Code::BadArguments);
    }
    {
        let mut policy = shared.policy.lock().map_err(|_| Code::Unavailable)?;
        match answer {
            Some(answer) => {
                policy.admit(program, answer);
            }
            None => policy.forget(program),
        }
    }
    shared.save_programs().map_err(|_| Code::Unavailable)?;
    shared.event(event, json!({"program": program}));
    Ok(json!({}))
}

/// Why a command did not succeed, on the client's side.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// The socket could not be used.
    #[error("{0}")]
    Io(#[from] io::Error),
    /// What came back is not a reply to the command.
    #[error("unexpected answer from pledge serve: {0}")]
    Protocol(String),
    /// pledge serve said no, with this code.
    #[error("pledge serve refused: {0}")]
    Refused(String),
}

/// The command line's end of `control.sock`.
pub struct Client {
    stream: UnixStream,
    lines: LineReader,
    next: u64,
}

impl Client {
    /// A client over a connection already made.
    #[must_use]
    pub fn from_stream(stream: UnixStream) -> Self {
        let lines = LineReader::new(&stream).expect("a socket can be cloned");
        Self { stream, lines, next: 1 }
    }

    /// Connects to the control socket at `path`.
    ///
    /// # Errors
    ///
    /// [`ClientError::Io`] if `pledge serve` is not there.
    pub fn connect(path: &Path) -> Result<Self, ClientError> {
        let stream = UnixStream::connect(path)?;
        let lines = LineReader::new(&stream)?;
        Ok(Self { stream, lines, next: 1 })
    }

    /// Sends a command and waits for its reply; returns its `data`.
    ///
    /// # Errors
    ///
    /// [`ClientError::Refused`] with the code if the command was refused.
    pub fn call(&mut self, name: &str, args: Value) -> Result<Value, ClientError> {
        let reference = self.next.to_string();
        self.next += 1;
        write_line(
            &mut self.stream,
            &json!({"schema_version": SCHEMA_VERSION, "type": "command", "ref": reference, "name": name, "args": args}),
        )?;
        let line = self
            .lines
            .next_line()
            .map_err(|e| ClientError::Protocol(format!("{e:?}")))?
            .ok_or_else(|| ClientError::Protocol("the connection ended".into()))?;
        let reply: Value = serde_json::from_slice(&line).map_err(|e| ClientError::Protocol(e.to_string()))?;
        if reply["type"] == "error" {
            return Err(ClientError::Protocol(reply["error"].as_str().unwrap_or("?").to_owned()));
        }
        if reply["type"] != "reply" || reply["ref"] != reference.as_str() {
            return Err(ClientError::Protocol("a reply to another command".into()));
        }
        match reply["result"].as_str() {
            Some("ok") => Ok(reply["data"].clone()),
            _ => Err(ClientError::Refused(reply["error"].as_str().unwrap_or("?").to_owned())),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;

    use super::*;
    use crate::dialog::Answer;
    use crate::testing::Rig;

    fn connect(rig: &Rig) -> UnixStream {
        let (client, server) = UnixStream::pair().expect("pair");
        let shared = Arc::clone(&rig.shared);
        thread::spawn(move || serve(&shared, server));
        client
    }

    fn raw(stream: &mut UnixStream, text: &str) -> Value {
        stream.write_all(text.as_bytes()).expect("write");
        let mut line = String::new();
        BufReader::new(stream.try_clone().expect("clone")).read_line(&mut line).expect("read");
        serde_json::from_str(&line).expect("json")
    }

    fn command(name: &str, args: &Value) -> String {
        format!("{}\n", json!({"schema_version": 1, "type": "command", "ref": "1", "name": name, "args": args}))
    }

    fn call(stream: &mut UnixStream, name: &str, args: Value) -> Value {
        raw(stream, &command(name, &args))
    }

    #[test]
    fn keys_are_made_listed_and_retired_with_a_presence_check_and_recorded() {
        let rig = Rig::new([
            Outcome::Answer(Answer::Yes(true)),
            Outcome::Answer(Answer::Yes(true)),
            Outcome::Answer(Answer::Yes(true)),
        ]);
        let mut conn = connect(&rig);
        let made = call(&mut conn, "keys.create", json!({"purpose": "shared"}));
        assert_eq!(made["result"], "ok", "{made}");
        let fingerprint = made["data"]["fingerprint"].as_str().expect("fingerprint").to_owned();
        assert!(made["data"]["public"].as_str().expect("public").starts_with("ssh-ed25519 AAAA"));
        let bound = call(
            &mut conn,
            "keys.create",
            json!({"purpose": "bound", "key_type": "ecdsa-p256", "program": "/opt/preserve", "user": "u1", "host": "backup.example.org"}),
        );
        assert_eq!(bound["data"]["use"], "login u1@backup.example.org");
        let listed = call(&mut conn, "keys.list", json!({}));
        assert_eq!(listed["data"]["keys"].as_array().map(Vec::len), Some(2));
        assert_eq!(call(&mut conn, "keys.retire", json!({"fingerprint": fingerprint}))["result"], "ok");
        assert_eq!(call(&mut conn, "keys.list", json!({}))["data"]["keys"].as_array().map(Vec::len), Some(1));
        let events: Vec<_> = rig.record().iter().filter_map(|e| e["event"].as_str().map(str::to_owned)).collect();
        assert_eq!(events, ["key-created", "key-created", "key-retired"]);
        assert!(rig.shown()[0].contains("make a shared ed25519 key"), "{:?}", rig.shown());
    }

    #[test]
    fn without_a_yes_nothing_is_made_and_without_a_terminal_it_is_unavailable() {
        let rig = Rig::new([Outcome::Answer(Answer::Yes(false)), Outcome::Timeout]);
        let mut conn = connect(&rig);
        for expected in ["presence-denied", "presence-denied", "unavailable"] {
            let reply = call(&mut conn, "keys.create", json!({"purpose": "shared"}));
            assert_eq!((reply["result"].as_str(), reply["error"].as_str()), (Some("error"), Some(expected)));
        }
        assert_eq!(call(&mut conn, "keys.list", json!({}))["data"]["keys"].as_array().map(Vec::len), Some(0));
    }

    #[test]
    fn decisions_about_programs_are_made_listed_remembered_and_recorded() {
        let rig = Rig::new([]);
        let mut conn = connect(&rig);
        assert_eq!(
            call(&mut conn, "programs.admit", json!({"program": "/usr/bin/git", "scope": "generally"}))["result"],
            "ok"
        );
        assert_eq!(call(&mut conn, "programs.block", json!({"program": "/usr/bin/curl"}))["result"], "ok");
        let listed = call(&mut conn, "programs.list", json!({}));
        assert_eq!(
            listed["data"]["programs"],
            json!([{"program": "/usr/bin/curl", "state": "blocked"}, {"program": "/usr/bin/git", "state": "admitted"}])
        );
        assert_eq!(call(&mut conn, "programs.forget", json!({"program": "/usr/bin/curl"}))["result"], "ok");
        assert_eq!(call(&mut conn, "programs.list", json!({}))["data"]["programs"].as_array().map(Vec::len), Some(1));
        let saved = std::fs::read_to_string(rig.dir.path().join("programs.json")).expect("saved");
        assert!(saved.contains("admitted") && !saved.contains("blocked"), "{saved}");
        let events: Vec<_> = rig.record().iter().filter_map(|e| e["event"].as_str().map(str::to_owned)).collect();
        assert_eq!(events, ["program-admitted", "program-blocked", "program-forgotten"]);
    }

    #[test]
    fn bad_commands_get_their_own_codes_and_the_connection_goes_on() {
        let rig = Rig::new([]);
        let mut conn = connect(&rig);
        for (name, args, code) in [
            ("nonsense", json!({}), "unknown-command"),
            ("status", json!({"extra": 1}), "bad-arguments"),
            ("keys.create", json!({"purpose": "other"}), "bad-arguments"),
            ("keys.create", json!({"purpose": "bound", "program": "p", "user": "a b", "host": "h"}), "bad-arguments"),
            ("keys.create", json!({"purpose": "bound", "program": "p", "user": "u", "host": "h\n"}), "bad-arguments"),
            ("keys.create", json!({"purpose": "shared", "key_type": "rsa"}), "bad-arguments"),
            ("keys.retire", json!({"fingerprint": "SHA256:none"}), "not-found"),
            ("programs.admit", json!({"program": "p", "scope": "once"}), "bad-arguments"),
            ("programs.block", json!({"program": "evil\u{202E}"}), "bad-arguments"),
            ("programs.block", json!({}), "bad-arguments"),
        ] {
            let reply = call(&mut conn, name, args.clone());
            assert_eq!(reply["error"], code, "{name} {args}");
        }
        assert_eq!(call(&mut conn, "status", Value::Null)["data"]["form"], "files");
    }

    #[test]
    fn protocol_violations_get_one_error_and_the_connection_is_closed() {
        let rig = Rig::new([]);
        for (text, expected) in [
            ("not json\n".to_owned(), "malformed-line"),
            (
                format!(
                    "{}\n",
                    json!({"schema_version": 1, "type": "command", "ref": "1", "name": "status", "extra": 1})
                ),
                "malformed-line",
            ),
            (
                format!("{}\n", json!({"schema_version": 2, "type": "command", "ref": "1", "name": "status"})),
                "unsupported-version",
            ),
            (
                format!("{}\n", json!({"schema_version": 1, "type": "request", "ref": "1", "name": "status"})),
                "unknown-type",
            ),
            (
                format!("{}\n", json!({"schema_version": 1, "type": "command", "ref": "a b", "name": "status"})),
                "unknown-type",
            ),
            (format!("{}\n", "x".repeat(MAX_LINE + 10)), "line-too-long"),
        ] {
            let mut conn = connect(&rig);
            let reply = raw(&mut conn, &text);
            assert_eq!(
                (reply["type"].as_str(), reply["error"].as_str()),
                (Some("error"), Some(expected)),
                "{}",
                &text[..text.len().min(40)]
            );
            let mut rest = String::new();
            assert_eq!(BufReader::new(conn).read_line(&mut rest).expect("eof"), 0, "closed");
        }
    }

    #[test]
    fn the_line_reader_enforces_its_limits() {
        let (mut a, b) = UnixStream::pair().expect("pair");
        let mut reader = LineReader::new(&b).expect("reader");
        a.write_all(b"one\ntwo\npart").expect("write");
        assert_eq!(reader.next_line().expect("line"), Some(b"one".to_vec()));
        assert_eq!(reader.next_line().expect("line"), Some(b"two".to_vec()));
        a.write_all(b"ial\n").expect("write");
        assert_eq!(reader.next_line().expect("line"), Some(b"partial".to_vec()));
        let writer = thread::spawn(move || {
            let _ = a.write_all(&vec![b'x'; MAX_LINE + 1]);
        });
        let outcome = reader.next_line();
        assert!(matches!(outcome, Err(LineError::TooLong)), "{outcome:?}");
        drop(reader);
        writer.join().expect("writer");
        let (mut c, d) = UnixStream::pair().expect("pair");
        let mut reader = LineReader::new(&d).expect("reader");
        c.write_all(b"ab").expect("write");
        drop(c);
        assert!(matches!(reader.next_line(), Err(LineError::Io(_))), "cut off inside a line");
        assert_eq!(LineReader::new(&UnixStream::pair().expect("pair").1).map(|_| ()).ok(), Some(()));
    }

    #[test]
    fn a_line_that_does_not_end_in_time_is_a_timeout_but_silence_between_lines_is_not() {
        let (mut a, b) = UnixStream::pair().expect("pair");
        let mut reader = LineReader::new(&b).expect("reader");
        reader.timeout = Duration::from_millis(150);
        a.write_all(b"begun").expect("write");
        assert!(matches!(reader.next_line(), Err(LineError::Timeout)));
        let (mut c, d) = UnixStream::pair().expect("pair");
        let mut reader = LineReader::new(&d).expect("reader");
        reader.timeout = Duration::from_millis(100);
        let late = thread::spawn(move || {
            thread::sleep(Duration::from_millis(400));
            c.write_all(b"late\n").expect("write");
        });
        assert_eq!(reader.next_line().expect("line"), Some(b"late".to_vec()), "no timeout before the first byte");
        late.join().expect("thread");
    }

    #[test]
    fn the_client_gets_data_and_refusals() {
        let rig = Rig::new([]);
        let (client_side, server_side) = UnixStream::pair().expect("pair");
        let shared = Arc::clone(&rig.shared);
        thread::spawn(move || serve(&shared, server_side));
        let mut client = Client { lines: LineReader::new(&client_side).expect("reader"), stream: client_side, next: 1 };
        assert_eq!(client.call("status", json!({})).expect("status")["form"], "files");
        assert!(
            matches!(client.call("keys.retire", json!({"fingerprint": "x"})), Err(ClientError::Refused(code)) if code == "not-found")
        );
    }
}
