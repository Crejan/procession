//! One connection on the SSH agent socket: the reader's side.
//!
//! Reads messages, parses and checks what is to be signed, applies the rules
//! of `SPEC.md`, section 3 (`policy.rs` decides), asks the person where the
//! rules say so, and only then asks the key holder to sign. For every signing
//! request the record entry is written and flushed **before** the signature
//! is handed over: no record, no signature.

use std::io::{Read, Write};

use serde_json::{Map, Value, json};

use crate::agent::Refusal;
use crate::agent::binding::{EXTENSION_NAME, Session};
use crate::agent::known_hosts::{HostName, KnownHosts};
use crate::agent::message::{self, Identity, Message, read_message};
use crate::agent::sign_content::SignContent;
use crate::agent::text::is_showable;
use crate::dialog::{Description, Outcome, Wait, describe};
use crate::mute::DECLINES;
use crate::policy::{Admission, Reason, SigningRequest, Verdict, login_use, sshsig_use};
use crate::record::hash_line;
use crate::shared::{KeyInfo, Shared};

/// Serves one connection until it ends. `program` is who the connecting
/// program is (its path in the development form), `None` if that could not
/// be found out: then nothing is offered and nothing is signed.
pub fn serve<S: Read + Write>(shared: &Shared, mut stream: S, program: Option<&str>) {
    let mut session = Session::new();
    while let Ok(Some(message)) = read_message(&mut stream) {
        let reply = match Message::parse(&message) {
            Ok(Message::ListIdentities) => list_identities(shared, program),
            Ok(Message::Sign { key_blob, data, .. }) => sign(shared, program, &session, key_blob, data),
            Ok(Message::Extension { name: EXTENSION_NAME, body }) => {
                if session.bind(body) {
                    message::success_reply()
                } else {
                    message::failure_reply()
                }
            }
            Ok(Message::Extension { .. } | Message::Unsupported(_)) | Err(_) => message::failure_reply(),
        };
        if stream.write_all(&reply).and_then(|()| stream.flush()).is_err() {
            return;
        }
    }
}

/// The program, if it can be named and shown as it is.
fn showable_program(program: Option<&str>) -> Option<&str> {
    program.filter(|program| !program.is_empty() && is_showable(program))
}

fn list_identities(shared: &Shared, program: Option<&str>) -> Vec<u8> {
    let Some(program) = showable_program(program) else { return message::identities_reply(&[]) };
    let offered: Vec<String> = match shared.policy.lock() {
        Ok(policy) => policy.offered(program).into_iter().map(str::to_owned).collect(),
        Err(_) => return message::failure_reply(),
    };
    let Ok(keys) = shared.keys.read() else { return message::failure_reply() };
    let identities: Vec<Identity<'_>> = keys
        .iter()
        .filter(|key| offered.contains(&key.fingerprint))
        .map(|key| Identity { blob: &key.blob, comment: key.meta.as_ref().map_or("", |m| m.comment.as_str()) })
        .collect();
    message::identities_reply(&identities)
}

/// The longest user of a login pledge shows, in characters.
pub const MAX_LOGIN_USER_CHARS: usize = 64;
/// The longest host name of a login pledge shows, in characters (the names listed for the host's key, joined as
/// the dialog shows them).
pub const MAX_LOGIN_HOST_CHARS: usize = 170;
/// The user, the `@` and the host together.
pub const MAX_LOGIN_CHARS: usize = 240;

/// Why a login cannot be shown whole, if it cannot: the sentence for the person. Only what is shown counts: a host
/// that is shown by fingerprint (it has no name pledge can vouch for) has the fingerprint's own fixed length.
fn login_too_long(content: &SignContent, names: &HostName) -> Option<String> {
    let SignContent::Userauth(login) = content else { return None };
    let user = login.user.chars().count();
    let host = match names {
        HostName::Named(names) => names.join(", ").chars().count(),
        _ => 0,
    };
    let (what, limit) = if user > MAX_LOGIN_USER_CHARS {
        ("the user name", MAX_LOGIN_USER_CHARS)
    } else if host > MAX_LOGIN_HOST_CHARS {
        ("the host name", MAX_LOGIN_HOST_CHARS)
    } else if user + 1 + host > MAX_LOGIN_CHARS {
        ("the user and host name together", MAX_LOGIN_CHARS)
    } else {
        return None;
    };
    Some(format!(
        "{what} is longer than the {limit} characters pledge shows whole, so it cannot be asked about; \
         give the host a shorter alias in your ssh configuration (Host/HostName)"
    ))
}

/// What a signing request is, for the record.
enum Use {
    Login { user: String, host: Option<String>, host_fingerprint: Option<String> },
    Sshsig { namespace: String },
    Unreadable { data_hash: String, data_len: usize },
}

/// How a signing request ended.
enum End {
    Approved(Vec<u8>),
    Declined,
    Refused(&'static str),
    Expired,
}

struct Attempt<'a> {
    program: Option<&'a str>,
    key: Option<&'a KeyInfo>,
    what: Use,
}

fn sign(shared: &Shared, program: Option<&str>, session: &Session, key_blob: &[u8], data: &[u8]) -> Vec<u8> {
    let key = shared.keys.read().ok().and_then(|keys| keys.iter().find(|key| key.blob == key_blob).cloned());
    let unreadable = || Use::Unreadable { data_hash: hash_line(data), data_len: data.len() };
    // 1. Data the SSH agent cannot interpret is refused, whichever program asked.
    let content = match SignContent::parse(data, &[key_blob]) {
        Ok(content) => content,
        Err(refusal) => {
            let attempt = Attempt { program, key: key.as_ref(), what: unreadable() };
            return finish(shared, &attempt, &End::Refused(refusal.label()));
        }
    };
    let verified = session.verified_host(&content);
    let names = verified.as_ref().map_or(HostName::Unknown, |binding| {
        KnownHosts::load(&shared.known_hosts).name(&binding.host_key, shared.now().unix().try_into().unwrap_or(0))
    });
    let what = match &content {
        SignContent::Userauth(login) => Use::Login {
            user: login.user.clone(),
            host: match &names {
                HostName::Named(names) => Some(names.join(", ")),
                _ => None,
            },
            host_fingerprint: verified.as_ref().map(|binding| binding.host_key.fingerprint()),
        },
        SignContent::Sshsig(signature) => Use::Sshsig { namespace: signature.namespace.clone() },
    };
    let attempt = Attempt { program, key: key.as_ref(), what };
    let Some(program) = showable_program(program) else {
        let reason = if program.is_none() { "program-unknown" } else { "program-not-showable" };
        return finish(shared, &attempt, &End::Refused(reason));
    };
    // A key pledge does not hold is offered to nobody (SPEC.md, section 3, rule 2).
    if key.is_none() {
        return finish(shared, &attempt, &End::Refused("key-not-offered"));
    }
    // A login must carry what SPEC.md section 3 asks; a forwarded connection is refused.
    if let Some(refusal) = session.refusal(&content, true) {
        if refusal == Refusal::HostNotVerified {
            // A client that does not bind cannot use pledge's keys; there is no setting for it.
            shared.dialogs.tell(&format!(
                "{program} asked to sign in without proving which host it is for (session-bind@openssh.com): refused. A client older than OpenSSH 8.9 cannot use pledge's keys."
            ));
        }
        return finish(shared, &attempt, &End::Refused(refusal.label()));
    }
    // A login whose user or host name is too long to be shown whole is refused, never shown shortened and never
    // replaced by the host key's fingerprint (that is a rule of its own about what pledge can vouch for).
    if let Some(why) = login_too_long(&content, &names) {
        shared.dialogs.tell(&format!("{program}: {why}: refused"));
        return finish(shared, &attempt, &End::Refused("not-showable"));
    }
    let now = u64::try_from(shared.now().unix()).unwrap_or(0);
    if shared.muter.lock().is_ok_and(|muter| muter.is_muted(program, now)) {
        return finish(shared, &attempt, &End::Refused("muted"));
    }
    let description = describe(&content, verified.as_ref(), &names);
    let verified_fingerprint = verified.as_ref().map(|binding| binding.host_key.fingerprint());
    let end =
        decide(shared, program, key.as_ref(), &content, verified_fingerprint.as_deref(), &description, key_blob, data);
    finish(shared, &attempt, &end)
}

#[allow(clippy::too_many_arguments)]
fn decide(
    shared: &Shared,
    program: &str,
    key: Option<&KeyInfo>,
    content: &SignContent,
    verified_host: Option<&str>,
    description: &Description,
    key_blob: &[u8],
    data: &[u8],
) -> End {
    // What the request is, for the key's purpose: a login is for a user on a host KEY.
    let use_ = match (content, verified_host) {
        (SignContent::Sshsig(signature), _) => sshsig_use(&signature.namespace),
        (SignContent::Userauth(login), Some(fingerprint)) => login_use(&login.user, fingerprint),
        (SignContent::Userauth(_), None) => return End::Refused("host-not-verified"),
    };
    let key_name = key.map_or("?", |key| key.fingerprint.as_str());
    let verdict = {
        let Ok(policy) = shared.policy.lock() else { return End::Refused("unavailable") };
        policy.decide(&SigningRequest { program: program.to_owned(), key: key_name.to_owned(), use_: Some(use_) })
    };
    let wait = Wait::up_to(shared.dialog_timeout);
    let presence = |shared: &Shared| match shared.dialogs.presence(program, description, &wait) {
        Outcome::Answer(true) => None,
        Outcome::Answer(false) => Some(declined(shared, program)),
        Outcome::Timeout => Some(End::Expired),
        Outcome::Unavailable | Outcome::Cancelled => Some(End::Refused("unavailable")),
    };
    let proceed = match verdict {
        Verdict::Refuse(Reason::NotUnderstood) => Some(End::Refused("unrecognised")),
        Verdict::Refuse(Reason::KeyNotOffered) => Some(End::Refused("key-not-offered")),
        Verdict::Refuse(Reason::Blocked) => Some(End::Refused("blocked")),
        Verdict::Sign => None,
        Verdict::CheckPresence => presence(shared),
        Verdict::AskAdmission => match shared.dialogs.ask_admission(program, description, &wait) {
            Outcome::Timeout => Some(End::Expired),
            Outcome::Unavailable | Outcome::Cancelled => Some(End::Refused("unavailable")),
            Outcome::Answer(answer) => admission(shared, program, answer).or_else(|| presence(shared)),
        },
    };
    if let Some(end) = proceed {
        return end;
    }
    match shared.holder.lock().map_err(|_| ()).and_then(|mut holder| holder.sign(key_blob, data).map_err(|_| ())) {
        Ok(signature) => End::Approved(signature),
        Err(()) => End::Refused("unavailable"),
    }
}

/// Applies the person's answer about an unknown program. `None` if the
/// signing request goes on to its presence check.
fn admission(shared: &Shared, program: &str, answer: Admission) -> Option<End> {
    let goes_on = shared.policy.lock().ok()?.admit(program, answer);
    match answer {
        Admission::Block => {
            persist(shared);
            shared.event("program-blocked", json!({"program": program}));
        }
        Admission::AdmitGenerally => {
            persist(shared);
            shared.event("program-admitted", json!({"program": program, "scope": "generally"}));
        }
        Admission::DeclineOnce | Admission::AdmitOnce => {}
    }
    match (goes_on, answer) {
        (true, _) => None,
        // The person said no to this signing request: it is a decline; the block is an event.
        (false, Admission::Block) => Some(End::Declined),
        (false, _) => Some(declined(shared, program)),
    }
}

fn persist(shared: &Shared) {
    if let Err(e) = shared.save_programs() {
        eprintln!("pledge: could not save the decisions about programs: {e}");
    }
}

fn declined(shared: &Shared, program: &str) -> End {
    let now = u64::try_from(shared.now().unix()).unwrap_or(0);
    if shared.muter.lock().is_ok_and(|mut muter| muter.declined(program, now)) {
        shared.event("program-muted", json!({"program": program}));
        shared.dialogs.tell(&format!(
            "{program} was declined {DECLINES} times within ten minutes: it is refused without a dialog for ten minutes"
        ));
    }
    End::Declined
}

/// Records how the signing request ended, then answers it. An approval is
/// only handed over if its entry was written and flushed.
fn finish(shared: &Shared, attempt: &Attempt<'_>, end: &End) -> Vec<u8> {
    let mut entry = Map::new();
    entry.insert("type".into(), "signing-request".into());
    let (result, reason) = match end {
        End::Approved(_) => ("approved", None),
        End::Declined => ("declined", None),
        End::Refused(reason) => ("refused", Some(*reason)),
        End::Expired => ("expired", None),
    };
    entry.insert("result".into(), result.into());
    if let Some(reason) = reason {
        entry.insert("reason".into(), reason.into());
    }
    match attempt.program {
        Some(program) if is_showable(program) => {
            entry.insert("program".into(), program.into());
        }
        Some(program) => {
            entry.insert("program_hash".into(), hash_line(program.as_bytes()).into());
        }
        None => {}
    }
    if let Some(key) = attempt.key {
        entry.insert("key_fingerprint".into(), key.fingerprint.clone().into());
        if let Some(meta) = &key.meta {
            entry.insert("key_purpose".into(), meta.purpose.clone().into());
        }
    }
    match &attempt.what {
        Use::Login { user, host, host_fingerprint } => {
            entry.insert("use".into(), "login".into());
            entry.insert("user".into(), user.clone().into());
            entry.insert("host_verified".into(), host_fingerprint.is_some().into());
            if let Some(host) = host {
                entry.insert("host".into(), host.clone().into());
            }
            if let Some(host_fingerprint) = host_fingerprint {
                entry.insert("host_fingerprint".into(), host_fingerprint.clone().into());
            }
        }
        Use::Sshsig { namespace } => {
            entry.insert("use".into(), "sshsig".into());
            entry.insert("namespace".into(), namespace.clone().into());
        }
        Use::Unreadable { data_hash, data_len } => {
            entry.insert("use".into(), "unreadable".into());
            entry.insert("data_hash".into(), data_hash.clone().into());
            entry.insert("data_len".into(), (*data_len).into());
        }
    }
    let written = shared.append(Value::Object(entry));
    if let Err(e) = &written {
        eprintln!("pledge: the record cannot be written, so nothing is signed: {e}");
    }
    match (end, written) {
        (End::Approved(signature), Ok(())) => message::sign_reply(signature),
        _ => message::failure_reply(),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::sync::Arc;
    use std::thread;

    use super::*;
    use crate::agent::message::{SIGN_RESPONSE, frame};
    use crate::agent::testing::{SESSION_ID, TestKey, UserauthData, bind_body, ed25519_key, known_hosts_line, sshsig};
    use crate::agent::wire::{Reader, strings};
    use crate::dialog::Answer;
    use crate::policy::login_use;
    use crate::record::Record;
    use crate::shared::KeyMeta;
    use crate::testing::Rig;

    fn exchange(stream: &mut UnixStream, message: &[u8]) -> (u8, Vec<u8>) {
        stream.write_all(&frame(message[0], &message[1..])).expect("write");
        let reply = read_message(stream).expect("read").expect("reply");
        (reply[0], reply[1..].to_vec())
    }

    fn sign_message(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut message = vec![message::SIGN_REQUEST];
        message.extend(strings(&[key, data]));
        message.extend_from_slice(&0_u32.to_be_bytes());
        message
    }

    fn identities(stream: &mut UnixStream) -> Vec<Vec<u8>> {
        let (kind, body) = exchange(stream, &[message::REQUEST_IDENTITIES]);
        assert_eq!(kind, message::IDENTITIES_ANSWER);
        let mut reader = Reader::new(&body);
        (0..reader.u32().expect("count"))
            .map(|_| {
                let blob = reader.string().expect("blob").to_vec();
                reader.string().expect("comment");
                blob
            })
            .collect()
    }

    fn yes() -> Outcome<Answer> {
        Outcome::Answer(Answer::Yes(true))
    }
    fn no() -> Outcome<Answer> {
        Outcome::Answer(Answer::Yes(false))
    }
    fn admit(a: Admission) -> Outcome<Answer> {
        Outcome::Answer(Answer::Admission(a))
    }

    fn verifies(key: &[u8], data: &[u8], reply_body: &[u8]) -> bool {
        let signature = Reader::new(reply_body).string().expect("signature blob").to_vec();
        crate::agent::host_key::HostKey::parse(key).expect("key").verify(&signature, data)
    }

    fn result_of(entry: &Value) -> (&str, Option<&str>) {
        (entry["result"].as_str().expect("result"), entry["reason"].as_str())
    }

    #[test]
    fn a_shared_key_is_offered_to_a_program_without_a_bound_key_and_a_bound_key_only_to_its_own() {
        let rig = Rig::new([]);
        let shared = rig.shared_key();
        let bound = rig.key(KeyMeta {
            purpose: "bound".into(),
            program: Some("/opt/preserve".into()),
            use_: Some("login jan@bound.example.org".into()),
            comment: "bound".into(),
            key_type: String::new(),
            created: String::new(),
        });
        assert_eq!(identities(&mut rig.connect("/usr/bin/git")), std::slice::from_ref(&shared));
        assert_eq!(identities(&mut rig.connect("/opt/preserve")), [bound]);
        let (kind, _) = exchange(&mut rig.connect("/usr/bin/git"), &sign_message(&shared, b"x"));
        assert_eq!(kind, message::FAILURE);
    }

    #[test]
    fn an_unknown_program_is_asked_about_then_gets_its_presence_check_and_the_signature_is_recorded_first() {
        let rig = Rig::new([admit(Admission::AdmitGenerally), yes(), yes(), no()]);
        let key = rig.shared_key();
        let data = sshsig("git");
        let mut git = rig.connect("/usr/bin/git");
        let (kind, body) = exchange(&mut git, &sign_message(&key, &data));
        assert_eq!(kind, SIGN_RESPONSE);
        assert!(verifies(&key, &data, &body), "the signature verifies under the key");
        // Admitted generally: the next one is only a presence check; then a decline.
        assert_eq!(exchange(&mut git, &sign_message(&key, &data)).0, SIGN_RESPONSE);
        assert_eq!(exchange(&mut git, &sign_message(&key, &data)).0, message::FAILURE);
        let record = rig.record();
        let results: Vec<_> = record.iter().filter(|e| e["type"] == "signing-request").map(result_of).collect();
        assert_eq!(results, [("approved", None), ("approved", None), ("declined", None)]);
        assert!(record.iter().any(|e| e["event"] == "program-admitted"));
        let first = record.iter().find(|e| e["type"] == "signing-request").expect("entry");
        assert_eq!(
            (first["use"].as_str(), first["namespace"].as_str(), first["program"].as_str()),
            (Some("sshsig"), Some("git"), Some("/usr/bin/git"))
        );
        let shown = rig.shown();
        assert!(shown[0].starts_with("admission /usr/bin/git") && shown[0].contains("namespace: git"), "{shown:?}");
        assert!(shown[1].starts_with("presence /usr/bin/git"), "{shown:?}");
        // A restart remembers the decision.
        assert!(fs_read(&rig.dir.path().join("programs.json")).contains("\"/usr/bin/git\": \"admitted\""));
    }

    fn fs_read(path: &Path) -> String {
        std::fs::read_to_string(path).expect("read")
    }

    #[test]
    fn declining_three_times_mutes_a_program_and_the_person_is_told() {
        let rig = Rig::new([admit(Admission::AdmitGenerally), no(), no(), no()]);
        let key = rig.shared_key();
        let mut git = rig.connect("/usr/bin/git");
        for _ in 0..3 {
            assert_eq!(exchange(&mut git, &sign_message(&key, &sshsig("git"))).0, message::FAILURE);
        }
        let dialogs_before = rig.shown().len();
        assert_eq!(exchange(&mut git, &sign_message(&key, &sshsig("git"))).0, message::FAILURE);
        assert!(
            rig.shown().iter().any(|s| s.starts_with("tell /usr/bin/git was declined 3 times")),
            "{:?}",
            rig.shown()
        );
        assert_eq!(rig.shown().len(), dialogs_before, "no dialog for the muted program");
        let record = rig.record();
        let last = record.iter().rfind(|e| e["type"] == "signing-request").expect("entry");
        assert_eq!(result_of(last), ("refused", Some("muted")));
    }

    #[test]
    fn a_blocked_program_is_refused_without_a_dialog_and_stays_blocked() {
        let rig = Rig::new([admit(Admission::Block)]);
        let key = rig.shared_key();
        let mut curl = rig.connect("/usr/bin/curl");
        assert_eq!(exchange(&mut curl, &sign_message(&key, &sshsig("git"))).0, message::FAILURE);
        let shown = rig.shown().len();
        assert_eq!(exchange(&mut curl, &sign_message(&key, &sshsig("git"))).0, message::FAILURE);
        assert_eq!(rig.shown().len(), shown, "no second dialog");
        let record = rig.record();
        let reasons: Vec<_> = record.iter().filter(|e| e["type"] == "signing-request").map(result_of).collect();
        assert_eq!(reasons, [("declined", None), ("refused", Some("blocked"))]);
    }

    #[test]
    fn what_cannot_be_interpreted_is_refused_without_a_dialog_for_every_program() {
        let rig = Rig::new([]);
        let key = rig.shared_key();
        let mut conn = rig.connect("/usr/bin/git");
        let refusals = [
            ("reserved namespace", sshsig("approval-v1@procession"), "reserved-namespace"),
            ("any other reserved namespace", sshsig("whatever@procession"), "reserved-namespace"),
            ("unknown data", b"hello".to_vec(), "unrecognised"),
            ("malformed sshsig", b"SSHSIG".to_vec(), "unrecognised"),
            ("namespace not offered to a shared key", sshsig("other"), "key-not-offered"),
        ];
        for (name, data, reason) in refusals {
            assert_eq!(exchange(&mut conn, &sign_message(&key, &data)).0, message::FAILURE, "{name}");
            let last = rig.record().into_iter().rfind(|e| e["type"] == "signing-request").expect("entry");
            assert_eq!(result_of(&last), ("refused", Some(reason)), "{name}");
        }
        assert!(rig.shown().is_empty(), "no dialog for any of them: {:?}", rig.shown());
        let unreadable = rig.record().into_iter().find(|e| e["reason"] == "unrecognised").expect("entry");
        assert!(unreadable["data_hash"].as_str().is_some_and(|h| h.starts_with("sha256:")));
        assert!(unreadable.get("namespace").is_none(), "unreadable data is not stored as text");
    }

    #[test]
    fn a_request_for_a_key_pledge_does_not_hold_is_refused_without_a_dialog() {
        let rig = Rig::new([]);
        rig.shared_key();
        let stranger = ed25519_key(77).blob;
        let data = UserauthData::new(&stranger).build();
        assert_eq!(exchange(&mut rig.connect("/usr/bin/ssh"), &sign_message(&stranger, &data)).0, message::FAILURE);
        assert!(rig.shown().is_empty());
        assert_eq!(result_of(&rig.record()[0]), ("refused", Some("key-not-offered")));
    }

    /// A host, a known_hosts line naming it, and a connection bound to it.
    fn bound_connection(rig: &Rig, program: &str, host: &TestKey, name: &str) -> UnixStream {
        std::fs::write(rig.dir.path().join("known_hosts"), known_hosts_line(name, &host.blob, ""))
            .expect("known_hosts");
        let mut conn = rig.connect(program);
        let mut message = vec![message::EXTENSION];
        message.extend(strings(&[EXTENSION_NAME.as_bytes()]));
        message.extend(bind_body(host, &SESSION_ID, 0, None, b""));
        assert_eq!(exchange(&mut conn, &message).0, message::SUCCESS);
        conn
    }

    #[test]
    fn a_login_is_signed_only_when_bound_to_a_verified_host_and_the_dialog_names_it() {
        let rig = Rig::new([admit(Admission::AdmitOnce), yes()]);
        let key = rig.shared_key();
        let host = ed25519_key(60);
        let login = UserauthData::hostbound(&key, &host.blob).build();
        // Unbound: refused at once.
        assert_eq!(exchange(&mut rig.connect("/usr/bin/ssh"), &sign_message(&key, &login)).0, message::FAILURE);
        assert_eq!(result_of(&rig.record()[0]), ("refused", Some("host-not-verified")));
        assert!(rig.shown().iter().all(|s| s.starts_with("tell ")), "no dialog: {:?}", rig.shown());
        assert!(rig.shown()[0].contains("session-bind@openssh.com"), "the person is told why: {:?}", rig.shown());
        // Bound to the host: asked, shows the host's name, signs.
        let mut conn = bound_connection(&rig, "/usr/bin/ssh", &host, "backup.example.org");
        let (kind, body) = exchange(&mut conn, &sign_message(&key, &login));
        assert_eq!(kind, SIGN_RESPONSE);
        assert!(verifies(&key, &login, &body));
        let shown: Vec<String> = rig.shown().into_iter().filter(|s| !s.starts_with("tell ")).collect();
        assert!(shown[0].contains("host: backup.example.org (SHA256:") && shown[0].contains("user: jan"), "{shown:?}");
        let entry = rig.record().into_iter().rfind(|e| e["type"] == "signing-request").expect("entry");
        assert_eq!(
            (entry["host"].as_str(), entry["host_verified"].as_bool(), entry["user"].as_str()),
            (Some("backup.example.org"), Some(true), Some("jan"))
        );
        // A login for another session, or naming another host, is refused.
        let other = UserauthData::hostbound(&key, &ed25519_key(61).blob).build();
        assert_eq!(exchange(&mut conn, &sign_message(&key, &other)).0, message::FAILURE);
        assert_eq!(result_of(&rig.record().into_iter().last().expect("entry")), ("refused", Some("session-mismatch")));
    }

    #[test]
    fn a_login_too_long_to_show_is_refused_not_shown_shortened_or_by_fingerprint() {
        let long_host = "h".repeat(MAX_LOGIN_HOST_CHARS + 1);
        let key_of = |rig: &Rig| rig.shared_key();
        // A verified host whose listed name is one character too long: refused, told, no dialog, no fingerprint shown.
        let rig = Rig::new([admit(Admission::AdmitOnce), yes()]);
        let key = key_of(&rig);
        let host = ed25519_key(70);
        let login = UserauthData::hostbound(&key, &host.blob).build();
        let mut conn = bound_connection(&rig, "/usr/bin/ssh", &host, &long_host);
        assert_eq!(exchange(&mut conn, &sign_message(&key, &login)).0, message::FAILURE);
        assert_eq!(result_of(&rig.record()[0]), ("refused", Some("not-showable")));
        let shown = rig.shown();
        assert!(shown.iter().all(|s| s.starts_with("tell ")), "no dialog: {shown:?}");
        assert!(shown[0].contains("host name") && shown[0].contains("shorter alias"), "{shown:?}");
        assert!(shown.iter().all(|s| !s.contains("SHA256:")), "never the fingerprint instead: {shown:?}");
        // The same host at exactly the bound is shown, whole.
        let fits = "h".repeat(MAX_LOGIN_HOST_CHARS);
        let rig = Rig::new([admit(Admission::AdmitOnce), yes()]);
        let key = key_of(&rig);
        let login = UserauthData::hostbound(&key, &host.blob).build();
        let mut conn = bound_connection(&rig, "/usr/bin/ssh", &host, &fits);
        assert_eq!(exchange(&mut conn, &sign_message(&key, &login)).0, SIGN_RESPONSE);
        // A user over its bound.
        let rig = Rig::new([admit(Admission::AdmitOnce), yes()]);
        let key = key_of(&rig);
        let mut long_user = UserauthData::hostbound(&key, &host.blob);
        long_user.user = "u".repeat(MAX_LOGIN_USER_CHARS + 1).into_bytes();
        let mut conn = bound_connection(&rig, "/usr/bin/ssh", &host, "backup.example.org");
        assert_eq!(exchange(&mut conn, &sign_message(&key, &long_user.build())).0, message::FAILURE);
        assert_eq!(result_of(&rig.record()[0]), ("refused", Some("not-showable")));
        assert!(rig.shown()[0].contains("user name"), "{:?}", rig.shown());
    }

    #[test]
    fn a_bound_key_signs_without_a_dialog_for_its_program_and_its_login_only() {
        let rig = Rig::new([]);
        let bound = rig.key(KeyMeta {
            purpose: "bound".into(),
            program: Some("/opt/preserve".into()),
            use_: Some(login_use(
                "jan",
                &crate::agent::host_key::HostKey::parse(&ed25519_key(62).blob).expect("key").fingerprint(),
            )),
            comment: "bound".into(),
            key_type: String::new(),
            created: String::new(),
        });
        let host = ed25519_key(62);
        let login = UserauthData::hostbound(&bound, &host.blob).build();
        let mut conn = bound_connection(&rig, "/opt/preserve", &host, "backup.example.org");
        let (kind, body) = exchange(&mut conn, &sign_message(&bound, &login));
        assert_eq!(kind, SIGN_RESPONSE);
        assert!(verifies(&bound, &login, &body));
        assert!(rig.shown().is_empty(), "no dialog");
        // Another user on the same host: refused, not offered.
        let other_user = UserauthData { user: b"root".to_vec(), ..UserauthData::hostbound(&bound, &host.blob) }.build();
        assert_eq!(exchange(&mut conn, &sign_message(&bound, &other_user)).0, message::FAILURE);
        assert_eq!(result_of(&rig.record().into_iter().last().expect("entry")), ("refused", Some("key-not-offered")));
        // Another program: refused.
        let mut git = bound_connection(&rig, "/usr/bin/git", &host, "backup.example.org");
        assert_eq!(exchange(&mut git, &sign_message(&bound, &login)).0, message::FAILURE);
    }

    #[test]
    fn a_forwarded_connection_and_a_failed_bind_sign_nothing() {
        let rig = Rig::new([]);
        let key = rig.shared_key();
        let (hop, host) = (ed25519_key(63), ed25519_key(64));
        let mut conn = rig.connect("/usr/bin/ssh");
        let mut forwarding = vec![message::EXTENSION];
        forwarding.extend(strings(&[EXTENSION_NAME.as_bytes()]));
        forwarding.extend(bind_body(&hop, &[0xA1; 32], 1, None, b""));
        assert_eq!(exchange(&mut conn, &forwarding).0, message::SUCCESS);
        let login = UserauthData::hostbound(&key, &host.blob).build();
        assert_eq!(exchange(&mut conn, &sign_message(&key, &login)).0, message::FAILURE);
        assert_eq!(exchange(&mut conn, &sign_message(&key, &sshsig("git"))).0, message::FAILURE);
        let reasons: Vec<_> = rig.record().iter().map(|e| e["reason"].as_str().map(str::to_owned)).collect();
        assert_eq!(reasons, [Some("forwarded".to_owned()), Some("forwarded".to_owned())]);
        let mut bad = rig.connect("/usr/bin/ssh");
        let mut body = vec![message::EXTENSION];
        body.extend(strings(&[EXTENSION_NAME.as_bytes()]));
        body.extend(bind_body(&host, &SESSION_ID, 0, Some(ed25519_key(65).sign(&SESSION_ID)), b""));
        assert_eq!(exchange(&mut bad, &body).0, message::FAILURE);
        assert_eq!(exchange(&mut bad, &sign_message(&key, &sshsig("git"))).0, message::FAILURE);
        assert_eq!(rig.record().last().and_then(|e| e["reason"].as_str()), Some("bind-failed"));
        assert!(rig.shown().is_empty());
    }

    #[test]
    fn silence_is_expiry_and_no_terminal_is_a_refusal() {
        let rig = Rig::new([Outcome::Timeout, Outcome::Unavailable]);
        let key = rig.shared_key();
        let mut conn = rig.connect("/usr/bin/git");
        assert_eq!(exchange(&mut conn, &sign_message(&key, &sshsig("git"))).0, message::FAILURE);
        assert_eq!(exchange(&mut conn, &sign_message(&key, &sshsig("git"))).0, message::FAILURE);
        let results: Vec<_> = rig.record().iter().map(|e| result_of(e).0.to_owned()).collect();
        assert_eq!(results, ["expired", "refused"]);
    }

    #[test]
    fn no_record_no_signature() {
        let rig = Rig::new([admit(Admission::AdmitOnce), yes()]);
        let key = rig.shared_key();
        *rig.shared.record.lock().expect("lock") = Record::failing();
        let (kind, _) = exchange(&mut rig.connect("/usr/bin/git"), &sign_message(&key, &sshsig("git")));
        assert_eq!(kind, message::FAILURE, "approved by the person, but not recorded: not signed");
    }

    #[test]
    fn a_program_that_cannot_be_named_or_shown_gets_nothing() {
        let rig = Rig::new([]);
        let key = rig.shared_key();
        for program in [None, Some("/usr/bin/\u{202E}git"), Some("")] {
            let (client, server) = UnixStream::pair().expect("pair");
            let shared = Arc::clone(&rig.shared);
            let owned = program.map(str::to_owned);
            thread::spawn(move || serve(&shared, server, owned.as_deref()));
            let mut client = client;
            assert!(identities(&mut client).is_empty(), "{program:?}");
            assert_eq!(exchange(&mut client, &sign_message(&key, &sshsig("git"))).0, message::FAILURE);
        }
        assert!(rig.shown().is_empty());
        let reasons: Vec<_> = rig.record().iter().map(|e| e["reason"].as_str().unwrap_or("").to_owned()).collect();
        assert_eq!(reasons, ["program-unknown", "program-not-showable", "program-not-showable"]);
        assert!(rig.record()[1].get("program").is_none() && rig.record()[1]["program_hash"].is_string());
    }

    #[test]
    fn unknown_messages_and_malformed_ones_get_failure_and_the_connection_goes_on() {
        let rig = Rig::new([]);
        let mut conn = rig.connect("/usr/bin/git");
        assert_eq!(exchange(&mut conn, &[0xFE, 1, 2]).0, message::FAILURE);
        assert_eq!(exchange(&mut conn, &[message::SIGN_REQUEST, 1]).0, message::FAILURE);
        assert_eq!(
            exchange(&mut conn, &[message::EXTENSION, 0, 0, 0, 5, b'q', b'u', b'e', b'r', b'y']).0,
            message::FAILURE
        );
        assert_eq!(identities(&mut conn), Vec::<Vec<u8>>::new());
    }
}
