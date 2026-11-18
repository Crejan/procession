//! Issuing an agent's key pair and certificate: the one seam
//! (`SPEC.md`, section 4, "Delegations"). pledge writes neither a private key
//! nor a certificate itself; OpenSSH does.
//!
//! - The key pair: `ssh-keygen -t ed25519 -N ''` into a private temporary
//!   directory (mode 0700), read, removed.
//! - The certificate: `ssh-keygen -s <delegation public key> -U ...`. With `-U`
//!   OpenSSH gets the signature from an SSH agent. That agent is a private
//!   socket in the same temporary directory, offered for this one issuing,
//!   holding only the delegation key, closed when `ssh-keygen` exits. It is not
//!   `agent.sock`, where the delegation key never appears.
//! - What the key holder signs: the reader reads the certificate that is to be
//!   signed out of that signing request, with p-act's reader for an agent's
//!   certificate (`doc/approval-formats.md`, section 3.1), and lets the key
//!   holder sign only if it is exactly the certificate this issuing asked for.
//!   The key holder parses nothing.
//!
//! Replacing this module (with another way to make a certificate) changes
//! nothing else: [`issue`] takes the person, the groups, the label and the
//! validity, and returns the key block, the certificate line and what the
//! certificate says.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p_act::limits::MAX_DELEGATION_SECONDS;
use p_act::pact::bundle::KeyBlock;
use p_act::sign::{Agent, agent_certificate};

use crate::agent::message::{self, Message, read_message};
use crate::agent::wire::put_string;
use crate::paths::ensure_private_dir;
use crate::shared::{KeyInfo, Shared};

/// How far before now a certificate's validity starts, for clocks that differ.
pub const BACKDATE_SECONDS: i64 = 60;
/// Slack when judging the validity `ssh-keygen` wrote against the one asked for.
const SLACK_SECONDS: i64 = 5;
const CERTIFICATE_PREFIX: &str = "ssh-ed25519-cert-v01@openssh.com ";

/// What the person chose for a delegation.
pub struct Issuing<'a> {
    /// The person: the certificate's only principal.
    pub person: &'a str,
    /// The groups, sorted, without duplicates.
    pub groups: &'a [String],
    /// A free label (the certificate's key id).
    pub label: &'a str,
    /// How long it lasts.
    pub valid_seconds: u64,
    /// Now, Unix time.
    pub now: i64,
}

/// A key pair and its certificate.
pub struct Issued {
    /// The agent's private key, as the OpenSSH block. Cannot be printed.
    pub key: KeyBlock,
    /// The agent's public key line.
    pub agent_public: String,
    /// The certificate, as a `-cert.pub` line without a line feed.
    pub certificate: String,
    /// What the certificate says, as p-act reads it.
    pub agent: Agent,
}

/// Why issuing failed. Nothing here holds key material.
#[derive(Debug, thiserror::Error)]
pub enum IssueError {
    /// A file, directory or socket operation failed.
    #[error("{0}")]
    Io(String),
    /// `ssh-keygen` failed.
    #[error("ssh-keygen: {0}")]
    Tool(String),
    /// What came back is not what was asked for.
    #[error("the certificate is not what was asked for: {0}")]
    Wrong(String),
}

fn io(context: &str) -> impl FnOnce(std::io::Error) -> IssueError + '_ {
    move |e| IssueError::Io(format!("{context}: {e}"))
}

/// A temporary directory that is removed, with everything in it, when dropped.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn random_name() -> Option<String> {
    let mut bytes = [0_u8; 8];
    fs::File::open("/dev/urandom").ok()?.read_exact(&mut bytes).ok()?;
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn keygen(args: &[&std::ffi::OsStr], env_agent: Option<&Path>) -> Result<(), IssueError> {
    // The system's ssh-keygen at its fixed path, checked once, with a cleared environment; the only variable added
    // is the private agent socket for the signing.
    let keygen = p_act::keygen::Keygen::system().map_err(|e| IssueError::Tool(e.to_string()))?;
    let mut command = match env_agent {
        Some(socket) => keygen.command_with_agent(socket),
        None => keygen.command(),
    };
    command.args(args);
    let output = command.stdin(Stdio::null()).output().map_err(io("running ssh-keygen"))?;
    if output.status.success() {
        Ok(())
    } else {
        // ssh-keygen's own words: escaped and bounded, for a log; never a notice to the person.
        Err(IssueError::Tool(crate::outside::bounded(String::from_utf8_lossy(&output.stderr).trim(), 200)))
    }
}

/// Whether `data` is the certificate this issuing asked for, without its
/// signature: read with p-act, and compared with what the person chose.
fn is_the_certificate_asked_for(data: &[u8], issuing: &Issuing<'_>, agent_public_blob: Option<&[u8]>) -> bool {
    let mut padded = data.to_vec();
    put_string(&mut padded, b""); // the signature, not there yet
    let line = format!("{CERTIFICATE_PREFIX}{}", STANDARD.encode(&padded));
    let Ok(agent) = agent_certificate(&line) else { return false };
    certificate_matches(&agent, issuing)
        && agent_public_blob.is_none_or(|blob| agent.delegation.as_str() == crate::agent::host_key::fingerprint(blob))
}

fn certificate_matches(agent: &Agent, issuing: &Issuing<'_>) -> bool {
    let (after, before) =
        (i64::try_from(agent.valid_after).unwrap_or(i64::MAX), i64::try_from(agent.valid_before).unwrap_or(i64::MAX));
    let wanted_end = issuing.now.saturating_add(i64::try_from(issuing.valid_seconds).unwrap_or(i64::MAX));
    agent.person == issuing.person
        && agent.groups == issuing.groups
        && agent.key_id == issuing.label
        && (issuing.now - BACKDATE_SECONDS - SLACK_SECONDS..=issuing.now + SLACK_SECONDS).contains(&after)
        && (wanted_end - SLACK_SECONDS..=wanted_end + SLACK_SECONDS).contains(&before)
        && before - after <= MAX_DELEGATION_SECONDS + BACKDATE_SECONDS + 2 * SLACK_SECONDS
}

/// Serves one connection of the private SSH agent: the delegation key, and
/// nothing else.
fn serve_issuing_agent(shared: &Shared, mut stream: UnixStream, key: &KeyInfo, issuing: &Issuing<'_>) {
    while let Ok(Some(message)) = read_message(&mut stream) {
        let reply = match Message::parse(&message) {
            Ok(Message::ListIdentities) => {
                message::identities_reply(&[message::Identity { blob: &key.blob, comment: "delegation" }])
            }
            Ok(Message::Sign { key_blob, data, .. })
                if key_blob == key.blob && is_the_certificate_asked_for(data, issuing, None) =>
            {
                match shared
                    .holder
                    .lock()
                    .map_err(|_| ())
                    .and_then(|mut holder| holder.sign(&key.blob, data).map_err(|_| ()))
                {
                    Ok(signature) => message::sign_reply(&signature),
                    Err(()) => message::failure_reply(),
                }
            }
            _ => message::failure_reply(),
        };
        if stream.write_all(&reply).and_then(|()| stream.flush()).is_err() {
            return;
        }
    }
}

/// What `ssh-keygen -s` is told. Always what the person chose; a test passes
/// something else to see that the private SSH agent refuses to sign it.
struct CertOptions<'a> {
    person: &'a str,
    groups: &'a [String],
    label: &'a str,
    valid_seconds: u64,
    clear: bool,
}

/// Makes an agent's key pair and its certificate.
///
/// # Errors
///
/// [`IssueError`] if `ssh-keygen` fails, the delegation key is not there, or
/// the certificate is not what was asked for.
pub fn issue(shared: &Shared, work_dir: &Path, issuing: &Issuing<'_>) -> Result<Issued, IssueError> {
    let options = CertOptions {
        person: issuing.person,
        groups: issuing.groups,
        label: issuing.label,
        valid_seconds: issuing.valid_seconds,
        clear: true,
    };
    issue_with(shared, work_dir, issuing, &options)
}

fn issue_with(
    shared: &Shared,
    work_dir: &Path,
    issuing: &Issuing<'_>,
    options: &CertOptions<'_>,
) -> Result<Issued, IssueError> {
    let delegation =
        shared.key_with_purpose("delegation").ok_or_else(|| IssueError::Wrong("there is no delegation key".into()))?;
    let name = random_name().ok_or_else(|| IssueError::Io("no random name".into()))?;
    let scratch = Scratch(work_dir.join(format!("issue-{name}")));
    ensure_private_dir(&scratch.0).map_err(|e| IssueError::Io(e.to_string()))?;
    let path = |file: &str| scratch.0.join(file);

    // The key pair, read and removed at once.
    keygen(
        &[
            "-q".as_ref(),
            "-t".as_ref(),
            "ed25519".as_ref(),
            "-N".as_ref(),
            "".as_ref(),
            "-C".as_ref(),
            "".as_ref(),
            "-f".as_ref(),
            path("agent").as_os_str(),
        ],
        None,
    )?;
    let block = KeyBlock::new(fs::read(path("agent")).map_err(io("reading the key"))?)
        .map_err(|e| IssueError::Wrong(e.to_string()))?;
    fs::remove_file(path("agent")).map_err(io("removing the key"))?;
    let agent_public = fs::read_to_string(path("agent.pub")).map_err(io("reading the public key"))?.trim().to_owned();

    // The private SSH agent, for this one issuing.
    fs::write(path("delegation.pub"), format!("{}\n", delegation.public_line()))
        .map_err(io("writing the delegation key"))?;
    let socket = path("issue.sock");
    let listener = UnixListener::bind(&socket).map_err(io("binding the private SSH agent socket"))?;
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).map_err(io("protecting the socket"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let result = thread::scope(|scope| {
        let server = scope.spawn(|| {
            for stream in listener.incoming() {
                if stop.load(Ordering::SeqCst) {
                    return;
                }
                if let Ok(stream) = stream {
                    serve_issuing_agent(shared, stream, &delegation, issuing);
                }
            }
        });
        let validity = format!("-{BACKDATE_SECONDS}s:+{}s", options.valid_seconds);
        let mut args: Vec<std::ffi::OsString> = ["-q", "-s"].map(Into::into).to_vec();
        args.extend([
            path("delegation.pub").into_os_string(),
            "-U".into(),
            "-I".into(),
            options.label.into(),
            "-n".into(),
            options.person.into(),
            "-V".into(),
            validity.into(),
        ]);
        if options.clear {
            args.extend(["-O".into(), "clear".into()]);
        }
        if !options.groups.is_empty() {
            args.extend(["-O".into(), format!("extension:groups@procession={}", options.groups.join(",")).into()]);
        }
        args.push(path("agent.pub").into_os_string());
        let refs: Vec<&std::ffi::OsStr> = args.iter().map(std::ffi::OsString::as_os_str).collect();
        let result = keygen(&refs, Some(&socket));
        // The private SSH agent is closed when `ssh-keygen` has exited.
        stop.store(true, Ordering::SeqCst);
        let _ = UnixStream::connect(&socket);
        let _ = server.join();
        result
    });
    result?;
    let certificate =
        fs::read_to_string(path("agent-cert.pub")).map_err(io("reading the certificate"))?.trim().to_owned();
    drop(scratch);

    // Judge the result before anything is handed out.
    let agent = agent_certificate(&certificate).map_err(|e| IssueError::Wrong(e.to_string()))?;
    if !certificate_matches(&agent, issuing) {
        return Err(IssueError::Wrong("person, groups, label or validity differ from what was chosen".into()));
    }
    let public_blob = agent_public
        .split(' ')
        .nth(1)
        .and_then(|b64| STANDARD.decode(b64).ok())
        .ok_or_else(|| IssueError::Wrong("the public key does not read".into()))?;
    if agent.delegation.as_str() != crate::agent::host_key::fingerprint(&public_blob) {
        return Err(IssueError::Wrong("the certificate is for another key".into()));
    }
    Ok(Issued { key: block, agent_public, certificate, agent })
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::holder::KeyType;
    use crate::shared::KeyMeta;
    use crate::testing::Rig;

    fn now() -> i64 {
        i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs()).expect("fits")
    }

    fn rig_with_delegation_key(key_type: KeyType) -> Rig {
        let rig = Rig::live([], |_| {});
        let meta = KeyMeta {
            purpose: "delegation".into(),
            program: None,
            use_: None,
            comment: "d".into(),
            key_type: String::new(),
            created: String::new(),
        };
        rig.shared.create_key(key_type, meta).expect("key");
        rig
    }

    fn issuing<'a>(groups: &'a [String]) -> Issuing<'a> {
        Issuing { person: "jan", groups, label: "pledge agent", valid_seconds: 3600, now: now() }
    }

    fn leftovers(rig: &Rig) -> usize {
        std::fs::read_dir(rig.dir.path().join("work")).map_or(0, Iterator::count)
    }

    #[test]
    fn ssh_keygen_issues_through_the_private_ssh_agent_for_ed25519_and_p256_delegation_keys() {
        for key_type in [KeyType::Ed25519, KeyType::EcdsaP256] {
            let rig = rig_with_delegation_key(key_type);
            let groups = vec!["admins".to_owned(), "diag".to_owned()];
            let issued = issue(&rig.shared, &rig.shared.work_dir, &issuing(&groups))
                .unwrap_or_else(|e| panic!("{key_type:?}: {e}"));
            assert_eq!((issued.agent.person.as_str(), issued.agent.groups.as_slice()), ("jan", groups.as_slice()));
            assert!(issued.certificate.starts_with(CERTIFICATE_PREFIX));
            assert!(
                issued.agent_public.starts_with("ssh-ed25519 "),
                "the agent's key is Ed25519 whatever signs for it"
            );
            assert_eq!(leftovers(&rig), 0, "the private directory, its socket and the key are gone");
            assert!(!format!("{:?}", issued.key).contains("PRIVATE"), "the key block cannot be printed");
        }
    }

    #[test]
    fn a_certificate_without_groups_has_no_extension() {
        let rig = rig_with_delegation_key(KeyType::Ed25519);
        let issued = issue(&rig.shared, &rig.shared.work_dir, &issuing(&[])).expect("issued");
        assert!(issued.agent.groups.is_empty());
    }

    #[test]
    fn the_private_agent_signs_only_the_certificate_that_was_asked_for() {
        let rig = rig_with_delegation_key(KeyType::Ed25519);
        let groups = vec!["admins".to_owned()];
        let wanted = issuing(&groups);
        let other_groups = vec!["root".to_owned()];
        let attempts: Vec<(&str, CertOptions<'_>)> = vec![
            (
                "another person",
                CertOptions {
                    person: "mallory",
                    groups: &groups,
                    label: "pledge agent",
                    valid_seconds: 3600,
                    clear: true,
                },
            ),
            (
                "other groups",
                CertOptions {
                    person: "jan",
                    groups: &other_groups,
                    label: "pledge agent",
                    valid_seconds: 3600,
                    clear: true,
                },
            ),
            (
                "no groups",
                CertOptions { person: "jan", groups: &[], label: "pledge agent", valid_seconds: 3600, clear: true },
            ),
            (
                "a longer validity",
                CertOptions {
                    person: "jan",
                    groups: &groups,
                    label: "pledge agent",
                    valid_seconds: 7 * 24 * 3600,
                    clear: true,
                },
            ),
            (
                "another label",
                CertOptions {
                    person: "jan",
                    groups: &groups,
                    label: "something else",
                    valid_seconds: 3600,
                    clear: true,
                },
            ),
            (
                "the login extensions (no -O clear)",
                CertOptions {
                    person: "jan",
                    groups: &groups,
                    label: "pledge agent",
                    valid_seconds: 3600,
                    clear: false,
                },
            ),
        ];
        for (what, options) in attempts {
            let result = issue_with(&rig.shared, &rig.shared.work_dir, &wanted, &options);
            assert!(
                matches!(result, Err(IssueError::Tool(_))),
                "{what}: ssh-keygen got no signature, got {:?}",
                result.map(|i| i.certificate)
            );
        }
        assert_eq!(leftovers(&rig), 0);
        // And what was asked for works.
        issue(&rig.shared, &rig.shared.work_dir, &wanted).expect("issued");
    }

    #[test]
    fn without_a_delegation_key_there_is_nothing_to_issue() {
        let rig = Rig::live([], |_| {});
        assert!(matches!(issue(&rig.shared, &rig.shared.work_dir, &issuing(&[])), Err(IssueError::Wrong(_))));
    }

    #[test]
    fn the_certificate_is_judged_against_what_was_chosen() {
        let agent = |person: &str, groups: &[&str], after: u64, before: u64| Agent {
            person: person.into(),
            groups: groups.iter().map(|g| (*g).to_owned()).collect(),
            key_id: "pledge agent".into(),
            delegation: "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse().expect("fingerprint"),
            valid_after: after,
            valid_before: before,
        };
        let groups = vec!["admins".to_owned()];
        let now = 1_800_000_000_i64;
        let wanted = Issuing { person: "jan", groups: &groups, label: "pledge agent", valid_seconds: 3600, now };
        let n = u64::try_from(now).expect("positive");
        assert!(certificate_matches(&agent("jan", &["admins"], n - 60, n + 3600), &wanted));
        assert!(!certificate_matches(&agent("jan", &["admins"], n - 60, n + 3700), &wanted), "ends later than chosen");
        assert!(
            !certificate_matches(&agent("jan", &["admins"], n - 3600, n + 3600), &wanted),
            "starts earlier than the backdating"
        );
        assert!(!certificate_matches(&agent("jan", &["admins", "x"], n - 60, n + 3600), &wanted));
        assert!(!certificate_matches(&agent("bob", &["admins"], n - 60, n + 3600), &wanted));
    }
}
