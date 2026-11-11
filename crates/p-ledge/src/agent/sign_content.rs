//! What a client asks the SSH agent to sign, read from the signed bytes
//! themselves. A key signs only what parses into one of these cases;
//! everything else is refused. Nothing here comes from a program's name,
//! command line or configuration.
//!
//! Every text field is checked to be showable as it is
//! ([`is_showable`]); a field that is not makes the
//! data not understood. Atticus shortened and cleaned such fields for its
//! dialog; `doc/approvals.md` R9 says refuse instead.

use super::Refusal;
use super::text::is_showable;
use super::wire::Reader;

/// The largest session identifier: the first key exchange's hash, and the
/// largest hash any SSH key exchange uses is SHA-512.
pub const MAX_SESSION_ID_LEN: usize = 64;

const MSG_USERAUTH_REQUEST: u8 = 50;
const SERVICE: &str = "ssh-connection";
const METHOD_PUBLICKEY: &str = "publickey";
const METHOD_HOSTBOUND: &str = "publickey-hostbound-v00@openssh.com";
const SSHSIG_MAGIC: &[u8] = b"SSHSIG";

/// A namespace containing this (ignoring ASCII case) belongs to the approval
/// system's own keys (`call-v1@procession`, `request-v1@procession`,
/// `approval-v1@procession`, `clearance-v1@procession`, and the connection
/// key's). No key on the SSH agent socket signs in it. The whole `@procession`
/// family is reserved, so a namespace added later is covered too.
pub const RESERVED_NAMESPACE_MARK: &str = "@procession";

/// One thing the SSH agent may be asked to sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignContent {
    /// A login (RFC 4252, section 7, and OpenSSH's hostbound method).
    Userauth(Userauth),
    /// An SSHSIG signature (`PROTOCOL.sshsig`).
    Sshsig(Sshsig),
}

impl SignContent {
    /// Strict parse of the data of a signing request. `key_blobs` are the
    /// blobs under which the signing key is offered (the raw key and its
    /// certificate): `ssh` signs a certificate login through the raw key's
    /// identity, so the key named in the data may be either.
    ///
    /// # Errors
    ///
    /// [`Refusal::ReservedNamespace`] for a well-formed SSHSIG in a reserved
    /// namespace, [`Refusal::Unrecognised`] for anything else that is not
    /// exactly one of the known formats.
    pub fn parse(data: &[u8], key_blobs: &[&[u8]]) -> Result<Self, Refusal> {
        if data.starts_with(SSHSIG_MAGIC) {
            Sshsig::parse(data).map(Self::Sshsig)
        } else {
            Userauth::parse(data, key_blobs).map(Self::Userauth).ok_or(Refusal::Unrecognised)
        }
    }
}

/// The data signed for public-key user authentication:
///
/// ```text
/// string   session identifier
/// byte     SSH_MSG_USERAUTH_REQUEST (50)
/// string   user name
/// string   service name ("ssh-connection")
/// string   method ("publickey" | "publickey-hostbound-v00@openssh.com")
/// boolean  TRUE
/// string   public key algorithm name
/// string   public key blob
/// string   server host key            (hostbound method only)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Userauth {
    /// The first key exchange's hash.
    pub session_id: Vec<u8>,
    /// The account logged in to, as signed. Showable.
    pub user: String,
    /// The public key algorithm named in the data.
    pub algorithm: String,
    /// The server host key the client states it is talking to. Present only
    /// for the hostbound method.
    pub host_key: Option<Vec<u8>>,
}

impl Userauth {
    /// Strict parse: exact field order, a key blob that is one of
    /// `key_blobs`, a showable user, and no trailing bytes.
    fn parse(data: &[u8], key_blobs: &[&[u8]]) -> Option<Self> {
        let mut reader = Reader::new(data);
        let session_id = reader.string().filter(|id| (1..=MAX_SESSION_ID_LEN).contains(&id.len()))?;
        (reader.u8()? == MSG_USERAUTH_REQUEST).then_some(())?;
        let user = reader.utf8().filter(|user| is_showable(user))?;
        (reader.utf8()? == SERVICE).then_some(())?;
        let method = reader.utf8()?;
        (reader.u8()? == 1).then_some(())?;
        let algorithm = reader.utf8().filter(|algorithm| !algorithm.is_empty())?;
        let key = reader.string()?;
        key_blobs.contains(&key).then_some(())?;
        let host_key = match method {
            METHOD_PUBLICKEY => None,
            METHOD_HOSTBOUND => Some(reader.string().filter(|host_key| !host_key.is_empty())?.to_vec()),
            _ => return None,
        };
        (reader.remaining() == 0).then_some(())?;
        Some(Self { session_id: session_id.to_vec(), user: user.to_owned(), algorithm: algorithm.to_owned(), host_key })
    }
}

/// The hash an SSHSIG signature signs over.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// `sha256`, a 32-byte digest.
    Sha256,
    /// `sha512`, a 64-byte digest.
    Sha512,
}

/// The data signed for an SSHSIG signature (`PROTOCOL.sshsig`, "Signed
/// Data"):
///
/// ```text
/// byte[6]  "SSHSIG"
/// string   namespace
/// string   reserved
/// string   hash_algorithm   ("sha256" | "sha512")
/// string   H(message)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sshsig {
    /// The namespace, as signed. Showable, and not reserved.
    pub namespace: String,
    /// The hash algorithm.
    pub hash_algorithm: HashAlgorithm,
    /// The digest of the message, whose length fits `hash_algorithm`.
    pub digest: Vec<u8>,
}

impl Sshsig {
    /// Strict parse: exact field order, a non-empty showable namespace that
    /// is not reserved, an empty `reserved` field (anything else is data the
    /// SSH agent cannot show), a known hash algorithm with a digest of its
    /// length, and no trailing bytes. Data that claims to be SSHSIG but does
    /// not parse strictly is refused, so a malformed blob cannot pass as "not
    /// SSHSIG".
    fn parse(data: &[u8]) -> Result<Self, Refusal> {
        let mut reader = Reader::new(data.strip_prefix(SSHSIG_MAGIC).ok_or(Refusal::Unrecognised)?);
        let (Some(namespace), Some(reserved), Some(algorithm), Some(digest)) =
            (reader.string(), reader.string(), reader.utf8(), reader.string())
        else {
            return Err(Refusal::Unrecognised);
        };
        if reader.remaining() != 0 {
            return Err(Refusal::Unrecognised);
        }
        if is_reserved_namespace(namespace) {
            return Err(Refusal::ReservedNamespace);
        }
        let hash_algorithm = match (algorithm, digest.len()) {
            ("sha256", 32) => HashAlgorithm::Sha256,
            ("sha512", 64) => HashAlgorithm::Sha512,
            _ => return Err(Refusal::Unrecognised),
        };
        let namespace = std::str::from_utf8(namespace).ok().filter(|ns| !ns.is_empty() && is_showable(ns));
        match (namespace, reserved.is_empty()) {
            (Some(namespace), true) => {
                Ok(Self { namespace: namespace.to_owned(), hash_algorithm, digest: digest.to_vec() })
            }
            _ => Err(Refusal::Unrecognised),
        }
    }
}

/// Whether `namespace` (raw bytes, not decoded or normalised) is one the
/// approval system's keys use. Matches the mark anywhere and ignores ASCII
/// case, so a variant cannot slip past.
#[must_use]
pub fn is_reserved_namespace(namespace: &[u8]) -> bool {
    let mark = RESERVED_NAMESPACE_MARK.as_bytes();
    namespace.windows(mark.len()).any(|window| window.eq_ignore_ascii_case(mark))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::testing::{HOSTBOUND, UserauthData, ed25519_key, sshsig, sshsig_data};
    use crate::agent::wire::strings;

    fn key() -> Vec<u8> {
        ed25519_key(1).blob
    }

    fn parse(data: &[u8]) -> Result<SignContent, Refusal> {
        SignContent::parse(data, &[&key()])
    }

    // ported: testSignContent_userauth_signed
    #[test]
    fn userauth_plain_and_hostbound_parse_from_the_signed_bytes() {
        let key = key();
        let plain = UserauthData::new(&key).build();
        assert!(matches!(parse(&plain), Ok(SignContent::Userauth(login)) if login.host_key.is_none()));

        let mut hostbound = UserauthData::hostbound(&key, &[9]);
        hostbound.user = b"alice".to_vec();
        let Ok(SignContent::Userauth(login)) = parse(&hostbound.build()) else { panic!("hostbound login") };
        assert_eq!(login.user, "alice");
        assert_eq!(login.host_key, Some(vec![9]));
        assert_eq!(login.session_id.len(), 32);
        assert_eq!(login.algorithm, "ssh-ed25519");
    }

    #[test]
    fn a_certificate_login_names_the_certificate_and_is_signed_through_either_blob() {
        // `ssh` signs a certificate login through the raw key's identity: the
        // request names one blob, the data the other.
        let raw = key();
        let certificate = vec![0xCE; 40];
        let data = UserauthData::new(&certificate).build();
        assert!(SignContent::parse(&data, &[&raw, &certificate]).is_ok());
        assert_eq!(SignContent::parse(&data, &[&raw]), Err(Refusal::Unrecognised));
    }

    // ported: testSignContent_userauthMalformed_refused (all fifteen cases)
    #[test]
    fn malformed_userauth_is_refused() {
        let key = key();
        let base = || UserauthData::new(&key);
        let hostbound = || UserauthData::hostbound(&key, &[1, 2, 3]);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("key blob differs from the requested key", UserauthData::new(&[1; 32]).build()),
            ("empty session id", UserauthData { session_id: vec![], ..base() }.build()),
            ("oversized session id", UserauthData { session_id: vec![1; 65], ..base() }.build()),
            ("wrong message number", UserauthData { message: 51, ..base() }.build()),
            ("user not UTF-8", UserauthData { user: vec![0xFF, 0xFE], ..base() }.build()),
            ("other service", UserauthData { service: "ssh-userauth", ..base() }.build()),
            ("method hostbased", UserauthData { method: "hostbased", ..base() }.build()),
            ("method password", UserauthData { method: "password", ..base() }.build()),
            ("query without signature (FALSE)", UserauthData { flag: 0, ..base() }.build()),
            ("boolean other than 1", UserauthData { flag: 2, ..base() }.build()),
            ("empty algorithm", UserauthData { algorithm: "", ..base() }.build()),
            ("trailing bytes", UserauthData { trailing: vec![0], ..base() }.build()),
            ("hostbound without host key", UserauthData { method: HOSTBOUND, ..base() }.build()),
            ("hostbound with empty host key", UserauthData { host_key: Some(vec![]), ..hostbound() }.build()),
            ("hostbound with trailing bytes", UserauthData { trailing: vec![0], ..hostbound() }.build()),
            ("publickey with an extra host key", UserauthData { host_key: Some(vec![1, 2, 3]), ..base() }.build()),
        ];
        for (name, data) in cases {
            assert_eq!(parse(&data), Err(Refusal::Unrecognised), "{name}");
        }
    }

    // new: R9, a field that cannot be shown as it is is refused, not cleaned
    #[test]
    fn a_user_that_cannot_be_shown_as_it_is_is_refused() {
        let key = key();
        for user in ["ja\nn", "ja\u{202E}n", "ja\u{200F}n", "ja\u{0}n", &"a".repeat(201)] {
            let data = UserauthData { user: user.as_bytes().to_vec(), ..UserauthData::new(&key) }.build();
            assert_eq!(parse(&data), Err(Refusal::Unrecognised), "{user:?}");
        }
        let longest = UserauthData { user: "a".repeat(200).into_bytes(), ..UserauthData::new(&key) }.build();
        assert!(parse(&longest).is_ok());
    }

    // ported: testSignContent_unknownData_refused
    #[test]
    fn unknown_data_is_refused() {
        for data in [&b"hello"[..], b"", &(0..64).map(|i: u8| i.wrapping_mul(37)).collect::<Vec<_>>()] {
            assert_eq!(parse(data), Err(Refusal::Unrecognised));
        }
    }

    // ported: testSSHSig_otherNamespace_stillSigned
    #[test]
    fn sshsig_in_other_namespaces_parses() {
        for namespace in ["git", "file", "Atticus-approval-v1", "x-atticus-approval-v1", "approval-v1", "procession"] {
            let Ok(SignContent::Sshsig(sig)) = parse(&sshsig(namespace)) else { panic!("{namespace}") };
            assert_eq!(sig.namespace, namespace);
            assert_eq!(sig.hash_algorithm, HashAlgorithm::Sha512);
            assert_eq!(sig.digest.len(), 64);
        }
        let sha256 = sshsig_data(b"git", "sha256", &[1; 32], b"", b"");
        assert!(matches!(parse(&sha256), Ok(SignContent::Sshsig(sig)) if sig.hash_algorithm == HashAlgorithm::Sha256));
    }

    // ported (adapted to this workspace's namespaces): testSSHSig_approvalNamespace_refused,
    // testSSHSig_anyAtticusNamespace_refused
    #[test]
    fn sshsig_in_a_reserved_namespace_is_refused() {
        let names = [
            "call-v1@procession",
            "request-v1@procession",
            "approval-v1@procession",
            "clearance-v1@procession",
            "connection-v1@procession",
            "approval-v2@procession",
            "anything@procession",
            "@procession",
            "APPROVAL-V1@PROCESSION",
            "Approval-v1@Procession",
            "approval-v1@procession\u{0}",
            "approval-v1@procession ",
            "x@procession-y",
        ];
        for namespace in names {
            assert_eq!(parse(&sshsig(namespace)), Err(Refusal::ReservedNamespace), "{namespace:?}");
        }
        let sha256 = sshsig_data(b"approval-v1@procession", "sha256", &[1; 32], b"", b"");
        assert_eq!(parse(&sha256), Err(Refusal::ReservedNamespace));
    }

    #[test]
    fn a_reserved_namespace_in_bytes_that_are_not_text_is_refused_as_reserved() {
        let data = sshsig_data(b"\xFF@procession", "sha512", &[0; 64], b"", b"");
        assert_eq!(parse(&data), Err(Refusal::ReservedNamespace));
    }

    // ported: testSSHSig_malformed_refused (the approval-with-trailing case
    // now answers "unrecognised" or "reserved": either way a refusal)
    #[test]
    fn malformed_sshsig_is_refused() {
        let full = sshsig("git");
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("bare magic", b"SSHSIG".to_vec()),
            ("truncated", full[..full.len() - 1].to_vec()),
            ("trailing bytes", sshsig_data(b"git", "sha512", &[0x5A; 64], b"", &[0])),
            ("unknown hash algorithm", sshsig_data(b"git", "sha1", &[1; 20], b"", b"")),
            ("digest length mismatch", sshsig_data(b"git", "sha256", &[0; 64], b"", b"")),
            ("sha512 with a short digest", sshsig_data(b"git", "sha512", &[0; 32], b"", b"")),
            (
                "approval namespace with trailing bytes",
                sshsig_data(b"approval-v1@procession", "sha512", &[0; 64], b"", &[0]),
            ),
        ];
        for (name, data) in cases {
            assert!(parse(&data).is_err(), "{name}");
        }
    }

    // new: R9
    #[test]
    fn an_sshsig_with_something_the_ssh_agent_cannot_show_is_refused() {
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("empty namespace", sshsig("")),
            ("namespace with a newline", sshsig("git\nfile")),
            ("namespace with a bidirectional mark", sshsig("g\u{202E}it")),
            ("namespace that is not UTF-8", sshsig_data(&[0xFF, 0xFE], "sha512", &[0; 64], b"", b"")),
            ("namespace of 201 characters", sshsig(&"a".repeat(201))),
            ("a reserved field with content", sshsig_data(b"git", "sha512", &[0; 64], b"x", b"")),
        ];
        for (name, data) in cases {
            assert_eq!(parse(&data), Err(Refusal::Unrecognised), "{name}");
        }
    }

    #[test]
    fn data_that_begins_like_a_session_id_never_reads_as_sshsig() {
        // A session identifier is a string of 1 to 64 bytes: its first byte is 0.
        assert_ne!(strings(&[&[1; 64]])[0], b'S');
    }
}
