//! What the broker and pledge say to each other besides the shared exchange
//! (`doc/approval-connections.md` sections 4 and 5): the two signed documents,
//! the **connection document** (the sign-in) and the **standing**, and the
//! unsigned messages of the broker's own connections.
//!
//! The shared exchange (`submit`, `answer`, `cancel`, `error`, `hello`) is
//! [`crate::exchange`]; nothing of it is written again here, and these
//! messages are read with the same strictness and the same framing
//! ([`crate::exchange::LineBuffer`]). They are kept apart from [`Message`]
//! because they differ by direction: a pledge may not send `submit`, a service
//! may send `ack` and nothing of pledge's, and a program that reads one
//! direction should not have to refuse the other's types by hand.

use crate::error::ParseError;
use crate::exchange::{ClearancePolicy, EncodeError, ErrorCode, ExchangeError, Message, SCHEMA_VERSION, closed_code};
use crate::hash::{Document, DocumentHash};
use crate::limits::{CONNECTION_SECRET_BYTES, MAX_CONNECTION_DOCUMENT_BYTES, MAX_STANDING_BYTES};
use crate::object::{Object, check_bytes};
use crate::sign::{
    Agent, Fingerprint, PublicKey, SignError, agent_certificate, certificate_line_blob, looks_armoured, sign_broker,
    sign_connection, signature_to_base64, verify_broker, verify_connection,
};
use crate::sshsig::SshsigSigner;
use crate::text;
use crate::time::Timestamp;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;

/// 32 random bytes: the sign-in's nonce, and the TLS exporter value.
pub type Secret32 = [u8; CONNECTION_SECRET_BYTES];

// What the two ends of the broker's TLS connection must agree on (`approval-connections.md` sections 5 and 8). `p-act`
// has no TLS dependency; both ends use these and say them to their TLS library.

/// The label of the TLS exporter whose value the sign-in carries (RFC 5705): `tls` of the connection document.
pub const TLS_EXPORTER_LABEL: &[u8] = crate::limits::TLS_EXPORTER_LABEL.as_bytes();
/// The exporter's context: none (`None`, not an empty context: RFC 5705 tells them apart).
pub const TLS_EXPORTER_CONTEXT: Option<&[u8]> = None;
/// The exporter's output length: 32 bytes, the length of `tls` and of the nonce.
pub const TLS_EXPORTER_LENGTH: usize = CONNECTION_SECRET_BYTES;
/// The only protocol version of both broker transports: TLS 1.3 (no 1.2, no fallback). This is its name as RFC 8446
/// and OpenSSL spell it. `p-act` has no TLS library, so it holds no typed value: each end passes its own library's
/// (`rustls::version::TLS13`), and this name is for logs and tests; [`is_tls_1_3`] compares a name from a library
/// (rustls's `Debug` spells it `TLSv1_3`) so that nobody normalises it by hand.
pub const TLS_PROTOCOL_VERSION: &str = "TLSv1.3";

/// Whether `name` is TLS 1.3 as a library spells it: `TLSv1.3` or `TLSv1_3`.
#[must_use]
pub fn is_tls_1_3(name: &str) -> bool {
    matches!(name, "TLSv1.3" | "TLSv1_3")
}
/// The crypto provider of both ends: `ring` (not `aws-lc-rs`: the C and CMake toolchain it needs).
pub const TLS_CRYPTO_PROVIDER: &str = "ring";

fn decode32(member: &'static str, s: &str) -> Result<Secret32, ParseError> {
    let bytes = STANDARD.decode(s).map_err(|_| ParseError::MalformedBase64(member))?;
    Secret32::try_from(bytes.as_slice())
        .map_err(|_| ParseError::BadLength { member, expected: CONNECTION_SECRET_BYTES })
}

// ---------------------------------------------------------------------------
// The connection document
// ---------------------------------------------------------------------------

/// The document pledge signs in with, `connection-v1@procession`, by the person's connection key. It
/// says who signs in and ties the signature to one connection: the broker's nonce and 32 bytes
/// exported from this TLS connection. There is no time in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionDocument {
    bytes: Vec<u8>,
    person: String,
    nonce: Secret32,
    tls: Secret32,
}

#[derive(Serialize)]
struct ConnectionWire<'a> {
    v: u8,
    #[serde(rename = "type")]
    kind: &'a str,
    person: &'a str,
    nonce: String,
    tls: String,
}

impl ConnectionDocument {
    /// Write a new document: its bytes are produced here, once, and checked by the parser.
    pub fn compose(person: &str, nonce: &Secret32, tls: &Secret32) -> Result<ConnectionDocument, ParseError> {
        let wire = ConnectionWire {
            v: 1,
            kind: "connection",
            person,
            nonce: STANDARD.encode(nonce),
            tls: STANDARD.encode(tls),
        };
        ConnectionDocument::parse_unverified(serde_json::to_vec(&wire).map_err(|e| ParseError::NotJson(e.to_string()))?)
    }

    /// Read a document's bytes. **Not verified**: the broker reads `person` to know which key to verify
    /// with, then calls [`ConnectionDocument::verify`], and only then trusts any of it.
    pub fn parse_unverified(bytes: impl Into<Vec<u8>>) -> Result<ConnectionDocument, ParseError> {
        let bytes = bytes.into();
        let mut o = Object::parse(check_bytes(&bytes, MAX_CONNECTION_DOCUMENT_BYTES)?, "")?;
        o.take_header("connection")?;
        let person = o.take_string("person")?;
        let nonce = decode32("nonce", &o.take_string("nonce")?)?;
        let tls = decode32("tls", &o.take_string("tls")?)?;
        o.finish()?;
        if !text::is_name(&person) {
            return Err(ParseError::MalformedName("person"));
        }
        Ok(ConnectionDocument { bytes, person, nonce, tls })
    }

    /// Who signs in: a name as the site project has it.
    #[must_use]
    pub fn person(&self) -> &str {
        &self.person
    }

    /// The nonce the broker sent on this connection.
    #[must_use]
    pub fn nonce(&self) -> &Secret32 {
        &self.nonce
    }

    /// The 32 bytes exported from this TLS connection (RFC 5705, [`crate::limits::TLS_EXPORTER_LABEL`], no context).
    #[must_use]
    pub fn tls(&self) -> &Secret32 {
        &self.tls
    }

    /// Sign it with the person's connection key (a plain key).
    pub fn sign(&self, signer: &(impl SshsigSigner + ?Sized)) -> Result<String, SignError> {
        sign_connection(signer, &self.bytes)
    }

    /// Verify `sig` against the connection key the site project has for [`ConnectionDocument::person`]. That
    /// the nonce and the TLS value are this connection's is the caller's to check ([`ConnectionDocument::is_for`]).
    pub fn verify(&self, connection_key: &PublicKey, sig: &str) -> Result<(), SignError> {
        verify_connection(&self.person, connection_key, sig, &self.bytes)
    }

    /// Whether this is for the connection with this `nonce` and TLS exporter value.
    #[must_use]
    pub fn is_for(&self, nonce: &Secret32, tls: &Secret32) -> bool {
        self.nonce == *nonce && self.tls == *tls
    }
}

impl Document for ConnectionDocument {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// ---------------------------------------------------------------------------
// The standing
// ---------------------------------------------------------------------------

/// What a standing says: completely, and every time, what the broker holds for one person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StandingContent {
    /// The person.
    pub to: String,
    /// The nonce of the sign-in this connection began with: the standing is for this connection and no other.
    pub nonce: Secret32,
    /// 0 in the first standing after the sign-in, rising by one with each later one on the same connection.
    pub n: u64,
    /// When the broker made it, UTC to the second. **Shown, never used to decide anything**: `accepted_by` does not
    /// look at it.
    pub at: Timestamp,
    /// An administrator blocked the person.
    pub blocked: bool,
    /// Fingerprints of this person's keys an administrator blocked.
    pub blocked_keys: Vec<Fingerprint>,
    /// Identifiers of delegations an administrator withdrew and that have not ended.
    pub withdrawn: Vec<Fingerprint>,
    /// The person's current certificates for the approval keys, as `-cert.pub` lines, as the broker was given them.
    pub certificates: Vec<String>,
    /// The names of the person's groups.
    pub groups: Vec<String>,
}

// The four lists are sets: written sorted, each entry once (`Standing::compose`).

/// The broker's standing for a person, signed in `broker-v1@procession`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Standing {
    bytes: Vec<u8>,
    content: StandingContent,
}

#[derive(Serialize)]
struct StandingWire<'a> {
    v: u8,
    #[serde(rename = "type")]
    kind: &'a str,
    to: &'a str,
    nonce: String,
    n: u64,
    at: String,
    blocked: bool,
    blocked_keys: Vec<String>,
    withdrawn: Vec<String>,
    certificates: Vec<String>,
    groups: Vec<String>,
}

/// Why a standing was not accepted.
#[derive(Debug, thiserror::Error)]
pub enum StandingError {
    #[error("the standing's signature does not verify: {0}")]
    Signature(SignError),
    #[error("the standing is refused: {0}")]
    Document(ParseError),
}

fn fingerprints(o: &mut Object, member: &'static str) -> Result<Vec<Fingerprint>, ParseError> {
    o.take_strings(member)?.into_iter().map(|s| s.parse().map_err(|_| ParseError::MalformedFingerprint(s))).collect()
}

/// A group name as an agent's certificate has it: not empty, no whitespace, none of the formats' forbidden characters.
fn is_group_name(s: &str) -> bool {
    !s.is_empty() && !s.contains(char::is_whitespace) && !s.contains(',') && text::check("groups", s).is_ok()
}

fn has_duplicate(entries: &[&str]) -> bool {
    let mut sorted = entries.to_vec();
    sorted.sort_unstable();
    sorted.windows(2).any(|w| w[0] == w[1])
}

fn sorted_strings<T: ToString>(entries: &[T]) -> Vec<String> {
    let mut v: Vec<String> = entries.iter().map(ToString::to_string).collect();
    v.sort_unstable();
    v
}

impl Standing {
    /// Write a new standing: its bytes are produced here, once, and checked by the parser. The lists are
    /// sets and are written **sorted** (bytewise); an entry given twice is refused by the parser.
    pub fn compose(content: &StandingContent) -> Result<Standing, ParseError> {
        let wire = StandingWire {
            v: 1,
            kind: "standing",
            to: &content.to,
            nonce: STANDARD.encode(content.nonce),
            n: content.n,
            at: content.at.to_string(),
            blocked: content.blocked,
            blocked_keys: sorted_strings(&content.blocked_keys),
            withdrawn: sorted_strings(&content.withdrawn),
            certificates: sorted_strings(&content.certificates),
            groups: sorted_strings(&content.groups),
        };
        Standing::parse_unverified(serde_json::to_vec(&wire).map_err(|e| ParseError::NotJson(e.to_string()))?)
    }

    /// Read a standing's bytes. **Not verified**; pledge uses [`Standing::parse_verified`].
    pub fn parse_unverified(bytes: impl Into<Vec<u8>>) -> Result<Standing, ParseError> {
        let bytes = bytes.into();
        let mut o = Object::parse(check_bytes(&bytes, MAX_STANDING_BYTES)?, "")?;
        o.take_header("standing")?;
        let to = o.take_string("to")?;
        let nonce = decode32("nonce", &o.take_string("nonce")?)?;
        let n = o.take_u64("n")?;
        let at = o.take_string("at")?.parse()?;
        let blocked = o.take_bool("blocked")?;
        let blocked_keys = fingerprints(&mut o, "blocked_keys")?;
        let withdrawn = fingerprints(&mut o, "withdrawn")?;
        // Every member is required, `certificates` and `groups` too (they may be empty).
        let certificates = o.take_strings("certificates")?;
        let groups = o.take_strings("groups")?;
        o.finish()?;
        // The lists are sets: a reader does not depend on their order and refuses a duplicate, which can only be a writer's fault.
        for (member, entries) in [
            ("blocked_keys", blocked_keys.iter().map(Fingerprint::as_str).collect::<Vec<_>>()),
            ("withdrawn", withdrawn.iter().map(Fingerprint::as_str).collect()),
            ("certificates", certificates.iter().map(String::as_str).collect()),
            ("groups", groups.iter().map(String::as_str).collect()),
        ] {
            if has_duplicate(&entries) {
                return Err(ParseError::DuplicateEntry(member));
            }
        }
        if !text::is_name(&to) {
            return Err(ParseError::MalformedName("to"));
        }
        if certificates.iter().any(|c| certificate_line_blob(c).is_err()) {
            return Err(ParseError::MalformedCertificateLine("certificates"));
        }
        if !groups.iter().all(|g| is_group_name(g)) {
            return Err(ParseError::MalformedName("groups"));
        }
        Ok(Standing {
            bytes,
            content: StandingContent { to, nonce, n, at, blocked, blocked_keys, withdrawn, certificates, groups },
        })
    }

    /// Verify `sig` over `bytes` as what the broker says in its own name (`broker-v1@procession`, under
    /// `broker`, against the site CA's key), and only then read it, as a verifier does. That `to` is the
    /// person's own, the nonce this connection's and `n` higher than the last accepted is
    /// [`Standing::accepted_by`].
    pub fn parse_verified(
        bytes: impl Into<Vec<u8>>,
        sig: &str,
        site_ca: &PublicKey,
    ) -> Result<Standing, StandingError> {
        let bytes = bytes.into();
        verify_broker(site_ca, sig, &bytes).map_err(StandingError::Signature)?;
        Standing::parse_unverified(bytes).map_err(StandingError::Document)
    }

    #[must_use]
    pub fn content(&self) -> &StandingContent {
        &self.content
    }

    /// Sign it with the broker's key, certified by the site CA as `broker`.
    pub fn sign(&self, signer: &(impl SshsigSigner + ?Sized)) -> Result<String, SignError> {
        sign_broker(signer, &self.bytes)
    }

    /// The rule of the document: pledge accepts a standing only on the connection it was made for (`to` is its
    /// person, `nonce` that connection's) and only if `n` is higher than the last it accepted
    /// (`last_n`, `None` before the first). Otherwise it ignores it and records that. No clock is involved.
    #[must_use]
    pub fn accepted_by(&self, person: &str, nonce: &Secret32, last_n: Option<u64>) -> bool {
        self.content.to == person && self.content.nonce == *nonce && last_n.is_none_or(|last| self.content.n > last)
    }
}

impl Document for Standing {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// ---------------------------------------------------------------------------
// The unsigned messages
// ---------------------------------------------------------------------------

closed_code! {
    /// Why the broker did not take a well-formed certificate into its register.
    NotRegisteredReason {
        BadCertificate => "bad-certificate",
        TooLong => "too-long",
        NotYours => "not-yours",
        Blocked => "blocked",
        Unavailable => "unavailable",
    }
}

/// A signed document in a message: the document's bytes and the armoured signature, both decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub doc: Vec<u8>,
    pub sig: String,
}

/// An agent's certificate sent for registration (`delegation`), read with the rules of formats section 3.1.
/// The issuer is not looked at: the broker checks it against the person's delegation key
/// ([`crate::sign::verify_agent_certificate`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationMessage {
    /// The text of the public certificate, one line.
    pub certificate: String,
    /// What the certificate says: the person, the groups, the identifier of the delegation.
    pub agent: Agent,
}

/// What pledge sends to the broker after `hello`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FromPledge {
    /// The sign-in: the connection document and the connection key's signature over it.
    Signin(Signed),
    Ping,
    Delegation(DelegationMessage),
    Withdraw(Fingerprint),
    /// A message of the shared exchange: `hello` first, then `answer`, `cancel`, `error`. A `submit` is
    /// not pledge's to send; the program refuses it.
    Exchange(Box<Message>),
}

/// What a service sends to the broker besides the exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FromService {
    /// The service has the answer and the broker may drop what it held.
    Ack(DocumentHash),
    Exchange(Box<Message>),
}

/// What the broker sends to pledge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToPledge {
    Challenge(Secret32),
    Ready,
    /// The broker is up and cannot vouch for anything: it has no valid certificate of its own. Sent in place of the
    /// standing (connections document 3.7 and 5); a pledge treats it as connected without a standing.
    NotReady,
    /// The standing: its bytes and the broker's signature, to be verified with [`Standing::parse_verified`].
    Notice(Signed),
    Registered(Fingerprint),
    NotRegistered {
        delegation: Fingerprint,
        reason: NotRegisteredReason,
    },
    /// The answer to a `withdraw`. `stored` is `false` when the withdrawal is in force in the broker's memory
    /// but could not be written to its register: pledge records that and sends the withdrawal again.
    Withdrawn {
        delegation: Fingerprint,
        stored: bool,
    },
    /// A signed document the broker only carries (stage 3: the list of hosts' keys), byte for byte, with the
    /// namespace it was signed in. The broker's own signature is not on it; whoever reads it verifies it
    /// themselves, and ignores one whose namespace they do not know. Parsed so that it is not a protocol error.
    Carried {
        namespace: String,
        signed: Signed,
    },
    /// `submit`, `cancel`, `error` of the shared exchange.
    Exchange(Box<Message>),
}

/// What a connection's first message says it is (section 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum First {
    /// `submit`: a service's exchange.
    Service,
    /// `hello`: a pledge's.
    Pledge,
    /// Anything else: an `error` with this code and the end.
    Refuse(ErrorCode),
}

/// Tell from the first line which exchange this connection carries. A well-formed `hello` or `submit` with a
/// `schema_version` this code does not know is [`ErrorCode::UnsupportedVersion`] (it tells a peer only which version
/// is spoken); anything else that is neither is `malformed-line`; a line over the limit is `line-too-long`.
#[must_use]
pub fn first_kind(line: &[u8]) -> First {
    match Message::parse(line, ClearancePolicy::Refused) {
        Ok(Message::Submit(_)) | Err(ExchangeError::BadRequest { .. }) => First::Service,
        Ok(Message::Hello) => First::Pledge,
        Err(ExchangeError::UnsupportedVersion) if is_well_formed_first(line) => {
            First::Refuse(ErrorCode::UnsupportedVersion)
        }
        Err(ExchangeError::LineTooLong) => First::Refuse(ErrorCode::LineTooLong),
        _ => First::Refuse(ErrorCode::MalformedLine),
    }
}

/// Whether `line`, whose `schema_version` is not 1, is otherwise exactly a `hello` or a `submit`: one object with
/// a numeric `schema_version`, the type, and for a `submit` its two strings `request` and `request_sig`, nothing else.
fn is_well_formed_first(line: &[u8]) -> bool {
    let Ok(text) = check_bytes(line, crate::exchange::MAX_LINE) else { return false };
    let Ok(mut o) = Object::parse(text, "") else { return false };
    let version_is_a_number =
        o.take_raw("schema_version").is_ok_and(|v| serde_json::from_str::<serde_json::Number>(v.get()).is_ok());
    let Ok(kind) = o.take_string("type") else { return false };
    let members = match kind.as_str() {
        "hello" => true,
        "submit" => o.take_string("request").is_ok() && o.take_string("request_sig").is_ok(),
        _ => false,
    };
    version_is_a_number && members && o.finish().is_ok()
}

#[derive(Serialize)]
struct Head<'a> {
    schema_version: u32,
    #[serde(rename = "type")]
    kind: &'a str,
}

#[derive(Serialize)]
struct WithSigned<'a> {
    #[serde(flatten)]
    head: Head<'a>,
    doc: String,
    doc_sig: String,
}

#[derive(Serialize)]
struct CarriedWire<'a> {
    #[serde(flatten)]
    head: Head<'a>,
    namespace: &'a str,
    doc: String,
    doc_sig: String,
}

#[derive(Serialize)]
struct WithText<'a> {
    #[serde(flatten)]
    head: Head<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cert: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stored: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

fn head(kind: &str) -> Head<'_> {
    Head { schema_version: SCHEMA_VERSION, kind }
}

fn text_message(kind: &str) -> WithText<'_> {
    WithText { head: head(kind), nonce: None, cert: None, delegation: None, stored: None, request: None, reason: None }
}

fn line<T: Serialize>(value: &T) -> Result<Vec<u8>, EncodeError> {
    let mut bytes = serde_json::to_vec(value).map_err(|e| EncodeError::Io(std::io::Error::other(e)))?;
    bytes.push(b'\n');
    if bytes.len() > crate::exchange::MAX_LINE + 1 { Err(EncodeError::LineTooLong) } else { Ok(bytes) }
}

fn signed_line(kind: &str, s: &Signed) -> Result<Vec<u8>, EncodeError> {
    if !looks_armoured(&s.sig) {
        return Err(EncodeError::NotArmoured("doc_sig"));
    }
    line(&WithSigned { head: head(kind), doc: STANDARD.encode(&s.doc), doc_sig: signature_to_base64(&s.sig) })
}

impl FromPledge {
    /// Parse a line from pledge.
    pub fn parse(line: &[u8]) -> Result<FromPledge, ExchangeError> {
        let Some((kind, mut o)) = broker_object(line, &["signin", "ping", "delegation", "withdraw"])? else {
            return Ok(FromPledge::Exchange(Box::new(Message::parse(line, ClearancePolicy::Refused)?)));
        };
        let message = match kind.as_str() {
            "signin" => FromPledge::Signin(take_signed(&mut o)?),
            "ping" => FromPledge::Ping,
            "delegation" => {
                let certificate = o.take_string("cert")?;
                let agent =
                    agent_certificate(&certificate).map_err(|e| ExchangeError::BadCertificate(e.to_string()))?;
                FromPledge::Delegation(DelegationMessage { certificate, agent })
            }
            _ => FromPledge::Withdraw(take_fingerprint(&mut o, "delegation")?),
        };
        o.finish()?;
        Ok(message)
    }

    /// The line to write, with its `\n`.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        match self {
            FromPledge::Signin(s) => signed_line("signin", s),
            FromPledge::Ping => line(&head("ping")),
            FromPledge::Delegation(d) => line(&WithText { cert: Some(&d.certificate), ..text_message("delegation") }),
            FromPledge::Withdraw(fp) => {
                line(&WithText { delegation: Some(fp.to_string()), ..text_message("withdraw") })
            }
            FromPledge::Exchange(m) => m.encode(ClearancePolicy::Refused),
        }
    }
}

impl FromService {
    /// Parse a line from a service.
    pub fn parse(line: &[u8]) -> Result<FromService, ExchangeError> {
        let Some((_, mut o)) = broker_object(line, &["ack"])? else {
            return Ok(FromService::Exchange(Box::new(Message::parse(line, ClearancePolicy::Refused)?)));
        };
        let request = o.take_string("request")?.parse().map_err(ExchangeError::Malformed)?;
        o.finish()?;
        Ok(FromService::Ack(request))
    }

    /// The line to write, with its `\n`.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        match self {
            FromService::Ack(h) => line(&WithText { request: Some(h.to_string()), ..text_message("ack") }),
            FromService::Exchange(m) => m.encode(ClearancePolicy::Refused),
        }
    }
}

impl ToPledge {
    /// Parse a line from the broker.
    pub fn parse(line: &[u8]) -> Result<ToPledge, ExchangeError> {
        let Some((kind, mut o)) = broker_object(
            line,
            &["challenge", "ready", "not-ready", "notice", "registered", "not-registered", "withdrawn", "carried"],
        )?
        else {
            return Ok(ToPledge::Exchange(Box::new(Message::parse(line, ClearancePolicy::Refused)?)));
        };
        let message = match kind.as_str() {
            "challenge" => ToPledge::Challenge(decode32("nonce", &o.take_string("nonce")?)?),
            "ready" => ToPledge::Ready,
            "not-ready" => ToPledge::NotReady,
            "notice" => ToPledge::Notice(take_signed(&mut o)?),
            "carried" => {
                let namespace = o.take_string("namespace")?;
                // A namespace is printable ASCII without spaces, as SSHSIG writes them; which ones are known is the reader's.
                if namespace.is_empty() || namespace.len() > 64 || !namespace.bytes().all(|b| (0x21..0x7f).contains(&b))
                {
                    return Err(ExchangeError::Malformed(ParseError::MalformedName("namespace")));
                }
                ToPledge::Carried { namespace, signed: take_signed(&mut o)? }
            }
            "registered" => ToPledge::Registered(take_fingerprint(&mut o, "delegation")?),
            "withdrawn" => {
                let delegation = take_fingerprint(&mut o, "delegation")?;
                ToPledge::Withdrawn { delegation, stored: o.take_bool("stored")? }
            }
            _ => {
                let delegation = take_fingerprint(&mut o, "delegation")?;
                ToPledge::NotRegistered {
                    delegation,
                    reason: NotRegisteredReason::from_wire(&o.take_string("reason")?),
                }
            }
        };
        o.finish()?;
        Ok(message)
    }

    /// The line to write, with its `\n`.
    pub fn encode(&self) -> Result<Vec<u8>, EncodeError> {
        match self {
            ToPledge::Challenge(n) => line(&WithText { nonce: Some(STANDARD.encode(n)), ..text_message("challenge") }),
            ToPledge::Ready => line(&head("ready")),
            ToPledge::NotReady => line(&head("not-ready")),
            ToPledge::Notice(s) => signed_line("notice", s),
            ToPledge::Carried { namespace, signed } => {
                if !looks_armoured(&signed.sig) {
                    return Err(EncodeError::NotArmoured("doc_sig"));
                }
                line(&CarriedWire {
                    head: head("carried"),
                    namespace,
                    doc: STANDARD.encode(&signed.doc),
                    doc_sig: signature_to_base64(&signed.sig),
                })
            }
            ToPledge::Registered(fp) => {
                line(&WithText { delegation: Some(fp.to_string()), ..text_message("registered") })
            }
            ToPledge::NotRegistered { delegation, reason } => line(&WithText {
                delegation: Some(delegation.to_string()),
                reason: Some(reason.wire()),
                ..text_message("not-registered")
            }),
            ToPledge::Withdrawn { delegation, stored } => line(&WithText {
                delegation: Some(delegation.to_string()),
                stored: Some(*stored),
                ..text_message("withdrawn")
            }),
            ToPledge::Exchange(m) => m.encode(ClearancePolicy::Refused),
        }
    }
}

/// The object of a line, with `schema_version` checked and `type` read; `None` if `type` is not one of `kinds`
/// (the line belongs to the shared exchange, whose own parser reads it again).
fn broker_object(line: &[u8], kinds: &[&str]) -> Result<Option<(String, Object)>, ExchangeError> {
    let mut o = Object::parse(check_bytes(line, crate::exchange::MAX_LINE)?, "")?;
    o.take_schema_version()?;
    let kind = o.take_string("type")?;
    Ok(kinds.contains(&kind.as_str()).then_some((kind, o)))
}

fn take_signed(o: &mut Object) -> Result<Signed, ExchangeError> {
    let doc = STANDARD.decode(o.take_string("doc")?).map_err(|_| ExchangeError::BadBase64("doc"))?;
    let sig = STANDARD.decode(o.take_string("doc_sig")?).map_err(|_| ExchangeError::BadBase64("doc_sig"))?;
    let sig =
        String::from_utf8(sig).ok().filter(|s| looks_armoured(s)).ok_or(ExchangeError::BadSignature("doc_sig"))?;
    Ok(Signed { doc, sig })
}

fn take_fingerprint(o: &mut Object, member: &'static str) -> Result<Fingerprint, ExchangeError> {
    let s = o.take_string(member)?;
    s.parse().map_err(|_| ExchangeError::Malformed(ParseError::MalformedFingerprint(s)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const N: Secret32 = [7; 32];
    const T: Secret32 = [9; 32];
    const SIG: &str = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n";

    fn fp(c: char) -> Fingerprint {
        format!("SHA256:{}", c.to_string().repeat(43)).parse().unwrap()
    }

    fn signed() -> Signed {
        Signed { doc: b"{\"v\":1}".to_vec(), sig: SIG.to_owned() }
    }

    fn hash() -> DocumentHash {
        DocumentHash::of(b"x")
    }

    fn nb() -> String {
        STANDARD.encode(N)
    }

    // --- the connection document -------------------------------------------------------------

    #[test]
    fn the_connection_document_has_the_documents_bytes_and_round_trips() {
        let d = ConnectionDocument::compose("jan", &N, &T).unwrap();
        let expected = format!(
            r#"{{"v":1,"type":"connection","person":"jan","nonce":"{}","tls":"{}"}}"#,
            STANDARD.encode(N),
            STANDARD.encode(T)
        );
        assert_eq!(d.as_bytes(), expected.as_bytes());
        let read = ConnectionDocument::parse_unverified(expected.clone()).unwrap();
        assert_eq!(read, d);
        assert_eq!((read.person(), read.nonce(), read.tls()), ("jan", &N, &T));
        assert!(read.is_for(&N, &T) && !read.is_for(&T, &N) && !read.is_for(&N, &N));
        // What was parsed keeps its bytes, however they were spaced.
        let spaced = expected.replacen("{\"v\":1,", "{ \"v\": 1, ", 1);
        assert_eq!(ConnectionDocument::parse_unverified(spaced.clone()).unwrap().as_bytes(), spaced.as_bytes());
    }

    #[test]
    fn the_connection_document_refusals() {
        let good = ConnectionDocument::compose("jan", &N, &T).unwrap();
        let text = String::from_utf8(good.as_bytes().to_vec()).unwrap();
        let swap = |from: &str, to: &str| text.replacen(from, to, 1).into_bytes();
        let parse = |b: Vec<u8>| ConnectionDocument::parse_unverified(b);
        assert_eq!(parse(swap(r#""v":1"#, r#""v":2"#)), Err(ParseError::UnsupportedVersion("2".into())));
        assert!(matches!(parse(swap("connection", "standing")), Err(ParseError::WrongDocumentType { .. })));
        assert_eq!(parse(swap(r#""tls""#, r#""x":1,"tls""#)), Err(ParseError::UnknownMember("x".into())));
        assert_eq!(
            parse(swap(r#","tls":"#, r#","person":"x","tls":"#)),
            Err(ParseError::DuplicateMember("person".into()))
        );
        assert_eq!(
            parse(swap(&format!(r#","tls":"{}""#, STANDARD.encode(T)), "")),
            Err(ParseError::MissingMember("tls"))
        );
        for person in ["", "a b", "a@b", "*", "a,b", &"a".repeat(65), "jan:confirmed"] {
            assert_eq!(
                parse(swap(r#""jan""#, &format!("\"{person}\""))),
                Err(ParseError::MalformedName("person")),
                "{person:?}"
            );
        }
        assert_eq!(parse(swap(r#""jan""#, r#""j\u0000n""#)), Err(ParseError::ControlCharacter("person".into())));
        // The nonce and the TLS value are exactly 32 bytes of padded standard base64.
        for (n, why) in [
            (STANDARD.encode([1u8; 31]), "31 bytes"),
            (STANDARD.encode([1u8; 33]), "33 bytes"),
            (String::new(), "empty"),
        ] {
            assert_eq!(parse(swap(&nb(), &n)), Err(ParseError::BadLength { member: "nonce", expected: 32 }), "{why}");
        }
        assert_eq!(parse(swap(&nb(), "!!!")), Err(ParseError::MalformedBase64("nonce")));
        assert_eq!(parse(swap(&nb(), nb().trim_end_matches('='))), Err(ParseError::MalformedBase64("nonce")));
        let urlsafe = STANDARD.encode([0xfbu8; 32]);
        assert!(urlsafe.contains('+') || urlsafe.contains('/'));
        assert_eq!(
            parse(swap(&nb(), &urlsafe.replace('+', "-").replace('/', "_"))),
            Err(ParseError::MalformedBase64("nonce"))
        );
        assert_eq!(
            parse(swap(&STANDARD.encode(T), "AAAA")),
            Err(ParseError::BadLength { member: "tls", expected: 32 })
        );
        // Lines, size, junk.
        assert_eq!(parse([text.as_bytes(), b"\n"].concat()), Err(ParseError::LineBreak));
        assert!(matches!(parse(vec![b' '; MAX_CONNECTION_DOCUMENT_BYTES + 1]), Err(ParseError::TooLarge { .. })));
        for bad in ["", "[]", "null", "{"] {
            assert!(matches!(parse(bad.as_bytes().to_vec()), Err(ParseError::NotJson(_))), "{bad}");
        }
        assert!(matches!(ConnectionDocument::compose("a b", &N, &T), Err(ParseError::MalformedName("person"))));
    }

    // --- the standing ---------------------------------------------------------------------------

    fn content() -> StandingContent {
        StandingContent {
            to: "jan".into(),
            nonce: N,
            n: 3,
            at: Timestamp::from_unix(1_794_409_481).unwrap(),
            blocked: false,
            blocked_keys: vec![fp('A')],
            withdrawn: vec![fp('Q'), fp('b')],
            certificates: vec![],
            groups: vec!["ops".into(), "rt".into()],
        }
    }

    #[test]
    fn the_time_of_a_standing_is_shown_and_never_decides() {
        let at = |secs| {
            Standing::compose(&StandingContent { at: Timestamp::from_unix(secs).unwrap(), ..content() }).unwrap()
        };
        // Long ago, now, far ahead: `accepted_by` says the same.
        for secs in [0, 1_794_409_481, 253_402_300_799] {
            let s = at(secs);
            assert_eq!(s.content().at.unix(), secs);
            assert!(s.accepted_by("jan", &N, None) && s.accepted_by("jan", &N, Some(2)));
            assert!(!s.accepted_by("jan", &N, Some(3)) && !s.accepted_by("eva", &N, None));
        }
    }

    #[test]
    fn the_standing_has_the_documents_bytes_and_round_trips() {
        let s = Standing::compose(&content()).unwrap();
        let expected = format!(
            r#"{{"v":1,"type":"standing","to":"jan","nonce":"{}","n":3,"at":"2026-11-11T15:04:41Z","blocked":false,"blocked_keys":["{}"],"withdrawn":["{}","{}"],"certificates":[],"groups":["ops","rt"]}}"#,
            nb(),
            fp('A'),
            fp('Q'),
            fp('b')
        );
        assert_eq!(s.as_bytes(), expected.as_bytes());
        assert_eq!(Standing::parse_unverified(expected).unwrap().content(), &content());
        let none = StandingContent {
            blocked: true,
            blocked_keys: vec![],
            withdrawn: vec![],
            groups: vec![],
            n: u64::MAX,
            ..content()
        };
        assert_eq!(
            Standing::parse_unverified(Standing::compose(&none).unwrap().as_bytes().to_vec()).unwrap().content(),
            &none
        );
    }

    #[test]
    fn every_member_of_the_standing_is_required_and_the_lists_are_sets() {
        // Required: `certificates` and `groups` too. Absent is refused, not read as empty; empty is fine.
        let base = |tail: &str| {
            format!(
                r#"{{"v":1,"type":"standing","to":"jan","nonce":"{}","n":0,"at":"2026-11-11T15:04:41Z","blocked":false,"blocked_keys":[],"withdrawn":[]{tail}}}"#,
                nb()
            )
        };
        assert!(Standing::parse_unverified(base(r#","certificates":[],"groups":[]"#)).is_ok());
        assert_eq!(Standing::parse_unverified(base("")), Err(ParseError::MissingMember("certificates")));
        assert_eq!(Standing::parse_unverified(base(r#","certificates":[]"#)), Err(ParseError::MissingMember("groups")));
        assert_eq!(Standing::parse_unverified(base(r#","groups":[]"#)), Err(ParseError::MissingMember("certificates")));
        for member in ["blocked_keys", "withdrawn"] {
            let without = base(r#","certificates":[],"groups":[]"#)
                .replacen(&format!(r#""{member}":[],"#), "", 1)
                .replacen(&format!(r#","{member}":[]"#), "", 1);
            assert!(matches!(Standing::parse_unverified(without), Err(ParseError::MissingMember(_))), "{member}");
        }
        // A writer writes each list sorted, whatever order it was given.
        let shuffled = StandingContent {
            blocked_keys: vec![fp('b'), fp('A'), fp('Q')],
            withdrawn: vec![fp('z'), fp('B')],
            groups: vec!["rt".into(), "ops".into(), "Admins".into()],
            ..content()
        };
        let written = String::from_utf8(Standing::compose(&shuffled).unwrap().as_bytes().to_vec()).unwrap();
        let (a, q, b) = (
            written.find(&fp('A').to_string()).unwrap(),
            written.find(&fp('Q').to_string()).unwrap(),
            written.rfind(&fp('b').to_string()).unwrap(),
        );
        assert!(a < q && q < b, "blocked_keys sorted: {written}");
        assert!(written.contains(r#""groups":["Admins","ops","rt"]"#), "{written}");
        // A reader does not depend on the order: what arrives unsorted is read, and keeps its bytes.
        let unsorted = base(r#","certificates":[],"groups":["rt","ops"]"#);
        let read = Standing::parse_unverified(unsorted.clone()).unwrap();
        assert_eq!(read.content().groups, ["rt", "ops"]);
        assert_eq!(read.as_bytes(), unsorted.as_bytes());
        // A duplicate is refused, in each of the four lists, and a writer cannot produce one.
        let dup = |member: &str, entry: &str| {
            let text = base(r#","certificates":[],"groups":[]"#).replacen(
                &format!(r#""{member}":[]"#),
                &format!(r#""{member}":[{entry},{entry}]"#),
                1,
            );
            Standing::parse_unverified(text)
        };
        let fingerprint = format!("\"{}\"", fp('Q'));
        assert_eq!(dup("blocked_keys", &fingerprint), Err(ParseError::DuplicateEntry("blocked_keys")));
        assert_eq!(dup("withdrawn", &fingerprint), Err(ParseError::DuplicateEntry("withdrawn")));
        assert_eq!(dup("groups", "\"ops\""), Err(ParseError::DuplicateEntry("groups")));
        assert_eq!(
            Standing::compose(&StandingContent { groups: vec!["ops".into(), "ops".into()], ..content() }),
            Err(ParseError::DuplicateEntry("groups"))
        );
        assert_eq!(
            Standing::compose(&StandingContent { withdrawn: vec![fp('Q'), fp('Q')], ..content() }),
            Err(ParseError::DuplicateEntry("withdrawn"))
        );
        // Entries that differ only in case or by a character are different entries.
        assert!(
            Standing::compose(&StandingContent {
                groups: vec!["ops".into(), "Ops".into(), "ops2".into()],
                ..content()
            })
            .is_ok()
        );
    }

    #[test]
    fn the_standing_refusals() {
        let text = String::from_utf8(Standing::compose(&content()).unwrap().as_bytes().to_vec()).unwrap();
        let swap = |from: &str, to: &str| {
            assert!(text.contains(from), "{from}");
            text.replacen(from, to, 1).into_bytes()
        };
        let parse = |b: Vec<u8>| Standing::parse_unverified(b);
        assert_eq!(parse(swap(r#""v":1"#, r#""v":2"#)), Err(ParseError::UnsupportedVersion("2".into())));
        assert!(matches!(parse(swap("standing", "connection")), Err(ParseError::WrongDocumentType { .. })));
        assert_eq!(parse(swap(r#""n":3"#, r#""n":3,"x":1"#)), Err(ParseError::UnknownMember("x".into())));
        assert_eq!(parse(swap(r#""n":3,"#, "")), Err(ParseError::MissingMember("n")));
        // `at` is required, a time, once, and after `n`.
        assert_eq!(parse(swap(r#""at":"2026-11-11T15:04:41Z","#, "")), Err(ParseError::MissingMember("at")));
        assert!(matches!(parse(swap("2026-11-11T15:04:41Z", "yesterday")), Err(ParseError::MalformedTime(_))));
        assert!(matches!(
            parse(swap(r#""at":"2026-11-11T15:04:41Z""#, r#""at":5"#)),
            Err(ParseError::WrongType { .. })
        ));
        assert_eq!(
            parse(swap(r#""at":"2026-11-11T15:04:41Z""#, r#""at":"2026-11-11T15:04:41Z","at":"2026-11-11T15:04:41Z""#)),
            Err(ParseError::DuplicateMember("at".into()))
        );
        assert_eq!(parse(swap(r#""n":3"#, r#""n":3,"n":4"#)), Err(ParseError::DuplicateMember("n".into())));
        for n in ["-1", "1.5", "\"3\"", "null", "18446744073709551616"] {
            let b = text.replacen(r#""n":3"#, &format!(r#""n":{n}"#), 1).into_bytes();
            assert!(matches!(parse(b), Err(ParseError::WrongType { member, .. }) if member == "n"), "{n}");
        }
        assert!(matches!(parse(swap(r#""blocked":false"#, r#""blocked":"no""#)), Err(ParseError::WrongType { .. })));
        assert!(matches!(parse(swap(r#""blocked":false"#, r#""blocked":0"#)), Err(ParseError::WrongType { .. })));
        for bad in ["SHA256:short", "sha256:AAAA", "MD5:aa", "", &format!("SHA256:{}=", "A".repeat(43))] {
            assert_eq!(
                parse(swap(&fp('A').to_string(), bad)),
                Err(ParseError::MalformedFingerprint(bad.into())),
                "{bad}"
            );
            assert_eq!(
                parse(swap(&fp('Q').to_string(), bad)),
                Err(ParseError::MalformedFingerprint(bad.into())),
                "{bad}"
            );
        }
        assert_eq!(parse(swap(r#""to":"jan""#, r#""to":"j n""#)), Err(ParseError::MalformedName("to")));
        for group in ["", "a b", "a,b", "a\\tb"] {
            let b = text.replacen(r#""ops""#, &format!("\"{group}\""), 1).into_bytes();
            assert!(parse(b).is_err(), "{group:?}");
        }
        assert_eq!(
            parse(swap(r#""certificates":[]"#, r#""certificates":["not a certificate"]"#)),
            Err(ParseError::MalformedCertificateLine("certificates"))
        );
        assert!(matches!(
            parse(swap(r#""certificates":[]"#, r#""certificates":[1]"#)),
            Err(ParseError::WrongType { .. })
        ));
        assert_eq!(
            parse(swap(&nb(), &STANDARD.encode([1u8; 16]))),
            Err(ParseError::BadLength { member: "nonce", expected: 32 })
        );
        assert!(matches!(parse(vec![b' '; MAX_STANDING_BYTES + 1]), Err(ParseError::TooLarge { .. })));
        assert_eq!(parse([text.as_bytes(), b"\n"].concat()), Err(ParseError::LineBreak));
    }

    #[test]
    fn a_standing_is_accepted_only_for_its_connection_and_only_if_newer() {
        let s = Standing::compose(&content()).unwrap();
        assert!(s.accepted_by("jan", &N, None));
        assert!(s.accepted_by("jan", &N, Some(2)));
        assert!(!s.accepted_by("jan", &N, Some(3)), "the same n changes nothing");
        assert!(!s.accepted_by("jan", &N, Some(9)), "an older one changes nothing");
        assert!(!s.accepted_by("bob", &N, None), "another person's");
        assert!(!s.accepted_by("jan", &T, None), "another connection's nonce");
        assert!(Standing::compose(&StandingContent { n: 0, ..content() }).unwrap().accepted_by("jan", &N, None));
        assert!(!Standing::compose(&StandingContent { n: 0, ..content() }).unwrap().accepted_by("jan", &N, Some(0)));
    }

    #[test]
    fn a_standing_with_many_entries_fits_a_line() {
        // 64 KiB of document is about 88 KiB in base64: with the signature it must still fit the 96 KiB line.
        let many = StandingContent {
            withdrawn: (0..1100).map(|i| format!("SHA256:{i:043}").parse().unwrap()).collect(),
            ..content()
        };
        let s = Standing::compose(&many).unwrap();
        assert!(s.as_bytes().len() < MAX_STANDING_BYTES);
        let line = ToPledge::Notice(Signed { doc: s.as_bytes().to_vec(), sig: SIG.into() }).encode().unwrap();
        assert!(line.len() <= crate::exchange::MAX_LINE + 1, "{}", line.len());
        let bound = MAX_STANDING_BYTES.div_ceil(3) * 4 + 4096;
        assert!(bound < crate::exchange::MAX_LINE, "{bound}");
    }

    // --- the unsigned messages -------------------------------------------------------------------

    fn round_trip_pledge(m: &FromPledge) {
        let line = m.encode().unwrap();
        assert_eq!(line.last(), Some(&b'\n'));
        assert_eq!(&FromPledge::parse(&line[..line.len() - 1]).unwrap(), m);
    }

    #[test]
    fn every_message_round_trips_in_its_direction() {
        round_trip_pledge(&FromPledge::Signin(signed()));
        round_trip_pledge(&FromPledge::Ping);
        round_trip_pledge(&FromPledge::Withdraw(fp('Q')));
        round_trip_pledge(&FromPledge::Exchange(Box::new(Message::Hello)));
        round_trip_pledge(&FromPledge::Exchange(Box::new(Message::Cancel(crate::exchange::Cancel {
            request: hash(),
        }))));
        for m in [
            FromService::Ack(hash()),
            FromService::Exchange(Box::new(Message::Cancel(crate::exchange::Cancel { request: hash() }))),
        ] {
            let line = m.encode().unwrap();
            assert_eq!(FromService::parse(&line[..line.len() - 1]).unwrap(), m);
        }
        for m in [
            ToPledge::Challenge(N),
            ToPledge::Ready,
            ToPledge::NotReady,
            ToPledge::Notice(signed()),
            ToPledge::Registered(fp('Q')),
            ToPledge::NotRegistered { delegation: fp('Q'), reason: NotRegisteredReason::TooLong },
            ToPledge::Exchange(Box::new(Message::Error(crate::exchange::ErrorMessage {
                error: ErrorCode::Superseded,
            }))),
        ] {
            let line = m.encode().unwrap();
            assert_eq!(ToPledge::parse(&line[..line.len() - 1]).unwrap(), m, "{m:?}");
        }
    }

    #[test]
    fn the_wire_forms_are_the_documents() {
        let doc = STANDARD.encode(b"{\"v\":1}");
        let sig = signature_to_base64(SIG);
        assert_eq!(FromPledge::Ping.encode().unwrap(), b"{\"schema_version\":1,\"type\":\"ping\"}\n");
        assert_eq!(ToPledge::Ready.encode().unwrap(), b"{\"schema_version\":1,\"type\":\"ready\"}\n");
        assert_eq!(ToPledge::NotReady.encode().unwrap(), b"{\"schema_version\":1,\"type\":\"not-ready\"}\n");
        // `not-ready` carries nothing else.
        assert!(ToPledge::parse(br#"{"schema_version":1,"type":"not-ready","x":1}"#).is_err());
        assert_eq!(
            FromPledge::Signin(signed()).encode().unwrap(),
            format!("{{\"schema_version\":1,\"type\":\"signin\",\"doc\":\"{doc}\",\"doc_sig\":\"{sig}\"}}\n")
                .into_bytes()
        );
        assert_eq!(
            ToPledge::Notice(signed()).encode().unwrap(),
            format!("{{\"schema_version\":1,\"type\":\"notice\",\"doc\":\"{doc}\",\"doc_sig\":\"{sig}\"}}\n")
                .into_bytes()
        );
        assert_eq!(
            ToPledge::Challenge(N).encode().unwrap(),
            format!("{{\"schema_version\":1,\"type\":\"challenge\",\"nonce\":\"{}\"}}\n", nb()).into_bytes()
        );
        assert_eq!(
            ToPledge::Registered(fp('Q')).encode().unwrap(),
            format!("{{\"schema_version\":1,\"type\":\"registered\",\"delegation\":\"{}\"}}\n", fp('Q')).into_bytes()
        );
        assert_eq!(
            ToPledge::NotRegistered { delegation: fp('Q'), reason: NotRegisteredReason::NotYours }.encode().unwrap(),
            format!(
                "{{\"schema_version\":1,\"type\":\"not-registered\",\"delegation\":\"{}\",\"reason\":\"not-yours\"}}\n",
                fp('Q')
            )
            .into_bytes()
        );
        assert_eq!(
            FromPledge::Withdraw(fp('Q')).encode().unwrap(),
            format!("{{\"schema_version\":1,\"type\":\"withdraw\",\"delegation\":\"{}\"}}\n", fp('Q')).into_bytes()
        );
        assert_eq!(
            FromService::Ack(hash()).encode().unwrap(),
            format!("{{\"schema_version\":1,\"type\":\"ack\",\"request\":\"{}\"}}\n", hash()).into_bytes()
        );
    }

    #[test]
    fn what_does_not_belong_in_a_direction_is_not_read_as_that_message() {
        // A broker type from the wrong side is an unknown type; an exchange type from the wrong side parses (the program refuses it).
        let ping = br#"{"schema_version":1,"type":"ping"}"#;
        let ready = br#"{"schema_version":1,"type":"ready"}"#;
        let signin =
            format!(r#"{{"schema_version":1,"type":"signin","doc":"e30=","doc_sig":"{}"}}"#, signature_to_base64(SIG));
        assert_eq!(FromService::parse(ping), Err(ExchangeError::UnknownType));
        assert_eq!(FromService::parse(signin.as_bytes()), Err(ExchangeError::UnknownType));
        assert_eq!(ToPledge::parse(ping), Err(ExchangeError::UnknownType));
        assert_eq!(FromPledge::parse(ready), Err(ExchangeError::UnknownType));
        assert_eq!(
            FromPledge::parse(br#"{"schema_version":1,"type":"ack","request":"sha256:00"}"#),
            Err(ExchangeError::UnknownType)
        );
        assert!(
            matches!(FromPledge::parse(br#"{"schema_version":1,"type":"hello"}"#), Ok(FromPledge::Exchange(m)) if *m == Message::Hello)
        );
    }

    #[test]
    fn every_message_refusal_has_its_own_error_and_code() {
        let sig = signature_to_base64(SIG);
        let doc = STANDARD.encode(b"x");
        let signin = |doc: &str, sig: &str| {
            format!(r#"{{"schema_version":1,"type":"signin","doc":"{doc}","doc_sig":"{sig}"}}"#).into_bytes()
        };
        assert!(FromPledge::parse(&signin(&doc, &sig)).is_ok());
        assert_eq!(FromPledge::parse(&signin("!!!", &sig)), Err(ExchangeError::BadBase64("doc")));
        assert_eq!(FromPledge::parse(&signin(&doc, "!!!")), Err(ExchangeError::BadBase64("doc_sig")));
        assert_eq!(FromPledge::parse(&signin(&doc, doc.as_str())), Err(ExchangeError::BadSignature("doc_sig")));
        assert_eq!(
            FromPledge::parse(&signin(&doc, &STANDARD.encode("plain text"))),
            Err(ExchangeError::BadSignature("doc_sig"))
        );
        assert_eq!(FromPledge::parse(&signin(doc.trim_end_matches('='), &sig)).is_ok(), !doc.ends_with('='));
        for (line, member) in [
            (br#"{"schema_version":1,"type":"signin","doc":"e30="}"#.to_vec(), "doc_sig"),
            (br#"{"schema_version":1,"type":"signin","doc_sig":"e30="}"#.to_vec(), "doc"),
        ] {
            assert_eq!(FromPledge::parse(&line), Err(ExchangeError::Malformed(ParseError::MissingMember(member))));
        }
        let unknown = format!(r#"{{"schema_version":1,"type":"signin","doc":"{doc}","doc_sig":"{sig}","x":1}}"#);
        assert_eq!(
            FromPledge::parse(unknown.as_bytes()),
            Err(ExchangeError::Malformed(ParseError::UnknownMember("x".into())))
        );
        assert_eq!(FromPledge::parse(br#"{"schema_version":2,"type":"ping"}"#), Err(ExchangeError::UnsupportedVersion));
        assert_eq!(
            FromPledge::parse(br#"{"schema_version":1,"type":"ping","x":1}"#),
            Err(ExchangeError::Malformed(ParseError::UnknownMember("x".into())))
        );
        // Fingerprints, hashes, nonces.
        for bad in ["", "SHA256:short", "sha256:AAAA"] {
            let line = format!(r#"{{"schema_version":1,"type":"withdraw","delegation":"{bad}"}}"#);
            assert_eq!(
                FromPledge::parse(line.as_bytes()),
                Err(ExchangeError::Malformed(ParseError::MalformedFingerprint(bad.into()))),
                "{bad}"
            );
        }
        assert!(matches!(
            FromService::parse(br#"{"schema_version":1,"type":"ack","request":"nope"}"#),
            Err(ExchangeError::Malformed(ParseError::MalformedHash(_)))
        ));
        assert!(matches!(
            ToPledge::parse(br#"{"schema_version":1,"type":"challenge","nonce":"AAAA"}"#),
            Err(ExchangeError::Malformed(ParseError::BadLength { .. }))
        ));
        assert!(matches!(
            ToPledge::parse(br#"{"schema_version":1,"type":"challenge"}"#),
            Err(ExchangeError::Malformed(ParseError::MissingMember("nonce")))
        ));
        // A certificate that is not one has no fingerprint to answer under: `error` `malformed-line`.
        let e =
            FromPledge::parse(br#"{"schema_version":1,"type":"delegation","cert":"not a certificate"}"#).unwrap_err();
        assert!(matches!(e, ExchangeError::BadCertificate(_)));
        assert_eq!(e.code(), Some(ErrorCode::MalformedLine));
        // Every one of these maps to a code a receiver sends.
        for line in [
            &br#"{"schema_version":1,"type":"ping""#[..],
            b"[]",
            b"",
            br#"{"schema_version":2,"type":"ping"}"#,
            br#"{"schema_version":1,"type":"gremlin"}"#,
        ] {
            assert!(FromPledge::parse(line).unwrap_err().code().is_some());
        }
        assert_eq!(FromPledge::parse(&vec![b' '; crate::exchange::MAX_LINE + 1]), Err(ExchangeError::LineTooLong));
    }

    #[test]
    fn an_unknown_reason_is_never_written_back() {
        let line =
            format!(r#"{{"schema_version":1,"type":"not-registered","delegation":"{}","reason":"gremlins"}}"#, fp('Q'));
        let m = ToPledge::parse(line.as_bytes()).unwrap();
        assert_eq!(m, ToPledge::NotRegistered { delegation: fp('Q'), reason: NotRegisteredReason::Unknown });
        let out = String::from_utf8(m.encode().unwrap()).unwrap();
        assert!(out.contains(r#""reason":"unknown""#) && !out.contains("gremlins"), "{out}");
        for r in NotRegisteredReason::ALL {
            assert_eq!(NotRegisteredReason::from_wire(r.wire()), *r);
        }
        assert_eq!(
            NotRegisteredReason::ALL.iter().map(|r| r.wire()).collect::<Vec<_>>(),
            ["bad-certificate", "too-long", "not-yours", "blocked", "unavailable"]
        );
    }

    #[test]
    fn the_first_line_says_which_exchange_this_is() {
        let hello = br#"{"schema_version":1,"type":"hello"}"#;
        assert_eq!(first_kind(hello), First::Pledge);
        let submit = crate::exchange::Message::Submit(
            crate::exchange::Submit::new(crate::request::tests::request(), crate::request::tests::SIG).unwrap(),
        );
        let line = submit.encode(ClearancePolicy::Refused).unwrap();
        assert_eq!(first_kind(&line[..line.len() - 1]), First::Service);
        // A `submit` whose request does not parse is still a service's.
        let bad_request = format!(
            r#"{{"schema_version":1,"type":"submit","request":"{}","request_sig":"{}"}}"#,
            STANDARD.encode(b"{}"),
            signature_to_base64(crate::request::tests::SIG)
        );
        assert_eq!(first_kind(bad_request.as_bytes()), First::Service);
        for other in [&br#"{"schema_version":1,"type":"ping"}"#[..], br#"{"schema_version":1,"type":"signin"}"#, br#"{"schema_version":1,"type":"cancel","request":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}"#] {
            assert_eq!(first_kind(other), First::Refuse(ErrorCode::MalformedLine), "{}", String::from_utf8_lossy(other));
        }
        assert_eq!(
            first_kind(br#"{"schema_version":1,"type":"hello","x":1}"#),
            First::Refuse(ErrorCode::MalformedLine)
        );
        assert_eq!(first_kind(br#"{"schema_version":2,"type":"hello"}"#), First::Refuse(ErrorCode::UnsupportedVersion));
        assert_eq!(first_kind(b"not json"), First::Refuse(ErrorCode::MalformedLine));
        assert_eq!(first_kind(&vec![b' '; crate::exchange::MAX_LINE + 1]), First::Refuse(ErrorCode::LineTooLong));
        let _ = json!(null);
    }

    #[test]
    fn withdrawn_answers_a_withdraw_and_says_whether_it_is_stored() {
        for stored in [true, false] {
            let m = ToPledge::Withdrawn { delegation: fp('Q'), stored };
            let line = m.encode().unwrap();
            assert_eq!(
                line,
                format!(
                    "{{\"schema_version\":1,\"type\":\"withdrawn\",\"delegation\":\"{}\",\"stored\":{stored}}}\n",
                    fp('Q')
                )
                .into_bytes()
            );
            assert_eq!(ToPledge::parse(&line[..line.len() - 1]).unwrap(), m);
        }
        let with =
            |tail: &str| format!(r#"{{"schema_version":1,"type":"withdrawn","delegation":"{}"{tail}}}"#, fp('Q'));
        assert_eq!(
            ToPledge::parse(with("").as_bytes()),
            Err(ExchangeError::Malformed(ParseError::MissingMember("stored")))
        );
        for bad in ["\"true\"", "1", "0", "null", "[]"] {
            assert!(
                matches!(
                    ToPledge::parse(with(&format!(r#","stored":{bad}"#)).as_bytes()),
                    Err(ExchangeError::Malformed(ParseError::WrongType { .. }))
                ),
                "{bad}"
            );
        }
        assert_eq!(
            ToPledge::parse(with(r#","stored":true,"x":1"#).as_bytes()),
            Err(ExchangeError::Malformed(ParseError::UnknownMember("x".into())))
        );
        assert!(matches!(
            ToPledge::parse(br#"{"schema_version":1,"type":"withdrawn","delegation":"nope","stored":true}"#),
            Err(ExchangeError::Malformed(ParseError::MalformedFingerprint(_)))
        ));
        // It is the broker's answer: a pledge does not send it, a service does not read it.
        assert_eq!(FromPledge::parse(with(r#","stored":true"#).as_bytes()), Err(ExchangeError::UnknownType));
        assert_eq!(FromService::parse(with(r#","stored":true"#).as_bytes()), Err(ExchangeError::UnknownType));
    }

    #[test]
    fn unavailable_is_a_reason_a_registration_can_get() {
        let m = ToPledge::NotRegistered { delegation: fp('Q'), reason: NotRegisteredReason::Unavailable };
        let line = m.encode().unwrap();
        assert!(String::from_utf8_lossy(&line).contains(r#""reason":"unavailable""#));
        assert_eq!(ToPledge::parse(&line[..line.len() - 1]).unwrap(), m);
        assert_eq!(NotRegisteredReason::from_wire("unavailable"), NotRegisteredReason::Unavailable);
    }

    #[test]
    fn a_first_message_with_an_unknown_version_is_told_apart() {
        let submit = |version: &str| {
            format!(
                r#"{{"schema_version":{version},"type":"submit","request":"{}","request_sig":"{}"}}"#,
                STANDARD.encode(b"{}"),
                signature_to_base64(crate::request::tests::SIG)
            )
        };
        let hello = |version: &str| format!(r#"{{"schema_version":{version},"type":"hello"}}"#);
        // Well-formed `hello` and `submit` of another version: `unsupported-version`.
        for version in ["2", "0", "99", "1.5", "-1"] {
            assert_eq!(
                first_kind(hello(version).as_bytes()),
                First::Refuse(ErrorCode::UnsupportedVersion),
                "hello {version}"
            );
            assert_eq!(
                first_kind(submit(version).as_bytes()),
                First::Refuse(ErrorCode::UnsupportedVersion),
                "submit {version}"
            );
        }
        // Version 1 is as before.
        assert_eq!(first_kind(hello("1").as_bytes()), First::Pledge);
        assert_eq!(first_kind(submit("1").as_bytes()), First::Service);
        // Anything else that is neither stays `malformed-line`: another type, extra members, missing ones, a version that is not a number.
        let others = [
            r#"{"schema_version":2,"type":"ping"}"#.to_owned(),
            r#"{"schema_version":2,"type":"signin","doc":"e30=","doc_sig":"e30="}"#.to_owned(),
            r#"{"schema_version":2,"type":"hello","x":1}"#.to_owned(),
            submit("2").replacen('}', r#","x":1}"#, 1),
            r#"{"schema_version":2,"type":"submit","request":"e30="}"#.to_owned(),
            r#"{"schema_version":2,"type":"submit"}"#.to_owned(),
            r#"{"schema_version":"2","type":"hello"}"#.to_owned(),
            r#"{"type":"hello"}"#.to_owned(),
            r#"{"schema_version":2}"#.to_owned(),
            r#"{"schema_version":2,"type":"hello","type":"hello"}"#.to_owned(),
            r#"{"schema_version":2,"type":"hel\u0000lo"}"#.to_owned(),
            hello("2").replace("hello", "Hello"),
            "[]".to_owned(),
            String::new(),
            "not json".to_owned(),
        ];
        for line in &others {
            assert_eq!(first_kind(line.as_bytes()), First::Refuse(ErrorCode::MalformedLine), "{line}");
        }
        assert_eq!(first_kind(&vec![b' '; crate::exchange::MAX_LINE + 1]), First::Refuse(ErrorCode::LineTooLong));
    }

    #[test]
    fn the_string_rules_apply_to_every_string_member_of_every_message() {
        // A control character or a bidirectional mark in any string member is refused, signed or not.
        let doc = STANDARD.encode(b"x");
        let sig = signature_to_base64(SIG);
        let nonce = nb();
        let delegation = fp('Q').to_string();
        let hash = hash().to_string();
        let lines = [
            (
                "signin",
                format!(r#"{{"schema_version":1,"type":"signin","doc":"{doc}","doc_sig":"{sig}"}}"#),
                vec!["type", "doc", "doc_sig"],
            ),
            (
                "withdraw",
                format!(r#"{{"schema_version":1,"type":"withdraw","delegation":"{delegation}"}}"#),
                vec!["type", "delegation"],
            ),
            ("ack", format!(r#"{{"schema_version":1,"type":"ack","request":"{hash}"}}"#), vec!["type", "request"]),
            (
                "challenge",
                format!(r#"{{"schema_version":1,"type":"challenge","nonce":"{nonce}"}}"#),
                vec!["type", "nonce"],
            ),
            (
                "notice",
                format!(r#"{{"schema_version":1,"type":"notice","doc":"{doc}","doc_sig":"{sig}"}}"#),
                vec!["type", "doc", "doc_sig"],
            ),
            (
                "registered",
                format!(r#"{{"schema_version":1,"type":"registered","delegation":"{delegation}"}}"#),
                vec!["type", "delegation"],
            ),
            (
                "not-registered",
                format!(
                    r#"{{"schema_version":1,"type":"not-registered","delegation":"{delegation}","reason":"blocked"}}"#
                ),
                vec!["type", "delegation", "reason"],
            ),
            (
                "withdrawn",
                format!(r#"{{"schema_version":1,"type":"withdrawn","delegation":"{delegation}","stored":true}}"#),
                vec!["type", "delegation"],
            ),
            (
                "answer",
                format!(
                    r#"{{"schema_version":1,"type":"answer","request":"{hash}","result":"refused","by":"pledge","reason":"limit"}}"#
                ),
                vec!["type", "request", "result", "by", "reason"],
            ),
            ("error", r#"{"schema_version":1,"type":"error","error":"signin"}"#.to_owned(), vec!["type", "error"]),
            (
                "approved answer",
                format!(
                    r#"{{"schema_version":1,"type":"answer","request":"{hash}","result":"approved","approval":"{sig}"}}"#
                ),
                vec!["result", "approval"],
            ),
            (
                "cancel",
                format!(r#"{{"schema_version":1,"type":"cancel","request":"{hash}"}}"#),
                vec!["type", "request"],
            ),
        ];
        let parse_any = |line: &[u8]| -> bool {
            FromPledge::parse(line).is_ok() || FromService::parse(line).is_ok() || ToPledge::parse(line).is_ok()
        };
        for (kind, line, members) in &lines {
            assert!(parse_any(line.as_bytes()), "{kind} as written");
            for member in members {
                for (mark, what) in [
                    ("\\u0000", "NUL"),
                    ("\\u001f", "unit separator"),
                    ("\\u007f", "DEL"),
                    ("\\u0085", "NEL"),
                    ("\\u202e", "bidi override"),
                    ("\\u2066", "bidi isolate"),
                ] {
                    let needle = format!("\"{member}\":\"");
                    let at = line.find(&needle).unwrap_or_else(|| panic!("{kind}: no {member}")) + needle.len();
                    let broken = format!("{}{mark}{}", &line[..at], &line[at..]);
                    assert!(!parse_any(broken.as_bytes()), "{kind}.{member} with {what} was read");
                }
            }
        }
        // The signed documents carry strings too: the person, the groups, the entries, the certificates.
        let connection = |person: &str| {
            format!(
                r#"{{"v":1,"type":"connection","person":"{person}","nonce":"{nonce}","tls":"{}"}}"#,
                STANDARD.encode(T)
            )
        };
        assert_eq!(
            ConnectionDocument::parse_unverified(connection("j\\u202en")),
            Err(ParseError::BidiMark("person".into()))
        );
        assert_eq!(
            ConnectionDocument::parse_unverified(connection("j\\u0007n")),
            Err(ParseError::ControlCharacter("person".into()))
        );
        let standing = |groups: &str, to: &str| {
            format!(
                r#"{{"v":1,"type":"standing","to":"{to}","nonce":"{nonce}","n":0,"at":"2026-11-11T15:04:41Z","blocked":false,"blocked_keys":[],"withdrawn":[],"certificates":[],"groups":[{groups}]}}"#
            )
        };
        assert_eq!(
            Standing::parse_unverified(standing("\"o\\u202eps\"", "jan")),
            Err(ParseError::BidiMark("groups".into()))
        );
        assert_eq!(
            Standing::parse_unverified(standing("\"o\\u0000ps\"", "jan")),
            Err(ParseError::ControlCharacter("groups".into()))
        );
        assert_eq!(
            Standing::parse_unverified(standing("", "ja\\u0000n")),
            Err(ParseError::ControlCharacter("to".into()))
        );
        let with_cert = standing("", "jan")
            .replace(r#""certificates":[]"#, r#""certificates":["ssh-ed25519-cert-v01@openssh.com AAAA\u0000"]"#);
        assert_eq!(Standing::parse_unverified(with_cert), Err(ParseError::ControlCharacter("certificates".into())));
        let key = standing("", "jan").replace(r#""blocked_keys":[]"#, r#""blocked_keys":["SHA256:\u202e"]"#);
        assert_eq!(Standing::parse_unverified(key), Err(ParseError::BidiMark("blocked_keys".into())));
    }

    #[test]
    fn the_tls_agreements_are_the_documents() {
        // Section 5: label `EXPORTER-procession-connection-v1`, no context, 32 bytes; sections 1 and 8: TLS 1.3 only, `ring`.
        assert_eq!(TLS_EXPORTER_LABEL, b"EXPORTER-procession-connection-v1");
        assert_eq!(TLS_EXPORTER_CONTEXT, None);
        assert_eq!(TLS_EXPORTER_LENGTH, 32);
        assert_eq!(TLS_EXPORTER_LENGTH, std::mem::size_of::<Secret32>());
        assert_eq!(TLS_PROTOCOL_VERSION, "TLSv1.3");
        assert!(is_tls_1_3(TLS_PROTOCOL_VERSION) && is_tls_1_3("TLSv1_3"));
        for other in ["TLSv1.2", "TLSv1_2", "tlsv1.3", "TLSv1.3 ", "", "TLS1.3", "SSLv3"] {
            assert!(!is_tls_1_3(other), "{other:?}");
        }
        assert_eq!(TLS_CRYPTO_PROVIDER, "ring");
        assert_eq!(TLS_EXPORTER_LABEL, crate::limits::TLS_EXPORTER_LABEL.as_bytes());
    }

    #[test]
    fn a_carried_document_is_parsed_and_its_bytes_kept() {
        let doc = br#"{"v":1,"type":"hosts"}"#.to_vec();
        let m = ToPledge::Carried {
            namespace: "hosts-v1@procession".into(),
            signed: Signed { doc: doc.clone(), sig: SIG.into() },
        };
        let line = m.encode().unwrap();
        assert_eq!(
            line,
            format!(
                "{{\"schema_version\":1,\"type\":\"carried\",\"namespace\":\"hosts-v1@procession\",\"doc\":\"{}\",\"doc_sig\":\"{}\"}}\n",
                STANDARD.encode(&doc),
                signature_to_base64(SIG)
            )
            .into_bytes()
        );
        let ToPledge::Carried { namespace, signed } = ToPledge::parse(&line[..line.len() - 1]).unwrap() else {
            panic!()
        };
        assert_eq!((namespace.as_str(), signed.doc, signed.sig.as_str()), ("hosts-v1@procession", doc, SIG));
        // A namespace its reader does not know is still parsed (the reader ignores it).
        let other = String::from_utf8(line.clone()).unwrap().replace("hosts-v1@procession", "future-v9@procession");
        assert!(
            matches!(ToPledge::parse(other.trim_end().as_bytes()), Ok(ToPledge::Carried { namespace, .. }) if namespace == "future-v9@procession")
        );
        // Refusals: members, namespace shape, base64, signature, strings.
        let text = String::from_utf8(line).unwrap();
        let text = text.trim_end();
        let swap = |from: &str, to: &str| text.replacen(from, to, 1).into_bytes();
        assert_eq!(
            ToPledge::parse(&swap(r#","namespace":"hosts-v1@procession""#, "")),
            Err(ExchangeError::Malformed(ParseError::MissingMember("namespace")))
        );
        assert_eq!(
            ToPledge::parse(&swap(r#""doc_sig""#, r#""x":1,"doc_sig""#)),
            Err(ExchangeError::Malformed(ParseError::UnknownMember("x".into())))
        );
        for bad in ["", "a b", "a\\u0000b", "a\\u202eb", &"a".repeat(65), "é"] {
            assert!(ToPledge::parse(&swap("hosts-v1@procession", bad)).is_err(), "{bad:?}");
        }
        assert_eq!(ToPledge::parse(&swap(&STANDARD.encode(m_doc()), "!!!")), Err(ExchangeError::BadBase64("doc")));
        assert!(matches!(
            ToPledge::parse(&swap(&signature_to_base64(SIG), &STANDARD.encode("plain"))),
            Err(ExchangeError::BadSignature("doc_sig"))
        ));
        // It is the broker's message: a pledge does not send it, a service does not read it.
        assert_eq!(FromPledge::parse(text.as_bytes()), Err(ExchangeError::UnknownType));
        assert_eq!(FromService::parse(text.as_bytes()), Err(ExchangeError::UnknownType));
        assert!(matches!(
            ToPledge::Carried { namespace: "x".into(), signed: Signed { doc: vec![], sig: "no".into() } }.encode(),
            Err(EncodeError::NotArmoured(_))
        ));
    }

    fn m_doc() -> Vec<u8> {
        br#"{"v":1,"type":"hosts"}"#.to_vec()
    }
}
