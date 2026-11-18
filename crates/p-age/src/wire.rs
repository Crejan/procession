//! The messages of the connections that are the broker's own: the sign-in, the
//! standing, delegations and withdrawals (`approval-connections.md`, sections
//! 4 and 5). The shared exchange (`submit`, `answer`, `cancel`, `error`) is
//! `p_act::exchange`; nothing of it is written here.
//!
//! The same strictness as the exchange: one object, every member known, a
//! `schema_version` of 1, nothing cleaned up.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p_act::DocumentHash;
use p_act::exchange::{
    Answer, Cancel, ClearancePolicy, ErrorCode, ErrorMessage, ExchangeError, Message, SCHEMA_VERSION, Submit,
};
use p_act::sign::{Fingerprint, signature_from_base64, signature_to_base64};
use serde::{Deserialize, Serialize};

use crate::site::valid_name;

/// What a document of the connections may be at most; they are small.
const MAX_DOCUMENT_BYTES: usize = 8 * 1024;

#[derive(Deserialize)]
struct Peek {
    #[serde(rename = "type")]
    kind: String,
}

/// A line from pledge on its connection.
#[derive(Debug)]
pub enum PledgeIn {
    /// The connection document's bytes and the armoured signature over them.
    Signin {
        doc: Vec<u8>,
        doc_sig: String,
    },
    Ping,
    /// An agent's certificate, as the line of its `-cert.pub` file.
    Delegation {
        cert: String,
    },
    Withdraw {
        delegation: Fingerprint,
    },
    /// A message of the shared exchange.
    Exchange(Box<Message>),
}

/// A line from a service on its connection.
#[derive(Debug)]
pub enum ServiceIn {
    /// The service has the answer and the broker may drop what it held.
    Ack {
        request: DocumentHash,
    },
    Exchange(Box<Message>),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SigninWire {
    schema_version: u32,
    #[serde(rename = "type")]
    _kind: String,
    doc: String,
    doc_sig: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BareWire {
    schema_version: u32,
    #[serde(rename = "type")]
    _kind: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DelegationWire {
    schema_version: u32,
    #[serde(rename = "type")]
    _kind: String,
    cert: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WithdrawWire {
    schema_version: u32,
    #[serde(rename = "type")]
    _kind: String,
    delegation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AckWire {
    schema_version: u32,
    #[serde(rename = "type")]
    _kind: String,
    request: String,
}

/// Why a line was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseFailure {
    /// The connection is closed, after this `error` if there is one (a cut-off or failed read has none).
    Close(Option<ErrorCode>),
    /// A `submit` whose request does not parse, with the hash of the bytes it carried: answered `refused`.
    BadRequest(DocumentHash),
}

const MALFORMED: ParseFailure = ParseFailure::Close(Some(ErrorCode::MalformedLine));

fn parse<'a, T: Deserialize<'a>>(line: &'a [u8]) -> Result<T, ParseFailure> {
    serde_json::from_slice(line).map_err(|_| MALFORMED)
}

fn version(v: u32) -> Result<(), ParseFailure> {
    if v == SCHEMA_VERSION { Ok(()) } else { Err(ParseFailure::Close(Some(ErrorCode::UnsupportedVersion))) }
}

fn exchange(line: &[u8]) -> Result<Message, ParseFailure> {
    Message::parse(line, ClearancePolicy::Refused).map_err(|e: ExchangeError| match e {
        ExchangeError::BadRequest { hash, .. } => ParseFailure::BadRequest(hash),
        other => ParseFailure::Close(other.code()),
    })
}

fn kind(line: &[u8]) -> Result<String, ParseFailure> {
    Ok(parse::<Peek>(line)?.kind)
}

/// What a connection's first message says it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum First {
    /// `submit`: a service's exchange.
    Service,
    /// `hello`: a pledge's.
    Pledge,
    /// Anything else, or a `hello` that is not exactly one: an `error` and the end.
    Refuse(ErrorCode),
}

/// Tell from the first line which exchange this connection carries. Nothing else is read from it here.
#[must_use]
pub fn first_kind(line: &[u8]) -> First {
    match kind(line).as_deref() {
        Ok("submit") => First::Service,
        // p-act's parse is the one rule for what a `hello` is.
        Ok("hello") => match exchange(line) {
            Ok(Message::Hello) => First::Pledge,
            // Nothing more is said than that this is not a beginning.
            _ => First::Refuse(ErrorCode::MalformedLine),
        },
        _ => First::Refuse(ErrorCode::MalformedLine),
    }
}

/// Parse a line from pledge.
pub fn parse_pledge_line(line: &[u8]) -> Result<PledgeIn, ParseFailure> {
    match kind(line)?.as_str() {
        "signin" => {
            let w: SigninWire = parse(line)?;
            version(w.schema_version)?;
            let doc = STANDARD.decode(&w.doc).map_err(|_| MALFORMED)?;
            let doc_sig = signature_from_base64(&w.doc_sig).map_err(|_| MALFORMED)?;
            Ok(PledgeIn::Signin { doc, doc_sig })
        }
        "ping" => {
            let w: BareWire = parse(line)?;
            version(w.schema_version)?;
            Ok(PledgeIn::Ping)
        }
        "delegation" => {
            let w: DelegationWire = parse(line)?;
            version(w.schema_version)?;
            Ok(PledgeIn::Delegation { cert: w.cert })
        }
        "withdraw" => {
            let w: WithdrawWire = parse(line)?;
            version(w.schema_version)?;
            let delegation = w.delegation.parse().map_err(|_| MALFORMED)?;
            Ok(PledgeIn::Withdraw { delegation })
        }
        _ => exchange(line).map(|m| PledgeIn::Exchange(Box::new(m))),
    }
}

/// Parse a line from a service.
pub fn parse_service_line(line: &[u8]) -> Result<ServiceIn, ParseFailure> {
    if kind(line)? == "ack" {
        let w: AckWire = parse(line)?;
        version(w.schema_version)?;
        let request = w.request.parse().map_err(|_| MALFORMED)?;
        return Ok(ServiceIn::Ack { request });
    }
    exchange(line).map(|m| ServiceIn::Exchange(Box::new(m)))
}

// ---------------------------------------------------------------------------
// The connection document and the standing
// ---------------------------------------------------------------------------

/// The signed document pledge signs in with (`approval-connections.md` section 5).
#[derive(Debug, PartialEq, Eq)]
pub struct ConnectionDoc {
    pub person: String,
    /// The nonce the broker sent, base64.
    pub nonce: String,
    /// The TLS exporter value, base64.
    pub tls: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnectionWire {
    v: u32,
    #[serde(rename = "type")]
    kind: String,
    person: String,
    nonce: String,
    tls: String,
}

impl ConnectionDoc {
    /// Parse the document's bytes. Not verified: the signature is.
    pub fn parse(bytes: &[u8]) -> Option<ConnectionDoc> {
        if bytes.len() > MAX_DOCUMENT_BYTES || bytes.contains(&b'\n') {
            return None;
        }
        let w: ConnectionWire = serde_json::from_slice(bytes).ok()?;
        (w.v == 1 && w.kind == "connection" && valid_name(&w.person)).then_some(ConnectionDoc {
            person: w.person,
            nonce: w.nonce,
            tls: w.tls,
        })
    }

    /// The bytes of a document, as pledge writes them (for tests and for pledge's own use).
    #[must_use]
    pub fn compose(person: &str, nonce: &str, tls: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({"v":1,"type":"connection","person":person,"nonce":nonce,"tls":tls}))
            .unwrap_or_default()
    }
}

/// What the broker holds for one person, completely, every time
/// (`approval-connections.md` section 5, "The standing").
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Standing {
    v: u32,
    #[serde(rename = "type")]
    kind: &'static str,
    pub to: String,
    pub nonce: String,
    pub n: u64,
    pub blocked: bool,
    pub blocked_keys: Vec<String>,
    pub withdrawn: Vec<String>,
    pub certificates: Vec<String>,
    pub groups: Vec<String>,
}

impl Standing {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        to: &str,
        nonce: &str,
        n: u64,
        blocked: bool,
        blocked_keys: Vec<String>,
        withdrawn: Vec<String>,
        certificates: Vec<String>,
        groups: Vec<String>,
    ) -> Standing {
        Standing {
            v: 1,
            kind: "standing",
            to: to.to_owned(),
            nonce: nonce.to_owned(),
            n,
            blocked,
            blocked_keys,
            withdrawn,
            certificates,
            groups,
        }
    }

    /// The bytes that are signed.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap_or_default()
    }
}

// ---------------------------------------------------------------------------
// What the broker writes
// ---------------------------------------------------------------------------

/// Why a delegation was not registered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotRegistered {
    BadCertificate,
    TooLong,
    NotYours,
    Blocked,
}

impl NotRegistered {
    #[must_use]
    pub fn wire(self) -> &'static str {
        match self {
            NotRegistered::BadCertificate => "bad-certificate",
            NotRegistered::TooLong => "too-long",
            NotRegistered::NotYours => "not-yours",
            NotRegistered::Blocked => "blocked",
        }
    }
}

/// What the broker sends to a pledge on its connection.
#[derive(Debug, Clone)]
pub enum PledgeOut {
    Ready,
    /// The standing's bytes and the broker's signature over them.
    Notice {
        doc: Vec<u8>,
        sig: String,
    },
    Submit(Box<Submit>),
    Cancel(DocumentHash),
    Registered(Fingerprint),
    NotRegistered(Fingerprint, NotRegistered),
    Error(ErrorCode),
    /// Close after what was queued before.
    Close,
}

/// What the broker sends to a service on its connection.
#[derive(Debug, Clone)]
pub enum ServiceOut {
    Answer(Answer),
    Error(ErrorCode),
    Close,
}

fn json_line(value: &serde_json::Value) -> Vec<u8> {
    let mut line = serde_json::to_vec(value).unwrap_or_default();
    line.push(b'\n');
    line
}

fn head(kind: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut m = serde_json::Map::new();
    m.insert("schema_version".into(), SCHEMA_VERSION.into());
    m.insert("type".into(), kind.into());
    m
}

/// The challenge line, with the nonce already in base64.
#[must_use]
pub fn challenge_line(nonce_b64: &str) -> Vec<u8> {
    let mut m = head("challenge");
    m.insert("nonce".into(), nonce_b64.into());
    json_line(&m.into())
}

/// The line for a message to a pledge. `None` for `Close`, which is no line.
#[must_use]
pub fn pledge_line(out: &PledgeOut) -> Option<Vec<u8>> {
    let refused = ClearancePolicy::Refused;
    Some(match out {
        PledgeOut::Ready => json_line(&head("ready").into()),
        PledgeOut::Notice { doc, sig } => {
            let mut m = head("notice");
            m.insert("doc".into(), STANDARD.encode(doc).into());
            m.insert("doc_sig".into(), signature_to_base64(sig).into());
            json_line(&m.into())
        }
        PledgeOut::Submit(s) => Message::Submit((**s).clone()).encode(refused).ok()?,
        PledgeOut::Cancel(h) => Message::Cancel(Cancel { request: *h }).encode(refused).ok()?,
        PledgeOut::Registered(fp) => {
            let mut m = head("registered");
            m.insert("delegation".into(), fp.to_string().into());
            json_line(&m.into())
        }
        PledgeOut::NotRegistered(fp, why) => {
            let mut m = head("not-registered");
            m.insert("delegation".into(), fp.to_string().into());
            m.insert("reason".into(), why.wire().into());
            json_line(&m.into())
        }
        PledgeOut::Error(code) => Message::Error(ErrorMessage { error: *code }).encode(refused).ok()?,
        PledgeOut::Close => return None,
    })
}

/// The line for a message to a service. `None` for `Close`, or if the answer cannot be written.
#[must_use]
pub fn service_line(out: &ServiceOut) -> Option<Vec<u8>> {
    match out {
        ServiceOut::Answer(a) => Message::Answer(a.clone()).encode(ClearancePolicy::Required).ok(),
        ServiceOut::Error(code) => Message::Error(ErrorMessage { error: *code }).encode(ClearancePolicy::Required).ok(),
        ServiceOut::Close => None,
    }
}
