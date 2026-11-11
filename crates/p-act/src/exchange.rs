//! The shared exchange of `doc/approval-connections.md` section 3: the
//! unsigned messages `submit`, `answer`, `cancel` and `error`, and a bounded
//! line reader and writer for them. The same on every transport.
//!
//! No sockets, no TLS, no policy: which answer is final, what is stored and who
//! may connect are the programs'. The 10-second line timeout is the
//! transport's.
//!
//! - A message is one JSON object per line, at most [`MAX_LINE`] bytes, with
//!   `schema_version` 1 and a `type`. Everything strict: unknown members, an
//!   unknown version or type, base64 that is not padded standard base64, strings
//!   that break the formats' rules, two objects on a line: each refused with its
//!   own [`ExchangeError`], which maps to one of the document's `error` codes.
//! - Codes (`result`, `by`, reasons, error codes) are closed enums. A code the
//!   reader does not know parses to `Unknown`, whose wire word is `unknown`:
//!   the received text is never kept, so it can never be written back out.
//! - Whether an `answer` carries a clearance is the receiver's configuration,
//!   [`ClearancePolicy`], never "if present".

use crate::clearance::Clearance;
use crate::error::ParseError;
use crate::hash::{Document, DocumentHash};
use crate::object::{Object, check_bytes};
use crate::request::Request;
use crate::sign::{looks_armoured, signature_to_base64};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;
use std::io::{self, Read, Write};
use thiserror::Error;

/// A line is at most 96 KiB, `\n` not counted, on every transport.
pub const MAX_LINE: usize = 96 * 1024;
/// The `schema_version` of every message.
pub const SCHEMA_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Closed code lists
// ---------------------------------------------------------------------------

macro_rules! closed_code {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $($variant,)+
            /// A code this reader does not know. Its wire word is `unknown`; what was received is not kept.
            Unknown,
        }

        impl $name {
            /// Every known code.
            pub const ALL: &'static [$name] = &[$($name::$variant),+];

            /// The code for a received word: `Unknown` for anything not in the list.
            #[must_use]
            pub fn from_wire(word: &str) -> $name {
                match word {
                    $($wire => $name::$variant,)+
                    _ => $name::Unknown,
                }
            }

            /// The word to write.
            #[must_use]
            pub fn wire(self) -> &'static str {
                match self {
                    $($name::$variant => $wire,)+
                    $name::Unknown => "unknown",
                }
            }
        }
    };
}

closed_code! {
    /// Who said no, or that time had run out.
    By { Pledge => "pledge", Broker => "broker" }
}

closed_code! {
    /// pledge's reasons for a refusal (`service-sock.md` section 5, and `blocked`).
    PledgeReason {
        Malformed => "malformed",
        UnknownDelegation => "unknown-delegation",
        DelegationEnded => "delegation-ended",
        DelegationWithdrawn => "delegation-withdrawn",
        DeadlinePast => "deadline-past",
        DeadlineTooFar => "deadline-too-far",
        CallUsed => "call-used",
        ServiceMismatch => "service-mismatch",
        NotShowable => "not-showable",
        Limit => "limit",
        Muted => "muted",
        Ceiling => "ceiling",
        Unavailable => "unavailable",
        Blocked => "blocked",
    }
}

closed_code! {
    /// The broker's reasons for a refusal (connections document 3.7).
    BrokerReason {
        BadRequest => "bad-request",
        Deadline => "deadline",
        Delegation => "delegation",
        Person => "person",
        NotEntitled => "not-entitled",
        TooManyWaiting => "too-many-waiting",
        Busy => "busy",
    }
}

closed_code! {
    /// What an `error` message says, before the sender closes the connection.
    ErrorCode {
        MalformedLine => "malformed-line",
        LineTooLong => "line-too-long",
        UnsupportedVersion => "unsupported-version",
        UnknownType => "unknown-type",
        TooManyOpen => "too-many-open",
        Signin => "signin",
        Blocked => "blocked",
        Superseded => "superseded",
        Busy => "busy",
        Timeout => "timeout",
    }
}

/// A program said no without asking the person: who, and why. The reason is
/// from the list of whoever said it; a known code of the other list, or of no
/// list, is `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refused {
    Pledge(PledgeReason),
    Broker(BrokerReason),
    /// `by` was not known; the reason is not interpreted.
    Unknown,
}

impl Refused {
    fn from_wire(by: &str, reason: &str) -> Refused {
        match By::from_wire(by) {
            By::Pledge => Refused::Pledge(PledgeReason::from_wire(reason)),
            By::Broker => Refused::Broker(BrokerReason::from_wire(reason)),
            By::Unknown => Refused::Unknown,
        }
    }

    fn wire(self) -> (&'static str, &'static str) {
        match self {
            Refused::Pledge(r) => (By::Pledge.wire(), r.wire()),
            Refused::Broker(r) => (By::Broker.wire(), r.wire()),
            Refused::Unknown => (By::Unknown.wire(), "unknown"),
        }
    }
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// Whether an `answer` carries a clearance. A receiver is set up for one of two
/// cases and refuses the other (connections document 3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClearancePolicy {
    /// An `approved` needs both `clearance` and `clearance_sig` (a service in stage 2).
    Required,
    /// An `answer` with either is invalid (a service in stage 1, pledge, the broker reading pledge).
    Refused,
}

/// A request handed over, with the service's signature over it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Submit {
    request: Request,
    request_sig: String,
    hash: DocumentHash,
}

impl Submit {
    /// `request_sig` is the service's armoured signature over the request's bytes. Not verified here.
    pub fn new(request: Request, request_sig: &str) -> Result<Submit, EncodeError> {
        if !looks_armoured(request_sig) {
            return Err(EncodeError::NotArmoured("request_sig"));
        }
        let hash = request.hash();
        Ok(Submit { request, request_sig: request_sig.to_owned(), hash })
    }

    /// The request, parsed from the decoded bytes.
    #[must_use]
    pub fn request(&self) -> &Request {
        &self.request
    }

    /// The service's armoured signature, to be verified by the receiver.
    #[must_use]
    pub fn request_sig(&self) -> &str {
        &self.request_sig
    }

    /// The hash of the request's bytes, which names the request in every later message.
    #[must_use]
    pub fn hash(&self) -> DocumentHash {
        self.hash
    }
}

/// A clearance and its signature, as the broker adds them to an `approved`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearanceAnswer {
    pub clearance: Clearance,
    clearance_sig: String,
}

impl ClearanceAnswer {
    pub fn new(clearance: Clearance, clearance_sig: &str) -> Result<ClearanceAnswer, EncodeError> {
        if !looks_armoured(clearance_sig) {
            return Err(EncodeError::NotArmoured("clearance_sig"));
        }
        Ok(ClearanceAnswer { clearance, clearance_sig: clearance_sig.to_owned() })
    }

    /// The broker's armoured signature over the clearance, to be verified by the receiver.
    #[must_use]
    pub fn clearance_sig(&self) -> &str {
        &self.clearance_sig
    }
}

/// pledge signed. Information only: a service acts only on what it verifies itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approved {
    approval: String,
    /// Present only where the receiver's [`ClearancePolicy`] is `Required`.
    pub clearance: Option<ClearanceAnswer>,
}

impl Approved {
    /// `approval` is the armoured SSHSIG over the request's bytes. Not verified here.
    pub fn new(approval: &str, clearance: Option<ClearanceAnswer>) -> Result<Approved, EncodeError> {
        if !looks_armoured(approval) {
            return Err(EncodeError::NotArmoured("approval"));
        }
        Ok(Approved { approval: approval.to_owned(), clearance })
    }

    /// The approval's armoured signature, to be verified by the receiver.
    #[must_use]
    pub fn approval(&self) -> &str {
        &self.approval
    }
}

/// The outcome of a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Approved(Approved),
    /// The person said no in a dialog.
    Declined,
    Refused(Refused),
    /// The deadline passed with no approval.
    Expired(By),
    /// A `result` this reader does not know. It carries nothing, and is written as `unknown`.
    Unknown,
}

/// What a receiver says about a request it holds, once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// The hash of the request's bytes.
    pub request: DocumentHash,
    pub outcome: Outcome,
}

/// The sender no longer wants an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cancel {
    pub request: DocumentHash,
}

/// The sender closes the connection. Nothing is said about the bytes received.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ErrorMessage {
    pub error: ErrorCode,
}

/// One line of the exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Submit(Submit),
    Answer(Answer),
    Cancel(Cancel),
    Error(ErrorMessage),
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a line was refused. Each has its own variant, and [`ExchangeError::code`]
/// is the `error` code a receiver sends before it closes the connection.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExchangeError {
    #[error("line is longer than {MAX_LINE} bytes")]
    LineTooLong,
    #[error("connection ended inside a line")]
    Truncated,
    #[error("schema_version is not known")]
    UnsupportedVersion,
    #[error("type is not known")]
    UnknownType,
    /// Not one JSON object, a missing, unknown, duplicate or mistyped member, a string that breaks
    /// the formats' rules, a malformed hash, a line break, a byte order mark, bad UTF-8.
    #[error("malformed line: {0}")]
    Malformed(ParseError),
    #[error("member `{0}` is not padded standard base64")]
    BadBase64(&'static str),
    #[error("member `{0}` is not an armoured signature")]
    BadSignature(&'static str),
    /// The request inside a `submit` does not parse. `hash` is that of its decoded bytes, so that a
    /// receiver that wants to can answer `refused`/`malformed` or `bad-request` instead of closing.
    #[error("the request in the submit is refused: {source}")]
    BadRequest { hash: DocumentHash, source: ParseError },
    #[error("the clearance in the answer is refused: {0}")]
    BadClearance(ParseError),
    #[error("an approved answer needs both clearance members")]
    ClearanceMissing,
    #[error("an answer must not carry clearance members here")]
    ClearanceNotAllowed,
    #[error("cannot read: {0}")]
    Io(String),
}

impl ExchangeError {
    /// The `error` code for this refusal. A cut-off or failed read has none: nobody is left to tell.
    #[must_use]
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            ExchangeError::LineTooLong => Some(ErrorCode::LineTooLong),
            ExchangeError::UnsupportedVersion => Some(ErrorCode::UnsupportedVersion),
            ExchangeError::UnknownType => Some(ErrorCode::UnknownType),
            ExchangeError::Truncated | ExchangeError::Io(_) => None,
            ExchangeError::Malformed(_)
            | ExchangeError::BadBase64(_)
            | ExchangeError::BadSignature(_)
            | ExchangeError::BadRequest { .. }
            | ExchangeError::BadClearance(_)
            | ExchangeError::ClearanceMissing
            | ExchangeError::ClearanceNotAllowed => Some(ErrorCode::MalformedLine),
        }
    }
}

impl From<ParseError> for ExchangeError {
    fn from(e: ParseError) -> Self {
        match e {
            ParseError::TooLarge { .. } => ExchangeError::LineTooLong,
            ParseError::UnsupportedVersion(_) => ExchangeError::UnsupportedVersion,
            other => ExchangeError::Malformed(other),
        }
    }
}

/// Why a message could not be written.
#[derive(Debug, Error)]
pub enum EncodeError {
    #[error("member `{0}` is not an armoured signature")]
    NotArmoured(&'static str),
    #[error("an approved answer needs both clearance members here")]
    ClearanceMissing,
    #[error("an answer must not carry clearance members here")]
    ClearanceNotAllowed,
    #[error("the line would be longer than {MAX_LINE} bytes")]
    LineTooLong,
    #[error("write failed: {0}")]
    Io(#[from] io::Error),
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

fn decode(member: &'static str, s: &str) -> Result<Vec<u8>, ExchangeError> {
    STANDARD.decode(s).map_err(|_| ExchangeError::BadBase64(member))
}

fn decode_armour(member: &'static str, s: &str) -> Result<String, ExchangeError> {
    let sig = String::from_utf8(decode(member, s)?).map_err(|_| ExchangeError::BadSignature(member))?;
    if looks_armoured(&sig) { Ok(sig) } else { Err(ExchangeError::BadSignature(member)) }
}

fn take_hash(o: &mut Object) -> Result<DocumentHash, ExchangeError> {
    Ok(o.take_string("request")?.parse()?)
}

impl Message {
    /// Parse one line, without its `\n`. `policy` decides how an `answer` may
    /// carry a clearance.
    pub fn parse(line: &[u8], policy: ClearancePolicy) -> Result<Message, ExchangeError> {
        let mut o = Object::parse(check_bytes(line, MAX_LINE)?, "")?;
        o.take_schema_version()?;
        let kind = o.take_string("type")?;
        let message = match kind.as_str() {
            "submit" => Message::Submit(parse_submit(&mut o)?),
            "answer" => Message::Answer(parse_answer(&mut o, policy)?),
            "cancel" => Message::Cancel(Cancel { request: take_hash(&mut o)? }),
            "error" => Message::Error(ErrorMessage { error: ErrorCode::from_wire(&o.take_string("error")?) }),
            _ => return Err(ExchangeError::UnknownType),
        };
        o.finish()?;
        Ok(message)
    }

    /// The line to write, with its `\n`. Under `policy`, an `approved` answer
    /// without both clearance members (`Required`) or with either (`Refused`)
    /// is refused, as the receiver would.
    pub fn encode(&self, policy: ClearancePolicy) -> Result<Vec<u8>, EncodeError> {
        let mut line = match self {
            Message::Submit(s) => to_json(&SubmitWire {
                schema_version: SCHEMA_VERSION,
                kind: "submit",
                request: STANDARD.encode(s.request.as_bytes()),
                request_sig: signature_to_base64(&s.request_sig),
            }),
            Message::Cancel(c) => {
                to_json(&CancelWire { schema_version: SCHEMA_VERSION, kind: "cancel", request: c.request.to_string() })
            }
            Message::Error(e) => {
                to_json(&ErrorWire { schema_version: SCHEMA_VERSION, kind: "error", error: e.error.wire() })
            }
            Message::Answer(a) => encode_answer(a, policy),
        }?;
        line.push(b'\n');
        if line.len() > MAX_LINE + 1 {
            return Err(EncodeError::LineTooLong);
        }
        Ok(line)
    }
}

fn parse_submit(o: &mut Object) -> Result<Submit, ExchangeError> {
    let request_bytes = decode("request", &o.take_string("request")?)?;
    let request_sig = decode_armour("request_sig", &o.take_string("request_sig")?)?;
    let hash = DocumentHash::of(&request_bytes);
    let request = Request::parse(request_bytes).map_err(|source| ExchangeError::BadRequest { hash, source })?;
    Ok(Submit { request, request_sig, hash })
}

fn parse_answer(o: &mut Object, policy: ClearancePolicy) -> Result<Answer, ExchangeError> {
    let request = take_hash(o)?;
    let outcome = match o.take_string("result")?.as_str() {
        "approved" => {
            let approval = decode_armour("approval", &o.take_string("approval")?)?;
            let (clearance, clearance_sig) =
                (o.take_optional_string("clearance")?, o.take_optional_string("clearance_sig")?);
            let clearance = match (policy, clearance, clearance_sig) {
                (ClearancePolicy::Required, Some(c), Some(s)) => {
                    let clearance = Clearance::parse(decode("clearance", &c)?).map_err(ExchangeError::BadClearance)?;
                    Some(ClearanceAnswer { clearance, clearance_sig: decode_armour("clearance_sig", &s)? })
                }
                (ClearancePolicy::Required, ..) => return Err(ExchangeError::ClearanceMissing),
                (ClearancePolicy::Refused, None, None) => None,
                (ClearancePolicy::Refused, ..) => return Err(ExchangeError::ClearanceNotAllowed),
            };
            Outcome::Approved(Approved { approval, clearance })
        }
        "declined" => Outcome::Declined,
        "refused" => {
            let (by, reason) = (o.take_string("by")?, o.take_string("reason")?);
            Outcome::Refused(Refused::from_wire(&by, &reason))
        }
        "expired" => Outcome::Expired(By::from_wire(&o.take_string("by")?)),
        // Any other word, `unknown` included: no member belongs to it.
        _ => Outcome::Unknown,
    };
    Ok(Answer { request, outcome })
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct SubmitWire {
    schema_version: u32,
    #[serde(rename = "type")]
    kind: &'static str,
    request: String,
    request_sig: String,
}

#[derive(Serialize)]
struct CancelWire {
    schema_version: u32,
    #[serde(rename = "type")]
    kind: &'static str,
    request: String,
}

#[derive(Serialize)]
struct ErrorWire {
    schema_version: u32,
    #[serde(rename = "type")]
    kind: &'static str,
    error: &'static str,
}

#[derive(Serialize)]
struct AnswerWire {
    schema_version: u32,
    #[serde(rename = "type")]
    kind: &'static str,
    request: String,
    result: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    approval: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    clearance: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    clearance_sig: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    by: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
}

fn to_json<T: Serialize>(value: &T) -> Result<Vec<u8>, EncodeError> {
    // Plain strings and numbers cannot fail to serialise.
    serde_json::to_vec(value).map_err(|e| EncodeError::Io(io::Error::other(e)))
}

fn encode_answer(a: &Answer, policy: ClearancePolicy) -> Result<Vec<u8>, EncodeError> {
    let mut wire = AnswerWire {
        schema_version: SCHEMA_VERSION,
        kind: "answer",
        request: a.request.to_string(),
        result: "unknown",
        approval: None,
        clearance: None,
        clearance_sig: None,
        by: None,
        reason: None,
    };
    match &a.outcome {
        Outcome::Approved(approved) => {
            wire.result = "approved";
            wire.approval = Some(signature_to_base64(&approved.approval));
            match (policy, &approved.clearance) {
                (ClearancePolicy::Required, Some(c)) => {
                    wire.clearance = Some(STANDARD.encode(c.clearance.as_bytes()));
                    wire.clearance_sig = Some(signature_to_base64(&c.clearance_sig));
                }
                (ClearancePolicy::Required, None) => return Err(EncodeError::ClearanceMissing),
                (ClearancePolicy::Refused, None) => {}
                (ClearancePolicy::Refused, Some(_)) => return Err(EncodeError::ClearanceNotAllowed),
            }
        }
        Outcome::Declined => wire.result = "declined",
        Outcome::Refused(refused) => {
            let (by, reason) = refused.wire();
            (wire.result, wire.by, wire.reason) = ("refused", Some(by), Some(reason));
        }
        Outcome::Expired(by) => (wire.result, wire.by) = ("expired", Some(by.wire())),
        Outcome::Unknown => {}
    }
    to_json(&wire)
}

/// Write one message as one line, in one `write_all`, and flush.
pub fn write_message<W: Write>(out: &mut W, message: &Message, policy: ClearancePolicy) -> Result<(), EncodeError> {
    out.write_all(&message.encode(policy)?)?;
    Ok(out.flush()?)
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// A reader of lines of at most [`MAX_LINE`] bytes. It holds at most one line
/// and one chunk, whatever the peer sends. The timeout for a line that is not
/// finished is the transport's.
#[derive(Debug)]
pub struct LineReader<R> {
    inner: R,
    buf: Vec<u8>,
    start: usize,
}

impl<R: Read> LineReader<R> {
    pub fn new(inner: R) -> LineReader<R> {
        LineReader { inner, buf: Vec::new(), start: 0 }
    }

    /// The next line without its `\n`; `None` at the end of the input between lines.
    /// After `LineTooLong`, `Truncated` or `Io` the connection is over and the reader is not to be used again.
    pub fn read_line(&mut self) -> Result<Option<Vec<u8>>, ExchangeError> {
        let mut scanned = self.start;
        loop {
            if let Some(offset) = self.buf[scanned..].iter().position(|&b| b == b'\n') {
                let end = scanned + offset;
                if end - self.start > MAX_LINE {
                    return Err(ExchangeError::LineTooLong);
                }
                let line = self.buf[self.start..end].to_vec();
                self.start = end + 1;
                if self.start == self.buf.len() {
                    self.buf.clear();
                    self.start = 0;
                }
                return Ok(Some(line));
            }
            scanned = self.buf.len();
            if self.buf.len() - self.start > MAX_LINE {
                return Err(ExchangeError::LineTooLong);
            }
            self.buf.drain(..self.start);
            scanned -= self.start;
            self.start = 0;
            let mut chunk = [0u8; 8192];
            let n = loop {
                match self.inner.read(&mut chunk) {
                    Ok(n) => break n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(ExchangeError::Io(e.kind().to_string())),
                }
            };
            if n == 0 {
                return if self.buf.is_empty() { Ok(None) } else { Err(ExchangeError::Truncated) };
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// The next message under `policy`; `None` at the end of the input.
    pub fn read_message(&mut self, policy: ClearancePolicy) -> Result<Option<Message>, ExchangeError> {
        self.read_line()?.map(|line| Message::parse(&line, policy)).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::tests::{SIG, request};
    use crate::time::Timestamp;

    const REQUIRED: ClearancePolicy = ClearancePolicy::Required;
    const REFUSED: ClearancePolicy = ClearancePolicy::Refused;

    fn hash() -> DocumentHash {
        request().hash()
    }

    fn submit() -> Message {
        Message::Submit(Submit::new(request(), SIG).unwrap())
    }

    fn answer(outcome: Outcome) -> Message {
        Message::Answer(Answer { request: hash(), outcome })
    }

    fn approved(clearance: bool) -> Message {
        let c = clearance.then(|| {
            let c = Clearance::compose(hash(), Timestamp::from_unix(1_794_409_481).unwrap()).unwrap();
            ClearanceAnswer::new(c, SIG).unwrap()
        });
        answer(Outcome::Approved(Approved::new(SIG, c).unwrap()))
    }

    fn text(m: &Message, policy: ClearancePolicy) -> String {
        String::from_utf8(m.encode(policy).unwrap()).unwrap()
    }

    /// The encoded line of `m` with `from` replaced by `to`, without its `\n`.
    fn edited(m: &Message, policy: ClearancePolicy, from: &str, to: &str) -> Vec<u8> {
        let t = text(m, policy);
        assert!(t.contains(from), "{from} not in {t}");
        t.trim_end().replacen(from, to, 1).into_bytes()
    }

    fn parse(line: &[u8], policy: ClearancePolicy) -> Result<Message, ExchangeError> {
        Message::parse(line, policy)
    }

    fn round_trip(m: &Message, policy: ClearancePolicy) {
        let line = m.encode(policy).unwrap();
        assert_eq!(line.last(), Some(&b'\n'));
        assert!(!line[..line.len() - 1].contains(&b'\n'));
        assert!(line.len() <= MAX_LINE + 1);
        assert_eq!(&parse(&line[..line.len() - 1], policy).unwrap(), m);
    }

    #[test]
    fn every_message_round_trips() {
        round_trip(&submit(), REFUSED);
        round_trip(&submit(), REQUIRED);
        let mut outcomes = vec![Outcome::Declined, Outcome::Unknown, Outcome::Refused(Refused::Unknown)];
        outcomes.extend(PledgeReason::ALL.iter().map(|r| Outcome::Refused(Refused::Pledge(*r))));
        outcomes.extend(BrokerReason::ALL.iter().map(|r| Outcome::Refused(Refused::Broker(*r))));
        outcomes.extend([By::Pledge, By::Broker, By::Unknown].map(Outcome::Expired));
        for outcome in outcomes {
            round_trip(&answer(outcome.clone()), REFUSED);
            round_trip(&answer(outcome), REQUIRED);
        }
        round_trip(&approved(false), REFUSED);
        round_trip(&approved(true), REQUIRED);
        round_trip(&Message::Cancel(Cancel { request: hash() }), REFUSED);
        for code in ErrorCode::ALL.iter().copied().chain([ErrorCode::Unknown]) {
            round_trip(&Message::Error(ErrorMessage { error: code }), REQUIRED);
        }
    }

    #[test]
    fn the_wire_form_is_the_documents() {
        let h = hash();
        assert_eq!(
            text(&answer(Outcome::Declined), REFUSED),
            format!("{{\"schema_version\":1,\"type\":\"answer\",\"request\":\"{h}\",\"result\":\"declined\"}}\n")
        );
        assert_eq!(
            text(&answer(Outcome::Refused(Refused::Broker(BrokerReason::NotEntitled))), REFUSED),
            format!(
                "{{\"schema_version\":1,\"type\":\"answer\",\"request\":\"{h}\",\"result\":\"refused\",\"by\":\"broker\",\"reason\":\"not-entitled\"}}\n"
            )
        );
        assert_eq!(
            text(&answer(Outcome::Expired(By::Broker)), REFUSED),
            format!(
                "{{\"schema_version\":1,\"type\":\"answer\",\"request\":\"{h}\",\"result\":\"expired\",\"by\":\"broker\"}}\n"
            )
        );
        assert_eq!(
            text(&Message::Cancel(Cancel { request: h }), REFUSED),
            format!("{{\"schema_version\":1,\"type\":\"cancel\",\"request\":\"{h}\"}}\n")
        );
        assert_eq!(
            text(&Message::Error(ErrorMessage { error: ErrorCode::MalformedLine }), REFUSED),
            "{\"schema_version\":1,\"type\":\"error\",\"error\":\"malformed-line\"}\n"
        );
        let approved = text(&approved(true), REQUIRED);
        assert!(
            approved.contains(r#""result":"approved","approval":"LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0K"#),
            "{approved}"
        );
        assert!(
            approved.contains(r#","clearance":"eyJ2IjoxLCJ0eXBlIjoiY2xlYXJhbmNlIi"#)
                && approved.contains(r#","clearance_sig":"LS0t"#),
            "{approved}"
        );
        let submit = text(&submit(), REFUSED);
        assert!(submit.starts_with(r#"{"schema_version":1,"type":"submit","request":"eyJ2IjoxLCJ0eXBl"#), "{submit}");
    }

    #[test]
    fn submit_gives_the_request_its_signature_and_its_hash() {
        let Message::Submit(s) = parse(text(&submit(), REFUSED).trim_end().as_bytes(), REFUSED).unwrap() else {
            panic!()
        };
        assert_eq!(s.request(), &request());
        assert_eq!(s.request().call().as_bytes(), crate::call::tests::EXAMPLE.as_bytes());
        assert_eq!(s.request_sig(), SIG);
        assert_eq!(s.hash(), request().hash());
        assert_eq!(s.hash(), DocumentHash::of(request().as_bytes()));
    }

    #[test]
    fn the_clearance_configuration_is_never_if_present() {
        let with = approved(true);
        let without = approved(false);
        // Required: both members, or invalid.
        assert_eq!(parse(with.encode(REQUIRED).unwrap().trim_ascii_end(), REQUIRED).unwrap(), with);
        assert_eq!(
            parse(without.encode(REFUSED).unwrap().trim_ascii_end(), REQUIRED),
            Err(ExchangeError::ClearanceMissing)
        );
        let no_sig = edited(&with, REQUIRED, r#","clearance_sig":"#, r#","x":"#);
        assert!(matches!(parse(&no_sig, REQUIRED), Err(ExchangeError::ClearanceMissing)));
        let t = text(&with, REQUIRED);
        let cut = |member: &str| {
            let start = t.find(&format!(",\"{member}\":")).unwrap();
            let end = t[start + 1..].find(",\"").map_or(t.len() - 2, |e| start + 1 + e);
            format!("{}{}", &t[..start], &t[end..]).trim_end().to_owned().into_bytes()
        };
        assert_eq!(parse(&cut("clearance"), REQUIRED), Err(ExchangeError::ClearanceMissing));
        assert_eq!(parse(&cut("clearance_sig"), REQUIRED), Err(ExchangeError::ClearanceMissing));
        // Refused: either member is invalid, both too.
        assert_eq!(parse(t.trim_end().as_bytes(), REFUSED), Err(ExchangeError::ClearanceNotAllowed));
        assert_eq!(parse(&cut("clearance"), REFUSED), Err(ExchangeError::ClearanceNotAllowed));
        assert_eq!(parse(&cut("clearance_sig"), REFUSED), Err(ExchangeError::ClearanceNotAllowed));
        assert_eq!(parse(text(&without, REFUSED).trim_end().as_bytes(), REFUSED).unwrap(), without);
        // Writing keeps to the same configuration.
        assert!(matches!(without.encode(REQUIRED), Err(EncodeError::ClearanceMissing)));
        assert!(matches!(with.encode(REFUSED), Err(EncodeError::ClearanceNotAllowed)));
        // Only `approved` has them: any other result with a clearance member is an unknown member.
        let declined =
            edited(&answer(Outcome::Declined), REQUIRED, r#""declined""#, r#""declined","clearance":"e30=""#);
        assert!(
            matches!(parse(&declined, REQUIRED), Err(ExchangeError::Malformed(ParseError::UnknownMember(m))) if m == "clearance")
        );
        assert!(matches!(parse(&declined, REFUSED), Err(ExchangeError::Malformed(ParseError::UnknownMember(_)))));
        // A clearance that is not one.
        let bad = edited(&with, REQUIRED, r#""clearance":""#, r#""clearance":"aGVsbG8=","x":""#);
        assert!(parse(&bad, REQUIRED).is_err());
        let not_clearance = t.trim_end().replacen(
            &t[t.find(r#""clearance":""#).unwrap() + 13..t.find(r#"","clearance_sig""#).unwrap()],
            "aGVsbG8=",
            1,
        );
        assert!(matches!(
            parse(not_clearance.as_bytes(), REQUIRED),
            Err(ExchangeError::BadClearance(ParseError::NotJson(_)))
        ));
    }

    #[test]
    fn members_that_do_not_belong_to_the_result_are_refused() {
        let line = |result: &str, extra: &str| {
            format!(r#"{{"schema_version":1,"type":"answer","request":"{}","result":"{result}"{extra}}}"#, hash())
                .into_bytes()
        };
        for (result, extra, member) in [
            ("declined", r#","by":"pledge""#, "by"),
            ("declined", r#","reason":"ceiling""#, "reason"),
            ("expired", r#","by":"pledge","reason":"ceiling""#, "reason"),
            ("refused", r#","approval":"LS0t""#, "approval"),
            ("approved", r#","by":"pledge""#, "by"),
            ("unknown", r#","by":"pledge""#, "by"),
            ("some-future-result", r#","approval":"LS0t""#, "approval"),
        ] {
            let l = line(result, extra);
            let r = parse(&l, REFUSED);
            // `approved` and `refused` also miss a member of their own, which is refused first.
            assert!(r.is_err(), "{result} {extra}");
            if !matches!(result, "approved" | "refused") {
                assert_eq!(
                    r,
                    Err(ExchangeError::Malformed(ParseError::UnknownMember(member.into()))),
                    "{result} {extra}"
                );
            }
        }
        assert_eq!(
            parse(&line("refused", r#","by":"pledge""#), REFUSED),
            Err(ExchangeError::Malformed(ParseError::MissingMember("reason")))
        );
        assert_eq!(
            parse(&line("expired", ""), REFUSED),
            Err(ExchangeError::Malformed(ParseError::MissingMember("by")))
        );
        assert_eq!(
            parse(&line("approved", ""), REFUSED),
            Err(ExchangeError::Malformed(ParseError::MissingMember("approval")))
        );
    }

    #[test]
    fn an_unknown_code_is_never_written_back() {
        let refused = |by: &str, reason: &str| {
            format!(r#"{{"schema_version":1,"type":"answer","request":"{}","result":"refused","by":"{by}","reason":"{reason}"}}"#, hash()).into_bytes()
        };
        for (by, reason, expected) in [
            ("pledge", "made-up-reason", Refused::Pledge(PledgeReason::Unknown)),
            ("pledge", "Ceiling", Refused::Pledge(PledgeReason::Unknown)),
            ("pledge", "not-entitled", Refused::Pledge(PledgeReason::Unknown)),
            ("broker", "ceiling", Refused::Broker(BrokerReason::Unknown)),
            ("broker", "unknown", Refused::Broker(BrokerReason::Unknown)),
            ("someone", "ceiling", Refused::Unknown),
        ] {
            let Message::Answer(a) = parse(&refused(by, reason), REFUSED).unwrap() else { panic!() };
            assert_eq!(a.outcome, Outcome::Refused(expected), "{by} {reason}");
            let out = text(&Message::Answer(a), REFUSED);
            for received in [by, reason] {
                if received != "unknown" && received != "pledge" && received != "broker" {
                    assert!(!out.contains(&format!("\"{received}\"")), "{received} was written back: {out}");
                }
            }
            assert!(out.contains(r#""reason":"unknown""#), "{out}");
        }
        // The same for `by` of an expiry, an unknown result and an unknown error code.
        let expired =
            format!(r#"{{"schema_version":1,"type":"answer","request":"{}","result":"expired","by":"mars"}}"#, hash());
        let out = text(&parse(expired.as_bytes(), REFUSED).unwrap(), REFUSED);
        assert!(out.contains(r#""by":"unknown""#) && !out.contains("mars"), "{out}");
        let result = format!(r#"{{"schema_version":1,"type":"answer","request":"{}","result":"vaporised"}}"#, hash());
        let out = text(&parse(result.as_bytes(), REFUSED).unwrap(), REFUSED);
        assert!(out.contains(r#""result":"unknown""#) && !out.contains("vaporised"), "{out}");
        let error = br#"{"schema_version":1,"type":"error","error":"gremlins"}"#;
        assert_eq!(parse(error, REFUSED).unwrap(), Message::Error(ErrorMessage { error: ErrorCode::Unknown }));
        assert!(!text(&parse(error, REFUSED).unwrap(), REFUSED).contains("gremlins"));
    }

    #[test]
    fn code_words_are_the_documents_and_fit_the_grammar() {
        let fits = |w: &str| {
            w.starts_with(|c: char| c.is_ascii_lowercase()) && w.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        };
        let mut all = vec![];
        all.extend(By::ALL.iter().map(|c| c.wire()));
        all.extend(PledgeReason::ALL.iter().map(|c| c.wire()));
        all.extend(BrokerReason::ALL.iter().map(|c| c.wire()));
        all.extend(ErrorCode::ALL.iter().map(|c| c.wire()));
        for w in &all {
            assert!(fits(w), "{w}");
        }
        assert_eq!(PledgeReason::ALL.len(), 14);
        assert_eq!(BrokerReason::ALL.len(), 7);
        assert_eq!(ErrorCode::ALL.len(), 10);
        for c in PledgeReason::ALL {
            assert_eq!(PledgeReason::from_wire(c.wire()), *c);
        }
        for c in BrokerReason::ALL {
            assert_eq!(BrokerReason::from_wire(c.wire()), *c);
        }
        assert_eq!(PledgeReason::Unknown.wire(), "unknown");
        assert_eq!(PledgeReason::from_wire("unknown"), PledgeReason::Unknown);
    }

    #[test]
    fn every_refusal_has_its_own_error_and_code() {
        let good = text(&Message::Cancel(Cancel { request: hash() }), REFUSED);
        let good = good.trim_end();
        let code = |line: &[u8]| parse(line, REFUSED).unwrap_err().code();
        // Version and type.
        for bad in ["2", "0", "1.0", "\"1\"", "null"] {
            let e = parse(
                good.replacen(r#""schema_version":1"#, &format!(r#""schema_version":{bad}"#), 1).as_bytes(),
                REFUSED,
            )
            .unwrap_err();
            assert!(
                matches!(e, ExchangeError::UnsupportedVersion | ExchangeError::Malformed(ParseError::WrongType { .. })),
                "{bad}: {e:?}"
            );
        }
        assert_eq!(
            parse(good.replacen(r#""schema_version":1"#, r#""schema_version":2"#, 1).as_bytes(), REFUSED),
            Err(ExchangeError::UnsupportedVersion)
        );
        assert_eq!(
            code(good.replacen(r#""schema_version":1"#, r#""schema_version":2"#, 1).as_bytes()),
            Some(ErrorCode::UnsupportedVersion)
        );
        // An unknown version wins over whatever else is wrong in a layout it may not share.
        assert_eq!(code(br#"{"schema_version":2,"type":"nonsense","x":1}"#), Some(ErrorCode::UnsupportedVersion));
        assert_eq!(parse(good.replacen("cancel", "retract", 1).as_bytes(), REFUSED), Err(ExchangeError::UnknownType));
        assert_eq!(code(good.replacen("cancel", "retract", 1).as_bytes()), Some(ErrorCode::UnknownType));
        assert_eq!(code(br#"{"schema_version":1,"type":"retract","x":1}"#), Some(ErrorCode::UnknownType));
        assert_eq!(
            parse(br#"{"type":"cancel"}"#, REFUSED),
            Err(ExchangeError::Malformed(ParseError::MissingMember("schema_version")))
        );
        assert_eq!(
            parse(br#"{"schema_version":1}"#, REFUSED),
            Err(ExchangeError::Malformed(ParseError::MissingMember("type")))
        );
        // Members.
        let unknown = good.replacen("}", r#","extra":1}"#, 1);
        assert_eq!(
            parse(unknown.as_bytes(), REFUSED),
            Err(ExchangeError::Malformed(ParseError::UnknownMember("extra".into())))
        );
        assert_eq!(code(unknown.as_bytes()), Some(ErrorCode::MalformedLine));
        let dup = good.replacen("}", r#","request":"sha256:00"}"#, 1);
        assert_eq!(
            parse(dup.as_bytes(), REFUSED),
            Err(ExchangeError::Malformed(ParseError::DuplicateMember("request".into())))
        );
        assert!(matches!(
            parse(good.replacen(&hash().to_string(), "sha256:ABC", 1).as_bytes(), REFUSED),
            Err(ExchangeError::Malformed(ParseError::MalformedHash(_)))
        ));
        assert!(matches!(
            parse(good.replacen(r#""request":""#, r#""request":1,"x":""#, 1).as_bytes(), REFUSED),
            Err(ExchangeError::Malformed(ParseError::WrongType { .. }))
        ));
        // Strings.
        let with_type = |t: &str| format!(r#"{{"schema_version":1,"type":"{t}"}}"#).into_bytes();
        assert_eq!(
            parse(&with_type(r"can\u0000cel"), REFUSED),
            Err(ExchangeError::Malformed(ParseError::ControlCharacter("type".into())))
        );
        let err = |code: &str| format!(r#"{{"schema_version":1,"type":"error","error":"{code}"}}"#).into_bytes();
        assert_eq!(
            parse(&err(r"a\u202eb"), REFUSED),
            Err(ExchangeError::Malformed(ParseError::BidiMark("error".into())))
        );
        assert_eq!(
            parse(&err(r"a\nb"), REFUSED),
            Err(ExchangeError::Malformed(ParseError::ControlCharacter("error".into())))
        );
        let refused = |reason: &str| {
            format!(r#"{{"schema_version":1,"type":"answer","request":"{}","result":"refused","by":"pledge","reason":"{reason}"}}"#, hash()).into_bytes()
        };
        assert_eq!(
            parse(&refused(r"a\u0007"), REFUSED),
            Err(ExchangeError::Malformed(ParseError::ControlCharacter("reason".into())))
        );
        assert_eq!(
            parse(&refused(r"a\u2066"), REFUSED),
            Err(ExchangeError::Malformed(ParseError::BidiMark("reason".into())))
        );
        // Lines.
        for bad in ["", "[]", "null", "1", "{", "not json"] {
            assert!(
                matches!(parse(bad.as_bytes(), REFUSED), Err(ExchangeError::Malformed(ParseError::NotJson(_)))),
                "{bad:?}"
            );
        }
        assert_eq!(
            parse(format!("{good}\n").as_bytes(), REFUSED),
            Err(ExchangeError::Malformed(ParseError::LineBreak))
        );
        assert_eq!(
            parse(good.replacen("{", "{\r", 1).as_bytes(), REFUSED),
            Err(ExchangeError::Malformed(ParseError::LineBreak))
        );
        assert_eq!(
            parse(&[&[0xEF, 0xBB, 0xBF][..], good.as_bytes()].concat(), REFUSED),
            Err(ExchangeError::Malformed(ParseError::ByteOrderMark))
        );
        assert_eq!(
            parse(&[good.as_bytes(), &[0xFF]].concat(), REFUSED),
            Err(ExchangeError::Malformed(ParseError::NotUtf8))
        );
        // Two objects on one line.
        for two in [format!("{good}{good}"), format!("{good} {good}"), format!("{good},{good}")] {
            assert!(
                matches!(parse(two.as_bytes(), REFUSED), Err(ExchangeError::Malformed(ParseError::NotJson(_)))),
                "{two}"
            );
        }
        assert_eq!(parse(&vec![b' '; MAX_LINE + 1], REFUSED), Err(ExchangeError::LineTooLong));
        assert_eq!(code(&vec![b' '; MAX_LINE + 1]), Some(ErrorCode::LineTooLong));
    }

    #[test]
    fn bad_base64_signatures_and_requests_are_refused() {
        let s = submit();
        let (request_b64, sig_b64) = (STANDARD.encode(request().as_bytes()), signature_to_base64(SIG));
        // Base64: not the alphabet, unpadded, url-safe, garbage in the middle.
        let unpadded = request_b64.trim_end_matches('=');
        let bad_request = [
            request_b64.replacen('e', "!", 1),
            unpadded.to_owned(),
            request_b64.replace('+', "-"),
            format!("{request_b64} "),
        ];
        for bad in bad_request.iter().filter(|b| **b != request_b64 && (**b != unpadded || request_b64.ends_with('=')))
        {
            assert_eq!(
                parse(&edited(&s, REFUSED, &request_b64, bad), REFUSED),
                Err(ExchangeError::BadBase64("request")),
                "{bad}"
            );
        }
        assert_eq!(
            parse(&edited(&s, REFUSED, &sig_b64, "!!!!"), REFUSED),
            Err(ExchangeError::BadBase64("request_sig"))
        );
        assert_eq!(
            parse(&edited(&s, REFUSED, &sig_b64, &STANDARD.encode("plain text")), REFUSED),
            Err(ExchangeError::BadSignature("request_sig"))
        );
        assert_eq!(
            parse(&edited(&s, REFUSED, &sig_b64, &STANDARD.encode([0xff, 0xfe])), REFUSED),
            Err(ExchangeError::BadSignature("request_sig"))
        );
        assert_eq!(
            parse(&edited(&s, REFUSED, &sig_b64, "-----BEGIN SSH SIGNATURE-----"), REFUSED),
            Err(ExchangeError::BadBase64("request_sig"))
        );
        let a = approved(false);
        assert_eq!(parse(&edited(&a, REFUSED, &sig_b64, "%%%"), REFUSED), Err(ExchangeError::BadBase64("approval")));
        assert_eq!(
            parse(&edited(&a, REFUSED, &sig_b64, &STANDARD.encode("nope")), REFUSED),
            Err(ExchangeError::BadSignature("approval"))
        );
        // The request inside does not parse: the error carries the hash of what was decoded.
        let not_a_request = STANDARD.encode(b"{\"v\":1}");
        let e = parse(&edited(&s, REFUSED, &request_b64, &not_a_request), REFUSED).unwrap_err();
        assert!(
            matches!(&e, ExchangeError::BadRequest { hash, source: ParseError::WrongDocumentType { .. } | ParseError::MissingMember(_) | ParseError::NotJson(_) } if *hash == DocumentHash::of(b"{\"v\":1}")),
            "{e:?}"
        );
        assert_eq!(e.code(), Some(ErrorCode::MalformedLine));
        let too_big = STANDARD.encode(vec![b' '; 40 * 1024]);
        assert!(matches!(
            parse(&edited(&s, REFUSED, &request_b64, &too_big), REFUSED),
            Err(ExchangeError::BadRequest { source: ParseError::TooLarge { .. }, .. })
        ));
        // Writing refuses a signature that is not armoured.
        assert!(matches!(Submit::new(request(), "not armour"), Err(EncodeError::NotArmoured("request_sig"))));
        assert!(matches!(Approved::new("", None), Err(EncodeError::NotArmoured("approval"))));
    }

    #[test]
    fn the_reader_splits_lines_and_bounds_them() {
        let (a, b) = (text(&submit(), REFUSED), text(&Message::Cancel(Cancel { request: hash() }), REFUSED));
        let input = format!("{a}{b}");
        // Whole, and one byte at a time.
        for chunk in [usize::MAX, 1, 7] {
            struct Chunked<'a>(&'a [u8], usize);
            impl Read for Chunked<'_> {
                fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                    let n = out.len().min(self.0.len()).min(self.1);
                    out[..n].copy_from_slice(&self.0[..n]);
                    self.0 = &self.0[n..];
                    Ok(n)
                }
            }
            let mut r = LineReader::new(Chunked(input.as_bytes(), chunk));
            assert!(matches!(r.read_message(REFUSED), Ok(Some(Message::Submit(_)))), "{chunk}");
            assert!(matches!(r.read_message(REFUSED), Ok(Some(Message::Cancel(_)))), "{chunk}");
            assert!(matches!(r.read_message(REFUSED), Ok(None)), "{chunk}");
            assert!(matches!(r.read_line(), Ok(None)));
        }
        // An end in the middle of a line is not a message.
        let mut r = LineReader::new(&input.as_bytes()[..input.len() - 3]);
        assert!(r.read_message(REFUSED).is_ok());
        assert_eq!(r.read_line(), Err(ExchangeError::Truncated));
        // Blank line: a line, and not a message.
        let mut r = LineReader::new(&b"\n"[..]);
        assert!(matches!(r.read_message(REFUSED), Err(ExchangeError::Malformed(ParseError::NotJson(_)))));
    }

    #[test]
    fn a_line_over_the_limit_ends_the_reading() {
        let line = |n: usize, newline: bool| {
            let mut v = vec![b'x'; n];
            if newline {
                v.push(b'\n');
            }
            v
        };
        // Exactly the limit is a line; one more is not; with or without its newline.
        let exact = line(MAX_LINE, true);
        let mut r = LineReader::new(&exact[..]);
        assert_eq!(r.read_line().unwrap().unwrap().len(), MAX_LINE);
        assert_eq!(LineReader::new(&line(MAX_LINE + 1, true)[..]).read_line(), Err(ExchangeError::LineTooLong));
        assert_eq!(LineReader::new(&line(MAX_LINE + 1, false)[..]).read_line(), Err(ExchangeError::LineTooLong));
        assert_eq!(LineReader::new(&line(MAX_LINE, false)[..]).read_line(), Err(ExchangeError::Truncated));
        // A short line after a long one in the same chunk does not hide it.
        let mut two = line(MAX_LINE + 5, true);
        two.extend_from_slice(b"{}\n");
        assert_eq!(LineReader::new(&two[..]).read_line(), Err(ExchangeError::LineTooLong));
        // A peer that never sends a newline cannot make the reader keep more than a line and a chunk.
        struct Endless(u64);
        impl Read for Endless {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                self.0 += out.len() as u64;
                assert!(self.0 < 10 * MAX_LINE as u64, "read far past the limit");
                out.fill(b'x');
                Ok(out.len())
            }
        }
        assert_eq!(LineReader::new(Endless(0)).read_line(), Err(ExchangeError::LineTooLong));
        // Two objects on one line are one line, and not a message.
        let two_objects = format!("{}{}\n", text(&submit(), REFUSED).trim_end(), text(&submit(), REFUSED).trim_end());
        let mut r = LineReader::new(two_objects.as_bytes());
        assert!(matches!(r.read_message(REFUSED), Err(ExchangeError::Malformed(ParseError::NotJson(_)))));
    }

    #[test]
    fn io_errors_are_reported_and_interrupts_are_retried() {
        struct Flaky(Vec<io::Result<Vec<u8>>>);
        impl Read for Flaky {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                match self.0.remove(0) {
                    Ok(v) => {
                        out[..v.len()].copy_from_slice(&v);
                        Ok(v.len())
                    }
                    Err(e) => Err(e),
                }
            }
        }
        let mut r = LineReader::new(Flaky(vec![Err(io::ErrorKind::Interrupted.into()), Ok(b"{}\n".to_vec())]));
        assert_eq!(r.read_line().unwrap().unwrap(), b"{}");
        let mut r = LineReader::new(Flaky(vec![Err(io::ErrorKind::TimedOut.into())]));
        let e = r.read_line().unwrap_err();
        assert!(matches!(e, ExchangeError::Io(_)));
        assert_eq!(e.code(), None);
        assert_eq!(ExchangeError::Truncated.code(), None);
    }

    #[test]
    fn the_writer_writes_one_line() {
        let mut out = Vec::new();
        let m = approved(true);
        write_message(&mut out, &m, REQUIRED).unwrap();
        write_message(&mut out, &submit(), REQUIRED).unwrap();
        let mut r = LineReader::new(&out[..]);
        assert_eq!(r.read_message(REQUIRED).unwrap().unwrap(), m);
        assert_eq!(r.read_message(REQUIRED).unwrap().unwrap(), submit());
        assert_eq!(r.read_message(REQUIRED).unwrap(), None);
        assert!(matches!(write_message(&mut Vec::new(), &m, REFUSED), Err(EncodeError::ClearanceNotAllowed)));
    }
}
