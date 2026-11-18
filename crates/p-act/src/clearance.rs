//! The clearance: the broker saying a request passed its checks, signed by the
//! broker (formats section 6).

use crate::error::ParseError;
use crate::hash::{Document, DocumentHash};
use crate::object::{Object, check_bytes};
use crate::request::Request;
use crate::time::Timestamp;
use serde::Serialize;

/// A clearance is small; the formats give no limit, so this one is p-act's.
pub const MAX_BYTES: usize = 1024;

/// A parsed clearance, with the bytes it was parsed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clearance {
    bytes: Vec<u8>,
    request: DocumentHash,
    approval: DocumentHash,
    at: Timestamp,
}

#[derive(Serialize)]
struct Wire {
    v: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    request: String,
    approval: String,
    at: String,
}

impl Clearance {
    pub fn parse(bytes: impl Into<Vec<u8>>) -> Result<Clearance, ParseError> {
        let bytes = bytes.into();
        let mut o = Object::parse(check_bytes(&bytes, MAX_BYTES)?, "")?;
        o.take_header("clearance")?;
        let request = o.take_string("request")?.parse()?;
        let approval = o.take_string("approval")?.parse()?;
        let at = o.take_string("at")?.parse()?;
        o.finish()?;
        Ok(Clearance { bytes, request, approval, at })
    }

    /// Write a new clearance for the request with hash `request` and the approval with hash `approval` (see
    /// [`approval_hash`]), issued at `at`. A clearance says exactly what it cleared: one approval by one key.
    pub fn compose(request: DocumentHash, approval: DocumentHash, at: Timestamp) -> Result<Clearance, ParseError> {
        let wire = Wire {
            v: 1,
            kind: "clearance",
            request: request.to_string(),
            approval: approval.to_string(),
            at: at.to_string(),
        };
        let bytes = serde_json::to_vec(&wire).map_err(|e| ParseError::NotJson(e.to_string()))?;
        Clearance::parse(bytes)
    }

    /// The hash of the request's bytes.
    #[must_use]
    pub fn request(&self) -> DocumentHash {
        self.request
    }

    /// The hash of the approval's bytes: the armoured signature as pledge made it.
    #[must_use]
    pub fn approval(&self) -> DocumentHash {
        self.approval
    }

    /// Whether this clearance names exactly `approval` (the armoured signature the service holds).
    #[must_use]
    pub fn names_approval(&self, approval: &str) -> bool {
        self.approval == approval_hash(approval)
    }

    /// When the broker issued it: when the approval came back.
    #[must_use]
    pub fn at(&self) -> Timestamp {
        self.at
    }

    /// Whether this clearance is over exactly `request`'s bytes.
    #[must_use]
    pub fn covers(&self, request: &Request) -> bool {
        self.request == request.hash()
    }
}

/// The hash a clearance carries for an approval: SHA-256 over the armoured signature's bytes as pledge made it, in the
/// form of every document hash (`sha256:<hex>`).
#[must_use]
pub fn approval_hash(approval: &str) -> DocumentHash {
    DocumentHash::of(approval.as_bytes())
}

impl Document for Clearance {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const EXAMPLE: &str = r#"{"v":1,"type":"clearance","request":"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","approval":"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","at":"2026-11-11T15:04:41Z"}"#;

    #[test]
    fn parses_composes_and_keeps_bytes() {
        let c = Clearance::parse(EXAMPLE).unwrap();
        assert_eq!(c.as_bytes(), EXAMPLE.as_bytes());
        assert_eq!(c.request().to_string(), HASH);
        assert_eq!(c.at().to_string(), "2026-11-11T15:04:41Z");
        assert_eq!(Clearance::compose(c.request(), c.approval(), c.at()).unwrap().as_bytes(), EXAMPLE.as_bytes());
    }

    #[test]
    fn covers_exactly_one_request() {
        let request = crate::request::tests::request();
        let c =
            Clearance::compose(request.hash(), approval_hash("an approval"), Timestamp::from_unix(0).unwrap()).unwrap();
        assert!(c.covers(&request));
        let other =
            Request::compose(request.call(), crate::request::tests::SIG, crate::rating::Rating::WORST, false).unwrap();
        assert!(!c.covers(&other));
        // And exactly one approval: the hash of its armoured bytes.
        assert!(c.names_approval("an approval") && !c.names_approval("an approval ") && !c.names_approval(""));
        assert_eq!(c.approval(), DocumentHash::of(b"an approval"));
    }

    #[test]
    fn refuses() {
        let swap = |from: &str, to: &str| EXAMPLE.replacen(from, to, 1);
        let parse = |s: String| Clearance::parse(s.into_bytes());
        assert_eq!(parse(swap(r#""v":1"#, r#""v":2"#)), Err(ParseError::UnsupportedVersion("2".into())));
        assert_eq!(
            parse(swap("clearance", "call")),
            Err(ParseError::WrongDocumentType { expected: "clearance", found: "call".into() })
        );
        assert_eq!(parse(swap(r#""at""#, r#""x":0,"at""#)), Err(ParseError::UnknownMember("x".into())));
        assert_eq!(parse(swap(r#","at":"2026-11-11T15:04:41Z""#, "")), Err(ParseError::MissingMember("at")));
        // `approval` is required, a hash, once.
        let no_approval = swap(&format!(r#""approval":"{HASH}","#), "");
        assert_eq!(parse(no_approval), Err(ParseError::MissingMember("approval")));
        assert!(matches!(
            parse(swap(&format!(r#""approval":"{HASH}""#), r#""approval":"nothing""#)),
            Err(ParseError::MalformedHash(_))
        ));
        assert!(matches!(
            parse(swap(&format!(r#""approval":"{HASH}""#), r#""approval":1"#)),
            Err(ParseError::WrongType { .. })
        ));
        assert_eq!(
            parse(swap(&format!(r#""approval":"{HASH}""#), &format!(r#""approval":"{HASH}","approval":"{HASH}""#))),
            Err(ParseError::DuplicateMember("approval".into()))
        );
        assert_eq!(
            parse(swap(r#""at":"2026-11-11T15:04:41Z""#, r#""at":"2026-11-11T15:04:41Z","at":"2026-11-11T15:04:41Z""#)),
            Err(ParseError::DuplicateMember("at".into()))
        );
        assert!(matches!(parse(swap("2026-11-11T15:04:41Z", "yesterday")), Err(ParseError::MalformedTime(_))));
        assert!(matches!(parse(swap("sha256:", "sha512:")), Err(ParseError::MalformedHash(_))));
        assert!(matches!(parse(swap(HASH, &HASH.to_uppercase())), Err(ParseError::MalformedHash(_))));
        assert!(matches!(parse(swap(HASH, r"sha256:\u202e")), Err(ParseError::BidiMark(_))));
        assert_eq!(parse(format!("{EXAMPLE}\n")), Err(ParseError::LineBreak));
        assert!(matches!(Clearance::parse(vec![b' '; MAX_BYTES + 1]), Err(ParseError::TooLarge { .. })));
    }
}
