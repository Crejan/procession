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
    at: Timestamp,
}

#[derive(Serialize)]
struct Wire {
    v: u8,
    #[serde(rename = "type")]
    kind: &'static str,
    request: String,
    at: String,
}

impl Clearance {
    pub fn parse(bytes: impl Into<Vec<u8>>) -> Result<Clearance, ParseError> {
        let bytes = bytes.into();
        let mut o = Object::parse(check_bytes(&bytes, MAX_BYTES)?, "")?;
        o.take_header("clearance")?;
        let request = o.take_string("request")?.parse()?;
        let at = o.take_string("at")?.parse()?;
        o.finish()?;
        Ok(Clearance { bytes, request, at })
    }

    /// Write a new clearance for the request with hash `request`, issued at `at`.
    pub fn compose(request: DocumentHash, at: Timestamp) -> Result<Clearance, ParseError> {
        let wire = Wire { v: 1, kind: "clearance", request: request.to_string(), at: at.to_string() };
        let bytes = serde_json::to_vec(&wire).map_err(|e| ParseError::NotJson(e.to_string()))?;
        Clearance::parse(bytes)
    }

    /// The hash of the request's bytes.
    #[must_use]
    pub fn request(&self) -> DocumentHash {
        self.request
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

impl Document for Clearance {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const EXAMPLE: &str = r#"{"v":1,"type":"clearance","request":"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","at":"2026-11-11T15:04:41Z"}"#;

    #[test]
    fn parses_composes_and_keeps_bytes() {
        let c = Clearance::parse(EXAMPLE).unwrap();
        assert_eq!(c.as_bytes(), EXAMPLE.as_bytes());
        assert_eq!(c.request().to_string(), HASH);
        assert_eq!(c.at().to_string(), "2026-11-11T15:04:41Z");
        assert_eq!(Clearance::compose(c.request(), c.at()).unwrap().as_bytes(), EXAMPLE.as_bytes());
    }

    #[test]
    fn covers_exactly_one_request() {
        let request = crate::request::tests::request();
        let c = Clearance::compose(request.hash(), Timestamp::from_unix(0).unwrap()).unwrap();
        assert!(c.covers(&request));
        let other = Request::compose(request.call(), crate::request::tests::SIG, crate::rating::Rating::WORST).unwrap();
        assert!(!c.covers(&other));
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
