//! The call: what an agent asks for, signed by the agent (formats section 3).

use crate::error::ParseError;
use crate::hash::Document;
use crate::object::{Object, check_bytes};
use crate::text;
use crate::time::Timestamp;
use serde::Serialize;
use std::fmt;

/// A call is at most 16 KiB.
pub const MAX_BYTES: usize = 16 * 1024;
/// At most this many parameters.
pub const MAX_PARAMS: usize = 64;
/// Each parameter is at most this many bytes.
pub const MAX_PARAM_BYTES: usize = 512;
/// The claim is at most this many characters.
pub const MAX_CLAIM_CHARS: usize = 200;

/// A UUID, version 4, lower case with hyphens, that the agent made for one call.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallId(String);

impl CallId {
    /// `s` as the identifier of a call, or why it is not one.
    pub fn parse(s: &str) -> Result<CallId, ParseError> {
        let bad = || ParseError::MalformedUuid(s.to_owned());
        let b = s.as_bytes();
        if b.len() != 36 {
            return Err(bad());
        }
        for (i, &c) in b.iter().enumerate() {
            let ok = match i {
                8 | 13 | 18 | 23 => c == b'-',
                14 => c == b'4',
                19 => matches!(c, b'8' | b'9' | b'a' | b'b'),
                _ => c.is_ascii_digit() || (b'a'..=b'f').contains(&c),
            };
            if !ok {
                return Err(bad());
            }
        }
        Ok(CallId(s.to_owned()))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CallId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The service a call names: its name on a host. Its principal for the
/// request's signature is `<name>@<host>`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct ServiceId {
    /// The host's name as the site project has it.
    pub host: String,
    /// The service's name on that host: `[a-z][a-z0-9-]*`.
    pub name: String,
}

impl ServiceId {
    /// The name the request's signature is verified under: `<name>@<host>`.
    #[must_use]
    pub fn principal(&self) -> String {
        format!("{}@{}", self.name, self.host)
    }
}

/// What a call says, without the bytes. To write a new call, fill this in and
/// give it to [`Call::compose`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallContent {
    pub id: CallId,
    /// After this the call, and the request made from it, is void.
    pub deadline: Timestamp,
    pub service: ServiceId,
    /// Lower-case words separated by single spaces, in the service's own words.
    pub action: String,
    /// The action's parameters in the order the service defines.
    pub params: Vec<String>,
    /// What the agent says about its reasons. Shown as the agent's claim, never acted on.
    pub claim: Option<String>,
}

/// A parsed call, with the bytes it was parsed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Call {
    bytes: Vec<u8>,
    content: CallContent,
}

#[derive(Serialize)]
struct Wire<'a> {
    v: u8,
    #[serde(rename = "type")]
    kind: &'a str,
    id: &'a str,
    deadline: String,
    service: &'a ServiceId,
    action: &'a str,
    params: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    claim: Option<&'a str>,
}

impl Call {
    /// Parse and validate `bytes`; the call owns them from now on.
    pub fn parse(bytes: impl Into<Vec<u8>>) -> Result<Call, ParseError> {
        let bytes = bytes.into();
        let content = parse_content(&bytes)?;
        Ok(Call { bytes, content })
    }

    /// Write a new call: its bytes are produced here, once, and checked by
    /// the same parser that reads every other call.
    pub fn compose(content: &CallContent) -> Result<Call, ParseError> {
        let wire = Wire {
            v: 1,
            kind: "call",
            id: content.id.as_str(),
            deadline: content.deadline.to_string(),
            service: &content.service,
            action: &content.action,
            params: &content.params,
            claim: content.claim.as_deref(),
        };
        // Serialising plain strings and numbers cannot fail.
        let bytes = serde_json::to_vec(&wire).map_err(|e| ParseError::NotJson(e.to_string()))?;
        Call::parse(bytes)
    }

    #[must_use]
    pub fn content(&self) -> &CallContent {
        &self.content
    }

    #[must_use]
    pub fn id(&self) -> &CallId {
        &self.content.id
    }

    #[must_use]
    pub fn deadline(&self) -> Timestamp {
        self.content.deadline
    }

    #[must_use]
    pub fn service(&self) -> &ServiceId {
        &self.content.service
    }

    #[must_use]
    pub fn action(&self) -> &str {
        &self.content.action
    }

    #[must_use]
    pub fn params(&self) -> &[String] {
        &self.content.params
    }

    #[must_use]
    pub fn claim(&self) -> Option<&str> {
        self.content.claim.as_deref()
    }
}

impl Document for Call {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn parse_content(bytes: &[u8]) -> Result<CallContent, ParseError> {
    let mut o = Object::parse(check_bytes(bytes, MAX_BYTES)?, "")?;
    o.take_header("call")?;
    let id = CallId::parse(&o.take_string("id")?)?;
    let deadline = o.take_string("deadline")?.parse()?;
    let mut s = o.take_object("service", "service.")?;
    let host = s.take_string("host")?;
    let name = s.take_string("name")?;
    s.finish()?;
    if !text::is_name(&host) {
        return Err(ParseError::MalformedHost(host));
    }
    if !text::is_service_name(&name) {
        return Err(ParseError::MalformedServiceName(name));
    }
    let action = o.take_string("action")?;
    if !text::is_action(&action) {
        return Err(ParseError::MalformedAction(action));
    }
    let params = o.take_strings("params")?;
    if params.len() > MAX_PARAMS {
        return Err(ParseError::TooManyParams { limit: MAX_PARAMS });
    }
    if let Some(index) = params.iter().position(|p| p.len() > MAX_PARAM_BYTES) {
        return Err(ParseError::ParamTooLong { index, limit: MAX_PARAM_BYTES });
    }
    let claim = o.take_optional_string("claim")?;
    if claim.as_ref().is_some_and(|c| c.chars().count() > MAX_CLAIM_CHARS) {
        return Err(ParseError::ClaimTooLong { limit: MAX_CLAIM_CHARS });
    }
    o.finish()?;
    Ok(CallContent { id, deadline, service: ServiceId { host, name }, action, params, claim })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const EXAMPLE: &str = r#"{"v":1,"type":"call","id":"3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11","deadline":"2026-11-11T15:06:05Z","service":{"host":"a.example","name":"probe"},"action":"rt procs","params":["pid=4711"],"claim":"checking why the control loop misses cycles"}"#;

    fn parse(s: &str) -> Result<Call, ParseError> {
        Call::parse(s.as_bytes())
    }

    fn replaced(from: &str, to: &str) -> String {
        assert!(EXAMPLE.contains(from), "{from}");
        EXAMPLE.replacen(from, to, 1)
    }

    #[test]
    fn parses_the_example_and_keeps_its_bytes() {
        let call = parse(EXAMPLE).unwrap();
        assert_eq!(call.as_bytes(), EXAMPLE.as_bytes());
        assert_eq!(call.id().as_str(), "3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11");
        assert_eq!(call.deadline().to_string(), "2026-11-11T15:06:05Z");
        assert_eq!(call.service().principal(), "probe@a.example");
        assert_eq!(call.action(), "rt procs");
        assert_eq!(call.params(), ["pid=4711"]);
        assert_eq!(call.claim(), Some("checking why the control loop misses cycles"));
    }

    #[test]
    fn what_is_signed_is_the_bytes_received_not_a_re_serialisation() {
        // Same content, different spacing and member order: the bytes stay as they came.
        let odd = r#"{ "type":"call", "v":1, "id":"3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11","deadline":"2026-11-11T15:06:05Z","service":{"name":"probe","host":"a.example"},"action":"rt procs","params":[]}"#;
        let call = parse(odd).unwrap();
        assert_eq!(call.as_bytes(), odd.as_bytes());
        assert_eq!(call.claim(), None);
        assert!(call.params().is_empty());
    }

    #[test]
    fn compose_round_trips() {
        let parsed = parse(EXAMPLE).unwrap();
        let composed = Call::compose(parsed.content()).unwrap();
        assert_eq!(composed.as_bytes(), EXAMPLE.as_bytes());
        assert_eq!(composed, parsed);
        let without_claim = CallContent { claim: None, ..parsed.content().clone() };
        let bytes = Call::compose(&without_claim).unwrap();
        assert!(!String::from_utf8_lossy(bytes.as_bytes()).contains("claim"));
        assert_eq!(Call::parse(bytes.as_bytes()).unwrap().content(), &without_claim);
    }

    #[test]
    fn compose_refuses_what_parse_refuses() {
        let mut content = parse(EXAMPLE).unwrap().content().clone();
        content.action = "Bad Action".into();
        assert!(matches!(Call::compose(&content), Err(ParseError::MalformedAction(_))));
        content.action = "ok".into();
        content.claim = Some("a\u{202e}b".into());
        assert!(matches!(Call::compose(&content), Err(ParseError::BidiMark(_))));
        content.claim = Some("quote \" and \\ and ü stay legal".into());
        assert!(Call::compose(&content).is_ok());
    }

    #[test]
    fn refuses_a_wrong_version_and_type() {
        assert_eq!(parse(&replaced(r#""v":1"#, r#""v":2"#)), Err(ParseError::UnsupportedVersion("2".into())));
        assert_eq!(parse(&replaced(r#""v":1"#, r#""v":1.0"#)), Err(ParseError::UnsupportedVersion("1.0".into())));
        assert!(matches!(parse(&replaced(r#""v":1"#, r#""v":"1""#)), Err(ParseError::WrongType { .. })));
        assert_eq!(
            parse(&replaced(r#""type":"call""#, r#""type":"request""#)),
            Err(ParseError::WrongDocumentType { expected: "call", found: "request".into() })
        );
        let no_v = EXAMPLE.replacen(r#""v":1,"#, "", 1);
        assert_eq!(parse(&no_v), Err(ParseError::MissingMember("v")));
    }

    #[test]
    fn refuses_unknown_missing_duplicate_and_mistyped_members() {
        assert_eq!(
            parse(&replaced(r#""action""#, r#""extra":1,"action""#)),
            Err(ParseError::UnknownMember("extra".into()))
        );
        assert_eq!(
            parse(&replaced(r#""name":"probe""#, r#""name":"probe","x":1"#)),
            Err(ParseError::UnknownMember("service.x".into()))
        );
        assert_eq!(parse(&replaced(r#""action":"rt procs","#, "")), Err(ParseError::MissingMember("action")));
        assert_eq!(
            parse(&replaced(r#""action":"rt procs""#, r#""action":"rt procs","action":"rt procs""#)),
            Err(ParseError::DuplicateMember("action".into()))
        );
        assert_eq!(
            parse(&replaced(r#""host":"a.example""#, r#""host":"a.example","host":"b""#)),
            Err(ParseError::DuplicateMember("service.host".into()))
        );
        assert!(matches!(
            parse(&replaced(r#""params":["pid=4711"]"#, r#""params":"pid=4711""#)),
            Err(ParseError::WrongType { .. })
        ));
        assert!(matches!(
            parse(&replaced(r#""params":["pid=4711"]"#, r#""params":[4711]"#)),
            Err(ParseError::WrongType { .. })
        ));
        assert!(matches!(
            parse(&replaced(r#""service":{"host":"a.example","name":"probe"}"#, r#""service":"probe""#)),
            Err(ParseError::WrongType { .. })
        ));
        assert_eq!(
            parse(&replaced(r#""claim":"checking why the control loop misses cycles""#, r#""claim":null"#))
                .unwrap_err(),
            ParseError::WrongType { member: "claim".into(), expected: "a string" }
        );
    }

    #[test]
    fn refuses_what_is_not_one_json_object_on_one_line() {
        for bad in ["", "[]", "1", "null", "{", &format!("{EXAMPLE}x"), &format!("{EXAMPLE}{EXAMPLE}")] {
            assert!(matches!(parse(bad), Err(ParseError::NotJson(_))), "{bad:?}");
        }
        assert_eq!(parse(&format!("{EXAMPLE}\n")), Err(ParseError::LineBreak));
        assert_eq!(parse(&EXAMPLE.replacen("{", "{\r", 1)), Err(ParseError::LineBreak));
        assert_eq!(Call::parse([&[0xEF, 0xBB, 0xBF][..], EXAMPLE.as_bytes()].concat()), Err(ParseError::ByteOrderMark));
        assert_eq!(Call::parse([EXAMPLE.as_bytes(), &[0xFF]].concat()), Err(ParseError::NotUtf8));
    }

    #[test]
    fn refuses_control_characters_and_bidi_marks_in_any_string() {
        assert_eq!(parse(&replaced("checking", r"che\u0000cking")), Err(ParseError::ControlCharacter("claim".into())));
        assert_eq!(parse(&replaced("checking", r"che\ncking")), Err(ParseError::ControlCharacter("claim".into())));
        assert_eq!(parse(&replaced("checking", r"che\u0085cking")), Err(ParseError::ControlCharacter("claim".into())));
        assert_eq!(parse(&replaced("checking", r"che\u202ecking")), Err(ParseError::BidiMark("claim".into())));
        assert_eq!(parse(&replaced("pid=4711", r"pid\u007f")), Err(ParseError::ControlCharacter("params".into())));
        assert_eq!(parse(&replaced("pid=4711", r"pid\u2066")), Err(ParseError::BidiMark("params".into())));
        assert_eq!(parse(&replaced("rt procs", r"rt\u0009procs")), Err(ParseError::ControlCharacter("action".into())));
        assert_eq!(parse(&replaced("a.example", r"a\u200e.example")), Err(ParseError::BidiMark("service.host".into())));
        assert_eq!(parse(&replaced("probe", r"pr\u0001obe")), Err(ParseError::ControlCharacter("service.name".into())));
        assert_eq!(parse(&replaced("3f2b6c1e", r"3f2b6c1\u200f")), Err(ParseError::BidiMark("id".into())));
    }

    #[test]
    fn refuses_malformed_ids_times_names_and_actions() {
        for bad in [
            "3F2B6C1E-8A57-4D0E-9B1A-5C2E7D9F0A11",
            "3f2b6c1e-8a57-1d0e-9b1a-5c2e7d9f0a11",
            "3f2b6c1e-8a57-4d0e-cb1a-5c2e7d9f0a11",
            "3f2b6c1e8a574d0e9b1a5c2e7d9f0a11",
            "3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a1",
            "3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a1g",
            "",
            "{3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11}",
        ] {
            assert_eq!(
                parse(&replaced("3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11", bad)),
                Err(ParseError::MalformedUuid(bad.into())),
                "{bad}"
            );
        }
        assert_eq!(
            parse(&replaced("2026-11-11T15:06:05Z", "2026-11-11 15:06:05")),
            Err(ParseError::MalformedTime("2026-11-11 15:06:05".into()))
        );
        assert!(matches!(parse(&replaced("a.example", "a example")), Err(ParseError::MalformedHost(_))));
        assert!(matches!(parse(&replaced("a.example", "")), Err(ParseError::MalformedHost(_))));
        assert!(matches!(parse(&replaced("a.example", "a@b")), Err(ParseError::MalformedHost(_))));
        assert!(matches!(parse(&replaced(r#""probe""#, r#""Probe""#)), Err(ParseError::MalformedServiceName(_))));
        assert!(matches!(parse(&replaced(r#""probe""#, r#""""#)), Err(ParseError::MalformedServiceName(_))));
        assert!(matches!(parse(&replaced("rt procs", "rt  procs")), Err(ParseError::MalformedAction(_))));
        assert!(matches!(parse(&replaced("rt procs", "Rt procs")), Err(ParseError::MalformedAction(_))));
        assert!(matches!(parse(&replaced("rt procs", "")), Err(ParseError::MalformedAction(_))));
    }

    #[test]
    fn enforces_the_limits() {
        let params = |n: usize| format!("[{}]", vec![r#""x""#; n].join(","));
        assert!(parse(&replaced(r#"["pid=4711"]"#, &params(MAX_PARAMS))).is_ok());
        assert_eq!(
            parse(&replaced(r#"["pid=4711"]"#, &params(MAX_PARAMS + 1))),
            Err(ParseError::TooManyParams { limit: 64 })
        );

        let param = |n: usize| format!(r#"["{}"]"#, "p".repeat(n));
        assert!(parse(&replaced(r#"["pid=4711"]"#, &param(512))).is_ok());
        assert_eq!(
            parse(&replaced(r#"["pid=4711"]"#, &param(513))),
            Err(ParseError::ParamTooLong { index: 0, limit: 512 })
        );
        // The limit is in bytes: 257 two-byte characters are 514.
        assert!(matches!(
            parse(&replaced(r#"["pid=4711"]"#, &format!(r#"["{}"]"#, "ü".repeat(257)))),
            Err(ParseError::ParamTooLong { .. })
        ));

        let claim = |s: String| replaced("checking why the control loop misses cycles", &s);
        assert!(parse(&claim("c".repeat(200))).is_ok());
        assert!(parse(&claim("ü".repeat(200))).is_ok(), "200 characters, 400 bytes");
        assert_eq!(parse(&claim("c".repeat(201))), Err(ParseError::ClaimTooLong { limit: 200 }));

        // 16 KiB in all, filled with parameters (each has its own limit).
        let with_params = |items: &[String]| {
            replaced(
                r#"["pid=4711"]"#,
                &format!("[{}]", items.iter().map(|p| format!(r#""{p}""#)).collect::<Vec<_>>().join(",")),
            )
        };
        let room = MAX_BYTES - with_params(&[]).len();
        let full = (room - 2) / 515;
        let mut items = vec!["p".repeat(512); full];
        items.push("p".repeat(room - 2 - full * 515));
        let at_limit = with_params(&items);
        assert_eq!(at_limit.len(), MAX_BYTES);
        assert!(parse(&at_limit).is_ok());
        items.push(String::new());
        items.last_mut().unwrap().push('p');
        let over = with_params(&items);
        assert!(over.len() > MAX_BYTES);
        assert_eq!(parse(&over), Err(ParseError::TooLarge { len: over.len(), limit: MAX_BYTES }));
    }
}
