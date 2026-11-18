//! The request: what a service states it will do, signed by the service
//! (formats section 4).

use crate::call::Call;
use crate::error::ParseError;
use crate::hash::Document;
use crate::object::{Object, check_bytes};
use crate::rating::{Damage, Disruption, Exposure, Rating};
use crate::sign::{looks_armoured, signature_to_base64};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::Serialize;

/// A request is at most 32 KiB.
pub const MAX_BYTES: usize = 32 * 1024;

/// A parsed request: the call inside it, the call's signature as the agent
/// sent it, and the service's rating. It owns the bytes it was parsed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    bytes: Vec<u8>,
    call: Call,
    call_sig: String,
    rating: Rating,
    host_text: bool,
}

#[derive(Serialize)]
struct Wire<'a> {
    v: u8,
    #[serde(rename = "type")]
    kind: &'a str,
    call: String,
    call_sig: String,
    rating: WireRating,
    host_text: bool,
}

#[derive(Serialize)]
struct WireRating {
    exposure: &'static str,
    damage: &'static str,
    disruption: &'static str,
}

/// The three scales by name, in one table so that reading and writing cannot disagree.
const EXPOSURE: [(&str, Exposure); 3] =
    [("open", Exposure::Open), ("internal", Exposure::Internal), ("secret", Exposure::Secret)];
const DAMAGE: [(&str, Damage); 3] =
    [("none", Damage::None), ("recoverable", Damage::Recoverable), ("lasting", Damage::Lasting)];
const DISRUPTION: [(&str, Disruption); 3] =
    [("none", Disruption::None), ("brief", Disruption::Brief), ("outage", Disruption::Outage)];

fn name_of<T: PartialEq + Copy>(table: &[(&'static str, T)], value: T) -> &'static str {
    table.iter().find(|(_, v)| *v == value).map_or("", |(n, _)| n)
}

fn value_of<T: Copy>(table: &[(&str, T)], member: &'static str, name: String) -> Result<T, ParseError> {
    table.iter().find(|(n, _)| *n == name).map(|(_, v)| *v).ok_or(ParseError::MalformedRating { member, value: name })
}

impl Request {
    /// Parse and validate `bytes`, and the call inside; the request owns the
    /// request's bytes from now on. The call is parsed from the bytes the
    /// request carries, never from anything else.
    pub fn parse(bytes: impl Into<Vec<u8>>) -> Result<Request, ParseError> {
        let bytes = bytes.into();
        let mut o = Object::parse(check_bytes(&bytes, MAX_BYTES)?, "")?;
        o.take_header("request")?;
        let encoded = o.take_string("call")?;
        let call_bytes = STANDARD.decode(&encoded).map_err(|_| ParseError::MalformedBase64("call"))?;
        let call = Call::parse(call_bytes).map_err(|e| ParseError::InnerCall(Box::new(e)))?;
        let encoded_sig = o.take_string("call_sig")?;
        let call_sig = STANDARD.decode(&encoded_sig).map_err(|_| ParseError::MalformedBase64("call_sig"))?;
        let call_sig =
            String::from_utf8(call_sig).ok().filter(|s| looks_armoured(s)).ok_or(ParseError::MalformedSignature)?;
        let mut r = o.take_object("rating", "rating.")?;
        let exposure = value_of(&EXPOSURE, "exposure", r.take_string("exposure")?)?;
        let damage = value_of(&DAMAGE, "damage", r.take_string("damage")?)?;
        let disruption = value_of(&DISRUPTION, "disruption", r.take_string("disruption")?)?;
        r.finish()?;
        // Required and always written: there is no "absent means false".
        let host_text = o.take_bool("host_text")?;
        o.finish()?;
        Ok(Request { bytes, call, call_sig, rating: Rating::new(exposure, damage, disruption), host_text })
    }

    /// Write a new request around `call`, which is carried as the bytes it
    /// was parsed from or written to. The bytes are produced here, once, and
    /// checked by the same parser that reads every other request. `host_text` is whether the action's result can
    /// carry text that is not the service's (formats section 4); there is no default.
    pub fn compose(call: &Call, call_sig: &str, rating: Rating, host_text: bool) -> Result<Request, ParseError> {
        if !looks_armoured(call_sig) {
            return Err(ParseError::MalformedSignature);
        }
        let wire = Wire {
            v: 1,
            kind: "request",
            call: STANDARD.encode(call.as_bytes()),
            call_sig: signature_to_base64(call_sig),
            rating: WireRating {
                exposure: name_of(&EXPOSURE, rating.exposure),
                damage: name_of(&DAMAGE, rating.damage),
                disruption: name_of(&DISRUPTION, rating.disruption),
            },
            host_text,
        };
        let bytes = serde_json::to_vec(&wire).map_err(|e| ParseError::NotJson(e.to_string()))?;
        Request::parse(bytes)
    }

    /// The call inside, parsed from the bytes the request carries.
    #[must_use]
    pub fn call(&self) -> &Call {
        &self.call
    }

    /// The call's signature, as the agent sent it. Not verified by parsing.
    #[must_use]
    pub fn call_sig(&self) -> &str {
        &self.call_sig
    }

    #[must_use]
    pub fn rating(&self) -> Rating {
        self.rating
    }

    /// Whether the action's result can carry text that is not the service's (what runs on the host chooses it, or a
    /// file that is read). pledge shows a fixed line when it is `true`; the dispatcher refuses a call whose row has it
    /// `true` when the approved request said `false`: the flag can only restrict.
    #[must_use]
    pub fn host_text(&self) -> bool {
        self.host_text
    }
}

impl Document for Request {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const SIG: &str = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n";

    pub(crate) fn call() -> Call {
        Call::parse(crate::call::tests::EXAMPLE).unwrap()
    }

    pub(crate) fn request() -> Request {
        Request::compose(&call(), SIG, Rating::new(Exposure::Internal, Damage::None, Disruption::None), false).unwrap()
    }

    /// The example's text with one member rewritten, as bytes.
    fn edited(f: impl Fn(&str) -> String) -> Vec<u8> {
        f(std::str::from_utf8(request().as_bytes()).unwrap()).into_bytes()
    }

    #[test]
    fn compose_then_parse_round_trips_and_keeps_the_calls_bytes() {
        let request = request();
        let text = std::str::from_utf8(request.as_bytes()).unwrap();
        assert!(text.starts_with(r#"{"v":1,"type":"request","call":"eyJ2IjoxLCJ0eXBlIjoiY2FsbCIs"#), "{text}");
        assert!(
            text.ends_with(
                r#""rating":{"exposure":"internal","damage":"none","disruption":"none"},"host_text":false}"#
            ),
            "{text}"
        );
        // The signature is carried as base64 of its armoured bytes: `-----BEGIN SSH SIGNATURE-----\n...`.
        assert!(text.contains(r#""call_sig":"LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0K"#), "{text}");
        assert!(!text.contains("BEGIN"));
        assert!(!text.contains('\n'));
        let parsed = Request::parse(request.as_bytes()).unwrap();
        assert_eq!(parsed, request);
        assert_eq!(parsed.call().as_bytes(), crate::call::tests::EXAMPLE.as_bytes());
        assert_eq!(parsed.call_sig(), SIG);
        assert_eq!(parsed.rating(), Rating::new(Exposure::Internal, Damage::None, Disruption::None));
        assert!(!parsed.host_text());
    }

    #[test]
    fn host_text_is_required_always_written_true_or_false_and_nothing_else() {
        for flag in [false, true] {
            let request = Request::compose(&call(), SIG, Rating::HARMLESS, flag).unwrap();
            let text = std::str::from_utf8(request.as_bytes()).unwrap();
            assert!(text.ends_with(&format!(r#""host_text":{flag}}}"#)), "{text}");
            assert_eq!(Request::parse(request.as_bytes()).unwrap().host_text(), flag);
            // The flag is part of what is signed: the two requests have different bytes and different hashes.
            let other = Request::compose(&call(), SIG, Rating::HARMLESS, !flag).unwrap();
            assert_ne!(request.as_bytes(), other.as_bytes());
            assert_ne!(request.hash(), other.hash());
        }
        let swap = |from: &str, to: &str| edited(|t| t.replacen(from, to, 1));
        // Absent is malformed, not false.
        assert_eq!(Request::parse(swap(r#","host_text":false"#, "")), Err(ParseError::MissingMember("host_text")));
        for bad in ["null", "0", "1", "\"false\"", "\"true\"", "[]", "{}", "False"] {
            assert!(Request::parse(swap("\"host_text\":false", &format!("\"host_text\":{bad}"))).is_err(), "{bad}");
        }
        assert_eq!(
            Request::parse(swap(r#""host_text":false"#, r#""host_text":false,"host_text":true"#)),
            Err(ParseError::DuplicateMember("host_text".into()))
        );
        // Inside the rating it is an unknown member.
        assert_eq!(
            Request::parse(swap(r#""disruption":"none""#, r#""disruption":"none","host_text":false"#)),
            Err(ParseError::UnknownMember("rating.host_text".into()))
        );
    }

    #[test]
    fn the_calls_bytes_are_not_re_serialised() {
        // A call whose spacing a re-serialisation would change.
        let spaced = crate::call::tests::EXAMPLE.replacen(r#""v":1,"#, r#""v": 1, "#, 1);
        let call = Call::parse(spaced.as_bytes()).unwrap();
        let request = Request::compose(&call, SIG, Rating::HARMLESS, false).unwrap();
        assert_eq!(Request::parse(request.as_bytes()).unwrap().call().as_bytes(), spaced.as_bytes());
    }

    #[test]
    fn every_rating_survives_the_round_trip() {
        for (_, e) in EXPOSURE {
            for (_, d) in DAMAGE {
                for (_, s) in DISRUPTION {
                    let rating = Rating::new(e, d, s);
                    assert_eq!(
                        Request::parse(Request::compose(&call(), SIG, rating, false).unwrap().as_bytes())
                            .unwrap()
                            .rating(),
                        rating
                    );
                }
            }
        }
    }

    #[test]
    fn refuses_header_members_and_size_like_the_call() {
        let swap = |from: &str, to: &str| edited(|t| t.replacen(from, to, 1));
        assert_eq!(Request::parse(swap(r#""v":1"#, r#""v":2"#)), Err(ParseError::UnsupportedVersion("2".into())));
        assert_eq!(
            Request::parse(swap(r#""type":"request""#, r#""type":"call""#)),
            Err(ParseError::WrongDocumentType { expected: "request", found: "call".into() })
        );
        assert_eq!(
            Request::parse(swap(r#""rating":"#, r#""x":1,"rating":"#)),
            Err(ParseError::UnknownMember("x".into()))
        );
        assert_eq!(Request::parse(swap(r#","disruption":"none""#, "")), Err(ParseError::MissingMember("disruption")));
        assert_eq!(
            Request::parse(swap(r#""disruption":"none""#, r#""disruption":"none","extra":0"#)),
            Err(ParseError::UnknownMember("rating.extra".into()))
        );
        assert_eq!(
            Request::parse(swap(r#""damage":"none""#, r#""damage":"none","damage":"none""#)),
            Err(ParseError::DuplicateMember("rating.damage".into()))
        );
        let mut newline = request().as_bytes().to_vec();
        newline.push(b'\n');
        assert_eq!(Request::parse(newline), Err(ParseError::LineBreak));
        let big = vec![b' '; MAX_BYTES + 1];
        assert_eq!(Request::parse(big), Err(ParseError::TooLarge { len: MAX_BYTES + 1, limit: MAX_BYTES }));
    }

    #[test]
    fn refuses_a_malformed_rating_member() {
        for (member, from) in [("exposure", "internal"), ("damage", "none"), ("disruption", "none")] {
            for value in ["", "Open", "worst", "Secret", "lasting "] {
                let bytes =
                    edited(|t| t.replacen(&format!(r#""{member}":"{from}""#), &format!(r#""{member}":"{value}""#), 1));
                let member: &'static str =
                    ["exposure", "damage", "disruption"].into_iter().find(|m| *m == member).unwrap();
                assert_eq!(
                    Request::parse(bytes),
                    Err(ParseError::MalformedRating { member, value: value.into() }),
                    "{member} {value:?}"
                );
            }
        }
        // A value of another scale is not a value of this one.
        let bytes = edited(|t| t.replacen(r#""exposure":"internal""#, r#""exposure":"lasting""#, 1));
        assert!(matches!(Request::parse(bytes), Err(ParseError::MalformedRating { member: "exposure", .. })));
    }

    #[test]
    fn refuses_a_malformed_call_member() {
        let swap_call = |new: &str| edited(|t| t.replacen("eyJ2IjoxLCJ0eXBlIjoiY2FsbCIs", new, 1));
        assert_eq!(Request::parse(swap_call("e!J2IjoxLCJ0eXBlIjoiY2FsbCIs")), Err(ParseError::MalformedBase64("call")));
        // Unpadded base64 is refused: the padding is part of the format.
        let padded = (0..3)
            .map(|extra| {
                let mut content = call().content().clone();
                content.claim = Some("c".repeat(extra + 1));
                Call::compose(&content).unwrap()
            })
            .find(|c| STANDARD.encode(c.as_bytes()).ends_with('='))
            .unwrap();
        let encoded = STANDARD.encode(padded.as_bytes());
        let request = Request::compose(&padded, SIG, Rating::HARMLESS, false).unwrap();
        let text = String::from_utf8(request.as_bytes().to_vec()).unwrap();
        let unpadded = text.replacen(&encoded, encoded.trim_end_matches('='), 1);
        assert_eq!(Request::parse(unpadded), Err(ParseError::MalformedBase64("call")));
        // Valid base64 of something that is not a call, and of a changed call.
        let not_a_call =
            |bytes: &[u8]| edited(|t| t.replacen(&STANDARD.encode(call().as_bytes()), &STANDARD.encode(bytes), 1));
        assert!(
            matches!(Request::parse(not_a_call(b"hello")), Err(ParseError::InnerCall(e)) if matches!(*e, ParseError::NotJson(_)))
        );
        let wrong_version = crate::call::tests::EXAMPLE.replacen(r#""v":1"#, r#""v":2"#, 1);
        assert_eq!(
            Request::parse(not_a_call(wrong_version.as_bytes())),
            Err(ParseError::InnerCall(Box::new(ParseError::UnsupportedVersion("2".into()))))
        );
        let with_newline = format!("{}\n", crate::call::tests::EXAMPLE);
        assert_eq!(
            Request::parse(not_a_call(with_newline.as_bytes())),
            Err(ParseError::InnerCall(Box::new(ParseError::LineBreak)))
        );
    }

    #[test]
    fn refuses_a_call_sig_that_is_not_armour() {
        for bad in [
            "",
            "AAAA",
            "-----BEGIN SSH SIGNATURE-----\nAAAA\n",
            "-----BEGIN SSH SIGNATURE-----\nAA\u{0}AA\n-----END SSH SIGNATURE-----\n",
        ] {
            assert_eq!(
                Request::compose(&call(), bad, Rating::HARMLESS, false),
                Err(ParseError::MalformedSignature),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn refuses_a_call_sig_member_that_is_not_base64_of_armour() {
        let text = String::from_utf8(request().as_bytes().to_vec()).unwrap();
        let encoded = signature_to_base64(SIG);
        let with = |value: &str| text.replacen(&encoded, value, 1).into_bytes();
        // The plain armour, as the earlier draft carried it, is not base64.
        assert_eq!(Request::parse(with("-----BEGIN SSH SIGNATURE-----")), Err(ParseError::MalformedBase64("call_sig")));
        // With its line breaks it is also a string with control characters.
        assert_eq!(Request::parse(with(r"-----BEGIN\n")), Err(ParseError::ControlCharacter("call_sig".into())));
        assert_eq!(Request::parse(with(encoded.trim_end_matches('='))), Err(ParseError::MalformedBase64("call_sig")));
        // Valid base64 of something else.
        for other in ["hello", "-----BEGIN SSH SIGNATURE-----\nAAAA\n"] {
            assert_eq!(
                Request::parse(with(&signature_to_base64(other))),
                Err(ParseError::MalformedSignature),
                "{other}"
            );
        }
        assert_eq!(Request::parse(with(&STANDARD.encode([0xff, 0xfe]))), Err(ParseError::MalformedSignature));
        assert_eq!(Request::parse(with("")), Err(ParseError::MalformedSignature));
        assert_eq!(Request::parse(with(r"\u202e")), Err(ParseError::BidiMark("call_sig".into())));
    }

    #[test]
    fn the_hash_is_over_the_requests_bytes() {
        let request = request();
        assert_eq!(request.hash(), crate::DocumentHash::of(request.as_bytes()));
        let other = Request::compose(&call(), SIG, Rating::WORST, false).unwrap();
        assert_ne!(request.hash(), other.hash());
    }
}
