//! No error of p-act's puts a control character or a bidirectional mark from outside into its `Display` or `Debug`:
//! every variant that holds a string is built from the probe strings (a C1 control character, a bidirectional mark,
//! escape), and so is every error that comes out of a real parser fed a document with the probes in it.
#![cfg(feature = "formats")]

use p_act::broker::{ConnectionDocument, Standing, StandingError, ToPledge};
use p_act::exchange::{ExchangeError, Message};
use p_act::keygen::KeygenError;
use p_act::sign::SignError;
use p_act::{Call, Clearance, DocumentHash, ParseError, Request};
use p_ermit::probe::{PROBE_ALL, PROBES, assert_clean_in};
use std::fmt::{Debug, Display};

fn clean(what: &str, e: &(impl Display + Debug)) {
    assert_clean_in(&format!("{what}: Display"), &e.to_string());
    assert_clean_in(&format!("{what}: Debug"), &format!("{e:?}"));
}

#[test]
fn every_variant_that_holds_a_string_is_clean_whatever_it_holds() {
    for p in PROBES.iter().copied().chain([PROBE_ALL]) {
        let long = format!("{p}{}", "x".repeat(500));
        for s in [p.to_owned(), long] {
            let s = s.as_str();
            for e in [
                ParseError::NotJson(s.into()),
                ParseError::DuplicateMember(s.into()),
                ParseError::UnknownMember(s.into()),
                ParseError::WrongType { member: s.into(), expected: "a string" },
                ParseError::UnsupportedVersion(s.into()),
                ParseError::WrongDocumentType { expected: "call", found: s.into() },
                ParseError::ControlCharacter(s.into()),
                ParseError::BidiMark(s.into()),
                ParseError::MalformedUuid(s.into()),
                ParseError::MalformedTime(s.into()),
                ParseError::MalformedHost(s.into()),
                ParseError::MalformedServiceName(s.into()),
                ParseError::MalformedAction(s.into()),
                ParseError::MalformedRating { member: "damage", value: s.into() },
                ParseError::MalformedHash(s.into()),
                ParseError::MalformedFingerprint(s.into()),
                ParseError::InnerCall(Box::new(ParseError::UnknownMember(s.into()))),
            ] {
                clean("ParseError", &e);
                assert!(e.to_string().chars().count() < 400, "bounded: {}", e.to_string().len());
                clean("ExchangeError", &ExchangeError::Malformed(e.clone()));
                clean("ExchangeError", &ExchangeError::BadRequest { hash: DocumentHash::of(b""), source: e.clone() });
                clean("ExchangeError", &ExchangeError::BadClearance(e.clone()));
                clean("StandingError", &StandingError::Document(e.clone()));
                clean("SignError", &SignError::Document(e));
            }
            for e in [
                SignError::MalformedPublicKey(s.into()),
                SignError::UnsupportedKeyType(s.into()),
                SignError::BadPrincipal(s.into()),
                SignError::AgentKeyNotEd25519(s.into()),
                SignError::CriticalOption(s.into()),
                SignError::SiteCertificateExtension(s.into()),
                SignError::UnknownExtension(s.into()),
                SignError::MalformedFingerprint(s.into()),
                SignError::NotBrokerName(s.into()),
                SignError::NotAnApprovalName(s.into()),
                SignError::ReservedName(s.into()),
                SignError::Holder(s.into()),
                SignError::CertificateNotVerified(s.into()),
                SignError::Tool { status: "exit status: 1".into(), stderr: s.into() },
                SignError::Tool { status: s.into(), stderr: String::new() },
                SignError::Rejected { stderr: s.into() },
            ] {
                clean("SignError", &e);
                // What the program said is not in `Display`; it is available escaped and bounded for a log.
                if let Some(detail) = e.log_detail() {
                    assert_clean_in("SignError::log_detail", &detail);
                    assert!(detail.chars().count() <= p_act::sign::MAX_LOG_DETAIL_CHARS);
                    assert!(!e.to_string().contains("xxxxxxxx"), "stderr is not forwarded by Display");
                }
            }
            for e in [ExchangeError::BadCertificate(s.into()), ExchangeError::Io(s.into())] {
                clean("ExchangeError", &e);
            }
            for e in [
                KeygenError::NotFound(s.into()),
                KeygenError::NotTrusted { path: s.into(), why: s.into() },
                KeygenError::Version { found: s.into(), needed: s.into() },
                KeygenError::Cannot(s.into(), s.into()),
            ] {
                // Paths and reasons are the program's own words; a path that is the caller's is escaped too.
                assert_clean_in("KeygenError", &e.to_string());
            }
        }
    }
}

/// A member name, a type, a value in every place a document can hold one, each with the probes.
#[test]
fn documents_with_the_probes_in_them_are_refused_with_clean_messages() {
    let probe = PROBE_ALL
        .replace('\u{1b}', "\\u001b")
        .replace('\u{85}', "\\u0085")
        .replace('\u{9b}', "\\u009b")
        .replace('\u{202e}', "\\u202e");
    let call = |f: &dyn Fn(&str) -> String| f(&probe);
    let example = r#"{"v":1,"type":"call","id":"3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11","deadline":"2026-11-11T15:06:05Z","service":{"host":"a.example","name":"probe"},"action":"rt procs","params":["pid=4711"],"claim":"x"}"#;
    let edits: Vec<String> = vec![
        call(&|p| example.replacen(r#""v":1,"#, &format!(r#""v":1,"{p}":1,"#), 1)),
        call(&|p| example.replacen(r#""type":"call""#, &format!(r#""type":"{p}""#), 1)),
        call(&|p| example.replacen(r#""v":1"#, &format!(r#""v":"{p}""#), 1)),
        call(&|p| example.replacen("3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11", p, 1)),
        call(&|p| example.replacen("2026-11-11T15:06:05Z", p, 1)),
        call(&|p| example.replacen("a.example", p, 1)),
        call(&|p| example.replacen("probe", p, 1)),
        call(&|p| example.replacen("rt procs", p, 1)),
        call(&|p| example.replacen("pid=4711", p, 1)),
        call(&|p| example.replacen(r#""claim":"x""#, &format!(r#""claim":"{p}""#), 1)),
        call(&|p| example.replacen(r#""action""#, &format!(r#""{p}""#), 1)),
        call(&|p| example.replacen(r#""id""#, &format!(r#""id":1,"{p}""#), 1)),
        call(&|p| format!("{example}{p}")),
        call(&|p| format!("{{\"{p}\":")),
    ];
    for text in &edits {
        if let Err(e) = Call::parse(text.as_bytes()) {
            clean("Call::parse", &e);
        }
        if let Err(e) = Request::parse(text.as_bytes()) {
            clean("Request::parse", &e);
        }
        if let Err(e) = Clearance::parse(text.as_bytes()) {
            clean("Clearance::parse", &e);
        }
        if let Err(e) = Standing::parse_unverified(text.as_bytes()) {
            clean("Standing::parse_unverified", &e);
        }
        if let Err(e) = ConnectionDocument::parse_unverified(text.as_bytes()) {
            clean("ConnectionDocument::parse", &e);
        }
        if let Err(e) = Message::parse(text.as_bytes(), p_act::exchange::ClearancePolicy::Refused) {
            clean("Message::parse", &e);
        }
        if let Err(e) = ToPledge::parse(text.as_bytes()) {
            clean("ToPledge::parse", &e);
        }
    }
    // The call's own refusals (parsed documents cannot hold a probe, so this builds the content and asks `showable`).
    for p in PROBES {
        let mut content = Call::parse(example.as_bytes()).unwrap().content().clone();
        content.action = format!("a{p}b");
        if let Ok(call) = Call::compose(&content) {
            if let Err(e) = call.showable() {
                clean("NotShowable", &e);
            }
        } else if let Err(e) = Call::compose(&content) {
            clean("Call::compose", &e);
        }
    }
}
