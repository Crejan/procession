//! A key twice in an object is refused at every depth of every signed or checked document, never read as the first or the
//! last (the workspace rule on repeated keys). Each document is written with one member repeated at a depth.
#![cfg(feature = "formats")]

use p_act::broker::{ConnectionDocument, Standing};
use p_act::exchange::{ClearancePolicy, Message};
use p_act::{Call, Clearance, ParseError, Request};

fn twice(text: &str, member: &str) -> String {
    // The member's own text, `"name":value`, written again right after itself.
    let start = text.find(&format!("\"{member}\":")).unwrap_or_else(|| panic!("{member} in {text}"));
    let rest = &text[start..];
    let mut depth = 0;
    let mut in_string = false;
    let mut escaped = false;
    let mut end = rest.len();
    for (i, c) in rest.char_indices() {
        if in_string {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            continue;
        }
        match c {
            '"' => in_string = true,
            '{' | '[' => depth += 1,
            '}' | ']' if depth == 0 => {
                end = i;
                break;
            }
            '}' | ']' => depth -= 1,
            ',' if depth == 0 => {
                end = i;
                break;
            }
            _ => {}
        }
    }
    let member_text = &rest[..end];
    format!("{}{member_text},{}", &text[..start], rest)
}

fn is_duplicate(e: &ParseError) -> bool {
    matches!(e, ParseError::DuplicateMember(_) | ParseError::InnerCall(_)) && e.to_string().contains("twice")
        || e.to_string().contains("appears twice")
}

#[test]
fn the_call_refuses_a_key_twice_at_the_top_and_in_the_service() {
    let call = r#"{"v":1,"type":"call","id":"3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11","deadline":"2026-11-11T15:06:05Z","service":{"host":"a.example","name":"probe"},"action":"rt procs","params":["pid=4711"],"claim":"x"}"#;
    assert!(Call::parse(call.as_bytes()).is_ok());
    for member in ["v", "type", "id", "deadline", "service", "host", "name", "action", "params", "claim"] {
        let e = Call::parse(twice(call, member).into_bytes()).unwrap_err();
        assert!(is_duplicate(&e), "{member}: {e}");
        assert!(e.to_string().contains(member), "{member}: {e}");
    }
}

#[test]
fn the_request_the_clearance_the_standing_and_the_connection_document_refuse_a_key_twice() {
    let call = Call::parse(
        br#"{"v":1,"type":"call","id":"3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11","deadline":"2026-11-11T15:06:05Z","service":{"host":"a.example","name":"probe"},"action":"rt procs","params":[],"claim":"x"}"#.to_vec(),
    )
    .unwrap();
    let sig = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n";
    let request = Request::compose(&call, sig, p_act::rating::Rating::HARMLESS, false).unwrap();
    let text = String::from_utf8(p_act::Document::as_bytes(&request).to_vec()).unwrap();
    for member in ["v", "type", "call", "call_sig", "rating", "exposure", "damage", "disruption", "host_text"] {
        let e = Request::parse(twice(&text, member).into_bytes()).unwrap_err();
        assert!(is_duplicate(&e) && e.to_string().contains(member), "request {member}: {e}");
    }
    let hash = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let clearance =
        format!(r#"{{"v":1,"type":"clearance","request":"{hash}","approval":"{hash}","at":"2026-11-11T15:04:41Z"}}"#);
    assert!(Clearance::parse(clearance.clone().into_bytes()).is_ok());
    for member in ["v", "type", "request", "approval", "at"] {
        let e = Clearance::parse(twice(&clearance, member).into_bytes()).unwrap_err();
        assert!(is_duplicate(&e) && e.to_string().contains(member), "clearance {member}: {e}");
    }
    let nonce = base64_of_32();
    let standing = format!(
        r#"{{"v":1,"type":"standing","to":"jan","nonce":"{nonce}","n":0,"at":"2026-11-11T15:04:41Z","blocked":false,"blocked_keys":[],"withdrawn":[],"certificates":[],"groups":[]}}"#
    );
    assert!(Standing::parse_unverified(standing.clone().into_bytes()).is_ok());
    for member in
        ["v", "type", "to", "nonce", "n", "at", "blocked", "blocked_keys", "withdrawn", "certificates", "groups"]
    {
        let e = Standing::parse_unverified(twice(&standing, member).into_bytes()).unwrap_err();
        assert!(is_duplicate(&e) && e.to_string().contains(member), "standing {member}: {e}");
    }
    let connection = ConnectionDocument::compose("jan", &[1; 32], &[2; 32]).unwrap();
    let text = String::from_utf8(p_act::Document::as_bytes(&connection).to_vec()).unwrap();
    let first_member = text.split("\":").nth(2).and_then(|_| text.split('"').nth(5)).unwrap().to_owned();
    for member in ["v", "type", "person", "nonce", "tls"].iter().filter(|m| text.contains(&format!("\"{m}\":"))) {
        let e = ConnectionDocument::parse_unverified(twice(&text, member).into_bytes()).unwrap_err();
        assert!(is_duplicate(&e) && e.to_string().contains(member), "connection {member}: {e} ({first_member})");
    }
}

fn base64_of_32() -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode([7u8; 32])
}

#[test]
fn an_exchange_message_refuses_a_key_twice_at_the_top_and_inside_a_member_object() {
    let hash = "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    let cancel = format!(r#"{{"schema_version":1,"type":"cancel","request":"{hash}"}}"#);
    assert!(Message::parse(cancel.as_bytes(), ClearancePolicy::Refused).is_ok());
    for member in ["schema_version", "type", "request"] {
        let e = Message::parse(twice(&cancel, member).as_bytes(), ClearancePolicy::Refused).unwrap_err();
        assert!(e.to_string().contains("twice") && e.to_string().contains(member), "{member}: {e}");
    }
}
