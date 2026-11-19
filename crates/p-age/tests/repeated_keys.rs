//! A reader of JSON that is signed, checked or decided on refuses an object with a repeated key (workspace rule). Each
//! reader of p-age that takes JSON from a file or a socket is tried with a key twice, and with the same document without
//! the repeat (which must be read), so that a refusal is for the repeat and not for something else.

use p_age::register::Snapshot;
use p_age::site::{Directory, SiteBase};

fn key_line(n: u8) -> String {
    use base64::Engine;
    let mut r = vec![0, 0, 0, 11];
    r.extend_from_slice(b"ssh-ed25519");
    r.extend_from_slice(&[0, 0, 0, 32]);
    r.extend_from_slice(&[n; 32]);
    format!("ssh-ed25519 {}", base64::engine::general_purpose::STANDARD.encode(r))
}

/// `plain` is read and each of `repeated` is refused.
fn only_the_repeat_is_refused<T, E>(reader: impl Fn(&str) -> Result<T, E>, plain: &str, repeated: &[&str]) {
    assert!(reader(plain).is_ok(), "the control is not read: {plain}");
    for text in repeated {
        assert!(reader(text).is_err(), "a repeated key was read: {text}");
    }
}

#[test]
fn the_register_refuses_a_repeated_key_at_every_level() {
    let fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let read = |t: &str| {
        serde_json::from_str::<Snapshot>(t)
            .map_err(|e| e.to_string())
            .and_then(|s| p_age::register::Register::restore(s).map(|_| ()).map_err(str::to_owned))
    };
    let with = |entry: &str| format!(r#"{{"v":1,"delegations":[],"blocked":[{entry}]}}"#);
    let entry = r#"{"name":"a","at":1,"by":{"kind":"administrator","uid":1}}"#;
    only_the_repeat_is_refused(
        read,
        &with(entry),
        &[
            r#"{"v":1,"v":1,"delegations":[],"blocked":[]}"#,
            &with(r#"{"name":"a","name":"b","at":1,"by":{"kind":"administrator","uid":1}}"#),
            &with(r#"{"name":"a","at":1,"at":2,"by":{"kind":"administrator","uid":1}}"#),
            &with(r#"{"name":"a","at":1,"by":{"kind":"administrator","uid":1,"uid":0}}"#),
            &with(r#"{"name":"a","at":1,"by":{"kind":"administrator","kind":"pledge","uid":1}}"#),
            &format!(
                r#"{{"v":1,"delegations":[{{"fingerprint":"{fp}","fingerprint":"x","person":"a","until":1,"withdrawn":false}}],"blocked":[]}}"#
            ),
        ],
    );
}

#[test]
fn the_administrators_command_refuses_a_repeated_key() {
    let read = |t: &str| p_age::admin::Command::parse(t.as_bytes()).ok_or(());
    only_the_repeat_is_refused(
        read,
        r#"{"schema_version":1,"type":"block","person":"a"}"#,
        &[
            r#"{"schema_version":1,"type":"block","person":"a","person":"b"}"#,
            r#"{"schema_version":1,"type":"status","type":"block","person":"a"}"#,
        ],
    );
}

#[test]
fn the_site_file_and_directory_json_refuse_a_repeated_key() {
    let keys = format!(
        r#""keys":{{"confirmed":{{"key":"{}"}},"automatic":{{"key":"{}"}},"delegation":{{"key":"{}"}},"connection":{{"key":"{}"}}}}"#,
        key_line(1),
        key_line(2),
        key_line(3),
        key_line(4)
    );
    let site = |inner: &str| format!(r#"{{"v":1,"persons":[{inner}],"hosts":[]}}"#);
    let twice_confirmed =
        keys.replacen(r#""confirmed":{"key":""#, r#""confirmed":{"key":"x"},"confirmed":{"key":""#, 1);
    let twice_key = keys.replacen(r#"{"key":""#, r#"{"key":"x","key":""#, 1);
    only_the_repeat_is_refused(
        SiteBase::from_text,
        &site(&format!(r#"{{"name":"a",{keys}}}"#)),
        &[
            &format!(r#"{{"v":1,"v":1,"persons":[{{"name":"a",{keys}}}],"hosts":[]}}"#),
            &site(&format!(r#"{{"name":"a","name":"b",{keys}}}"#)),
            &site(&format!(r#"{{"name":"a",{twice_confirmed}}}"#)),
            &site(&format!(r#"{{"name":"a",{twice_key}}}"#)),
        ],
    );
    let now = std::time::SystemTime::now();
    let directory = |source: &str, members: &str| {
        format!(r#"{{"v":1,{source}"as_of":"2026-11-19T10:00:00Z","active":[],"members":{members}}}"#)
    };
    only_the_repeat_is_refused(
        |t: &str| Directory::from_text(t, now),
        &directory(r#""source":"model","#, r#"{"a":[]}"#),
        &[
            &directory(r#""source":"ldap","source":"model","#, "{}"),
            &directory(r#""source":"model","#, r#"{"a":[],"a":[]}"#),
        ],
    );
}
