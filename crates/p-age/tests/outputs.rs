//! The workspace's rule on strings from outside (`README.md`, "Strings from outside"): a C1 control character
//! (U+0085, U+009B) and a bidirectional mark (U+202E) are fed through every output the broker has, and none comes out
//! raw. The sites are the audit's (`proposals/REPORT.md`, "Audit"). `serde_json` escapes controls but writes
//! bidirectional marks raw, so what is pinned for the log and the JSON status is that their *inputs* cannot carry one.

mod common;

use std::os::unix::fs::PermissionsExt;

use common::*;
use p_age::admin::{Command, Reply, Target, execute};
use p_age::certs::{self, CertificateInput};
use p_age::crypto::SshCrypto;
use p_age::site::Site;
use p_ermit::text::check;

/// U+0085, U+009B and U+202E among ordinary letters.
const NASTY: &str = "x\u{85}y\u{9b}z\u{202e}w";

fn clean(what: &str, s: &str) {
    // several lines are several strings: the line break is the output's own
    for line in s.lines() {
        assert!(check(line).is_ok(), "{what} carries a raw control character or bidirectional mark: {line:?}");
    }
}

fn key_line(n: u8) -> String {
    let mut raw = vec![0, 0, 0, 11];
    raw.extend_from_slice(b"ssh-ed25519");
    raw.extend_from_slice(&[0, 0, 0, 32]);
    raw.extend_from_slice(&[n; 32]);
    use base64::Engine;
    format!("ssh-ed25519 {}", base64::engine::general_purpose::STANDARD.encode(raw))
}

fn keys(n: u8) -> serde_json::Value {
    let row = |k: u8| serde_json::json!({"key": key_line(k)});
    serde_json::json!({"keys": {"confirmed": row(n), "automatic": row(n + 1), "delegation": row(n + 2), "connection": row(n + 3)}})
}

fn site_error(persons: serde_json::Value, hosts: serde_json::Value, members: Option<serde_json::Value>) -> String {
    let mut v = serde_json::json!({"v": 1, "persons": persons, "hosts": hosts});
    if let Some(m) = members {
        v["members"] = m;
    }
    Site::from_json(&v.to_string()).err().map(|e| e.to_string()).expect("the site file should be refused")
}

#[test]
fn the_site_file_errors_that_echo_what_failed_escape_it() {
    let person = |name: &str, extra: serde_json::Value| {
        let mut p = serde_json::json!({"name": name, "enabled": true});
        if let (Some(o), Some(e)) = (p.as_object_mut(), extra.as_object()) {
            o.extend(e.clone());
        }
        p
    };
    // a bad person name, a bad host name, a duplicate that is bad, a bad date, a bad key line, bad members
    let cases = [
        site_error(serde_json::json!([person(NASTY, keys(1))]), serde_json::json!([]), None),
        site_error(serde_json::json!([]), serde_json::json!([{"name": NASTY, "key": key_line(9)}]), None),
        site_error(
            serde_json::json!([person(
                "jan",
                serde_json::json!({"keys": {
                "confirmed": {"key": key_line(1), "verified_on": NASTY},
                "automatic": {"key": key_line(2)}, "delegation": {"key": key_line(3)}, "connection": {"key": key_line(4)}}})
            )]),
            serde_json::json!([]),
            None,
        ),
        site_error(
            serde_json::json!([person(
                "jan",
                serde_json::json!({"keys": {
                "confirmed": {"key": NASTY}, "automatic": {"key": key_line(2)},
                "delegation": {"key": key_line(3)}, "connection": {"key": key_line(4)}}})
            )]),
            serde_json::json!([]),
            None,
        ),
        site_error(
            serde_json::json!([person("jan", keys(1))]),
            serde_json::json!([]),
            Some(serde_json::json!({ NASTY: ["jan"] })),
        ),
        site_error(
            serde_json::json!([person("jan", keys(1))]),
            serde_json::json!([]),
            Some(serde_json::json!({"staff": [NASTY]})),
        ),
    ];
    for (i, text) in cases.iter().enumerate() {
        clean(&format!("site error {i}"), text);
    }
}

#[test]
fn a_register_with_an_entry_that_breaks_the_rule_is_refused_whole_and_its_errors_are_clean() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("register.json");
    let fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    for (text, why) in [
        (
            serde_json::json!({"v": 1, "delegations": [], "blocked": [{"name": NASTY, "at": 1, "by": {"kind": "administrator", "uid": 0}}]}),
            "a bad name in blocked",
        ),
        (
            serde_json::json!({"v": 1, "delegations": [], "blocked": [], "blocked_keys": [{"name": NASTY, "at": 1, "by": {"kind": "pledge", "person": "jan"}}]}),
            "a bad fingerprint",
        ),
        (
            serde_json::json!({"v": 1, "delegations": [{"fingerprint": fp, "person": NASTY, "until": 1, "withdrawn": false}], "blocked": []}),
            "a bad person in a delegation",
        ),
        (serde_json::json!({"v": 1, "delegations": [], "blocked": NASTY}), "a parse error that quotes the value"),
    ] {
        std::fs::write(&path, text.to_string()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let e = p_age::core::Core::read_state(&path).err().unwrap_or_else(|| panic!("{why}: the register was read"));
        clean(why, &e.to_string());
    }
}

#[tokio::test]
async fn a_certificate_file_and_its_reason_are_shown_escaped_everywhere() {
    let w = World::new();
    let dir = w.keys.path("collection");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    // a file whose name carries the characters, and whose content is a certificate line with them in its comment
    let name = format!("{NASTY}-cert.pub");
    std::fs::write(dir.join(&name), format!("ssh-ed25519-cert-v01@openssh.com AAAA {NASTY}\n")).unwrap();
    std::fs::set_permissions(dir.join(&name), std::fs::Permissions::from_mode(0o644)).unwrap();
    let now =
        std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(u64::try_from(w.clock.unix()).unwrap());
    let input = CertificateInput { site_ca: w.keys.public(&w.site_ca), directory: dir.clone() };
    let loaded = certs::load(&input, &w.site, &SshCrypto::new(&w.broker_key), now);
    assert!(!loaded.not_carried.is_empty(), "the file is not carried");
    for n in &loaded.not_carried {
        clean("a certificate's file name", &n.file);
        clean("a certificate's reason", &n.reason);
    }
    // a directory that is refused whole: its reason is shown as well
    let bad = w.keys.path("open");
    std::fs::create_dir_all(&bad).unwrap();
    std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o777)).unwrap();
    let refused = certs::load(
        &CertificateInput { site_ca: input.site_ca.clone(), directory: bad },
        &w.site,
        &SshCrypto::new(&w.broker_key),
        now,
    );
    clean("a directory's reason", refused.directory_refused.as_deref().unwrap_or(""));
}

#[test]
fn a_status_answer_whose_lists_break_the_rule_is_refused_not_printed() {
    let fp = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let good = |names: &str, keys: &str, uncovered: &str| {
        format!(
            r#"{{"schema_version":1,"type":"status","degraded":false,"pledges":0,"held":0,"delegations":0,"withdrawn":0,"broker_uid":501,"blocked_persons":{names},"blocked_keys":{keys},"broker_certificate_path":"/x","broker_certificate_valid":true,"broker_certificate_days":3,"certificates_carried":0,"certificates_not_carried":0,"certificates_directory_refused":false,"uncovered":{uncovered}}}"#
        )
    };
    let fine = good(r#"["jan"]"#, &format!(r#"["{fp}"]"#), r#"["eva:automatic"]"#);
    assert!(Reply::parse(fine.as_bytes()).is_some(), "the control answer parses");
    for bad in [
        good(&serde_json::json!([NASTY]).to_string(), "[]", "[]"),
        good("[]", &serde_json::json!([NASTY]).to_string(), "[]"),
        good("[]", "[]", &serde_json::json!([NASTY]).to_string()),
    ] {
        assert_eq!(Reply::parse(bad.as_bytes()), None);
    }
}

#[tokio::test]
async fn the_verbs_say_nothing_raw_about_what_the_operator_typed() {
    let w = World::new();
    let config = config_file(&w);
    // an unknown verb is echoed escaped
    let out = tokio::task::spawn_blocking(|| {
        std::process::Command::new(env!("CARGO_BIN_EXE_page")).arg(NASTY).output().unwrap()
    })
    .await
    .unwrap();
    clean("`unknown verb` on standard error", &String::from_utf8_lossy(&out.stderr));
    clean("`unknown verb` on standard output", &String::from_utf8_lossy(&out.stdout));
    // a name typed on `block` is refused and not echoed, with or without a broker
    let (_, out, err) = page(&config, &["block", NASTY]).await;
    clean("block's output", &out);
    clean("block's errors", &err);
    // and the broker, asked directly, refuses it
    let reply = execute(&w.broker, Command::Block(Target::Person(NASTY.to_owned()))).await;
    assert!(matches!(reply, Reply::Refused(..)), "{reply:?}");
    let socket = serve_admin(&w);
    let (_, out, err) = page(&config, &["block", NASTY]).await;
    assert!(socket.exists());
    clean("block's output with a broker", &out);
    clean("block's errors with a broker", &err);
}

#[tokio::test]
async fn the_log_and_the_json_status_cannot_carry_what_the_rule_refuses() {
    let w = World::new();
    // a request for a host and a service the broker parses before it logs anything
    let mut svc = open_service(&w);
    svc.send(&submit_line(&w.submit(1, 120))).await;
    wait_logged(&w, 1).await;
    for e in w.log.entries() {
        for (what, s) in [
            ("host", Some(&e.host)),
            ("service", Some(&e.service)),
            ("person", e.person.as_ref()),
            ("result", Some(&e.result)),
            ("delegation", e.delegation.as_ref()),
        ] {
            clean(&format!("the log's {what}"), s.map_or("", String::as_str));
        }
    }
    // an attempt to put the characters in through a verb changes nothing that the log or status carries
    let _ = execute(&w.broker, Command::Block(Target::Person(NASTY.to_owned()))).await;
    let Reply::Status(s) = execute(&w.broker, Command::Status).await else { panic!("status") };
    clean("the JSON status", &p_age::admin::conditions_json(&s));
    for list in [&s.blocked_persons, &s.blocked_keys] {
        assert!(list.iter().all(|x| check(x).is_ok()));
    }
    let (text, _) = p_age::admin::render(&Command::Status, &Reply::Status(s));
    clean("the text status", &text);
}
