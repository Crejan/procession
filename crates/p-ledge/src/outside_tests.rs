//! One sweep: strings that came from outside (a C1 control, a CSI, an ESC sequence, a bidirectional mark) are
//! put through every output pledge has. The audit's list of sites in `proposals/REPORT.md` is the checklist; what
//! a person is asked about is refused at entry and tested where it is refused (`agent_conn`, `approvals`).

use serde_json::{Value, json};

use crate::outside::{PROBES, assert_clean, bounded, json as escaped_json};
use crate::policy::Purpose;
use crate::shared::KeyMeta;
use crate::testing::Rig;

/// A record entry (or any object) with a probe in every string member.
fn with_probe(probe: &str) -> Value {
    json!({
        "type": "request", "result": "refused", "reason": "blocked", "seq": 7, "time": "2026-11-18T10:00:00Z",
        "mode": probe, "person": probe, "delegation": probe, "action": probe, "call": probe, "why": probe,
        "params": [probe], "service": {"host": probe, "name": probe}, "peer": {"uid": 1, "program": probe},
        "program": probe, "purpose": probe, "fingerprint": probe, "public": probe, "state": probe,
        "groups": [probe], "valid_until": probe, "last_asked": probe,
    })
}

#[test]
fn the_json_forms_escape_everything_read_back_and_say_so() {
    // Sites 12-15 (history, keys, programs and agents list in JSON).
    for probe in PROBES {
        let out = escaped_json(&with_probe(probe)).to_string();
        assert_clean(&out, "json");
        assert!(out.contains("\"escaped\":true"), "{probe:?} was escaped and the object says so: {out}");
    }
    let plain = escaped_json(&json!({"program": "/usr/bin/ssh", "n": 1}));
    assert!(plain.get("escaped").is_none(), "absent when nothing was escaped");
    // A member name from a file is outside too.
    let named = escaped_json(&json!({ "a\u{9b}b": 1 }));
    assert_clean(&named.to_string(), "member name");
}

#[test]
fn the_text_forms_print_nothing_raw() {
    // Sites 11, 13-15: `pledge history` and the lists in text.
    for probe in PROBES {
        assert_clean(&crate::cli::history_line(&with_probe(probe)), "history");
        assert_clean(&crate::outside::text(probe), "text");
    }
    for kind in ["signing-request", "request", "received", "lost", "event"] {
        let mut entry = with_probe("a\u{85}b\u{202e}");
        entry["type"] = kind.into();
        assert_clean(&crate::cli::history_line(&entry), kind);
    }
}

#[test]
fn the_program_of_a_peer_is_written_escaped_and_cut_not_left_out() {
    // Site 8.
    for probe in PROBES {
        let seen = crate::peer::Seen { uid: 1, pid: Some(2), program: Some(format!("/bin/{probe}")) };
        let entry = crate::approvals::peer_json(&seen);
        assert_clean(&entry.to_string(), "peer");
        assert_eq!(entry["escaped"], true);
        assert!(entry["program"].as_str().is_some(), "still says which program");
    }
    let long = crate::peer::Seen { uid: 1, pid: None, program: Some("x".repeat(500)) };
    let entry = crate::approvals::peer_json(&long);
    assert_eq!(entry["program"].as_str().map(|p| p.chars().count()), Some(200));
    assert_eq!(entry["clipped"], true);
}

#[test]
fn a_key_comment_is_offered_escaped_and_the_key_is_not_refused_over_it() {
    // Site 16.
    let rig = Rig::new([]);
    for probe in PROBES {
        let blob = rig.key(KeyMeta {
            purpose: "shared".into(),
            program: None,
            use_: None,
            comment: probe.into(),
            key_type: String::new(),
            created: String::new(),
        });
        let _ = blob;
    }
    let reply = crate::agent_conn::list_identities(&rig.shared, Some("/usr/bin/ssh"));
    // Frame: u32 length, type, u32 count, then per key a string (blob) and a string (comment). The blobs are binary and
    // may hold any byte; only the comments are text.
    let string_at = |at: usize| {
        let len = u32::from_be_bytes(reply[at..at + 4].try_into().expect("length")) as usize;
        (&reply[at + 4..at + 4 + len], at + 4 + len)
    };
    let count = u32::from_be_bytes(reply[5..9].try_into().expect("count"));
    assert!(count >= 4, "every key is offered, none refused over its comment");
    let mut at = 9;
    for _ in 0..count {
        let (_blob, next) = string_at(at);
        let (comment, next) = string_at(next);
        assert_clean(std::str::from_utf8(comment).expect("text"), "comment");
        at = next;
    }
    assert!(reply.len() > 5, "the keys are offered, not refused");
}

#[test]
fn programs_json_with_a_name_that_breaks_the_rule_is_refused_whole_and_the_error_repeats_nothing() {
    // Site 14, the read-back.
    for probe in PROBES {
        let rig = Rig::new([]);
        let file = rig.dir.path().join("programs.json");
        std::fs::write(&file, json!({"programs": {"/usr/bin/ok": "admitted", probe: "admitted"}}).to_string())
            .expect("write");
        std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o600)).expect("chmod");
        let error = rig.shared.load_programs().expect_err("refused whole").to_string();
        assert_clean(&error, "error");
        assert!(!error.contains("ok"), "nothing of the file is repeated: {error}");
        assert!(rig.shared.policy.lock().expect("policy").programs().next().is_none(), "none of it counts");
    }
    let _ = Purpose::Shared;
}

#[test]
fn errors_and_logs_carry_outside_text_only_escaped_and_bounded() {
    // Sites 19-21: ssh-keygen's stderr, serde errors, paths, the command line.
    for probe in PROBES {
        let shown = bounded(&format!("{probe} {}", "y".repeat(1000)), 200);
        assert_clean(&shown, "bounded");
        assert!(shown.chars().count() <= 203, "bounded: {}", shown.chars().count());
    }
}
