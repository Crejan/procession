//! The workspace rule for strings from outside (`README.md`, Conventions): one test that feeds a C1 control
//! character and a bidirectional mark through every output `probe` has: the dispatcher's lines, the catalogue, the
//! MCP result, the audit lines, the errors, `sys kit`. Nothing that `p_ermit::text::check` refuses may come out of
//! any of them, and what was refused must be visible as literal text, never dropped.
#![cfg(feature = "test-verbs")]

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const PROBE: &str = env!("CARGO_BIN_EXE_probe");

/// A C1 control (U+0085), an ESC, a bidirectional override (U+202E) and a backslash.
const HOSTILE: &str = "a\u{85}b\u{1b}[31m\u{202e}c\\d";

fn sandbox(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("probe-outside-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("locks")).unwrap();
    dir
}

fn probe(args: &[&str], dir: Option<&Path>) -> Output {
    let mut command = Command::new(PROBE);
    command.args(args).env_clear().env("SUDO_USER", "jan");
    if let Some(dir) = dir {
        command.env("PROBE_TEST_SANDBOX", dir);
    }
    command.output().unwrap()
}

/// Every line of `text` is free of what the rule refuses (the line break between records is the format's own).
fn clean(what: &str, text: &str) {
    for line in text.lines() {
        if let Err(kind) = p_ermit::text::check(line) {
            panic!("{what} lets through a character the rule refuses ({kind:?}): {line:?}");
        }
    }
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[test]
fn a_c1_control_and_a_bidirectional_mark_are_visible_in_every_output_and_in_none_raw() {
    // -- a verb's answer: the bytes of a file, and a path that was reached through a link whose target is named so.
    let plain = sandbox("plain");
    for sub in ["open", "private"] {
        std::fs::create_dir(plain.join(sub)).unwrap();
        std::fs::set_permissions(plain.join(sub), std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let target = plain.join("open/t\u{202e}arget\u{85}");
    std::fs::write(&target, HOSTILE).unwrap();
    symlink(&target, plain.join("open/link")).unwrap();
    let read = probe(
        &["--within", "open,none,none,text", "test", "read", &plain.join("open/link").display().to_string()],
        Some(&plain),
    );
    assert_eq!(read.status.code(), Some(0), "{}", text(&read.stderr));
    let answer = text(&read.stdout);
    clean("the dispatcher's lines", &answer);
    // Visible, not dropped: the form of the rule, in the field that holds the bytes and in the one that holds the path.
    let file = answer.lines().find(|l| l.contains("\"type\":\"file\"")).expect("a file record");
    let record: serde_json::Value = serde_json::from_str(file).unwrap();
    assert_eq!(record["text"], "a\\u{85}b\\u{1b}[31m\\u{202e}c\\\\d", "{file}");
    assert!(record["resolved"].as_str().unwrap().contains("t\\u{202e}arget\\u{85}"), "{file}");
    assert_eq!(record["escaped"], true, "a record with an escaped string says so");

    // -- the audit lines of that call, and of a refused one whose argument and message carry the characters.
    let audit_of = |dir: &Path| std::fs::read_to_string(dir.join("audit.log")).unwrap_or_default();
    clean("the audit lines", &audit_of(&plain));
    let refused = probe(&["test", "echo", HOSTILE], Some(&plain));
    assert_eq!(refused.status.code(), Some(64));
    clean("the error", &text(&refused.stderr));
    clean("the answer of a refused call", &text(&refused.stdout));
    let audit = audit_of(&plain);
    clean("the audit lines", &audit);
    assert!(audit.lines().all(|l| l.is_ascii()), "an audit line is ASCII: {audit}");
    assert!(audit.contains("\\u{85}") && audit.contains("\\u{202e}"), "visible in the audit line: {audit}");
    assert!(p_robe::audit::line("refused", &[("reason", HOSTILE), ("cmd", HOSTILE)]).is_ascii());
    clean("audit::line", &p_robe::audit::line("refused", &[("reason", HOSTILE)]));

    // -- `sys kit` in a place whose name carries them (it reports the lock directory and the audit sink).
    let odd = sandbox("odd\u{202e}\u{85}");
    let kit = probe(&["sys", "kit"], Some(&odd));
    let kit_lines = text(&kit.stdout);
    clean("sys kit", &kit_lines);
    assert!(kit_lines.contains("\\u{202e}") && kit_lines.contains("\\u{85}"), "visible in sys kit: {kit_lines}");
    let installation: serde_json::Value =
        serde_json::from_str(kit_lines.lines().find(|l| l.contains("\"type\":\"installation\"")).unwrap()).unwrap();
    assert_eq!(installation["escaped"], true);

    // -- the catalogue, as text and as records.
    clean("the catalogue", &text(&probe(&["catalog"], None).stdout));
    clean("the catalogue records", &text(&probe(&["catalog", "--format", "json"], None).stdout));

    // -- the MCP result of the call that was run: text blocks and the structured result.
    let outcome = p_robe::outcome::Outcome::Done { rc: 0, answer };
    let result = p_robe::mcp::tool_result(&outcome, "3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11");
    for block in result["content"].as_array().unwrap() {
        clean("an MCP text block", block["text"].as_str().unwrap());
    }
    let structured = result["structuredContent"].to_string();
    clean("the MCP structured result", &structured);
    assert!(
        result["structuredContent"]["records"].as_array().unwrap().iter().any(|r| r["escaped"] == true),
        "{structured}"
    );
    assert_eq!(result["structuredContent"]["escaped_records"], 1);
}
