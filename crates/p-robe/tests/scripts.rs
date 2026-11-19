//! The deadlines in the scripts the owner runs, against the dispatcher's own rule.
//!
//! `a2-check-rule.sh` once used a fixed deadline in the year 2100 for its ordinary calls; the dispatcher, rightly,
//! refuses a deadline more than ten minutes (and the tolerance) ahead, and the owner's run failed at its first call.
//! Nothing connected the script's numbers to the rule. This does: every `--until` in the scripts is read and
//! judged by `p_robe::dispatch::until_too_far`.

use std::path::Path;

use p_robe::dispatch::until_too_far;

const NOW: i64 = 1_800_000_000;

/// How a script gives a deadline.
#[derive(Debug, PartialEq)]
enum Until {
    /// A plain number: only a deadline in the past makes sense.
    Literal(i64),
    /// `$(( $(date +%s) + N ))`: now plus N seconds.
    Ahead(i64),
    /// A variable the script sets itself, judged where it is set.
    Variable(String),
}

fn parse_until(token_rest: &str) -> Option<Until> {
    let rest = token_rest.trim_start();
    if let Some(expr) = rest.strip_prefix("$(( $(date +%s) + ") {
        let n: String = expr.chars().take_while(char::is_ascii_digit).collect();
        return n.parse().ok().map(Until::Ahead);
    }
    if let Some(var) = rest.strip_prefix('$') {
        let name: String = var.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '_').collect();
        return Some(Until::Variable(name));
    }
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok().map(Until::Literal)
}

/// Every deadline in `text`, with the lines around it (a check's name is on the line before its command).
fn deadlines(text: &str) -> Vec<(Until, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut found = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if line.trim_start().starts_with('#') {
            continue;
        }
        // `--until <value>` in a command, or `NAME=$(( $(date +%s) + N ))` assigning a deadline variable.
        if let Some(at) = line.find("--until ")
            && let Some(until) = parse_until(&line[at + "--until ".len()..])
        {
            let context = lines[index.saturating_sub(3)..=index].join("\n");
            found.push((until, context));
        }
        if let Some((name, value)) = line.split_once("=$(( $(date +%s) + ")
            && name.chars().all(|c| c.is_ascii_uppercase() || c == '_')
        {
            let n: String = value.chars().take_while(char::is_ascii_digit).collect();
            let context = lines[index.saturating_sub(1)..=index].join("\n");
            found.push((Until::Ahead(n.parse().unwrap()), format!("{name}\n{context}")));
        }
    }
    found
}

#[test]
fn no_script_holds_a_deadline_the_dispatcher_would_refuse_unless_that_is_the_check() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("proposals/stage1");
    let mut checked = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "sh") {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        // A fixed epoch time anywhere: a deadline that will be wrong tomorrow.
        for word in text.split(|c: char| !c.is_ascii_digit()).filter(|w| w.len() >= 10) {
            let n: i64 = word.parse().unwrap_or(0);
            assert!(!(1_000_000_000..10_000_000_000).contains(&n), "{}: a fixed time, {n}", path.display());
        }
        for (until, context) in deadlines(&text) {
            checked += 1;
            let expects_refusal = context.contains("more than ten minutes");
            match until {
                Until::Literal(n) => {
                    assert!(n < 1000, "{}: a literal deadline {n} that is not a past one\n{context}", path.display())
                }
                Until::Ahead(n) => assert_eq!(
                    until_too_far(NOW + n, NOW),
                    expects_refusal,
                    "{}: `now + {n}` is {} by the dispatcher, but the check around it {}\n{context}",
                    path.display(),
                    if until_too_far(NOW + n, NOW) { "refused" } else { "accepted" },
                    if expects_refusal { "expects a refusal" } else { "expects it to run" },
                ),
                Until::Variable(_) => {}
            }
        }
    }
    assert!(checked >= 8, "the scripts' deadlines were found ({checked}): the reading is broken if this fails");
}

#[test]
fn the_reading_finds_what_it_should_and_judges_the_old_mistake() {
    assert_eq!(parse_until("$(( $(date +%s) + 300 )) sys kit"), Some(Until::Ahead(300)));
    assert_eq!(parse_until("1 sys kit"), Some(Until::Literal(1)));
    assert_eq!(parse_until("$DEADLINE sys kit"), Some(Until::Variable("DEADLINE".into())));
    // The mistake: a fixed deadline in the year 2100.
    let old = "FAR=4102444800\n  \"sudo -n $PROBE --within open,none,none --call $U1 --until $FAR sys kit\"";
    assert_eq!(deadlines(old).iter().filter(|(u, _)| matches!(u, Until::Variable(v) if v == "FAR")).count(), 1);
    assert!(old.split(|c: char| !c.is_ascii_digit()).any(|w| w == "4102444800"));
    // The bound itself.
    assert!(!until_too_far(NOW + 300, NOW) && until_too_far(NOW + 3600, NOW));
}

// -- a3 finds its executables from cargo's own messages ---------------------------------------------------

fn find_artifact(kind: &str, name: &str, messages: &str) -> (bool, String, String) {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("proposals/stage1/find-artifact.sh");
    let mut child = Command::new("sh")
        .arg(script)
        .args([kind, name])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(messages.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    (
        out.status.success(),
        String::from_utf8(out.stdout).unwrap().trim().to_string(),
        String::from_utf8(out.stderr).unwrap(),
    )
}

/// Messages in the shape cargo 1.97 prints them (`--message-format=json`, one compact object per line).
fn artifact(kind: &str, name: &str, executable: &str) -> String {
    format!(
        "{{\"reason\":\"compiler-artifact\",\"package_id\":\"path+file:///c/crates/p-robe#0.0.0\",\"manifest_path\":\"/c/crates/p-robe/Cargo.toml\",\"target\":{{\"kind\":[\"{kind}\"],\"crate_types\":[\"bin\"],\"name\":\"{name}\",\"src_path\":\"/c/{name}.rs\",\"edition\":\"2024\",\"doc\":false,\"doctest\":false,\"test\":true}},\"profile\":{{\"opt_level\":\"0\",\"debuginfo\":2,\"debug_assertions\":true,\"overflow_checks\":true,\"test\":true}},\"features\":[\"test-verbs\"],\"filenames\":[\"{executable}\"],\"executable\":{},\"fresh\":true}}\n",
        if executable.is_empty() { "null".to_string() } else { format!("\"{executable}\"") }
    )
}

#[test]
fn the_executable_is_the_one_cargo_names_for_that_target_and_nothing_else() {
    let messages = [
        "{\"reason\":\"compiler-message\",\"message\":{\"rendered\":\"warning: name stage1_sudo\"}}\n".to_string(),
        artifact("lib", "p_robe", ""),
        artifact("test", "stage1", "/c/target/debug/deps/stage1-aaaa"),
        artifact("test", "stage1_sudo", "/c/target/debug/build/p-robe/0db5/out/stage1_sudo-0db5"),
        artifact("bin", "pledge", "/c/target/debug/pledge"),
        "{\"reason\":\"build-finished\",\"success\":true}\n".to_string(),
    ]
    .concat();
    // The layout of the owner's cargo: not under `deps/`; the script does not mind.
    assert_eq!(
        find_artifact("test", "stage1_sudo", &messages),
        (true, "/c/target/debug/build/p-robe/0db5/out/stage1_sudo-0db5".to_string(), String::new())
    );
    assert_eq!(find_artifact("bin", "pledge", &messages).1, "/c/target/debug/pledge");
    // A test and a bin of the same name are told apart by their kind.
    let both = [artifact("test", "x", "/c/t/x-test"), artifact("bin", "x", "/c/t/x-bin")].concat();
    assert_eq!(find_artifact("bin", "x", &both).1, "/c/t/x-bin");
}

#[test]
fn nothing_is_guessed_when_cargo_does_not_name_exactly_one() {
    let none = artifact("lib", "p_robe", "");
    let two = [artifact("test", "stage1_sudo", "/c/a"), artifact("test", "stage1_sudo", "/c/b")].concat();
    let relative = artifact("test", "stage1_sudo", "target/debug/deps/stage1_sudo-1");
    let spaced = artifact("test", "stage1_sudo", "/c/my checkout/stage1_sudo-1");
    let quoted = artifact("test", "stage1_sudo", "/c/x;rm -rf /");
    let only_null = artifact("test", "stage1_sudo", "");
    for (what, messages) in [
        ("empty", String::new()),
        ("another target", none),
        ("two", two),
        ("a relative path", relative),
        ("a path with a space", spaced),
        ("a path with shell characters", quoted),
        ("no executable", only_null),
    ] {
        let (ok, out, err) = find_artifact("test", "stage1_sudo", &messages);
        assert!(!ok && out.is_empty() && err.starts_with("find-artifact:"), "{what}: {out:?} {err:?}");
    }
}

#[test]
fn a3_does_not_look_in_a_directory_for_the_newest_file_and_is_valid_shell() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("proposals/stage1");
    let a3 = std::fs::read_to_string(dir.join("a3-run-cross.sh")).unwrap();
    for guess in ["ls -t", "deps/", "target/debug/deps", "*.d"] {
        assert!(!a3.contains(guess), "a3 guesses where a file is: {guess}");
    }
    assert!(
        a3.contains("find-artifact.sh")
            && a3.contains("--message-format=json")
            && a3.contains("PROBE_EXPECT_BUILT_FROM")
    );
    for script in ["a3-run-cross.sh", "find-artifact.sh"] {
        let status = std::process::Command::new("sh").arg("-n").arg(dir.join(script)).status().unwrap();
        assert!(status.success(), "{script} is not valid shell");
    }
}

// -- the value of --within has four tokens everywhere (the dispatcher refuses three) ---------------------------

#[test]
fn every_within_in_the_scripts_has_four_tokens_except_the_one_check_that_it_is_refused() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("proposals/stage1");
    let mut three = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "sh") {
            continue;
        }
        for line in std::fs::read_to_string(&path).unwrap().lines().filter(|l| !l.trim_start().starts_with('#')) {
            let mut words = line.split_whitespace();
            while let Some(word) = words.next() {
                if word != "--within" {
                    continue;
                }
                let value = words.next().unwrap_or("");
                // A mention in a sentence ("the form without --within is ...") has no value of the form.
                // (and a1's sudoers pattern, which is a wildcard: its `*` matches commas, so it admits four tokens too)
                if !value.contains(',') || value.contains(['[', '*']) {
                    continue;
                }
                let tokens = value.split(',').count();
                if tokens == 3 {
                    three.push(format!("{}: {line}", path.file_name().unwrap().to_string_lossy()));
                } else {
                    assert_eq!(tokens, 4, "{}: {line}", path.display());
                    assert!(value.ends_with(",text") || value.ends_with(",plain"), "{}: {line}", path.display());
                }
            }
        }
    }
    assert_eq!(three.len(), 1, "only the check that three tokens are refused may have three: {three:?}");
    assert!(three[0].contains("$U8"), "{three:?}");
}

// -- Stage B scripts: b1, b2, b3, undo-b and what they share ---------------------------------------------------

fn stage1(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("proposals/stage1").join(name)
}

/// Runs `body` in `sh` with b-common.sh sourced, and returns (success, stdout).
fn with_common(body: &str) -> (bool, String) {
    let script = format!(". '{}'\n{body}", stage1("b-common.sh").display());
    let out = std::process::Command::new("sh").arg("-c").arg(script).output().unwrap();
    (out.status.success(), String::from_utf8(out.stdout).unwrap())
}

#[test]
fn the_stage_b_scripts_are_valid_shell_and_guess_no_path() {
    for name in ["b-common.sh", "b1-prepare-person.sh", "b2-service.sh", "b3-agent-calls.sh", "undo-b.sh"] {
        let path = stage1(name);
        let status = std::process::Command::new("sh").arg("-n").arg(&path).status().unwrap();
        assert!(status.success(), "{name} is not valid shell");
        let text = std::fs::read_to_string(&path).unwrap();
        for guess in ["ls -t", "deps/", "target/debug/", "jq ", "python"] {
            assert!(!text.contains(guess), "{name} guesses or needs something it should not: {guess}");
        }
    }
    // The executables are found from cargo's own output, by the helper that is tested above.
    let common = std::fs::read_to_string(stage1("b-common.sh")).unwrap();
    assert!(common.contains("find-artifact.sh") && common.contains("--message-format=json"));
}

#[test]
fn every_script_that_changes_the_host_says_what_to_do_next_and_what_passing_looks_like() {
    for (name, next) in [("b1-prepare-person.sh", "b2-service.sh"), ("b2-service.sh", "b3-agent-calls.sh")] {
        let text = std::fs::read_to_string(stage1(name)).unwrap();
        assert!(text.contains(next), "{name} does not name the next step");
        assert!(text.contains("pass ") && text.contains("stop "), "{name}");
    }
    let b3 = std::fs::read_to_string(stage1("b3-agent-calls.sh")).unwrap();
    assert!(b3.contains("ALL PASSED") && b3.contains("undo-b.sh"));
}

#[test]
fn undo_b_knows_every_mark_that_b1_to_b3_write() {
    let undo = std::fs::read_to_string(stage1("undo-b.sh")).unwrap();
    let mut marks = std::collections::BTreeSet::new();
    for name in ["b1-prepare-person.sh", "b2-service.sh", "b3-agent-calls.sh"] {
        for line in std::fs::read_to_string(stage1(name)).unwrap().lines() {
            let line = line.trim_start();
            if let Some(rest) = line.strip_prefix("mark ").or_else(|| line.split("&& mark ").nth(1)) {
                marks.insert(rest.split_whitespace().next().unwrap().trim_matches('"').to_string());
            }
        }
    }
    assert!(marks.len() >= 10, "{marks:?}");
    for mark in &marks {
        // `ADDED_$member` is read as a pattern.
        let key = if mark.starts_with("ADDED_") { "ADDED_" } else { mark.as_str() };
        assert!(undo.contains(key), "undo-b.sh does not know {mark}");
    }
}

#[test]
fn the_marker_round_trips_and_the_public_key_is_taken_from_pledges_list() {
    let dir = std::env::temp_dir().join(format!("probe-bscripts-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let marker = dir.join("marker");
    // The directory is this test's own and private: `mark` refuses a marker that is not root's alone, so the test says
    // which uid counts as root's.
    let uid = std::os::unix::fs::MetadataExt::uid(&std::fs::metadata(&dir).unwrap());
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    let (ok, out) = with_common(&format!(
        "TRUSTED_UID={uid}; STATEDIR='{}'; MARKER='{}'; mark A 1; mark PARENT_MADE /x/y; mark PARENT_MADE /x; marked A && echo yes; marked B || echo no; marker_value PARENT_MADE",
        dir.display(),
        marker.display()
    ));
    assert!(ok && out.lines().collect::<Vec<_>>() == ["yes", "no", "/x"], "{out}");
    // The list as `pledge keys list` prints it: purpose, fingerprint, key and its comment.
    let list = "delegation SHA256:aaa  ssh-ed25519 AAAAdel pledge delegation\\nconfirmed SHA256:bbb  ssh-ed25519 AAAAconf pledge confirmed\\nautomatic SHA256:ccc  ssh-ed25519 AAAAauto pledge automatic";
    let (ok, out) = with_common(&format!(
        "L=$(printf '{list}'); public_key_of \"$L\" confirmed; public_key_of \"$L\" automatic; public_key_of \"$L\" nothing; echo end"
    ));
    assert!(ok);
    assert_eq!(
        out.lines().collect::<Vec<_>>(),
        ["ssh-ed25519 AAAAconf pledge confirmed", "ssh-ed25519 AAAAauto pledge automatic", "end"]
    );
}

#[test]
fn the_settings_and_pledge_configuration_the_scripts_write_are_read_by_the_programs_that_read_them() {
    // /etc/probe.json, by probe's own reader (`Config::parse`: unknown members, member given twice, types).
    let (ok, json) = with_common("probe_settings_json alice testhost /run/pledge-alice/service.sock 1000");
    assert!(ok);
    let config = p_robe::config::Config::parse(&json).unwrap_or_else(|e| panic!("{e}\n{json}"));
    assert_eq!(
        (config.person.as_str(), config.pledge_uid, config.listen.as_str()),
        ("alice", Some(1000), "127.0.0.1:8765")
    );
    assert_eq!(config.pledge_socket, Path::new("/run/pledge-alice/service.sock"));
    assert_eq!(config.confirmed_key, Path::new("/etc/probe/alice-confirmed.pub"));
    // pledge's config.json: valid JSON with the members p-ledge's `Config` has (checked there against the real
    // pledge by the author's rehearsal: it started, made the socket directory 0710 and the socket 0660 of the group).
    let (ok, json) = with_common(
        "pledge_config_json alice testhost 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' pledge-svc http://127.0.0.1:8765/mcp",
    );
    assert!(ok);
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["person"], "alice");
    assert_eq!(value["service_group"], "pledge-svc");
    assert_eq!(value["hosts"][0]["host"], "testhost");
    assert_eq!(value["services"][0]["host"], "testhost");
    assert_eq!(value["services"][0]["url"], "http://127.0.0.1:8765/mcp");
    let members: Vec<&str> = value.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(members, ["hosts", "person", "service_group", "services"]);
}

// -- the marker: nothing root obeys lies where another account could have put it -------------------------------

#[test]
fn the_marker_is_read_only_if_it_and_its_directory_are_root_alone_and_paths_from_it_are_sane() {
    use std::os::unix::fs::{PermissionsExt, symlink};
    let dir = std::env::temp_dir().join(format!("probe-bmarker-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let state = dir.join("state");
    std::fs::create_dir_all(&state).unwrap();
    let mode = |path: &Path, bits: u32| std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
    let marker = state.join("b-state");
    std::fs::write(&marker, "PERSON=alice\n").unwrap();
    let me = std::fs::metadata(&marker).unwrap().uid_of();
    // `root` is this test's own uid here (TRUSTED_UID); the real script has 0.
    let check = |trusted: u32| {
        let (_, out) = with_common(&format!(
            "TRUSTED_UID={trusted}; STATEDIR='{}'; MARKER='{}'; marker_safe && echo safe || echo unsafe",
            state.display(),
            marker.display()
        ));
        out.trim().to_string()
    };
    mode(&state, 0o700);
    mode(&marker, 0o600);
    assert_eq!(check(me), "safe");
    // Another account's file is not root's; group- or other-writable is not safe, for the file and for the directory.
    assert_eq!(check(me + 1), "unsafe");
    mode(&marker, 0o660);
    assert_eq!(check(me), "unsafe");
    mode(&marker, 0o602);
    assert_eq!(check(me), "unsafe");
    mode(&marker, 0o600);
    mode(&state, 0o770);
    assert_eq!(check(me), "unsafe");
    mode(&state, 0o700);
    // A symlink where the marker should be (a name another account made) is not read, whatever it points at.
    let target = dir.join("elsewhere");
    std::fs::write(&target, "RUNDIR_MADE=/etc\n").unwrap();
    mode(&target, 0o600);
    std::fs::remove_file(&marker).unwrap();
    symlink(&target, &marker).unwrap();
    assert_eq!(check(me), "unsafe");
    // A dangling one too: `exists` sees it (`-e` alone does not), so b1 refuses to go on.
    std::fs::remove_file(&marker).unwrap();
    symlink(dir.join("nothing"), &marker).unwrap();
    assert_eq!(check(me), "unsafe");
    let (ok, out) = with_common(&format!("exists '{}' && echo there || echo absent", marker.display()));
    assert!(ok && out.trim() == "there", "{out}");
    // No marker yet is fine for the directory check (b1 has not written it).
    std::fs::remove_file(&marker).unwrap();
    assert_eq!(check(me), "safe");
    // The directory itself being a link is not accepted.
    let linked = dir.join("linked");
    symlink(&state, &linked).unwrap();
    let (_, out) = with_common(&format!(
        "TRUSTED_UID={me}; STATEDIR='{}'; MARKER=\"$STATEDIR/b-state\"; marker_safe && echo safe || echo unsafe",
        linked.display()
    ));
    assert_eq!(out.trim(), "unsafe");
    // The paths read back are absolute, plain and not near the top.
    for (path, sane) in [
        ("/run/pledge-alice", true),
        ("/home/alice/.local/state/pledge", true),
        ("/etc", false),
        ("/", false),
        ("relative/dir", false),
        ("/home/../etc", false),
        ("/a/b\n/c", false),
    ] {
        let (_, out) = with_common(&format!("sane_path \"$(printf '%s' '{}')\" && echo yes || echo no", path));
        assert_eq!(out.trim() == "yes", sane, "{path:?}");
    }
}

#[test]
fn undo_b_reads_nothing_before_it_has_checked_the_marker_and_no_script_writes_into_var_tmp() {
    let undo = std::fs::read_to_string(stage1("undo-b.sh")).unwrap();
    let check = undo.find("root_only \"$MARKER\" f").expect("the marker is checked");
    let first_read = undo.find("sed -n").expect("it reads the marker");
    assert!(check < first_read, "undo-b reads the marker before it has checked it");
    assert!(undo.contains("sane_path"));
    for name in ["b-common.sh", "b1-prepare-person.sh", "b2-service.sh", "b3-agent-calls.sh", "undo-b.sh"] {
        for line in std::fs::read_to_string(stage1(name)).unwrap().lines().filter(|l| !l.trim_start().starts_with('#'))
        {
            assert!(!line.contains("/var/tmp"), "{name} uses a world-writable place: {line}");
        }
    }
}

trait UidOf {
    fn uid_of(&self) -> u32;
}

impl UidOf for std::fs::Metadata {
    fn uid_of(&self) -> u32 {
        std::os::unix::fs::MetadataExt::uid(self)
    }
}
