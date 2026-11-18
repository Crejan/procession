//! The `pact` binary, end to end as far as it goes without an HTTP client: bundle on standard input,
//! the socket, the stdio shim. Keys are real, made with `ssh-keygen` in a temporary directory.
#![cfg(feature = "pact")]

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn pact() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pact"))
}

fn keygen(args: &[&str]) {
    let out = Command::new("ssh-keygen").args(args).stdin(Stdio::null()).output().expect("these tests need ssh-keygen");
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

/// A bundle: configuration line, key, certificate; and the text of the key's base64 body.
fn bundle(dir: &Path, validity: &str) -> (Vec<u8>, String) {
    let (delegation, agent) = (dir.join("delegation"), dir.join("agent"));
    for k in [&delegation, &agent] {
        keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", k.to_str().unwrap()]);
    }
    keygen(&[
        "-q",
        "-s",
        delegation.to_str().unwrap(),
        "-I",
        "agent",
        "-n",
        "alice",
        "-V",
        validity,
        "-O",
        "clear",
        dir.join("agent.pub").to_str().unwrap(),
    ]);
    let key = std::fs::read_to_string(&agent).unwrap();
    let cert = std::fs::read_to_string(dir.join("agent-cert.pub")).unwrap();
    let config = r#"{"v":1,"services":[{"host":"a.example","name":"probe","url":"http://127.0.0.1:1/mcp"}],"deadline_seconds":5}"#;
    let body: String = key.lines().filter(|l| !l.starts_with("-----")).collect();
    (format!("{config}\n{key}{}\n", cert.trim_end()).into_bytes(), body)
}

fn run(args: &[&str], stdin: &[u8]) -> (i32, String, String) {
    let mut child =
        pact().args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    let out = child.wait_with_output().unwrap();
    (out.status.code().unwrap(), String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap())
}

#[test]
fn usage_errors_exit_2() {
    for args in
        [&[][..], &["frobnicate"], &["serve", "--bogus"], &["call", "--min-wait"], &["serve", "--min-wait", "x"]]
    {
        let (code, _, stderr) = run(args, b"");
        assert_eq!(code, 2, "{args:?}: {stderr}");
        assert!(stderr.contains("usage") || stderr.contains("pact:"));
    }
}

#[test]
fn a_bad_bundle_is_refused_and_the_key_is_not_in_the_message() {
    let dir = tempfile::tempdir().unwrap();
    let (good, body) = bundle(dir.path(), "20200101Z:20990101Z");
    let text = String::from_utf8(good.clone()).unwrap();
    for (label, broken) in [
        ("empty", String::new()),
        ("no key", text.split_once('\n').unwrap().0.to_owned() + "\n"),
        ("trailing", format!("{text}x")),
        ("damaged key", text.replacen(&body[20..30], "!!!!!!!!!!", 1)),
        ("bad config", text.replacen("\"v\":1", "\"v\":2", 1)),
    ] {
        let (code, stdout, stderr) = run(&["tools"], broken.as_bytes());
        assert_eq!(code, 1, "{label}: {stderr}");
        assert!(stdout.is_empty(), "{label}");
        assert!(!stderr.contains(&body[30..50]) && !stderr.contains("BEGIN OPENSSH"), "{label}: {stderr}");
    }
    let expired_dir = tempfile::tempdir().unwrap();
    let (expired, _) = bundle(expired_dir.path(), "20200101Z:20200102Z");
    let (code, _, stderr) = run(&["tools"], &expired);
    assert_eq!(code, 1);
    assert!(stderr.contains("expired"), "{stderr}");
    let (code, _, stderr) = run(&["tools"], &vec![b'x'; 70_000]);
    assert_eq!(code, 1);
    assert!(stderr.contains("larger"), "{stderr}");
}

#[test]
fn tools_and_call_without_a_service_say_so_in_the_closed_list() {
    let dir = tempfile::tempdir().unwrap();
    let (good, body) = bundle(dir.path(), "20200101Z:20990101Z");
    let (code, stdout, stderr) = run(&["tools", "--min-wait", "1"], &good);
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(stdout.trim(), "[]", "no HTTP client in this build: no tools");
    assert!(stderr.contains("no tool list") && stderr.contains("alice"), "{stderr}");
    assert!(!stderr.contains(&body[30..50]));
    let (code, stdout, _) = run(&["call", "rt_procs", r#"{"params":["a"]}"#], &good);
    assert_eq!(code, 0);
    let result: Value = serde_json::from_str(stdout.trim()).unwrap();
    assert_eq!(result["isError"], true);
    assert!(result["content"][0]["text"].as_str().unwrap().contains("no tool"));
    let (code, _, stderr) = run(&["call", "rt_procs", "{not json"], &good);
    assert_eq!(code, 1);
    assert!(stderr.contains("not JSON"));
}

fn wait_for_socket(path: &Path, child: &mut Child) {
    for _ in 0..400 {
        if path.exists() {
            return;
        }
        if let Some(status) = child.try_wait().unwrap() {
            let mut stderr = String::new();
            child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
            panic!("pact serve ended early: {status}: {stderr}");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    panic!("no socket");
}

#[test]
fn serve_speaks_mcp_on_its_socket_and_stdio_is_a_shim_to_it() {
    let dir = tempfile::tempdir().unwrap();
    // Some sandboxes do not let a process bind a Unix socket; then there is nothing here to test, and it is said.
    if let Err(e) = std::os::unix::net::UnixListener::bind(dir.path().join("probe.sock")) {
        eprintln!("SKIPPED: this environment does not allow binding a Unix socket: {e}");
        return;
    }
    std::fs::remove_file(dir.path().join("probe.sock")).unwrap();
    let (good, _) = bundle(dir.path(), "20200101Z:20990101Z");
    let socket = dir.path().join("p.sock");
    let mut server = pact()
        .args(["serve", "--socket", socket.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    server.stdin.take().unwrap().write_all(&good).unwrap();
    wait_for_socket(&socket, &mut server);
    assert_eq!(std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777, 0o600);

    // Directly on the socket.
    let mut s = UnixStream::connect(&socket).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut ask = |v: Value| {
        writeln!(s, "{v}").unwrap();
        let mut line = String::new();
        r.read_line(&mut line).unwrap();
        serde_json::from_str::<Value>(&line).unwrap()
    };
    let init = ask(json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}));
    assert_eq!(init["result"]["serverInfo"]["name"], "pact");
    assert_eq!(ask(json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))["result"]["tools"], json!([]));

    // Through `pact stdio`, as a model's client would start it.
    let mut shim = pact()
        .args(["stdio", "--socket", socket.to_str().unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    writeln!(shim.stdin.as_mut().unwrap(), "{}", json!({"jsonrpc": "2.0", "id": 3, "method": "ping"})).unwrap();
    let mut line = String::new();
    BufReader::new(shim.stdout.as_mut().unwrap()).read_line(&mut line).unwrap();
    assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["result"], json!({}));
    drop(shim.stdin.take());
    assert!(shim.wait().unwrap().success());

    server.kill().unwrap();
    let mut stderr = String::new();
    server.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
    assert!(stderr.contains("listening on"), "{stderr}");
    assert!(stderr.contains("alice") && stderr.contains("SHA256:"), "the identity and delegation are logged: {stderr}");
    server.wait().unwrap();
}

#[test]
fn serve_refuses_to_replace_a_socket_and_needs_one() {
    let dir = tempfile::tempdir().unwrap();
    let (good, _) = bundle(dir.path(), "20200101Z:20990101Z");
    let (code, _, stderr) = run(&["serve"], &good);
    assert_eq!(code, 1);
    assert!(stderr.contains("--socket"), "{stderr}");
    let taken = dir.path().join("taken.sock");
    std::fs::write(&taken, b"").unwrap();
    let (code, _, stderr) = run(&["serve", "--socket", taken.to_str().unwrap()], &good);
    assert_eq!(code, 1);
    assert!(stderr.contains("cannot listen"), "{stderr}");
    let (code, _, stderr) = run(&["stdio", "--socket", dir.path().join("nothing.sock").to_str().unwrap()], b"");
    assert_eq!(code, 1);
    assert!(stderr.contains("cannot connect"), "{stderr}");
}

#[cfg(not(feature = "pact-tls"))]
#[test]
fn an_https_bundle_is_refused_at_start_by_a_build_without_tls() {
    let dir = tempfile::tempdir().unwrap();
    let (good, _) = bundle(dir.path(), "20200101Z:20990101Z");
    let text = String::from_utf8(good).unwrap();
    let (first, rest) = text.split_once('\n').unwrap();
    let https = first.replace("\"url\":\"http://127.0.0.1:1/mcp\"", "\"url\":\"https://a.example/mcp\"").replace(
        "\"deadline_seconds\":5",
        "\"deadline_seconds\":5,\"tls_root\":\"-----BEGIN CERTIFICATE-----\\nAAAA\\n-----END CERTIFICATE-----\\n\"",
    );
    let (code, stdout, stderr) = run(&["tools"], format!("{https}\n{rest}").as_bytes());
    assert_eq!(code, 1, "{stderr}");
    assert!(stdout.is_empty());
    assert!(stderr.contains("without TLS") && stderr.contains("pact-tls"), "{stderr}");
}
