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

/// A fresh directory under which a test may bind a Unix socket: under `PACT_TEST_DIR` if set, else `/tmp/claude` if it
/// is there (some sandboxes allow sockets only under one directory), else the system's temporary directory.
fn socket_tempdir() -> tempfile::TempDir {
    let base = std::env::var_os("PACT_TEST_DIR").map(std::path::PathBuf::from).unwrap_or_else(|| {
        let sandbox = std::path::PathBuf::from("/tmp/claude");
        if sandbox.is_dir() { sandbox } else { std::env::temp_dir() }
    });
    tempfile::Builder::new().prefix("pact-").tempdir_in(base).unwrap()
}

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
    // `pact` may end before it reads (a usage error, a refused option): the write then fails with `Broken pipe`, and
    // the exit status and the messages are what the tests judge.
    let _ = child.stdin.take().unwrap().write_all(stdin);
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
    let dir = socket_tempdir();
    // Some sandboxes do not let a process bind a Unix socket; then there is nothing here to test, and it is said.
    if let Err(e) = std::os::unix::net::UnixListener::bind(dir.path().join("probe.sock")) {
        // Under PACT_REQUIRE_TCP=1 (which also covers this Unix socket) not being able to bind is a failure.
        assert!(
            std::env::var_os("PACT_REQUIRE_TCP").is_none_or(|v| v.is_empty() || v == "0"),
            "PACT_REQUIRE_TCP is set and this environment does not allow binding a Unix socket: {e}"
        );
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
    let _ = server.stdin.take().unwrap().write_all(&good); // if the server ended, `wait_for_socket` says why
    wait_for_socket(&socket, &mut server);
    assert_eq!(std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777, 0o600);

    // Directly on the socket.
    let mut s = UnixStream::connect(&socket).unwrap();
    // The timeout only matters while the server keeps the connection; if the peer is gone, `set_read_timeout` fails
    // (EINVAL on macOS) and the read that follows shows it.
    let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
    let mut r = BufReader::new(s.try_clone().unwrap());
    let mut ask = |v: Value| {
        let _ = writeln!(s, "{v}"); // a closed server shows in the read below
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
    let _ = writeln!(shim.stdin.as_mut().unwrap(), "{}", json!({"jsonrpc": "2.0", "id": 3, "method": "ping"}));
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
    let dir = socket_tempdir();
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

/// `pact ARGS` with standard input redirected from the file `path`, as `pact call TOOL < bundle` is.
fn run_from_file(args: &[&str], path: &Path) -> (i32, String, String) {
    let out = pact()
        .args(args)
        .stdin(std::fs::File::open(path).unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    (out.status.code().unwrap(), String::from_utf8(out.stdout).unwrap(), String::from_utf8(out.stderr).unwrap())
}

fn sockets_allowed(dir: &Path) -> bool {
    let probe = dir.join("probe.sock");
    let ok = std::os::unix::net::UnixListener::bind(&probe).is_ok();
    let _ = std::fs::remove_file(&probe);
    if !ok {
        assert!(
            std::env::var_os("PACT_REQUIRE_TCP").is_none_or(|v| v.is_empty() || v == "0"),
            "PACT_REQUIRE_TCP is set and this environment does not allow binding a Unix socket"
        );
        eprintln!("SKIPPED: this environment does not allow binding a Unix socket");
    }
    ok
}

#[test]
fn a_bundle_in_a_file_that_group_or_others_can_access_is_refused_before_a_byte_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let (good, body) = bundle(dir.path(), "20200101Z:20990101Z");
    let file = dir.path().join("bundle");
    for mode in [0o644, 0o640, 0o604, 0o660, 0o606, 0o666, 0o610, 0o601, 0o744] {
        // The content is garbage: if a byte were read first, the error would be about the bundle's form.
        std::fs::write(&file, b"garbage\n").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        let (code, stdout, stderr) = run_from_file(&["tools"], &file);
        assert_eq!(code, 1, "{mode:o}: {stderr}");
        assert!(stdout.is_empty());
        assert!(
            stderr.contains(&format!("{mode:04o}"))
                && stderr.contains("chmod 600")
                && stderr.contains("standard input"),
            "{mode:o}: {stderr}"
        );
        assert!(!stderr.contains("garbage"));
    }
    // The real bundle, readable by others, is refused too, and its key does not appear.
    std::fs::write(&file, &good).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    for command in [&["tools"][..], &["call", "x"], &["serve", "--socket", "/nonexistent/s"]] {
        let (code, _, stderr) = run_from_file(command, &file);
        assert_eq!(code, 1, "{stderr}");
        assert!(stderr.contains("chmod 600") && !stderr.contains(&body[30..50]), "{stderr}");
    }
}

#[test]
fn a_bundle_in_a_private_file_or_on_a_pipe_is_read() {
    let dir = tempfile::tempdir().unwrap();
    let (good, _) = bundle(dir.path(), "20200101Z:20990101Z");
    let file = dir.path().join("bundle");
    for mode in [0o600, 0o400] {
        let _ = std::fs::remove_file(&file);
        std::fs::write(&file, &good).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
        let (code, stdout, stderr) = run_from_file(&["tools", "--min-wait", "1"], &file);
        assert_eq!(code, 0, "{mode:o}: {stderr}");
        assert_eq!(stdout.trim(), "[]");
    }
    // A pipe has nothing to check, whatever its writer's mode.
    let (code, ..) = run(&["tools", "--min-wait", "1"], &good);
    assert_eq!(code, 0);
    // A file that is garbage and private is refused as a bundle, not for its mode.
    std::fs::remove_file(&file).unwrap();
    std::fs::write(&file, b"garbage\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (code, _, stderr) = run_from_file(&["tools"], &file);
    assert_eq!(code, 1);
    assert!(!stderr.contains("chmod"), "{stderr}");
}

#[test]
fn the_options_for_who_may_connect_are_checked_at_start() {
    let dir = tempfile::tempdir().unwrap();
    let (good, _) = bundle(dir.path(), "20200101Z:20990101Z");
    let socket = dir.path().join("never.sock");
    let socket = socket.to_str().unwrap();
    let (code, _, stderr) = run(&["serve", "--socket", socket, "--refuse-own-user"], &good);
    assert_eq!(code, 1);
    assert!(stderr.contains("--client-uid"), "{stderr}");
    let own = unsafe { libc::geteuid() }.to_string();
    let (code, _, stderr) = run(&["serve", "--socket", socket, "--refuse-own-user", "--client-uid", &own], &good);
    assert_eq!(code, 1);
    assert!(stderr.contains("own user"), "{stderr}");
    let (code, _, _) = run(&["serve", "--socket", socket, "--client-uid", "x"], &good);
    assert_eq!(code, 2);
    assert!(!Path::new(socket).exists());
}

#[test]
fn serve_admits_the_running_user_only_and_says_so_and_drops_other_clients_in_silence() {
    let dir = socket_tempdir();
    if !sockets_allowed(dir.path()) {
        return;
    }
    let (good, _) = bundle(dir.path(), "20200101Z:20990101Z");
    let own: u32 = unsafe { libc::geteuid() };
    let wide = dir.path().join("wide");
    std::fs::create_dir(&wide).unwrap();
    std::fs::set_permissions(&wide, std::fs::Permissions::from_mode(0o777)).unwrap();
    let start = |args: &[&str], socket: &Path| {
        let mut server = pact()
            .args(["serve", "--socket", socket.to_str().unwrap()])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let _ = server.stdin.take().unwrap().write_all(&good); // if the server ended, `wait_for_socket` says why
        wait_for_socket(socket, &mut server);
        server
    };
    let ping = |socket: &Path| -> String {
        let mut s = UnixStream::connect(socket).unwrap();
        // A server that drops this client has closed its end: setting the timeout may fail (EINVAL on macOS), and
        // the read below shows the drop, which is what the test is about.
        let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
        let _ = writeln!(s, "{}", json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}));
        let mut line = String::new();
        let _ = BufReader::new(s).read_line(&mut line);
        line
    };
    let finish = |mut server: Child| {
        let _ = server.kill(); // it may have ended already
        let mut stderr = String::new();
        server.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
        server.wait().unwrap();
        stderr
    };

    // Stage 1: the running user is admitted, and the start says that this means the model can read what pact can; the
    // socket's directory is warned about; the socket's mode is 0600 whatever the umask.
    let socket = wide.join("stage1.sock");
    let server = start(&[], &socket);
    assert_eq!(std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(ping(&socket).contains(r#""result":{}"#));
    let stderr = finish(server);
    assert!(stderr.contains("same user as pact"), "{stderr}");
    assert!(stderr.contains("directory of the socket") && stderr.contains("0777"), "{stderr}");

    // Stage 2: somebody else is the client and the running user is refused, with one line and nothing told to it.
    let other = (own + 1).to_string();
    let socket = dir.path().join("stage2.sock");
    let server = start(&["--client-uid", &other, "--refuse-own-user"], &socket);
    assert_eq!(ping(&socket), "", "the connection is closed without a word");
    for _ in 0..3 {
        assert_eq!(ping(&socket), "");
    }
    let stderr = finish(server);
    assert!(!stderr.contains("same user as pact"), "{stderr}");
    let refused: Vec<_> = stderr.lines().filter(|l| l.contains("a client was refused")).collect();
    assert_eq!(refused.len(), 1, "throttled to one line: {stderr}");
    assert!(refused[0].contains(&own.to_string()), "{stderr}");
}

#[test]
fn nothing_raw_comes_out_of_the_binary_whatever_the_bundle_and_the_model_hold() {
    use p_ermit::probe::{PROBE_ALL, PROBES, assert_clean_in};
    let dir = tempfile::tempdir().unwrap();
    let (good, _) = bundle(dir.path(), "20200101Z:20990101Z");
    let text = String::from_utf8(good.clone()).unwrap();
    // The probes in the configuration: a host and a service name (JSON-escaped, so the bundle is valid JSON).
    let json_escaped = PROBE_ALL
        .replace('\u{1b}', "\\u001b")
        .replace('\u{85}', "\\u0085")
        .replace('\u{9b}', "\\u009b")
        .replace('\u{202e}', "\\u202e");
    for (from, to) in [
        ("a.example", json_escaped.as_str()),
        ("\"probe\"", &format!("\"{json_escaped}\"")),
        ("\"v\":1", &format!("\"v\":1,\"{json_escaped}\":1")),
    ] {
        let (code, stdout, stderr) = run(&["tools"], text.replacen(from, to, 1).as_bytes());
        assert_eq!(code, 1, "{stderr}");
        stdout.lines().for_each(|l| assert_clean_in("stdout", l));
        stderr.lines().for_each(|l| assert_clean_in("stderr", l));
    }
    // The model's own names and arguments through `pact call`, and what `pact` logs about them.
    for p in PROBES.iter().chain([&PROBE_ALL]) {
        let (_, stdout, stderr) = run(&["call", &format!("no{p}tool"), r#"{"params":["a"]}"#], &good);
        stdout.lines().for_each(|l| assert_clean_in("stdout", l));
        stderr.lines().for_each(|l| assert_clean_in("stderr", l));
        let (_, stdout, stderr) = run(&["call", "x", &format!(r#"{{"{p}":"{p}"}}"#)], &good);
        stdout.lines().for_each(|l| assert_clean_in("stdout", l));
        stderr.lines().for_each(|l| assert_clean_in("stderr", l));
        let (_, stdout, stderr) = run(&["serve", "--socket", &format!("/nonexistent/{p}/s")], &good);
        stdout.lines().for_each(|l| assert_clean_in("stdout", l));
        stderr.lines().for_each(|l| assert_clean_in("stderr", l));
        let (_, stdout, stderr) = run(&["frobnicate", p], &[]);
        stdout.lines().for_each(|l| assert_clean_in("stdout", l));
        stderr.lines().for_each(|l| assert_clean_in("stderr", l));
    }
}
