//! Approvals against the real `pledge` binary: `pledge agents start` writes a
//! bundle, an agent's call is signed with the key and certificate in it by the
//! real `ssh-keygen`, and a service faked here submits requests on
//! `service.sock` with the codec of `p-act`. The dialogs are answered on the
//! server's standard input.

mod common;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::time::Duration;

use common::{Dir, Server, text};
use p_act::exchange::{
    Answer, ClearancePolicy, LineReader, Message, Outcome, PledgeReason, Refused, Submit, write_message,
};
use p_act::rating::{Damage, Disruption, Exposure, Rating};
use p_act::sign::{ApprovalKind, ApprovalTrust, PublicKey, Signer, sign_call, sign_request, verify_approval};
use p_act::{Call, CallContent, CallId, Document, Request, ServiceId, Timestamp};
use serde_json::{Value, json};

fn keygen(args: &[&str]) {
    let out = Command::new("ssh-keygen").args(args).stdin(Stdio::null()).output().expect("ssh-keygen");
    assert!(out.status.success(), "ssh-keygen {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

fn now() -> i64 {
    Timestamp::now().expect("clock").unix()
}

/// A host, and a service key it certified, in `dir`.
fn world(dir: &Dir) {
    let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
    for key in ["host", "svc"] {
        keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", &path(key)]);
    }
    keygen(&[
        "-q",
        "-s",
        &path("host"),
        "-I",
        "svc",
        "-n",
        "probe@a.example",
        "-V",
        "20200101Z:20990101Z",
        "-O",
        "clear",
        &format!("{}.pub", path("svc")),
    ]);
}

fn start(name: &str, services: bool) -> Server {
    Server::start_with(name, None, |state, dir| {
        world(dir);
        let host = fs::read_to_string(dir.join("host.pub")).expect("host.pub");
        let mut config = json!({"person": "jan", "hosts": [{"host": "a.example", "key": host.trim()}]});
        if services {
            config["services"] = json!([{"host": "a.example", "name": "probe", "url": "http://127.0.0.1:8443/mcp"}]);
        }
        // Mode 0600 whatever the umask: pledge refuses a settings file others can write.
        fs::write(state.join("config.json"), config.to_string()).expect("config");
        fs::set_permissions(state.join("config.json"), fs::Permissions::from_mode(0o600)).expect("chmod");
    })
}

fn make_keys(server: &mut Server) {
    for purpose in ["delegation", "confirmed", "automatic"] {
        server.answer("y\n");
        server.ok(&["keys", "create", purpose]);
    }
}

struct Agent {
    signer: Signer,
    id: String,
}

/// Starts an agent with `pledge agents start`, and reads the bundle it wrote.
fn agent(server: &mut Server, extra: &[&str]) -> (Agent, Value) {
    server.answer("y\n");
    let file = server._dir.join(&format!("bundle{}", extra.len()));
    let mut args = vec!["agents", "start", "--groups", "admins", "--output", file.to_str().expect("path")];
    args.extend_from_slice(extra);
    server.ok(&args);
    let bundle = fs::read_to_string(&file).expect("bundle");
    assert_eq!(fs::metadata(&file).expect("meta").permissions().mode() & 0o777, 0o600);
    let (first, rest) = bundle.split_once('\n').expect("line 1");
    let configuration: Value = serde_json::from_str(first).expect("line 1 is JSON");
    let end = "-----END OPENSSH PRIVATE KEY-----\n";
    let split = rest.find(end).expect("key block") + end.len();
    let (block, certificate) = rest.split_at(split);
    assert!(block.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n"));
    assert!(
        certificate.starts_with("ssh-ed25519-cert-v01@openssh.com ")
            && certificate.ends_with('\n')
            && certificate.matches('\n').count() == 1
    );
    let key = server._dir.join(&format!("agent{}", extra.len()));
    fs::write(&key, block).expect("key");
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("chmod");
    fs::write(format!("{}-cert.pub", key.display()), certificate).expect("cert");
    let list = server.ok(&["agents", "list", "--format", "json"]);
    let delegations: Value = serde_json::from_str(&list).expect("json");
    let id = delegations["delegations"].as_array().expect("list").last().expect("one")["delegation"]
        .as_str()
        .expect("id")
        .to_owned();
    (Agent { signer: Signer::certified(&key).expect("signer"), id }, configuration)
}

fn call(agent: &Agent, n: u32, params: &[&str], in_seconds: i64) -> (Call, String) {
    let content = CallContent {
        id: CallId::parse(&format!("00000000-0000-4000-8000-{n:012}")).expect("uuid"),
        deadline: Timestamp::from_unix(now() + in_seconds).expect("time"),
        service: ServiceId { host: "a.example".into(), name: "probe".into() },
        action: "rt procs".into(),
        params: params.iter().map(|p| (*p).to_owned()).collect(),
        claim: Some("checking the loop".into()),
    };
    let call = Call::compose(&content).expect("call");
    let sig = sign_call(&agent.signer, &call).expect("sign");
    (call, sig)
}

struct Service {
    stream: UnixStream,
    lines: LineReader<UnixStream>,
    signer: Signer,
}

impl Service {
    fn connect(server: &Server) -> Self {
        let stream = UnixStream::connect(server.sockets.join("service.sock")).expect("connect to service.sock");
        stream.set_read_timeout(Some(Duration::from_secs(20))).expect("timeout");
        let lines = LineReader::new(stream.try_clone().expect("clone"));
        Self { stream, lines, signer: Signer::certified(server._dir.join("svc")).expect("svc") }
    }

    fn ask(&mut self, call: &Call, call_sig: &str, rating: Rating) -> (Request, Answer) {
        let request = Request::compose(call, call_sig, rating).expect("request");
        let sig = sign_request(&self.signer, &request).expect("sign request");
        let submit = Submit::new(request.clone(), &sig).expect("submit");
        write_message(&mut self.stream, &Message::Submit(submit), ClearancePolicy::Refused).expect("write");
        match self.lines.read_message(ClearancePolicy::Refused).expect("read").expect("an answer") {
            Message::Answer(answer) => (request, answer),
            other => panic!("{other:?}"),
        }
    }
}

fn verify(server: &Server, request: &Request, answer: &Answer) -> ApprovalKind {
    let Outcome::Approved(approved) = &answer.outcome else { panic!("not approved: {answer:?}") };
    let keys: Value = serde_json::from_str(&server.ok(&["keys", "list", "--format", "json"])).expect("json");
    let key = |purpose: &str| {
        let entry = keys["keys"].as_array().expect("keys").iter().find(|k| k["purpose"] == purpose).expect("key");
        PublicKey::parse(entry["public"].as_str().expect("public")).expect("parse")
    };
    let (confirmed, automatic) = (key("confirmed"), key("automatic"));
    verify_approval(
        request,
        approved.approval(),
        ApprovalTrust::PersonKeys { person: "jan", confirmed: &confirmed, automatic: &automatic },
    )
    .expect("verifies")
}

const INTERNAL: Rating = Rating { exposure: Exposure::Internal, damage: Damage::None, disruption: Disruption::None };

#[test]
fn a_bundle_from_agents_start_signs_calls_pledge_approves_and_the_record_holds() {
    let mut server = start("approvals", true);
    make_keys(&mut server);
    let (agent, line) = agent(&mut server, &[]);
    assert_eq!(
        line,
        json!({"v": 1, "services": [{"host": "a.example", "name": "probe", "url": "http://127.0.0.1:8443/mcp"}], "deadline_seconds": 120})
    );
    assert!(server.ok(&["agents", "list"]).starts_with("active"));
    let mut service = Service::connect(&server);

    // Harmless: automatic, nobody is asked.
    let (c, s) = call(&agent, 1, &["pid=1"], 120);
    let (request, answer) = service.ask(&c, &s, Rating::HARMLESS);
    assert_eq!(verify(&server, &request, &answer), ApprovalKind::Automatic);
    // The record shows who connected to service.sock: the uid of this account, the process and its program,
    // as read from the kernel (`SO_PEERCRED` on Linux, `LOCAL_PEERCRED`/`getpeereid` on macOS).
    let first = server.history().into_iter().find(|e| e["type"] == "request").expect("an entry");
    let uid = unsafe { libc::getuid() };
    assert_eq!(first["peer"]["uid"], uid, "{first}");
    assert!(first["peer"]["pid"].as_i64().is_some_and(|pid| pid > 0), "{first}");
    assert!(first["peer"]["program"].as_str().is_some_and(|p| p.contains("real_approvals")), "{first}");

    // Above the automatic ceiling: asked, then the presence check; confirmed key.
    server.answer("y\ny\n");
    let (c, s) = call(&agent, 2, &["pid=2"], 120);
    let (request, answer) = service.ask(&c, &s, INTERNAL);
    assert_eq!(verify(&server, &request, &answer), ApprovalKind::Confirmed);
    let line = server.wait_for("action:");
    assert!(line.contains("rt procs"), "{line}");

    // Declined.
    server.answer("n\n");
    let (c, s) = call(&agent, 3, &["pid=3"], 120);
    let (_, answer) = service.ask(&c, &s, INTERNAL);
    assert!(matches!(answer.outcome, Outcome::Declined), "{answer:?}");

    // A call that cannot be shown is refused; the same bytes again are answered again.
    let long = "x".repeat(450);
    let (c, s) = call(&agent, 4, &[long.as_str(); 5], 120);
    let (_, answer) = service.ask(&c, &s, Rating::HARMLESS);
    assert!(matches!(answer.outcome, Outcome::Refused(Refused::Pledge(PledgeReason::NotShowable))), "{answer:?}");

    // Withdrawn: no more.
    server.ok(&["agents", "withdraw", &agent.id]);
    let (c, s) = call(&agent, 5, &[], 120);
    let (_, answer) = service.ask(&c, &s, Rating::HARMLESS);
    assert!(
        matches!(answer.outcome, Outcome::Refused(Refused::Pledge(PledgeReason::DelegationWithdrawn))),
        "{answer:?}"
    );
    assert!(server.ok(&["agents", "list"]).starts_with("withdrawn"));

    let history = server.history();
    let results: Vec<(&str, Option<&str>)> = history
        .iter()
        .filter(|e| e["type"] == "request")
        .map(|e| (e["result"].as_str().expect("result"), e["reason"].as_str()))
        .collect();
    assert_eq!(
        results,
        [
            ("approved", None),
            ("approved", None),
            ("declined", None),
            ("refused", Some("not-showable")),
            ("refused", Some("delegation-withdrawn"))
        ]
    );
    let events: Vec<&str> = history.iter().filter_map(|e| e["event"].as_str()).collect();
    assert!(events.contains(&"delegation-issued") && events.contains(&"delegation-withdrawn"), "{events:?}");
    // The record never holds the agent's key.
    let record = fs::read_to_string(server.state.join("record.jsonl")).expect("record");
    assert!(!record.contains("PRIVATE KEY"));
}

#[test]
fn the_same_bytes_get_the_same_answer_after_pledge_is_restarted() {
    let mut server = start("restart", true);
    make_keys(&mut server);
    let (agent, _) = agent(&mut server, &[]);
    let (c, s) = call(&agent, 10, &[], 120);
    let (_, first) = Service::connect(&server).ask(&c, &s, Rating::HARMLESS);
    let Outcome::Approved(first) = first.outcome else { panic!("approved") };
    // Stop pledge serve and start it again on the same directories.
    let (state, sockets) = (server.state.clone(), server.sockets.clone());
    let mut child = std::mem::replace(&mut server.child, Command::new("true").spawn().expect("spawn"));
    child.kill().expect("kill");
    child.wait().expect("wait");
    let restarted = Command::new(common::PLEDGE)
        .args(["serve", "--state-dir"])
        .arg(&state)
        .arg("--socket-dir")
        .arg(&sockets)
        .arg("--known-hosts")
        .arg(server._dir.join("known_hosts"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("restart");
    server.child = restarted;
    for _ in 0..100 {
        if UnixStream::connect(sockets.join("service.sock")).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut service = Service::connect(&server);
    let (_, again) = service.ask(&c, &s, Rating::HARMLESS);
    let Outcome::Approved(again) = again.outcome else { panic!("approved again") };
    assert_eq!(first.approval(), again.approval());
}

#[test]
fn agents_start_refuses_without_services_and_a_delegation_it_could_not_deliver_never_exists() {
    let mut server = start("bundle-errors", false);
    make_keys(&mut server);
    server.answer("y\n");
    let file = server._dir.join("nowhere");
    let out = server.pledge(&["agents", "start", "--output", file.to_str().expect("path")]);
    assert_eq!(out.status.code(), Some(4), "{}", text(&out));
    assert!(text(&out).contains("no services"), "{}", text(&out));
    assert!(!file.exists());
    assert!(
        server.ok(&["agents", "list"]).is_empty(),
        "no delegation was started for a bundle that could not be written"
    );

    let mut server = start("bundle-exists", true);
    make_keys(&mut server);
    server.answer("y\n");
    let existing = server._dir.join("existing");
    fs::write(&existing, "mine").expect("write");
    let out = server.pledge(&["agents", "start", "--output", existing.to_str().expect("path")]);
    assert_eq!(out.status.code(), Some(3), "{}", text(&out));
    assert_eq!(fs::read_to_string(&existing).expect("read"), "mine", "nothing it did not create is touched");
    assert!(server.ok(&["agents", "list"]).is_empty(), "a bundle that did not arrive: the delegation never existed");
    let events: Vec<(String, String)> = server
        .history()
        .iter()
        .filter_map(|e| e["event"].as_str().map(|ev| (ev.to_owned(), e["by"].as_str().unwrap_or("").to_owned())))
        .collect();
    assert!(events.iter().any(|(e, _)| e == "delegation-not-delivered"), "{events:?}");
    assert!(!events.iter().any(|(e, _)| e == "delegation-withdrawn"));
    assert!(!events.iter().any(|(e, _)| e == "delegation-issued"));
}

#[test]
fn a_kill_with_a_dialog_open_leaves_received_and_the_next_start_records_lost() {
    let mut server = start("lost", true);
    make_keys(&mut server);
    let (agent, _) = agent(&mut server, &[]);
    let (c, sig) = call(&agent, 20, &["pid=20"], 300);
    let request = Request::compose(&c, &sig, INTERNAL).expect("request");
    let mut service = Service::connect(&server);
    let request_sig = sign_request(&service.signer, &request).expect("sign request");
    let submit = Submit::new(request.clone(), &request_sig).expect("submit");
    write_message(&mut service.stream, &Message::Submit(submit), ClearancePolicy::Refused).expect("write");
    // The dialog is open: nobody answers it.
    server.wait_for("action:");
    let before = server.history();
    assert!(before.iter().any(|e| e["type"] == "received"), "received is on disk before any answer");
    assert!(!before.iter().any(|e| e["result"] == "lost"));
    // Kill the real binary, and start it again on the same directories.
    let (state, sockets) = (server.state.clone(), server.sockets.clone());
    let mut child = std::mem::replace(&mut server.child, Command::new("true").spawn().expect("spawn"));
    child.kill().expect("kill");
    child.wait().expect("wait");
    server.child = Command::new(common::PLEDGE)
        .args(["serve", "--state-dir"])
        .arg(&state)
        .arg("--socket-dir")
        .arg(&sockets)
        .arg("--known-hosts")
        .arg(server._dir.join("known_hosts"))
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("restart");
    for _ in 0..100 {
        if UnixStream::connect(sockets.join("service.sock")).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // `history --verify` exits 0 (the chain holds) and shows received, then lost, for the same request.
    let history = server.history();
    let hash = request.hash().to_string();
    let positions: Vec<(usize, &str)> = history
        .iter()
        .enumerate()
        .filter(|(_, e)| e["request_hash"] == hash.as_str())
        .map(|(i, e)| (i, if e["type"] == "received" { "received" } else { e["result"].as_str().unwrap_or("?") }))
        .collect();
    assert_eq!(positions.iter().map(|(_, w)| *w).collect::<Vec<_>>(), ["received", "lost"], "{positions:?}");
    let text_output = server.ok(&["history"]);
    assert!(text_output.contains("received") && text_output.contains("lost"), "{text_output}");
    // The text output carries the legend on standard error.
    let out = server.pledge(&["history"]);
    assert!(text(&out).contains("`approved` means this machine signed"), "{}", text(&out));
}

/// The same stage-1 run under `umask 002`, as a system account or a shared-group setup has it: the
/// files this harness writes, and the files pledge writes, must not lean on the umask.
#[test]
fn the_harness_and_pledge_do_not_lean_on_the_umask() {
    if std::env::var_os("PLEDGE_UMASK_CHILD").is_some() {
        return;
    }
    let exe = std::env::current_exe().expect("exe");
    let out = Command::new("sh")
        .args(["-c", "umask 002; exec \"$0\" --test-threads=1 --exact \"$@\"", exe.to_str().expect("path")])
        .arg("a_bundle_from_agents_start_signs_calls_pledge_approves_and_the_record_holds")
        .arg("agents_start_refuses_without_services_and_a_delegation_it_could_not_deliver_never_exists")
        .env("PLEDGE_UMASK_CHILD", "1")
        .output()
        .expect("sh");
    let all = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success() && all.contains("2 passed"), "under umask 002: {all}");
}
