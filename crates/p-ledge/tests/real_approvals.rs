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
use p_act::{Call, CallContent, CallId, Request, ServiceId, Timestamp};
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
        fs::write(state.join("config.json"), config.to_string()).expect("config");
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
        ApprovalTrust::PersonKeys { confirmed: &confirmed, automatic: &automatic },
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
    let (c, s) = call(&agent, 4, &[&"x".repeat(300)], 120);
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
fn agents_start_refuses_without_services_and_withdraws_a_delegation_it_could_not_deliver() {
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
    assert!(
        server.ok(&["agents", "list"]).starts_with("withdrawn"),
        "a bundle that did not arrive is a delegation that ends at once"
    );
}
