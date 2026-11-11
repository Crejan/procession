//! Approvals, end to end inside the process: a service faked here speaks the
//! shared exchange to `service.sock`'s connection handler and signs its
//! requests with a throwaway key certified by a throwaway host key; calls are
//! signed by agents under delegations pledge's own `agents start` issued, read
//! by the real `ssh-keygen`. The clock is the real one, since `ssh-keygen`
//! checks certificates against it.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p_act::exchange::{
    Answer, Cancel, ClearancePolicy, LineReader, Message, Outcome as Result_, PledgeReason, Refused, Submit,
    write_message,
};
use p_act::rating::{Damage, Disruption, Exposure, Rating};
use p_act::sign::{ApprovalKind, ApprovalTrust, PublicKey, Signer, sign_call, sign_request, verify_approval};
use p_act::{Call, CallContent, CallId, Document, Request, ServiceId, Timestamp};
use serde_json::{Value, json};

use crate::agents::{self, StartArgs};
use crate::config::ServiceEntry;
use crate::delegations::RatingWords;
use crate::dialog::{Answer as Scripted, Outcome};
use crate::holder::KeyType;
use crate::service_conn;
use crate::shared::KeyMeta;
use crate::testing::{Rig, TestDir};

const INTERNAL: Rating = Rating { exposure: Exposure::Internal, damage: Damage::None, disruption: Disruption::None };
const SECRET: Rating = Rating { exposure: Exposure::Secret, damage: Damage::None, disruption: Disruption::None };

fn yes() -> Outcome<Scripted> {
    Outcome::Answer(Scripted::Yes(true))
}
fn no() -> Outcome<Scripted> {
    Outcome::Answer(Scripted::Yes(false))
}
fn hold() -> Outcome<Scripted> {
    Outcome::Answer(Scripted::Hold)
}
fn words(e: &str, d: &str, s: &str) -> RatingWords {
    RatingWords { exposure: e.into(), damage: d.into(), disruption: s.into() }
}
fn uuid(n: u32) -> String {
    format!("00000000-0000-4000-8000-{n:012}")
}
fn keygen(args: &[&str]) {
    let out = Command::new("ssh-keygen").args(args).stdin(Stdio::null()).output().expect("ssh-keygen");
    assert!(out.status.success(), "ssh-keygen {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}
fn now() -> i64 {
    Timestamp::now().expect("clock").unix()
}

/// The keys of the world outside pledge: a host, a service certified by it, a rogue service.
struct Material {
    dir: TestDir,
}

impl Material {
    fn new() -> Self {
        let dir = TestDir::new("material");
        let path = |name: &str| dir.path().join(name).to_string_lossy().into_owned();
        for key in ["host", "other-host", "svc", "rogue"] {
            keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", &path(key)]);
        }
        let certify = |ca: &str, key: &str, principal: &str| {
            keygen(&[
                "-q",
                "-s",
                &path(ca),
                "-I",
                key,
                "-n",
                principal,
                "-V",
                "20200101Z:20990101Z",
                "-O",
                "clear",
                &format!("{}.pub", path(key)),
            ]);
        };
        certify("host", "svc", "probe@a.example");
        certify("other-host", "rogue", "probe@a.example");
        Self { dir }
    }
    fn signer(&self, name: &str) -> Signer {
        Signer::certified(self.dir.path().join(name)).expect("certified")
    }
    fn host_line(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("host.pub")).expect("host.pub").trim().to_owned()
    }
}

struct Agent {
    id: String,
    signer: Signer,
}

/// pledge, a service, and agents.
struct Lab {
    rig: Rig,
    material: Material,
    next_call: u32,
    next_agent: u32,
}

impl Lab {
    fn new() -> Self {
        Self::with(json!({}))
    }

    fn with(extra: Value) -> Self {
        Self::build(extra, KeyType::Ed25519)
    }

    fn build(extra: Value, delegation_type: KeyType) -> Self {
        let material = Material::new();
        let host = material.host_line();
        let rig = Rig::live([], move |dir| {
            let mut config = json!({"person": "jan", "hosts": [{"host": "a.example", "key": host}]});
            config.as_object_mut().expect("object").extend(extra.as_object().expect("object").clone());
            std::fs::write(dir.join("config.json"), config.to_string()).expect("config");
        });
        for purpose in ["delegation", "confirmed", "automatic"] {
            rig.shared
                .create_key(
                    if purpose == "delegation" { delegation_type } else { KeyType::Ed25519 },
                    KeyMeta {
                        purpose: purpose.into(),
                        program: None,
                        use_: None,
                        comment: purpose.into(),
                        key_type: String::new(),
                        created: String::new(),
                    },
                )
                .expect("key");
        }
        Self { rig, material, next_call: 1, next_agent: 1 }
    }

    fn start_args(
        groups: &[&str],
        automatic: Option<RatingWords>,
        ask: Option<RatingWords>,
        valid: Option<u64>,
    ) -> StartArgs {
        StartArgs {
            groups: groups.iter().map(|g| (*g).to_owned()).collect(),
            automatic_ceiling: automatic,
            ask_ceiling: ask,
            valid_seconds: valid,
            label: None,
            services: vec![ServiceEntry {
                host: "a.example".into(),
                name: "probe".into(),
                url: "http://127.0.0.1:8443/mcp".into(),
            }],
            tls_root: None,
            deadline_seconds: None,
        }
    }

    /// Writes the key block and certificate of a bundle as `<name>` and `<name>-cert.pub`; the signer for them.
    fn write_bundle(&self, data: &Value, name: &str) -> Signer {
        let bundle = String::from_utf8(STANDARD.decode(data["bundle"].as_str().expect("bundle")).expect("base64"))
            .expect("text");
        let (_, rest) = bundle.split_once('\n').expect("line 1");
        let end = "-----END OPENSSH PRIVATE KEY-----\n";
        let split = rest.find(end).expect("key block") + end.len();
        let (block, certificate) = rest.split_at(split);
        let file = self.material.dir.path().join(name);
        std::fs::write(&file, block).expect("key");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        std::fs::write(format!("{}-cert.pub", file.display()), certificate).expect("cert");
        Signer::certified(&file).expect("signer")
    }

    /// An agent under a delegation `agents start` issued and delivered, with its bundle's key and certificate on disk.
    fn agent(&mut self, groups: &[&str], automatic: RatingWords, ask: RatingWords, valid: u64) -> Agent {
        self.rig.dialogs.push(yes());
        let args = Self::start_args(groups, Some(automatic), Some(ask), Some(valid));
        let (data, delegation) = agents::start(&self.rig.shared, args).expect("agents start");
        let signer = self.write_bundle(&data, &format!("agent{}", self.next_agent));
        self.next_agent += 1;
        let id = delegation.id.clone();
        agents::delivered(&self.rig.shared, delegation).expect("delivered");
        Agent { id, signer }
    }

    fn default_agent(&mut self) -> Agent {
        self.agent(&["admins"], words("open", "none", "none"), words("secret", "lasting", "outage"), 3600)
    }

    fn call(&mut self, agent: &Agent, params: &[&str], deadline_in: i64) -> (Call, String) {
        let id = uuid(self.next_call);
        self.next_call += 1;
        self.call_with_id(agent, &id, params, deadline_in)
    }

    fn call_with_id(&self, agent: &Agent, id: &str, params: &[&str], deadline_in: i64) -> (Call, String) {
        let content = CallContent {
            id: CallId::parse(id).expect("uuid"),
            deadline: Timestamp::from_unix(now() + deadline_in).expect("time"),
            service: ServiceId { host: "a.example".into(), name: "probe".into() },
            action: "rt procs".into(),
            params: params.iter().map(|p| (*p).to_owned()).collect(),
            claim: Some("checking why the control loop misses cycles".into()),
        };
        let call = Call::compose(&content).expect("call");
        let sig = sign_call(&agent.signer, &call).expect("sign call");
        (call, sig)
    }

    fn request(&self, call: &Call, call_sig: &str, rating: Rating, service: &str) -> (Request, String) {
        let request = Request::compose(call, call_sig, rating).expect("request");
        let sig = sign_request(&self.material.signer(service), &request).expect("sign request");
        (request, sig)
    }

    /// A whole request from `agent`, signed by the service.
    fn make(&mut self, agent: &Agent, params: &[&str], rating: Rating) -> (Request, String) {
        let (call, sig) = self.call(agent, params, 120);
        self.request(&call, &sig, rating, "svc")
    }

    fn connect(&self) -> Svc {
        let (client, server) = UnixStream::pair().expect("pair");
        let shared = Arc::clone(&self.rig.shared);
        thread::spawn(move || service_conn::serve(&shared, server, Some((0, None))));
        Svc::new(client)
    }

    fn entries(&self) -> Vec<Value> {
        self.rig.record().into_iter().filter(|e| e["type"] == "request").collect()
    }

    fn results(&self) -> Vec<(String, Option<String>)> {
        self.entries()
            .iter()
            .map(|e| (e["result"].as_str().expect("result").to_owned(), e["reason"].as_str().map(str::to_owned)))
            .collect()
    }

    fn verifies(&self, request: &Request, approval: &str) -> ApprovalKind {
        let key = |purpose: &str| {
            let key = self.rig.shared.key_with_purpose(purpose).expect("key");
            PublicKey::parse(&key.public_line()).expect("public key")
        };
        let (confirmed, automatic) = (key("confirmed"), key("automatic"));
        verify_approval(
            request,
            approval,
            ApprovalTrust::PersonKeys { person: "jan", confirmed: &confirmed, automatic: &automatic },
        )
        .expect("the approval verifies with ssh-keygen")
    }
}

/// The fake service's end of a connection.
struct Svc {
    stream: UnixStream,
    lines: LineReader<UnixStream>,
}

impl Svc {
    fn new(stream: UnixStream) -> Self {
        stream.set_read_timeout(Some(Duration::from_secs(15))).expect("timeout");
        let lines = LineReader::new(stream.try_clone().expect("clone"));
        Self { stream, lines }
    }

    fn submit(&mut self, request: &Request, sig: &str) {
        let submit = Submit::new(request.clone(), sig).expect("submit");
        write_message(&mut self.stream, &Message::Submit(submit), ClearancePolicy::Refused).expect("write");
    }

    fn cancel(&mut self, request: &Request) {
        write_message(&mut self.stream, &Message::Cancel(Cancel { request: request.hash() }), ClearancePolicy::Refused)
            .expect("write");
    }

    fn raw(&mut self, line: &str) {
        use std::io::Write;
        self.stream.write_all(line.as_bytes()).expect("write");
    }

    /// The next answer; panics if there is none in 15 seconds.
    fn answer(&mut self) -> Answer {
        match self.lines.read_message(ClearancePolicy::Refused).expect("a message") {
            Some(Message::Answer(answer)) => answer,
            other => panic!("expected an answer, got {other:?}"),
        }
    }

    /// An answer within `wait`, or `None`.
    fn try_answer(&mut self, wait: Duration) -> Option<Answer> {
        self.stream.set_read_timeout(Some(wait)).expect("timeout");
        let answer = match self.lines.read_message(ClearancePolicy::Refused) {
            Ok(Some(Message::Answer(answer))) => Some(answer),
            _ => None,
        };
        self.stream.set_read_timeout(Some(Duration::from_secs(15))).expect("timeout");
        answer
    }

    fn ask(&mut self, request: &Request, sig: &str) -> Answer {
        self.submit(request, sig);
        self.answer()
    }
}

fn approval(answer: &Answer) -> &str {
    match &answer.outcome {
        Result_::Approved(approved) => approved.approval(),
        other => panic!("not approved: {other:?}"),
    }
}

fn refusal(answer: &Answer) -> PledgeReason {
    match &answer.outcome {
        Result_::Refused(Refused::Pledge(reason)) => *reason,
        other => panic!("not refused by pledge: {other:?}"),
    }
}

fn shown(lab: &Lab) -> Vec<String> {
    lab.rig.shown().into_iter().filter(|s| s.starts_with("request")).collect()
}

fn dialogs(lab: &Lab) -> usize {
    lab.rig.shown().iter().filter(|s| s.starts_with("request") || s.starts_with("confirm sign the approval")).count()
}

// ---------------------------------------------------------------------------
// The three modes
// ---------------------------------------------------------------------------

#[test]
fn a_harmless_request_is_approved_with_the_automatic_key_and_without_asking() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    let (request, sig) = lab.make(&agent, &["pid=4711"], Rating::HARMLESS);
    let answer = lab.connect().ask(&request, &sig);
    assert_eq!(answer.request, request.hash());
    assert_eq!(lab.verifies(&request, approval(&answer)), ApprovalKind::Automatic);
    assert_eq!(dialogs(&lab), 0, "nobody was asked");
    let entry = &lab.entries()[0];
    assert_eq!(
        (entry["result"].as_str(), entry["mode"].as_str(), entry["key"].as_str()),
        (Some("approved"), Some("automatic"), Some("automatic"))
    );
    assert_eq!(entry["request_hash"], request.hash().to_string());
    assert_eq!(entry["delegation"], agent.id.as_str());
    assert_eq!(entry["person"], "jan");
}

#[test]
fn a_request_above_the_automatic_ceiling_is_shown_as_it_is_and_approved_with_the_confirmed_key() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    lab.rig.dialogs.push(yes());
    lab.rig.dialogs.push(yes());
    let (request, sig) = lab.make(&agent, &["pid=4711", "all=yes"], INTERNAL);
    let answer = lab.connect().ask(&request, &sig);
    assert_eq!(lab.verifies(&request, approval(&answer)), ApprovalKind::Confirmed);
    let text = shown(&lab).join("\n");
    for expected in [
        "person: jan",
        &format!("agent: {}", agent.id),
        "service: probe on a.example",
        "action: rt procs",
        "parameter: pid=4711",
        "parameter: all=yes",
        "the agent's claim: checking why the control loop misses cycles",
        "exposure: internal",
    ] {
        assert!(text.contains(expected), "{expected} in {text}");
    }
    assert!(lab.rig.shown().iter().any(|s| s.starts_with("confirm sign the approval")), "then the presence check");
    assert_eq!(lab.entries()[0]["key"], "confirmed");
}

#[test]
fn the_top_of_a_scale_is_never_signed_with_the_automatic_key_whatever_the_delegation_says() {
    let mut lab = Lab::new();
    // The highest automatic ceiling a person can set: internal, recoverable, brief.
    let agent = lab.agent(&[], words("internal", "recoverable", "brief"), words("secret", "lasting", "outage"), 3600);
    lab.rig.dialogs.push(yes());
    lab.rig.dialogs.push(yes());
    let (request, sig) = lab.make(&agent, &[], SECRET);
    let answer = lab.connect().ask(&request, &sig);
    assert_eq!(lab.verifies(&request, approval(&answer)), ApprovalKind::Confirmed);
    assert_eq!(dialogs(&lab), 2);
    // Just below the top, it is automatic.
    let below = Rating::new(Exposure::Internal, Damage::Recoverable, Disruption::Brief);
    let (request, sig) = lab.make(&agent, &[], below);
    let answer = lab.connect().ask(&request, &sig);
    assert_eq!(lab.verifies(&request, approval(&answer)), ApprovalKind::Automatic);
    // And pledge refuses to issue a delegation whose automatic ceiling is above that.
    lab.rig.dialogs.push(yes());
    let too_high = Lab::start_args(&[], Some(words("secret", "none", "none")), None, None);
    assert_eq!(agents::start(&lab.rig.shared, too_high).err(), Some(crate::control::Code::Refused));
}

#[test]
fn an_automatic_ceiling_tampered_with_on_disk_is_not_honoured() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    let path = lab.rig.dir.path().join("delegations.json");
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json");
    file["delegations"][0]["automatic"] = json!({"exposure": "secret", "damage": "lasting", "disruption": "outage"});
    std::fs::write(&path, file.to_string()).expect("write");
    lab.rig.restart();
    lab.rig.dialogs.push(yes());
    lab.rig.dialogs.push(yes());
    let (request, sig) = lab.make(&agent, &[], SECRET);
    let answer = lab.connect().ask(&request, &sig);
    assert_eq!(
        lab.verifies(&request, approval(&answer)),
        ApprovalKind::Confirmed,
        "asked, and signed with the confirmed key"
    );
    assert_eq!(dialogs(&lab), 2);
    assert_eq!(lab.entries()[0]["automatic_ceiling_clamped"], true);
    // A harmless request is still automatic; the one above `internal` is asked.
    let (above, sig) = lab.make(&agent, &[], Rating::new(Exposure::Open, Damage::Lasting, Disruption::None));
    lab.rig.dialogs.push(no());
    let answer = lab.connect().ask(&above, &sig);
    assert!(matches!(answer.outcome, Result_::Declined), "{answer:?}");
}

#[test]
fn above_the_ask_ceiling_is_refused_as_a_verdict_and_answered_again_from_the_store() {
    let mut lab = Lab::new();
    let agent = lab.agent(&[], words("open", "none", "none"), words("internal", "none", "none"), 3600);
    let (request, sig) = lab.make(&agent, &[], SECRET);
    let mut svc = lab.connect();
    assert_eq!(refusal(&svc.ask(&request, &sig)), PledgeReason::Ceiling);
    let again = svc.ask(&request, &sig);
    assert_eq!(refusal(&again), PledgeReason::Ceiling);
    assert_eq!(lab.results(), [("refused".to_owned(), Some("ceiling".to_owned()))], "recorded once");
    assert_eq!(dialogs(&lab), 0);
}

// ---------------------------------------------------------------------------
// Final until the deadline
// ---------------------------------------------------------------------------

#[test]
fn the_same_bytes_again_get_the_same_approval_without_a_second_dialog_or_entry() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    lab.rig.dialogs.push(yes());
    lab.rig.dialogs.push(yes());
    let (request, sig) = lab.make(&agent, &["a=b"], INTERNAL);
    let mut svc = lab.connect();
    let first = svc.ask(&request, &sig);
    let again = svc.ask(&request, &sig);
    assert_eq!(approval(&first), approval(&again), "the same approval bytes");
    // Also on another connection, as after a reconnect.
    let third = lab.connect().ask(&request, &sig);
    assert_eq!(approval(&first), approval(&third));
    assert_eq!(dialogs(&lab), 2, "one dialog and its presence check, once");
    assert_eq!(lab.results(), [("approved".to_owned(), None)]);
}

#[test]
fn a_different_request_under_a_used_identifier_is_refused_call_used_and_that_is_not_kept() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    let (call, call_sig) = lab.call(&agent, &[], 120);
    let (first, first_sig) = lab.request(&call, &call_sig, Rating::HARMLESS, "svc");
    let mut svc = lab.connect();
    approval(&svc.ask(&first, &first_sig));
    // The same call, a different rating: different bytes, same identifier.
    let (second, second_sig) = lab.request(&call, &call_sig, INTERNAL, "svc");
    assert_ne!(first.hash(), second.hash());
    assert_eq!(refusal(&svc.ask(&second, &second_sig)), PledgeReason::CallUsed);
    assert!(
        lab.rig.shared.approvals.answers.answer(&second.hash().to_string(), now()).is_none(),
        "call-used is not stored"
    );
    assert_eq!(dialogs(&lab), 0);
}

#[test]
fn a_declined_call_is_declined_again_not_put_to_the_person_again_and_counts_once() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    lab.rig.dialogs.push(no());
    let (call, call_sig) = lab.call(&agent, &[], 120);
    let (request, sig) = lab.request(&call, &call_sig, INTERNAL, "svc");
    let mut svc = lab.connect();
    assert!(matches!(svc.ask(&request, &sig).outcome, Result_::Declined));
    assert!(matches!(svc.ask(&request, &sig).outcome, Result_::Declined), "the same bytes: the same answer");
    assert_eq!(dialogs(&lab), 1);
    // Another request under the identifier: refused, not asked.
    let (other, other_sig) = lab.request(&call, &call_sig, SECRET, "svc");
    assert_eq!(refusal(&svc.ask(&other, &other_sig)), PledgeReason::CallUsed);
    assert_eq!(lab.results(), [("declined".to_owned(), None), ("refused".to_owned(), Some("call-used".to_owned()))]);
}

#[test]
fn a_restart_between_submit_and_repeat_changes_nothing() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    let (call, call_sig) = lab.call(&agent, &[], 120);
    let (approved, approved_sig) = lab.request(&call, &call_sig, Rating::HARMLESS, "svc");
    lab.rig.dialogs.push(no());
    let (declined, declined_sig) = lab.make(&agent, &["x=1"], INTERNAL);
    let first = {
        let mut svc = lab.connect();
        let first = approval(&svc.ask(&approved, &approved_sig)).to_owned();
        assert!(matches!(svc.ask(&declined, &declined_sig).outcome, Result_::Declined));
        first
    };
    lab.rig.restart();
    let mut svc = lab.connect();
    assert_eq!(approval(&svc.ask(&approved, &approved_sig)), first, "the same approval after a restart");
    assert!(matches!(svc.ask(&declined, &declined_sig).outcome, Result_::Declined));
    let (other, other_sig) = lab.request(&call, &call_sig, INTERNAL, "svc");
    assert_eq!(refusal(&svc.ask(&other, &other_sig)), PledgeReason::CallUsed, "the used identifier survived");
    // A verdict is kept across a restart too.
    let tight = lab.agent(&[], words("open", "none", "none"), words("open", "none", "none"), 3600);
    let (over, over_sig) = lab.make(&tight, &[], INTERNAL);
    assert_eq!(refusal(&svc.ask(&over, &over_sig)), PledgeReason::Ceiling);
    lab.rig.restart();
    let before = lab.entries().len();
    assert_eq!(refusal(&lab.connect().ask(&over, &over_sig)), PledgeReason::Ceiling);
    assert_eq!(lab.entries().len(), before, "answered from the store, not decided again");
}

#[test]
fn what_is_not_a_verdict_is_not_kept_and_the_identifier_is_not_used() {
    let mut lab = Lab::with(json!({"max_waiting": 1}));
    let agent = lab.default_agent();
    // `limit`: one request waits (its dialog stays open), so a second is refused.
    lab.rig.dialogs.push(hold());
    let (waiting, waiting_sig) = lab.make(&agent, &["a"], INTERNAL);
    let mut first = lab.connect();
    first.submit(&waiting, &waiting_sig);
    thread::sleep(Duration::from_millis(300));
    let (second, second_sig) = lab.make(&agent, &["b"], Rating::HARMLESS);
    let mut other = lab.connect();
    assert_eq!(refusal(&other.ask(&second, &second_sig)), PledgeReason::Limit);
    assert!(lab.rig.shared.approvals.answers.answer(&second.hash().to_string(), now()).is_none());
    // The one that waited is cancelled; the same bytes as the refused one now go through.
    first.cancel(&waiting);
    thread::sleep(Duration::from_millis(300));
    approval(&other.ask(&second, &second_sig));
    // `unavailable`: nobody to ask. The identifier is not used, so the same call can be asked again.
    lab.rig.dialogs.push(Outcome::Unavailable);
    let (call, call_sig) = lab.call(&agent, &[], 120);
    let (request, sig) = lab.request(&call, &call_sig, INTERNAL, "svc");
    assert_eq!(refusal(&other.ask(&request, &sig)), PledgeReason::Unavailable);
    assert!(lab.rig.shared.approvals.answers.used_for(call.id().as_str(), now()).is_none());
    lab.rig.dialogs.push(yes());
    lab.rig.dialogs.push(yes());
    approval(&other.ask(&request, &sig));
}

#[test]
fn an_agent_declined_three_times_is_muted_and_the_person_is_told() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    let mut svc = lab.connect();
    for _ in 0..3 {
        lab.rig.dialogs.push(no());
        let (request, sig) = lab.make(&agent, &[], INTERNAL);
        assert!(matches!(svc.ask(&request, &sig).outcome, Result_::Declined));
    }
    let shown_before = lab.rig.shown().len();
    let (request, sig) = lab.make(&agent, &[], Rating::HARMLESS);
    assert_eq!(refusal(&svc.ask(&request, &sig)), PledgeReason::Muted, "even a harmless one: refused without a dialog");
    assert_eq!(lab.rig.shown().len(), shown_before);
    assert!(
        lab.rig.shown().iter().any(|s| s.starts_with("tell the agent") && s.contains("declined 3 times")),
        "{:?}",
        lab.rig.shown()
    );
    assert!(lab.rig.shared.approvals.answers.answer(&request.hash().to_string(), now()).is_none(), "muted is not kept");
    assert!(lab.rig.record().iter().any(|e| e["event"] == "agent-muted"));
}

// ---------------------------------------------------------------------------
// Delegations
// ---------------------------------------------------------------------------

#[test]
fn a_call_under_a_withdrawn_delegation_is_refused_and_so_is_one_under_an_ended_one() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    let (request, sig) = lab.make(&agent, &[], Rating::HARMLESS);
    let mut svc = lab.connect();
    approval(&svc.ask(&request, &sig));
    agents::withdraw(&lab.rig.shared, &agent.id).expect("withdraw");
    let (later, later_sig) = lab.make(&agent, &["later"], Rating::HARMLESS);
    assert_eq!(refusal(&svc.ask(&later, &later_sig)), PledgeReason::DelegationWithdrawn);
    assert_eq!(refusal(&svc.ask(&later, &later_sig)), PledgeReason::DelegationWithdrawn, "a verdict, kept");
    assert!(lab.rig.record().iter().any(|e| e["event"] == "delegation-withdrawn" && e["by"] == "person"));
    // A delegation whose end has passed (here: its end edited on disk, and pledge restarted).
    let short = lab.agent(&[], words("open", "none", "none"), words("secret", "lasting", "outage"), 3600);
    let path = lab.rig.dir.path().join("delegations.json");
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json");
    let index =
        file["delegations"].as_array().expect("list").iter().position(|d| d["id"] == short.id.as_str()).expect("it");
    file["delegations"][index]["valid_until"] = json!(now() - 10);
    std::fs::write(&path, file.to_string()).expect("write");
    lab.rig.restart();
    let mut svc = lab.connect();
    let (call, call_sig) = lab.call(&short, &[], 120);
    let (ended, ended_sig) = lab.request(&call, &call_sig, Rating::HARMLESS, "svc");
    assert_eq!(refusal(&svc.ask(&ended, &ended_sig)), PledgeReason::DelegationEnded);
}

#[test]
fn a_call_under_another_pledges_delegation_is_refused() {
    let mine = Lab::new();
    let mut foreign = Lab::new();
    let their_agent = foreign.default_agent();
    // The call is theirs, the service is ours (certified by our host).
    let (call, call_sig) = foreign.call(&their_agent, &[], 120);
    let (request, sig) = mine.request(&call, &call_sig, Rating::HARMLESS, "svc");
    assert_eq!(refusal(&mine.connect().ask(&request, &sig)), PledgeReason::UnknownDelegation);
    assert_eq!(dialogs(&mine), 0);
    // And a call signed by no certified key at all.
    let plain = Material::new();
    keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", &plain.dir.path().join("loose").to_string_lossy()]);
    let loose = Agent { id: String::new(), signer: Signer::plain(plain.dir.path().join("loose")) };
    let (call, call_sig) = mine.call_with_id(&loose, &uuid(900), &[], 120);
    let (request, sig) = mine.request(&call, &call_sig, Rating::HARMLESS, "svc");
    assert_eq!(
        refusal(&mine.connect().ask(&request, &sig)),
        PledgeReason::Malformed,
        "no certificate: not a valid call"
    );
}

#[test]
fn a_call_whose_signature_is_over_other_bytes_is_refused_even_under_a_real_delegation() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    let (_, signed_for_other_params) = lab.call(&agent, &["pid=1"], 120);
    // The same agent's signature, carried to a call with other parameters.
    let content = |params: &[&str]| CallContent {
        id: CallId::parse(&uuid(700)).expect("uuid"),
        deadline: Timestamp::from_unix(now() + 100).expect("time"),
        service: ServiceId { host: "a.example".into(), name: "probe".into() },
        action: "rt procs".into(),
        params: params.iter().map(|p| (*p).to_owned()).collect(),
        claim: None,
    };
    let altered = Call::compose(&content(&["pid=999"])).expect("call");
    let (request, sig) = lab.request(&altered, &signed_for_other_params, Rating::HARMLESS, "svc");
    assert_eq!(refusal(&lab.connect().ask(&request, &sig)), PledgeReason::Malformed, "the signature does not verify");
    assert_eq!(dialogs(&lab), 0);
}

#[test]
fn an_agent_under_a_p256_delegation_key_is_approved_and_its_call_verifies() {
    let mut lab = Lab::build(json!({}), KeyType::EcdsaP256);
    let agent = lab.default_agent();
    let (request, sig) = lab.make(&agent, &["pid=1"], Rating::HARMLESS);
    let answer = lab.connect().ask(&request, &sig);
    assert_eq!(lab.verifies(&request, approval(&answer)), ApprovalKind::Automatic);
    let delegation = lab.rig.shared.approvals.delegations.get(&agent.id).expect("delegation");
    let issuer = lab.rig.shared.key_by_fingerprint(&delegation.issuer).expect("issuer");
    assert!(issuer.public_line().starts_with("ecdsa-sha2-nistp256 "));
}

#[test]
fn a_delegation_exists_for_pledge_only_from_delivered() {
    let mut lab = Lab::new();
    lab.rig.dialogs.push(yes());
    let (data, delegation) = agents::start(&lab.rig.shared, Lab::start_args(&[], None, None, None)).expect("start");
    let signer = lab.write_bundle(&data, "pending");
    let agent = Agent { id: delegation.id.clone(), signer };
    let (request, sig) = lab.make(&agent, &[], Rating::HARMLESS);
    assert_eq!(
        refusal(&lab.connect().ask(&request, &sig)),
        PledgeReason::UnknownDelegation,
        "not delivered: pledge has never heard of it"
    );
    assert!(agents::list(&lab.rig.shared)["delegations"].as_array().expect("list").is_empty(), "written nowhere");
    assert!(lab.rig.shared.approvals.delegations.all().is_empty());
    agents::delivered(&lab.rig.shared, delegation).expect("delivered");
    let (request, sig) = lab.make(&agent, &["after"], Rating::HARMLESS);
    approval(&lab.connect().ask(&request, &sig));
    assert_eq!(agents::list(&lab.rig.shared)["delegations"][0]["state"], "active");
}

#[test]
fn a_control_connection_that_ends_before_delivery_leaves_only_a_record_entry() {
    let lab = Lab::new();
    lab.rig.dialogs.push(yes());
    let (client, server) = UnixStream::pair().expect("pair");
    let shared = Arc::clone(&lab.rig.shared);
    let handler = thread::spawn(move || crate::control::serve(&shared, server));
    let mut client = crate::control::Client::from_stream(client);
    let mut args = json!({"groups": ["admins"], "services": [{"host": "a.example", "name": "probe", "url": "http://127.0.0.1:8443/mcp"}]});
    args["valid_seconds"] = json!(3600);
    let data = client.call("agents.start", args).expect("start");
    let id = data["delegation"].as_str().expect("id").to_owned();
    drop(client);
    handler.join().expect("handler");
    assert!(lab.rig.shared.approvals.delegations.all().is_empty(), "it never existed");
    assert!(
        lab.rig.record().iter().any(|e| e["event"] == "delegation-not-delivered" && e["delegation"] == id.as_str())
    );
    assert!(
        !lab.rig.record().iter().any(|e| e["event"] == "delegation-withdrawn"),
        "nothing that could sign was stopped"
    );
    assert!(!lab.rig.record().iter().any(|e| e["event"] == "delegation-issued"));
}

#[test]
fn the_certificate_is_what_the_formats_say_as_ssh_keygen_reads_it() {
    let mut lab = Lab::new();
    let agent = lab.agent(
        &["diag-readers", "admins", "admins"],
        words("open", "none", "none"),
        words("secret", "lasting", "outage"),
        8 * 3600,
    );
    let cert = lab.material.dir.path().join("agent1-cert.pub");
    let out = Command::new("ssh-keygen").args(["-L", "-f"]).arg(&cert).output().expect("ssh-keygen");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(text.contains("user certificate") && text.contains("ED25519-CERT"), "{text}");
    assert!(text.contains("Principals:") && text.contains("                jan\n"), "{text}");
    assert!(text.contains("Critical Options: (none)"), "{text}");
    // The extension is encoded as `ssh-keygen -O extension:name=value` encodes it: compare with one it made.
    let reference = lab.material.dir.path().join("reference");
    keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", &reference.to_string_lossy()]);
    keygen(&[
        "-q",
        "-s",
        &lab.material.dir.path().join("host").to_string_lossy(),
        "-I",
        "x",
        "-n",
        "jan",
        "-V",
        "+1h",
        "-O",
        "clear",
        "-O",
        "extension:groups@procession=admins,diag-readers",
        &format!("{}.pub", reference.display()),
    ]);
    let made = Command::new("ssh-keygen")
        .args(["-L", "-f"])
        .arg(format!("{}-cert.pub", reference.display()))
        .output()
        .expect("ssh-keygen");
    let extension = |text: &str| text.lines().find(|l| l.contains("groups@procession")).map(|l| l.trim().to_owned());
    assert!(extension(&text).is_some(), "{text}");
    assert_eq!(
        extension(&text),
        extension(&String::from_utf8_lossy(&made.stdout)),
        "the groups, sorted, without duplicates, as ssh-keygen writes them"
    );
    assert!(!text.contains("permit-"), "issued as -O clear: {text}");
    let fingerprint = Command::new("ssh-keygen").args(["-l", "-f"]).arg(&cert).output().expect("ssh-keygen");
    assert!(
        String::from_utf8_lossy(&fingerprint.stdout).contains(&agent.id),
        "the delegation's identifier is the key's fingerprint"
    );
}

// ---------------------------------------------------------------------------
// The checks of SPEC section 4
// ---------------------------------------------------------------------------

#[test]
fn a_request_not_signed_by_a_service_a_known_host_certified_is_refused_service_mismatch() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    let (call, call_sig) = lab.call(&agent, &[], 120);
    let (request, sig) = lab.request(&call, &call_sig, Rating::HARMLESS, "rogue");
    let mut svc = lab.connect();
    assert_eq!(refusal(&svc.ask(&request, &sig)), PledgeReason::ServiceMismatch);
    assert_eq!(refusal(&svc.ask(&request, &sig)), PledgeReason::ServiceMismatch);
    assert_eq!(lab.results().len(), 1, "a verdict: decided once");
    // A call naming a host pledge does not know.
    let content = CallContent {
        id: CallId::parse(&uuid(800)).expect("uuid"),
        deadline: Timestamp::from_unix(now() + 100).expect("time"),
        service: ServiceId { host: "unknown.example".into(), name: "probe".into() },
        action: "x".into(),
        params: vec![],
        claim: None,
    };
    let call = Call::compose(&content).expect("call");
    let sig = sign_call(&agent.signer, &call).expect("sig");
    let (request, request_sig) = lab.request(&call, &sig, Rating::HARMLESS, "svc");
    assert_eq!(refusal(&svc.ask(&request, &request_sig)), PledgeReason::ServiceMismatch);
}

#[test]
fn a_field_that_cannot_be_shown_as_it_is_is_refused_and_a_request_that_does_not_parse_is_malformed() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    // One long parameter (up to 512) is shown whole; all parameters together over 2000 characters are not.
    lab.rig.dialogs.push(yes());
    lab.rig.dialogs.push(yes());
    let long_one = "q".repeat(300);
    let (shown_request, shown_sig) = lab.make(&agent, &[&long_one], INTERNAL);
    approval(&lab.connect().ask(&shown_request, &shown_sig));
    assert!(shown(&lab).join("\n").contains(&format!("parameter: {long_one}")), "shown whole, not shortened");
    let long = "p".repeat(450);
    let params = [long.as_str(); 5];
    let (request, sig) = lab.make(&agent, &params, INTERNAL);
    let mut svc = lab.connect();
    assert_eq!(refusal(&svc.ask(&request, &sig)), PledgeReason::NotShowable);
    assert_eq!(refusal(&svc.ask(&request, &sig)), PledgeReason::NotShowable);
    assert_eq!(dialogs(&lab), 2, "only the first request's dialog and presence check");
    // Bytes that are not a request: refused malformed, for their hash, and the connection stays.
    let bytes = b"this is not a request";
    let armour = "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n";
    svc.raw(&format!(
        "{}\n",
        json!({"schema_version": 1, "type": "submit", "request": STANDARD.encode(bytes), "request_sig": STANDARD.encode(armour)})
    ));
    let answer = svc.answer();
    assert_eq!(answer.request.to_string(), crate::record::hash_line(bytes));
    assert_eq!(refusal(&answer), PledgeReason::Malformed);
    let (fine, fine_sig) = lab.make(&agent, &[], Rating::HARMLESS);
    approval(&svc.ask(&fine, &fine_sig));
}

#[test]
fn deadlines_are_pledges_own_clock_and_the_tolerance_never_extends_one() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    let mut svc = lab.connect();
    let past = |lab: &mut Lab, delta: i64| {
        let (call, sig) = lab.call(&agent, &[], delta);
        lab.request(&call, &sig, Rating::HARMLESS, "svc")
    };
    let (request, sig) = past(&mut lab, -1);
    assert_eq!(refusal(&svc.ask(&request, &sig)), PledgeReason::DeadlinePast, "one second past is past");
    assert!(lab.rig.shared.approvals.answers.answer(&request.hash().to_string(), now()).is_none(), "not kept");
    let (request, sig) = past(&mut lab, 1000);
    assert_eq!(refusal(&svc.ask(&request, &sig)), PledgeReason::DeadlineTooFar);
    let (request, sig) = past(&mut lab, 630);
    approval(&svc.ask(&request, &sig));
    let (request, sig) = past(&mut lab, 670);
    assert_eq!(
        refusal(&svc.ask(&request, &sig)),
        PledgeReason::DeadlineTooFar,
        "ten minutes and the tolerance, no more"
    );
}

#[test]
fn the_deadline_passing_with_the_dialog_open_closes_it_and_answers_expired() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    lab.rig.dialogs.push(hold());
    let (call, call_sig) = lab.call(&agent, &[], 2);
    let (request, sig) = lab.request(&call, &call_sig, INTERNAL, "svc");
    let started = std::time::Instant::now();
    let answer = lab.connect().ask(&request, &sig);
    assert!(matches!(answer.outcome, Result_::Expired(p_act::exchange::By::Pledge)), "{answer:?}");
    assert!(started.elapsed() < Duration::from_secs(6));
    assert_eq!(lab.results(), [("expired".to_owned(), None)]);
    assert!(lab.rig.shared.approvals.answers.answer(&request.hash().to_string(), now()).is_none());
    assert!(
        lab.rig.shared.approvals.answers.used_for(call.id().as_str(), now()).is_none(),
        "nothing was approved or declined"
    );
}

#[test]
fn cancel_closes_the_dialog_sends_no_answer_records_cancelled_and_the_request_is_over() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    lab.rig.dialogs.push(hold());
    let (request, sig) = lab.make(&agent, &[], INTERNAL);
    let mut svc = lab.connect();
    svc.submit(&request, &sig);
    thread::sleep(Duration::from_millis(300));
    svc.cancel(&request);
    assert!(svc.try_answer(Duration::from_millis(700)).is_none(), "no answer follows a cancel");
    assert_eq!(lab.results(), [("cancelled".to_owned(), None)]);
    // The same bytes again are a new request.
    lab.rig.dialogs.push(yes());
    lab.rig.dialogs.push(yes());
    approval(&svc.ask(&request, &sig));
    // A cancel for a request pledge does not hold is ignored, and the connection goes on.
    svc.cancel(&request);
    let (other, other_sig) = lab.make(&agent, &["x"], Rating::HARMLESS);
    approval(&svc.ask(&other, &other_sig));
}

#[test]
fn a_connection_that_ends_cancels_what_it_had_open() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    lab.rig.dialogs.push(hold());
    let (request, sig) = lab.make(&agent, &[], INTERNAL);
    let mut svc = lab.connect();
    svc.submit(&request, &sig);
    thread::sleep(Duration::from_millis(300));
    drop(svc);
    thread::sleep(Duration::from_millis(500));
    assert_eq!(lab.results(), [("cancelled".to_owned(), None)]);
}

#[test]
fn two_connections_with_the_same_open_request_both_get_its_answer() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    lab.rig.dialogs.push(hold());
    let (request, sig) = lab.make(&agent, &[], INTERNAL);
    let (mut a, mut b) = (lab.connect(), lab.connect());
    a.submit(&request, &sig);
    thread::sleep(Duration::from_millis(300));
    b.submit(&request, &sig);
    // The first goes away; the dialog stays for the second.
    a.cancel(&request);
    thread::sleep(Duration::from_millis(300));
    assert_eq!(dialogs(&lab), 1, "one dialog for the one request");
    drop(a);
    b.cancel(&request);
    assert!(b.try_answer(Duration::from_millis(500)).is_none());
}

#[test]
fn no_record_no_approval() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    let (request, sig) = lab.make(&agent, &[], Rating::HARMLESS);
    *lab.rig.shared.record.lock().expect("lock") = crate::record::Record::failing();
    assert_eq!(
        refusal(&lab.connect().ask(&request, &sig)),
        PledgeReason::Unavailable,
        "signed, but not recorded: not handed over"
    );
    assert!(
        lab.rig.shared.approvals.answers.answer(&request.hash().to_string(), now()).is_none(),
        "an approval nobody has is not kept"
    );
}

#[test]
fn the_approval_keys_and_the_delegation_key_are_never_offered_on_the_ssh_agent_socket() {
    let lab = Lab::new();
    let blob = lab.rig.shared.key_with_purpose("confirmed").expect("key").blob;
    let mut conn = lab.rig.connect("/usr/bin/ssh-add");
    let mut list = vec![crate::agent::message::REQUEST_IDENTITIES];
    use std::io::Write;
    conn.write_all(&crate::agent::message::frame(list.remove(0), &[])).expect("write");
    let reply = crate::agent::message::read_message(&mut conn).expect("read").expect("reply");
    assert_eq!(&reply[1..], [0, 0, 0, 0], "no identities");
    // Even named, a signing request for it is refused (an SSHSIG in the approval namespace never is signed either).
    let data = crate::agent::testing::sshsig("git");
    let mut message = Vec::new();
    crate::agent::wire::put_string(&mut message, &blob);
    crate::agent::wire::put_string(&mut message, &data);
    message.extend_from_slice(&[0, 0, 0, 0]);
    conn.write_all(&crate::agent::message::frame(crate::agent::message::SIGN_REQUEST, &message)).expect("write");
    let reply = crate::agent::message::read_message(&mut conn).expect("read").expect("reply");
    assert_eq!(reply[0], crate::agent::message::FAILURE);
    assert_eq!(lab.rig.record()[0]["reason"], "key-not-offered");
}

#[test]
fn a_connection_may_have_sixteen_requests_open_and_the_seventeenth_ends_it() {
    let mut lab = Lab::with(json!({"max_waiting": 100}));
    let agent = lab.default_agent();
    let mut svc = lab.connect();
    for _ in 0..17 {
        lab.rig.dialogs.push(hold());
    }
    for i in 0..17 {
        let (request, sig) = lab.make(&agent, &[&format!("n={i}")], INTERNAL);
        svc.submit(&request, &sig);
    }
    // The seventeenth gets an `error` and the connection closes.
    let mut saw_error = false;
    for _ in 0..40 {
        match svc.lines.read_message(ClearancePolicy::Refused) {
            Ok(Some(Message::Error(e))) => {
                assert_eq!(e.error, p_act::exchange::ErrorCode::TooManyOpen);
                saw_error = true;
                break;
            }
            Ok(Some(_)) => {}
            _ => break,
        }
    }
    assert!(saw_error, "too-many-open");
}

#[test]
fn ceilings_pledge_cannot_read_are_unavailable_an_event_and_not_kept() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    let path = lab.rig.dir.path().join("delegations.json");
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).expect("read")).expect("json");
    file["delegations"][0]["ask"] = json!({"exposure": "everything", "damage": "none", "disruption": "none"});
    std::fs::write(&path, file.to_string()).expect("write");
    lab.rig.restart();
    let (request, sig) = lab.make(&agent, &[], Rating::HARMLESS);
    let mut svc = lab.connect();
    assert_eq!(refusal(&svc.ask(&request, &sig)), PledgeReason::Unavailable);
    assert!(lab.rig.record().iter().any(|e| e["event"] == "delegation-unusable"), "the person learns of it");
    assert!(
        lab.rig.shared.approvals.answers.answer(&request.hash().to_string(), now()).is_none(),
        "pledge's fault is not a verdict"
    );
}

// ---------------------------------------------------------------------------
// received, lost, and where a cancel becomes an expiry
// ---------------------------------------------------------------------------

fn types(lab: &Lab) -> Vec<(String, Option<String>)> {
    lab.rig
        .record()
        .iter()
        .filter(|e| e["type"] == "received" || e["type"] == "request")
        .map(|e| (e["type"].as_str().expect("type").to_owned(), e["result"].as_str().map(str::to_owned)))
        .collect()
}

#[test]
fn a_request_that_waits_is_recorded_when_it_arrives_and_answered_in_a_second_entry_and_one_answered_at_once_has_one() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    // At once (automatic): a single entry.
    let (request, sig) = lab.make(&agent, &[], Rating::HARMLESS);
    approval(&lab.connect().ask(&request, &sig));
    assert_eq!(types(&lab), [("request".to_owned(), Some("approved".to_owned()))]);
    // One that waits: `received` first, while the dialog is open; the answer names the same hash.
    lab.rig.dialogs.push(hold());
    let (request, sig) = lab.make(&agent, &["x"], INTERNAL);
    let mut svc = lab.connect();
    svc.submit(&request, &sig);
    thread::sleep(Duration::from_millis(400));
    let entries = lab.rig.record();
    let received = entries.iter().find(|e| e["type"] == "received").expect("received while waiting");
    assert_eq!(received["request_hash"], request.hash().to_string());
    assert_eq!((received["action"].as_str(), received["mode"].as_str()), (Some("rt procs"), Some("ask")));
    assert_eq!(types(&lab).len(), 2, "no answer yet");
    svc.cancel(&request);
    thread::sleep(Duration::from_millis(400));
    assert_eq!(
        types(&lab),
        [
            ("request".to_owned(), Some("approved".to_owned())),
            ("received".to_owned(), None),
            ("request".to_owned(), Some("cancelled".to_owned()))
        ]
    );
    assert_eq!(lab.entries()[1]["request_hash"], request.hash().to_string());
}

#[test]
fn no_record_no_dialog() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    let (request, sig) = lab.make(&agent, &[], INTERNAL);
    *lab.rig.shared.record.lock().expect("lock") = crate::record::Record::failing();
    assert_eq!(refusal(&lab.connect().ask(&request, &sig)), PledgeReason::Unavailable);
    assert_eq!(dialogs(&lab), 0, "the dialog was never shown");
}

#[test]
fn a_submitter_gone_three_seconds_before_the_deadline_cancels_one_gone_one_second_before_or_after_it_expires() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    let mut results = Vec::new();
    for (deadline_in, gone_after_ms) in [(4_i64, 300_u64), (4, 3000), (2, 3000)] {
        lab.rig.dialogs.push(hold());
        let (call, call_sig) = lab.call(&agent, &[], deadline_in);
        let (request, sig) = lab.request(&call, &call_sig, INTERNAL, "svc");
        let mut svc = lab.connect();
        svc.submit(&request, &sig);
        thread::sleep(Duration::from_millis(gone_after_ms));
        drop(svc); // the connection ends: the submitter is gone
        thread::sleep(Duration::from_millis(700));
        results.push(lab.entries().last().expect("entry")["result"].as_str().expect("result").to_owned());
    }
    // 3 s before: cancelled. 1 s before: expired. 1 s after (the deadline passed with the dialog open): expired.
    assert_eq!(results, ["cancelled", "expired", "expired"]);
}

#[test]
fn a_request_pledge_was_holding_when_it_went_down_is_recorded_lost_at_the_next_start() {
    let mut lab = Lab::new();
    let agent = lab.default_agent();
    lab.rig.dialogs.push(hold());
    lab.rig.dialogs.push(hold());
    let mut svc = lab.connect();
    let (first, first_sig) = lab.make(&agent, &["one"], INTERNAL);
    let (second, second_sig) = lab.make(&agent, &["two"], INTERNAL);
    svc.submit(&first, &first_sig);
    svc.submit(&second, &second_sig);
    thread::sleep(Duration::from_millis(500));
    lab.rig.restart();
    let entries = lab.rig.record();
    let lost: Vec<&Value> = entries.iter().filter(|e| e["result"] == "lost").collect();
    assert_eq!(lost.len(), 2, "{entries:?}");
    let hashes: Vec<&str> = lost.iter().filter_map(|e| e["request_hash"].as_str()).collect();
    assert!(
        hashes.contains(&first.hash().to_string().as_str()) && hashes.contains(&second.hash().to_string().as_str())
    );
    assert!(lost.iter().all(|e| e["received"].is_string() && e["last_entry_before_start"].is_string()));
    // Settled once: another start finds nothing more to settle.
    lab.rig.restart();
    assert_eq!(lab.rig.record().iter().filter(|e| e["result"] == "lost").count(), 2);
    drop(svc);
}
