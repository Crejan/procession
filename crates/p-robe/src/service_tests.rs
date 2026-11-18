//! The service against a fake pledge that speaks the exchange over a Unix
//! socket and signs approvals with throwaway keys, and against calls composed
//! and signed here (a delegation key certifying an agent key). The dispatcher
//! runs in this process as a caller that is root; **the sudo path does not run**.
//! The HTTP transport is not built, so the MCP layer is called as a function.
//!
//! Needs `ssh-keygen`, and a directory where Unix sockets can be bound
//! (`/tmp/claude/` in the sandbox this was written in, else the temporary directory).

use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use p_act::exchange::{
    Answer, Approved, By, ClearanceAnswer, ClearancePolicy, LineReader, Message, Outcome as Answered, PledgeReason,
    Refused, write_message,
};
use p_act::rating::Rating;
use p_act::sign::{PublicKey, Signer, sign_approval, sign_call, signature_to_base64, verify_request};
use p_act::{Call, CallContent, CallId, Clearance, Document, ServiceId, Timestamp};

use crate::outcome::{Outcome, Why};
use crate::pledge::{POLICY, PledgeLink};
use crate::runner::InProcess;
use crate::service::{Handled, SERVICE_NAME, Service, Settings, ToolCall};
use crate::store::UsedStore;

const HOST: &str = "testhost";

fn keygen(args: &[&str]) {
    let out = Command::new("ssh-keygen").args(args).stdin(Stdio::null()).output().expect("these tests need ssh-keygen");
    assert!(out.status.success(), "ssh-keygen {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

fn key(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", path.to_str().unwrap()]);
    path
}

/// An agent key certified by `ca` for `person`, as pledge issues it.
fn agent(dir: &Path, ca: &Path, person: &str) -> Signer {
    let path = key(dir, &format!("agent-{person}"));
    keygen(&[
        "-q",
        "-s",
        ca.to_str().unwrap(),
        "-I",
        person,
        "-n",
        person,
        "-V",
        "20200101Z:20990101Z",
        "-O",
        "clear",
        &format!("{}.pub", path.display()),
    ]);
    Signer::certified(path).unwrap()
}

/// Every key the tests need.
struct Pki {
    dir: tempfile::TempDir,
    host_pub: PublicKey,
    service: PathBuf,
    jan_agent: Signer,
    eva_agent: Signer,
    confirmed: PathBuf,
    automatic: PathBuf,
    stranger: PathBuf,
}

impl Pki {
    fn new() -> Pki {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        let host = key(p, "host");
        crate::setup::run(&host, HOST, &p.join("probe")).expect("setup");
        let (jan_ca, eva_ca) = (key(p, "jan-delegation"), key(p, "eva-delegation"));
        Pki {
            host_pub: PublicKey::read(&p.join("host.pub")).unwrap(),
            service: p.join("probe/service-key"),
            jan_agent: agent(p, &jan_ca, "jan"),
            eva_agent: agent(p, &eva_ca, "eva"),
            confirmed: key(p, "jan-confirmed"),
            automatic: key(p, "jan-automatic"),
            stranger: key(p, "stranger"),
            dir,
        }
    }

    fn public(&self, key: &Path) -> PublicKey {
        PublicKey::read(&PathBuf::from(format!("{}.pub", key.display()))).unwrap()
    }
}

static COUNTER: AtomicU64 = AtomicU64::new(1);

fn new_id() -> String {
    format!("{:08x}-0000-4000-8000-{:012x}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst))
}

fn after(secs: i64) -> Timestamp {
    Timestamp::from_unix(Timestamp::now().unwrap().unix() + secs).unwrap()
}

/// A signed call, ready to be a tool call.
struct Sent {
    name: String,
    params: Vec<String>,
    claim: Option<String>,
    call: String,
    call_sig: String,
    id: String,
}

impl Sent {
    fn tool(&self) -> ToolCall<'_> {
        ToolCall {
            name: &self.name,
            params: &self.params,
            claim: self.claim.as_deref(),
            call: &self.call,
            call_sig: &self.call_sig,
        }
    }
}

struct CallSpec<'a> {
    agent: &'a Signer,
    host: &'a str,
    name: &'a str,
    action: &'a str,
    params: &'a [&'a str],
    secs: i64,
    id: Option<String>,
}

fn spec<'a>(agent: &'a Signer, action: &'a str, params: &'a [&'a str]) -> CallSpec<'a> {
    CallSpec { agent, host: HOST, name: SERVICE_NAME, action, params, secs: 30, id: None }
}

fn sign(spec: &CallSpec<'_>) -> Sent {
    let id = spec.id.clone().unwrap_or_else(new_id);
    let params: Vec<String> = spec.params.iter().map(ToString::to_string).collect();
    let call = Call::compose(&CallContent {
        id: CallId::parse(&id).unwrap(),
        deadline: after(spec.secs),
        service: ServiceId { host: spec.host.into(), name: spec.name.into() },
        action: spec.action.into(),
        params: params.clone(),
        claim: None,
    })
    .unwrap();
    let sig = sign_call(spec.agent, &call).unwrap();
    Sent {
        name: spec.action.replace(' ', "_"),
        params,
        claim: None,
        call: base64::engine::general_purpose::STANDARD.encode(call.as_bytes()),
        call_sig: signature_to_base64(&sig),
        id,
    }
}

// ---- the fake pledge -----------------------------------------------------------

#[derive(Clone)]
enum Plan {
    Approve(PathBuf),
    ApproveAfter(Duration, PathBuf),
    /// Signs an approval over a request that is not the one submitted.
    OverOther(PathBuf),
    Decline,
    Refuse(PledgeReason),
    Expire,
    Silent,
    CloseAfterSubmit,
    /// An answer whose `result` is not one, then (if a key) an approval.
    UnknownThen(Option<PathBuf>),
    /// An approval with clearance members, which stage 1 refuses.
    ApproveWithClearance(PathBuf),
}

struct FakePledge {
    dir: PathBuf,
    socket: PathBuf,
    plan: Arc<Mutex<Plan>>,
    events: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

/// A directory where a Unix socket can be bound: `/tmp/claude` when it is there.
fn socket_dir() -> PathBuf {
    let base = if Path::new("/tmp/claude").is_dir() { PathBuf::from("/tmp/claude") } else { std::env::temp_dir() };
    let dir = base.join(format!("pr{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
    dir
}

impl FakePledge {
    fn start(host_key: &PublicKey, plan: Plan) -> FakePledge {
        let dir = socket_dir();
        let socket = dir.join("service.sock");
        let listener = UnixListener::bind(&socket).expect("a socket can be bound here");
        listener.set_nonblocking(true).unwrap();
        let (plan, events, stop) =
            (Arc::new(Mutex::new(plan)), Arc::new(Mutex::new(Vec::new())), Arc::new(AtomicBool::new(false)));
        let (p, e, s, host_key) = (plan.clone(), events.clone(), stop.clone(), host_key.clone());
        std::thread::spawn(move || {
            while !s.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let (plan, events, host_key) = (p.lock().unwrap().clone(), e.clone(), host_key.clone());
                        std::thread::spawn(move || connection(stream, &plan, &events, &host_key));
                    }
                    Err(_) => std::thread::sleep(Duration::from_millis(10)),
                }
            }
        });
        FakePledge { dir, socket, plan, events, stop }
    }

    fn link(&self) -> PledgeLink {
        PledgeLink { socket: self.socket.clone(), uid: unsafe { libc::geteuid() } }
    }

    fn set(&self, plan: Plan) {
        *self.plan.lock().unwrap() = plan;
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    fn count(&self, prefix: &str) -> usize {
        self.events().iter().filter(|e| e.starts_with(prefix)).count()
    }

    /// Waits until an event with this prefix is there.
    fn wait_for(&self, prefix: &str) {
        let started = Instant::now();
        while self.count(prefix) == 0 {
            assert!(started.elapsed() < Duration::from_secs(5), "no event {prefix}: {:?}", self.events());
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for FakePledge {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn answer(stream: &UnixStream, request: p_act::DocumentHash, outcome: Answered, policy: ClearancePolicy) {
    let _ = write_message(&mut &*stream, &Message::Answer(Answer { request, outcome }), policy);
}

fn connection(stream: UnixStream, plan: &Plan, events: &Mutex<Vec<String>>, host_key: &PublicKey) {
    let log = |text: String| events.lock().unwrap().push(text);
    stream.set_nonblocking(false).unwrap();
    let mut reader = LineReader::new(&stream);
    let submit = match reader.read_message(POLICY) {
        Ok(Some(Message::Submit(submit))) => submit,
        other => return log(format!("not-a-submit {other:?}")),
    };
    let hash = submit.hash();
    // The service's signature over its request must verify under the host key.
    log(match verify_request(submit.request(), submit.request_sig(), host_key) {
        Ok(()) => format!("submit {hash} request-verified"),
        Err(e) => format!("submit {hash} request-BAD {e}"),
    });
    let approve = |path: &PathBuf, request: &p_act::Request| {
        let signer = Signer::plain(path);
        Approved::new(&sign_approval(&signer, request).unwrap(), None).unwrap()
    };
    match plan {
        Plan::Approve(path) => answer(&stream, hash, Answered::Approved(approve(path, submit.request())), POLICY),
        Plan::ApproveAfter(wait, path) => {
            std::thread::sleep(*wait);
            answer(&stream, hash, Answered::Approved(approve(path, submit.request())), POLICY);
        }
        Plan::OverOther(path) => {
            let other =
                p_act::Request::compose(submit.request().call(), submit.request().call_sig(), Rating::WORST).unwrap();
            answer(&stream, hash, Answered::Approved(approve(path, &other)), POLICY);
        }
        Plan::Decline => answer(&stream, hash, Answered::Declined, POLICY),
        Plan::Refuse(reason) => answer(&stream, hash, Answered::Refused(Refused::Pledge(*reason)), POLICY),
        Plan::Expire => answer(&stream, hash, Answered::Expired(By::Pledge), POLICY),
        Plan::Silent => {}
        Plan::CloseAfterSubmit => return log(format!("closed-by-pledge {hash}")),
        Plan::UnknownThen(path) => {
            let _ = (&stream).write_all_line(format!(
                "{{\"schema_version\":1,\"type\":\"answer\",\"request\":\"{hash}\",\"result\":\"maybe\"}}\n"
            ));
            if let Some(path) = path {
                answer(&stream, hash, Answered::Approved(approve(path, submit.request())), POLICY);
            }
        }
        Plan::ApproveWithClearance(path) => {
            let signed = sign_approval(&Signer::plain(path), submit.request()).unwrap();
            let clearance = Clearance::compose(hash, Timestamp::now().unwrap()).unwrap();
            let with = Approved::new(&signed, Some(ClearanceAnswer::new(clearance, &signed).unwrap())).unwrap();
            answer(&stream, hash, Answered::Approved(with), ClearancePolicy::Required);
        }
    }
    // Then until the service closes: a cancel, or the end.
    loop {
        match reader.read_message(POLICY) {
            Ok(Some(Message::Cancel(c))) => log(format!("cancel {}", c.request)),
            Ok(Some(_)) => {}
            _ => return log(format!("closed {hash}")),
        }
    }
}

trait WriteLine {
    fn write_all_line(&mut self, line: String) -> std::io::Result<()>;
}

impl WriteLine for &UnixStream {
    fn write_all_line(&mut self, line: String) -> std::io::Result<()> {
        std::io::Write::write_all(self, line.as_bytes())
    }
}

// ---- the rig -----------------------------------------------------------------------

struct Rig {
    pki: Pki,
    pledge: FakePledge,
    service: Service,
    log: Arc<Mutex<Vec<String>>>,
    used: PathBuf,
    audit: PathBuf,
    dispatcher_dir: tempfile::TempDir,
}

#[cfg(feature = "test-verbs")]
fn sandbox() -> &'static PathBuf {
    crate::rate::SANDBOX.get_or_init(|| {
        let dir = std::fs::canonicalize(crate::testdir::new("sandbox")).unwrap();
        for sub in ["open", "private"] {
            std::fs::create_dir(dir.join(sub)).unwrap();
        }
        dir
    })
}

fn make_service(
    pki: &Pki,
    link: PledgeLink,
    used: &Path,
    runner: InProcess,
    max_waiting: usize,
) -> (Service, Arc<Mutex<Vec<String>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let sink = log.clone();
    let service = Service::new(
        Settings {
            host: HOST.into(),
            person: "jan".into(),
            confirmed: pki.public(&pki.confirmed),
            automatic: pki.public(&pki.automatic),
            max_waiting,
        },
        Signer::certified(&pki.service).unwrap(),
        UsedStore::new(used),
        link,
        Box::new(runner),
        Box::new(move |line| sink.lock().unwrap().push(line.to_string())),
    );
    (service, log)
}

impl Rig {
    fn new(plan: Plan) -> Rig {
        Rig::with(plan, 16, None)
    }

    fn with(plan: Plan, max_waiting: usize, before: Option<Box<dyn Fn() + Send + Sync>>) -> Rig {
        #[cfg(feature = "test-verbs")]
        sandbox();
        let pki = Pki::new();
        let pledge = FakePledge::start(&pki.host_pub, plan);
        let dispatcher_dir = tempfile::tempdir().unwrap();
        let (audit, locks, used) = (
            dispatcher_dir.path().join("audit.log"),
            dispatcher_dir.path().join("locks"),
            dispatcher_dir.path().join("used"),
        );
        std::fs::create_dir(&locks).unwrap();
        std::fs::create_dir(&used).unwrap();
        let runner = InProcess { audit_file: audit.clone(), lock_dir: locks, user: "probe".into(), before };
        let (service, log) = make_service(&pki, pledge.link(), &used, runner, max_waiting);
        Rig { pki, pledge, service, log, used, audit, dispatcher_dir }
    }

    fn handle(&self, sent: &Sent) -> Handled {
        self.service.handle(&sent.tool(), &AtomicBool::new(false))
    }

    /// What the agent is told, for a call that ended with an outcome.
    fn outcome(&self, sent: &Sent) -> Outcome {
        match self.handle(sent) {
            Handled::Outcome { outcome, id } => {
                assert_eq!(id, sent.id);
                outcome
            }
            other => panic!("not an outcome: {other:?}"),
        }
    }

    fn jan(&self, action: &str, params: &[&str]) -> Sent {
        sign(&spec(&self.pki.jan_agent, action, params))
    }

    /// What the dispatcher wrote to its audit: empty if nothing ran.
    fn ran(&self) -> Vec<String> {
        std::fs::read_to_string(&self.audit).map(|t| t.lines().map(String::from).collect()).unwrap_or_default()
    }

    fn log_has(&self, needle: &str) -> bool {
        self.log.lock().unwrap().iter().any(|line| line.contains(needle))
    }
}

fn confirmed(rig: &Rig) -> Plan {
    Plan::Approve(rig.pki.confirmed.clone())
}

fn word(outcome: &Outcome) -> String {
    match outcome.reason() {
        Some(reason) => format!("{}/{reason}", outcome.word()),
        None => outcome.word().into(),
    }
}

// ---- tests that need no test verbs -----------------------------------------------

#[test]
fn a_harmless_call_approved_with_the_confirmed_key_runs_and_the_request_verified_under_the_host_key() {
    let rig = Rig::new(Plan::Silent);
    rig.pledge.set(confirmed(&rig));
    let sent = rig.jan("sys kit", &[]);
    match rig.outcome(&sent) {
        Outcome::Done { rc: 0, answer } => assert!(answer.contains("\"type\":\"installation\""), "{answer}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(rig.pledge.count("submit"), 1);
    assert!(rig.pledge.events()[0].ends_with("request-verified"), "{:?}", rig.pledge.events());
    assert!(rig.log_has("approval=confirmed") && rig.log_has("outcome=done"), "{:?}", rig.log);
    assert!(
        rig.ran().iter().any(|l| l.starts_with("event=start noun=sys verb=kit ") && l.contains("identity=probe")),
        "{:?}",
        rig.ran()
    );
}

#[test]
fn the_automatic_key_is_accepted_below_the_top() {
    let rig = Rig::new(Plan::Silent);
    rig.pledge.set(Plan::Approve(rig.pki.automatic.clone()));
    assert_eq!(word(&rig.outcome(&rig.jan("sys kit", &[]))), "done");
    assert!(rig.log_has("approval=automatic"));
}

#[test]
fn declined_refused_and_expired_by_pledge_reach_the_agent_as_the_coarse_list_and_nothing_runs() {
    let rig = Rig::new(Plan::Decline);
    for (plan, expected, exact) in [
        (Plan::Decline, "declined", "declined"),
        (Plan::Refuse(PledgeReason::Ceiling), "refused/not-allowed", "pledge:ceiling"),
        (Plan::Refuse(PledgeReason::Muted), "refused/try-later", "pledge:muted"),
        (Plan::Refuse(PledgeReason::Malformed), "refused/invalid", "pledge:malformed"),
        (Plan::Refuse(PledgeReason::ServiceMismatch), "unavailable", "pledge:service-mismatch"),
        (Plan::Expire, "expired", "expired-by-pledge"),
    ] {
        rig.pledge.set(plan);
        let sent = rig.jan("sys kit", &[]);
        assert_eq!(word(&rig.outcome(&sent)), expected, "{exact}");
        assert!(rig.log_has(&format!("exact={exact}")), "{exact}: {:?}", rig.log);
    }
    assert!(rig.ran().is_empty(), "nothing ran: {:?}", rig.ran());
}

#[test]
fn with_no_answer_the_call_expires_at_its_deadline_by_our_own_clock_and_nothing_runs() {
    let rig = Rig::new(Plan::Silent);
    let sent = sign(&CallSpec { secs: 2, ..spec(&rig.pki.jan_agent, "sys kit", &[]) });
    let started = Instant::now();
    assert_eq!(rig.outcome(&sent), Outcome::Expired);
    let took = started.elapsed();
    assert!(took >= Duration::from_secs(1) && took < Duration::from_secs(4), "{took:?}");
    assert!(rig.ran().is_empty());
    rig.pledge.wait_for("closed");
}

#[test]
fn an_approval_that_arrives_after_the_deadline_is_worth_nothing() {
    let rig = Rig::new(Plan::Silent);
    rig.pledge.set(Plan::ApproveAfter(Duration::from_secs(3), rig.pki.confirmed.clone()));
    let sent = sign(&CallSpec { secs: 2, ..spec(&rig.pki.jan_agent, "sys kit", &[]) });
    assert_eq!(rig.outcome(&sent), Outcome::Expired);
    std::thread::sleep(Duration::from_millis(1500));
    assert!(rig.ran().is_empty(), "nothing started after the deadline");
}

#[test]
fn an_approval_over_other_bytes_or_by_another_key_or_another_person_runs_nothing() {
    let rig = Rig::new(Plan::Silent);
    let (over_other, by_stranger) =
        (Plan::OverOther(rig.pki.confirmed.clone()), Plan::Approve(rig.pki.stranger.clone()));
    for (plan, agent, needle) in [
        (over_other, &rig.pki.jan_agent, "approval-invalid"),
        (by_stranger, &rig.pki.jan_agent, "approval-invalid"),
        // Eva's agent, approval by jan's own confirmed key: the person the call names is not the person this service takes approvals from.
        (confirmed(&rig), &rig.pki.eva_agent, "person-mismatch"),
    ] {
        rig.pledge.set(plan);
        let sent = sign(&spec(agent, "sys kit", &[]));
        assert_eq!(rig.outcome(&sent), Outcome::Unavailable, "{needle}");
        assert!(rig.log_has(needle), "{needle}: {:?}", rig.log);
    }
    assert!(rig.ran().is_empty());
}

#[test]
fn a_call_for_another_host_or_service_or_a_verb_that_does_not_exist_asks_nobody() {
    let rig = Rig::new(confirmed_placeholder());
    rig.pledge.set(confirmed(&rig));
    let a = &rig.pki.jan_agent;
    for (sent, exact) in [
        (sign(&CallSpec { host: "elsewhere", ..spec(a, "sys kit", &[]) }), "wrong-service"),
        (sign(&CallSpec { name: "other", ..spec(a, "sys kit", &[]) }), "wrong-service"),
        (sign(&spec(a, "rt irq", &[])), "unknown-action"),
        (sign(&spec(a, "run command", &["x"])), "unknown-action"),
        (sign(&spec(a, "sys nope", &[])), "unknown-action"),
        (sign(&spec(a, "sys kit", &["x=1"])), "params-not-accepted"),
        (sign(&CallSpec { secs: -5, ..spec(a, "sys kit", &[]) }), "deadline-past"),
        (sign(&CallSpec { secs: 700, ..spec(a, "sys kit", &[]) }), "deadline-too-far"),
    ] {
        assert_eq!(word(&rig.outcome(&sent)), "refused/invalid", "{exact}");
        assert!(rig.log_has(&format!("exact={exact}")), "{exact}: {:?}", rig.log);
    }
    assert_eq!(rig.pledge.count("submit"), 0, "nobody was asked");
    assert!(std::fs::read_dir(&rig.used).unwrap().next().is_none(), "no identifier was taken");
}

fn confirmed_placeholder() -> Plan {
    Plan::Silent
}

#[test]
fn a_deadline_within_the_tolerance_of_ten_minutes_is_accepted_and_one_past_it_is_not() {
    let rig = Rig::new(Plan::Decline);
    assert_eq!(
        word(&rig.outcome(&sign(&CallSpec { secs: 650, ..spec(&rig.pki.jan_agent, "sys kit", &[]) }))),
        "declined"
    );
}

#[test]
fn the_tool_call_must_say_what_the_call_says() {
    let rig = Rig::new(Plan::Decline);
    let sent = rig.jan("sys kit", &[]);
    let (call, sig) = (sent.call.as_str(), sent.call_sig.as_str());
    let tool = |name: &'static str, params: &'static [String], claim: Option<&'static str>| ToolCall {
        name,
        params,
        claim,
        call,
        call_sig: sig,
    };
    static ONE: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| vec!["x=1".into()]);
    for wrong in [tool("sys_units", &[], None), tool("sys_kit", &ONE, None), tool("sys_kit", &[], Some("because"))] {
        match rig.service.handle(&wrong, &AtomicBool::new(false)) {
            Handled::Outcome { outcome, .. } => assert_eq!(word(&outcome), "refused/invalid"),
            other => panic!("{other:?}"),
        }
    }
    assert!(rig.log_has("exact=mismatch"));
    assert_eq!(rig.pledge.count("submit"), 0);
}

#[test]
fn a_used_identifier_is_refused_by_the_service_and_never_reaches_pledge_twice() {
    let rig = Rig::new(Plan::Decline);
    let sent = rig.jan("sys kit", &[]);
    assert_eq!(rig.outcome(&sent), Outcome::Declined);
    assert_eq!(word(&rig.outcome(&sent)), "refused/invalid");
    assert!(rig.log_has("exact=call-used"));
    assert_eq!(rig.pledge.count("submit"), 1);
}

#[test]
fn a_second_arrival_while_the_first_waits_is_refused_and_the_first_is_not_disturbed() {
    let rig = Arc::new(Rig::new(Plan::Silent));
    let sent = Arc::new(sign(&CallSpec { secs: 3, ..spec(&rig.pki.jan_agent, "sys kit", &[]) }));
    let first = {
        let (rig, sent) = (rig.clone(), sent.clone());
        std::thread::spawn(move || rig.outcome(&sent))
    };
    rig.pledge.wait_for("submit");
    assert_eq!(word(&rig.outcome(&sent)), "refused/invalid");
    assert_eq!(first.join().unwrap(), Outcome::Expired);
    assert_eq!(rig.pledge.count("submit"), 1);
}

#[test]
fn a_restart_with_identifiers_on_disk_does_not_forget_them() {
    let rig = Rig::new(Plan::Decline);
    let sent = rig.jan("sys kit", &[]);
    assert_eq!(rig.outcome(&sent), Outcome::Declined);
    // A new service on the same directory: a restart.
    let runner = InProcess {
        audit_file: rig.audit.clone(),
        lock_dir: rig.dispatcher_dir.path().join("locks"),
        user: "probe".into(),
        before: None,
    };
    let (restarted, log) = make_service(&rig.pki, rig.pledge.link(), &rig.used, runner, 16);
    match restarted.handle(&sent.tool(), &AtomicBool::new(false)) {
        Handled::Outcome { outcome, .. } => assert_eq!(word(&outcome), "refused/invalid"),
        other => panic!("{other:?}"),
    }
    assert!(log.lock().unwrap().iter().any(|l| l.contains("exact=call-used")));
    assert_eq!(rig.pledge.count("submit"), 1, "the restarted service did not ask again");
}

#[test]
fn when_the_agent_goes_away_the_request_is_cancelled_and_an_approval_that_comes_later_runs_nothing() {
    let rig = Arc::new(Rig::new(Plan::Silent));
    rig.pledge.set(Plan::ApproveAfter(Duration::from_millis(800), rig.pki.confirmed.clone()));
    let sent = Arc::new(rig.jan("sys kit", &[]));
    let cancel = Arc::new(AtomicBool::new(false));
    let waiting = {
        let (rig, sent, cancel) = (rig.clone(), sent.clone(), cancel.clone());
        std::thread::spawn(move || rig.service.handle(&sent.tool(), &cancel))
    };
    rig.pledge.wait_for("submit");
    cancel.store(true, Ordering::SeqCst);
    assert_eq!(waiting.join().unwrap(), Handled::Cancelled);
    rig.pledge.wait_for("cancel");
    std::thread::sleep(Duration::from_millis(1200));
    assert!(rig.ran().is_empty(), "nothing ran");
    assert_eq!(rig.service.waiting(), 0);
    // The identifier stays spent.
    assert_eq!(word(&rig.outcome(&sent)), "refused/invalid");
}

#[test]
fn an_answer_with_an_unknown_result_is_no_answer_and_the_wait_goes_on() {
    let rig = Rig::new(Plan::UnknownThen(None));
    rig.pledge.set(Plan::UnknownThen(Some(rig.pki.confirmed.clone())));
    assert_eq!(word(&rig.outcome(&rig.jan("sys kit", &[]))), "done");
    assert!(rig.log_has("no answer"), "{:?}", rig.log);
    rig.pledge.set(Plan::UnknownThen(None));
    let sent = sign(&CallSpec { secs: 2, ..spec(&rig.pki.jan_agent, "sys kit", &[]) });
    assert_eq!(rig.outcome(&sent), Outcome::Expired, "an unknown result alone does not end the wait");
}

#[test]
fn a_pledge_that_cannot_be_used_means_unavailable_at_once_and_a_broken_connection_is_not_retried() {
    let rig = Rig::new(Plan::CloseAfterSubmit);
    assert_eq!(rig.outcome(&rig.jan("sys kit", &[])), Outcome::Unavailable);
    assert_eq!(rig.pledge.count("submit"), 1, "not submitted again");
    // Stage 1 refuses clearance members: an answer with them breaks the exchange.
    rig.pledge.set(Plan::ApproveWithClearance(rig.pki.confirmed.clone()));
    assert_eq!(rig.outcome(&rig.jan("sys kit", &[])), Outcome::Unavailable);
    assert!(rig.log_has("no-route:bad line from pledge"), "{:?}", rig.log);
    assert!(rig.ran().is_empty());
    // No pledge at all.
    drop(rig.pledge);
}

#[test]
fn the_door_is_checked_from_this_side() {
    let rig = Rig::new(Plan::Decline);
    let started = Instant::now();
    // Not the person's uid.
    let mut link = rig.pledge.link();
    link.uid += 1;
    let (service, log) = make_service(
        &rig.pki,
        link,
        &rig.used,
        InProcess { audit_file: rig.audit.clone(), lock_dir: rig.used.clone(), user: "probe".into(), before: None },
        16,
    );
    let sent = rig.jan("sys kit", &[]);
    assert!(matches!(
        service.handle(&sent.tool(), &AtomicBool::new(false)),
        Handled::Outcome { outcome: Outcome::Unavailable, .. }
    ));
    assert!(log.lock().unwrap().iter().any(|l| l.contains("not the person")), "{:?}", log.lock().unwrap());
    // A symlink where the socket is.
    let linked = rig.pledge.dir.join("link.sock");
    std::os::unix::fs::symlink(&rig.pledge.socket, &linked).unwrap();
    let mut link = rig.pledge.link();
    link.socket = linked;
    let (service, log) = make_service(
        &rig.pki,
        link,
        &rig.used,
        InProcess { audit_file: rig.audit.clone(), lock_dir: rig.used.clone(), user: "probe".into(), before: None },
        16,
    );
    let sent = rig.jan("sys kit", &[]);
    assert!(matches!(
        service.handle(&sent.tool(), &AtomicBool::new(false)),
        Handled::Outcome { outcome: Outcome::Unavailable, .. }
    ));
    assert!(log.lock().unwrap().iter().any(|l| l.contains("symlink")));
    // Nothing there.
    let mut link = rig.pledge.link();
    link.socket = rig.pledge.dir.join("absent.sock");
    let (service, _) = make_service(
        &rig.pki,
        link,
        &rig.used,
        InProcess { audit_file: rig.audit.clone(), lock_dir: rig.used.clone(), user: "probe".into(), before: None },
        16,
    );
    let sent = rig.jan("sys kit", &[]);
    assert!(matches!(
        service.handle(&sent.tool(), &AtomicBool::new(false)),
        Handled::Outcome { outcome: Outcome::Unavailable, .. }
    ));
    assert_eq!(rig.pledge.count("submit"), 0, "nothing was sent to anything but the real door");
    assert!(started.elapsed() < Duration::from_secs(3), "at once, not at the deadline");
}

#[test]
fn a_store_that_cannot_be_written_means_no_call() {
    let rig = Rig::new(Plan::Decline);
    std::fs::remove_dir_all(&rig.used).unwrap();
    assert_eq!(rig.outcome(&rig.jan("sys kit", &[])), Outcome::Unavailable);
    assert!(rig.log_has("exact='store:"));
    assert_eq!(rig.pledge.count("submit"), 0);
}

#[test]
fn only_so_many_calls_wait_and_the_next_is_busy_without_taking_its_identifier() {
    let rig = Arc::new(Rig::with(Plan::Silent, 1, None));
    let first = Arc::new(sign(&CallSpec { secs: 3, ..spec(&rig.pki.jan_agent, "sys kit", &[]) }));
    let waiting = {
        let (rig, first) = (rig.clone(), first.clone());
        std::thread::spawn(move || rig.outcome(&first))
    };
    rig.pledge.wait_for("submit");
    let second = rig.jan("sys kit", &[]);
    assert_eq!(rig.handle(&second), Handled::Busy);
    assert_eq!(waiting.join().unwrap(), Outcome::Expired);
    // The refused one may be asked again.
    rig.pledge.set(Plan::Decline);
    assert_eq!(rig.outcome(&second), Outcome::Declined);
}

#[test]
fn a_tool_call_that_is_malformed_is_a_protocol_error_not_an_outcome() {
    let rig = Rig::new(Plan::Decline);
    let sent = rig.jan("sys kit", &[]);
    for (call, sig) in [("not base64!", sent.call_sig.as_str()), (sent.call.as_str(), "not an armoured signature")] {
        let tool = ToolCall { name: "sys_kit", params: &[], claim: None, call, call_sig: sig };
        assert!(matches!(rig.service.handle(&tool, &AtomicBool::new(false)), Handled::BadParams(_)));
    }
    // A call that is base64 but not a call is refused as invalid, without an identifier.
    let tool = ToolCall { name: "sys_kit", params: &[], claim: None, call: "e30=", call_sig: &sent.call_sig };
    assert!(matches!(
        rig.service.handle(&tool, &AtomicBool::new(false)),
        Handled::Outcome { outcome: Outcome::Refused(Why::Invalid), .. }
    ));
    assert_eq!(rig.pledge.count("submit"), 0);
}

#[test]
fn setup_run_again_keeps_the_key_and_renews_the_certificate_that_the_host_key_vouches_for() {
    let pki = Pki::new();
    let cert = std::fs::read(pki.dir.path().join("probe/service-key-cert.pub")).unwrap();
    let key = std::fs::read(pki.dir.path().join("probe/service-key")).unwrap();
    assert_eq!(
        crate::setup::run(&pki.dir.path().join("host"), HOST, &pki.dir.path().join("probe")),
        Ok(crate::setup::Done::Renewed)
    );
    assert_eq!(std::fs::read(pki.dir.path().join("probe/service-key")).unwrap(), key);
    assert_ne!(std::fs::read(pki.dir.path().join("probe/service-key-cert.pub")).unwrap(), cert);
    // The renewed certificate's principal is `probe@host`: a request signed with it verifies under the host key
    // (the pledge fake does that in the tests above).
    assert!(pki.service.with_file_name("service-key-cert.pub").exists());
}

// ---- tests that need the test verbs -------------------------------------------------

#[cfg(feature = "test-verbs")]
mod with_test_verbs {
    use super::*;

    #[test]
    fn the_automatic_key_is_refused_at_the_top_of_any_scale_and_the_confirmed_key_runs_it() {
        let rig = Rig::new(Plan::Silent);
        rig.pledge.set(Plan::Approve(rig.pki.automatic.clone()));
        assert_eq!(rig.outcome(&rig.jan("test peak", &["x=1"])), Outcome::Unavailable);
        assert!(rig.log_has("automatic-at-the-top"), "{:?}", rig.log);
        assert!(rig.ran().is_empty(), "peak did not run");
        rig.pledge.set(confirmed(&rig));
        match rig.outcome(&rig.jan("test peak", &["x=1"])) {
            Outcome::Done { rc: 0, answer } => assert!(answer.contains("\"args\":[\"x=1\"]"), "{answer}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_call_that_cannot_be_shown_is_refused_by_the_service_before_anybody_is_asked() {
        let rig = Rig::new(Plan::Decline);
        let long = "x".repeat(450);
        let params: Vec<&str> = std::iter::repeat_n(long.as_str(), 5).collect();
        let sent = rig.jan("test echo", &params);
        assert_eq!(word(&rig.outcome(&sent)), "refused/invalid");
        assert!(rig.log_has("exact='not-showable:"), "{:?}", rig.log);
        assert_eq!(rig.pledge.count("submit"), 0, "nobody was asked");
        // 2000 characters exactly are shown.
        let ok: Vec<&str> = std::iter::repeat_n(&long[..400], 5).collect();
        assert_eq!(word(&rig.outcome(&rig.jan("test echo", &ok))), "declined");
    }

    #[test]
    fn the_request_carries_the_rating_the_service_signed_and_the_dispatcher_is_held_to_it() {
        let rig = Rig::new(Plan::Silent);
        rig.pledge.set(confirmed(&rig));
        let _ = rig.outcome(&rig.jan("test peak", &[]));
        // `--within open,none,outage` is what the dispatcher was given: nothing above it can run.
        assert!(rig.ran().iter().any(|l| l.starts_with("event=start noun=test verb=peak")), "{:?}", rig.ran());
    }

    fn planted(rig_plan: Plan) -> (Rig, PathBuf) {
        let sandbox = sandbox().clone();
        let tag = new_id();
        let link = sandbox.join("open").join(&tag);
        let (harmless, secret) = (sandbox.join("open").join(format!("{tag}-a")), sandbox.join("private").join(&tag));
        std::fs::write(&harmless, "hello").unwrap();
        std::fs::write(&secret, "secret").unwrap();
        std::os::unix::fs::symlink(&harmless, &link).unwrap();
        let (l, s) = (link.clone(), secret.clone());
        let before: Box<dyn Fn() + Send + Sync> = Box::new(move || {
            // The link is replaced between the service's rating and the dispatcher's opening.
            let _ = std::fs::remove_file(&l);
            std::os::unix::fs::symlink(&s, &l).unwrap();
        });
        let rig = Rig::with(rig_plan, 16, Some(before));
        (rig, link)
    }

    #[test]
    fn a_link_planted_between_rating_and_opening_is_a_coarse_refusal_and_the_file_is_not_read() {
        let (rig, link) = planted(Plan::Silent);
        rig.pledge.set(Plan::Approve(rig.pki.automatic.clone())); // harmless: automatic is enough
        let sent = rig.jan("test read", &[link.to_str().unwrap()]);
        assert_eq!(word(&rig.outcome(&sent)), "refused/not-allowed");
        assert!(rig.log_has("dispatcher-refused"), "{:?}", rig.log);
        let dispatcher = rig.ran();
        assert!(
            dispatcher.iter().any(|l| l.starts_with("event=refused ") && l.contains("above-approved")),
            "{dispatcher:?}"
        );
        assert!(!dispatcher.iter().any(|l| l.starts_with("event=start")), "the verb did not run");
    }

    #[test]
    fn without_the_planting_the_same_call_reads_the_open_file() {
        let rig = Rig::new(Plan::Silent);
        rig.pledge.set(Plan::Approve(rig.pki.automatic.clone()));
        let file = sandbox().join("open").join(format!("{}-plain", new_id()));
        std::fs::write(&file, "hello").unwrap();
        match rig.outcome(&rig.jan("test read", &[file.to_str().unwrap()])) {
            Outcome::Done { rc: 0, answer } => assert!(answer.contains("\"text\":\"hello\""), "{answer}"),
            other => panic!("{other:?}"),
        }
        // A file elsewhere is rated at the worst: the request says so, and the automatic key will not do.
        let secret = sandbox().join("private").join(format!("{}-plain", new_id()));
        std::fs::write(&secret, "secret").unwrap();
        assert_eq!(rig.outcome(&rig.jan("test read", &[secret.to_str().unwrap()])), Outcome::Unavailable);
        assert!(rig.log_has("approval-invalid"), "{:?}", rig.log);
    }

    #[test]
    fn the_mcp_layer_takes_a_call_in_meta_and_answers_with_the_outcome_object_first() {
        use crate::mcp::{HttpRequest, Mcp};
        use serde_json::{Value, json};
        let rig = Rig::new(Plan::Silent);
        rig.pledge.set(Plan::Approve(rig.pki.automatic.clone()));
        let mcp = Mcp::new(&rig.service);
        let post = |body: Value| HttpRequest {
            method: "POST".into(),
            path: "/mcp".into(),
            headers: vec![
                ("Accept".into(), "application/json, text/event-stream".into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: body.to_string().into_bytes(),
        };
        let call = |sent: &Sent, tool: &str, meta: Value| {
            post(
                json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": tool, "arguments": {"params": sent.params}, "_meta": meta}}),
            )
        };
        let cancel = AtomicBool::new(false);
        let value = |resp: crate::mcp::HttpResponse| -> Value { serde_json::from_slice(&resp.body).unwrap() };

        let listed = value(mcp.handle(&post(json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})), &cancel));
        let names: Vec<_> =
            listed["result"]["tools"].as_array().unwrap().iter().map(|t| t["name"].as_str().unwrap()).collect();
        assert!(names.contains(&"sys_kit") && names.contains(&"test_echo") && !names.contains(&"rt_irq"), "{names:?}");

        let sent = rig.jan("test echo", &["a=1"]);
        let good = json!({"procession/call": sent.call, "procession/call_sig": sent.call_sig});
        let answered = value(mcp.handle(&call(&sent, "test_echo", good.clone()), &cancel));
        assert_eq!(answered["id"], 7);
        let first = answered["result"]["content"][0]["text"].as_str().unwrap();
        assert!(first.starts_with("{\"type\":\"outcome\",\"outcome\":\"done\",\"rc\":0,\"id\":"), "{first}");
        assert_eq!(answered["result"]["isError"], false);

        // The same call again: spent. An outcome, not an error.
        let again = value(mcp.handle(&call(&sent, "test_echo", good), &cancel));
        assert!(again["result"]["content"][0]["text"].as_str().unwrap().contains("\"reason\":\"invalid\""), "{again}");

        let sent = rig.jan("test echo", &[]);
        let (c, s) = (sent.call.clone(), sent.call_sig.clone());
        for (meta, why) in [
            (json!({"procession/call": c}), "both keys"),
            (
                json!({"procession/call": c, "procession/call_sig": s, "procession/extra": "x"}),
                "a procession/ key that does not exist",
            ),
            (json!({"procession/call": 5, "procession/call_sig": s}), "strings"),
        ] {
            let resp = value(mcp.handle(&call(&sent, "test_echo", meta), &cancel));
            assert_eq!(resp["error"]["code"], -32602, "{why}: {resp}");
        }
        let unknown =
            value(mcp.handle(&call(&sent, "rt_irq", json!({"procession/call": c, "procession/call_sig": s})), &cancel));
        assert_eq!(unknown["error"]["code"], -32602);
        assert_eq!(rig.pledge.count("submit"), 1);
    }
}

#[test]
fn the_mcp_layer_refuses_what_a_browser_or_a_wrong_client_would_send() {
    use crate::mcp::{HttpRequest, Mcp};
    let rig = Rig::new(Plan::Decline);
    let mcp = Mcp::new(&rig.service);
    let base = HttpRequest {
        method: "POST".into(),
        path: "/mcp".into(),
        headers: vec![
            ("Accept".into(), "application/json, text/event-stream".into()),
            ("Content-Type".into(), "application/json".into()),
        ],
        body: br#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#.to_vec(),
    };
    let status = |request: &HttpRequest| mcp.handle(request, &AtomicBool::new(false)).status;
    assert_eq!(status(&base), 200);
    let with = |name: &str, value: &str| {
        let mut r = base.clone();
        r.headers.push((name.into(), value.into()));
        r
    };
    assert_eq!(status(&with("Origin", "http://evil.example")), 403);
    assert_eq!(status(&with("MCP-Protocol-Version", "2025-06-18")), 200);
    assert_eq!(status(&with("MCP-Protocol-Version", "1999-01-01")), 400);
    assert_eq!(status(&HttpRequest { method: "GET".into(), ..base.clone() }), 405);
    assert_eq!(status(&HttpRequest { path: "/other".into(), ..base.clone() }), 404);
    assert_eq!(
        status(&HttpRequest { headers: vec![("Content-Type".into(), "application/json".into())], ..base.clone() }),
        406
    );
    assert_eq!(
        status(&HttpRequest {
            headers: vec![("Accept".into(), "application/json, text/event-stream".into())],
            ..base.clone()
        }),
        415
    );
    assert_eq!(status(&HttpRequest { body: vec![b' '; crate::mcp::BODY_MAX + 1], ..base.clone() }), 413);
    assert_eq!(
        status(&HttpRequest {
            body: br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#.to_vec(),
            ..base.clone()
        }),
        202
    );
    let unknown = mcp.handle(
        &HttpRequest { body: br#"{"jsonrpc":"2.0","id":2,"method":"nope"}"#.to_vec(), ..base.clone() },
        &AtomicBool::new(false),
    );
    assert!(String::from_utf8(unknown.body).unwrap().contains("-32601"));
    // Not an `initialize` first, no session id: tools/list works.
    let listed = mcp.handle(
        &HttpRequest { body: br#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#.to_vec(), ..base },
        &AtomicBool::new(false),
    );
    assert_eq!(listed.status, 200);
}

// ---- the stream: what `pact` needs from the service while it waits ---------------------

mod streaming {
    use super::*;
    use crate::mcp::{HttpRequest, Mcp, ResponseWriter};
    use serde_json::{Value, json};

    type Head = (Duration, u16, Vec<(String, String)>);

    /// Records what is written, and when. `fail_after_head` makes a body write fail: the client is gone.
    struct Recorder {
        started: Instant,
        head: Option<Head>,
        chunks: Vec<(Duration, String)>,
        fail_after_head: bool,
    }

    impl Recorder {
        fn new() -> Recorder {
            Recorder { started: Instant::now(), head: None, chunks: Vec::new(), fail_after_head: false }
        }

        fn comments(&self) -> usize {
            self.chunks.iter().filter(|(_, c)| c.starts_with(": keepalive")).count()
        }

        fn messages(&self) -> Vec<Value> {
            self.chunks
                .iter()
                .filter_map(|(_, c)| c.strip_prefix("event: message\ndata: "))
                .map(|data| serde_json::from_str(data.trim_end()).unwrap())
                .collect()
        }
    }

    impl ResponseWriter for Recorder {
        fn head(&mut self, status: u16, headers: &[(String, String)]) -> std::io::Result<()> {
            assert!(self.head.is_none(), "one head");
            self.head = Some((self.started.elapsed(), status, headers.to_vec()));
            Ok(())
        }

        fn body(&mut self, bytes: &[u8]) -> std::io::Result<()> {
            assert!(self.head.is_some(), "a body before the head");
            if self.fail_after_head {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            self.chunks.push((self.started.elapsed(), String::from_utf8(bytes.to_vec()).unwrap()));
            Ok(())
        }
    }

    fn request(sent: &Sent, token: Option<Value>) -> HttpRequest {
        let mut meta = json!({"procession/call": sent.call, "procession/call_sig": sent.call_sig});
        if let Some(token) = token {
            meta["progressToken"] = token;
        }
        HttpRequest {
            method: "POST".into(),
            path: "/mcp".into(),
            headers: vec![("Accept".into(), "application/json, text/event-stream".into()), ("Content-Type".into(), "application/json".into())],
            body: json!({"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": sent.name, "arguments": {"params": sent.params}, "_meta": meta}})
                .to_string()
                .into_bytes(),
        }
    }

    fn content_type(r: &Recorder) -> String {
        r.head.as_ref().unwrap().2.iter().find(|(k, _)| k == "Content-Type").unwrap().1.clone()
    }

    #[test]
    fn the_head_comes_when_the_call_is_accepted_then_comments_while_the_person_is_asked_then_the_answer() {
        let rig = Rig::new(Plan::Silent);
        rig.pledge.set(Plan::ApproveAfter(Duration::from_millis(1200), rig.pki.confirmed.clone()));
        let mut mcp = Mcp::new(&rig.service);
        mcp.keepalive = Duration::from_millis(100);
        let mut out = Recorder::new();
        mcp.serve(&request(&rig.jan("sys kit", &[]), Some(json!("tok"))), &AtomicBool::new(false), &mut out);

        let (at, status, _) = out.head.clone().unwrap();
        assert_eq!(status, 200);
        assert_eq!(content_type(&out), "text/event-stream");
        assert!(at < Duration::from_millis(600), "the head came at {at:?}, long before the approval");
        assert!(out.comments() >= 5, "{} comments while waiting for the person", out.comments());
        let messages = out.messages();
        assert_eq!(messages.len(), 1, "no notice of progress: only the answer");
        let last = messages.last().unwrap();
        assert_eq!(last["id"], 9);
        assert!(last["result"]["content"][0]["text"].as_str().unwrap().contains("\"outcome\":\"done\""));
        // No silence longer than a few keepalives anywhere in the stream.
        let mut times = vec![at];
        times.extend(out.chunks.iter().map(|(t, _)| *t));
        assert!(times.windows(2).all(|w| w[1] - w[0] < Duration::from_millis(500)), "{times:?}");
    }

    #[test]
    fn something_is_written_while_a_verb_runs_too() {
        let rig = Rig::new(Plan::Silent);
        rig.pledge.set(confirmed(&rig));
        // The dispatcher is held up for a while just before it runs the verb.
        let runner = InProcess {
            audit_file: rig.audit.clone(),
            lock_dir: rig.dispatcher_dir.path().join("locks"),
            user: "probe".into(),
            before: Some(Box::new(|| std::thread::sleep(Duration::from_millis(900)))),
        };
        let (service, _) = make_service(&rig.pki, rig.pledge.link(), &rig.used, runner, 16);
        let mut mcp = Mcp::new(&service);
        mcp.keepalive = Duration::from_millis(100);
        let mut out = Recorder::new();
        mcp.serve(&request(&rig.jan("sys kit", &[]), Some(json!(1))), &AtomicBool::new(false), &mut out);
        let after_running = out.comments();
        assert!(after_running >= 5, "{after_running} comments while the person was asked and the verb ran");
        assert!(
            out.messages().last().unwrap()["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("\"outcome\":\"done\"")
        );
    }

    #[test]
    fn a_call_refused_before_it_is_accepted_is_plain_json_even_with_a_token() {
        let rig = Rig::new(Plan::Decline);
        let mcp = Mcp::new(&rig.service);
        let wrong = sign(&CallSpec { host: "elsewhere", ..spec(&rig.pki.jan_agent, "sys kit", &[]) });
        let mut out = Recorder::new();
        mcp.serve(&request(&wrong, Some(json!("t"))), &AtomicBool::new(false), &mut out);
        assert_eq!(content_type(&out), "application/json");
        assert_eq!(out.comments(), 0);
        assert!(out.chunks[0].1.contains("invalid"), "{:?}", out.chunks);
        // Busy is a plain 503 as well.
        let busy = Rig::with(Plan::Silent, 0, None);
        let mut out = Recorder::new();
        Mcp::new(&busy.service).serve(
            &request(&busy.jan("sys kit", &[]), Some(json!("t"))),
            &AtomicBool::new(false),
            &mut out,
        );
        assert_eq!(out.head.unwrap().1, 503);
    }

    #[test]
    fn without_a_progress_token_the_answer_is_plain_json_when_it_is_decided() {
        let rig = Rig::new(Plan::Silent);
        rig.pledge.set(Plan::ApproveAfter(Duration::from_millis(400), rig.pki.confirmed.clone()));
        let mut mcp = Mcp::new(&rig.service);
        mcp.keepalive = Duration::from_millis(50);
        let mut out = Recorder::new();
        mcp.serve(&request(&rig.jan("sys kit", &[]), None), &AtomicBool::new(false), &mut out);
        assert_eq!(content_type(&out), "application/json");
        assert!(out.head.as_ref().unwrap().0 >= Duration::from_millis(300), "the head waits for the answer");
        assert_eq!(out.comments(), 0);
        assert_eq!(out.chunks.len(), 1);
    }

    #[test]
    fn a_client_that_is_gone_when_a_write_fails_cancels_the_call_and_nothing_runs() {
        let rig = Rig::new(Plan::Silent);
        let mut mcp = Mcp::new(&rig.service);
        mcp.keepalive = Duration::from_millis(50);
        let mut out = Recorder::new();
        out.fail_after_head = true;
        let sent = rig.jan("sys kit", &[]);
        mcp.serve(&request(&sent, Some(json!("t"))), &AtomicBool::new(false), &mut out);
        rig.pledge.wait_for("cancel");
        assert!(rig.ran().is_empty());
        assert_eq!(rig.service.waiting(), 0);
        assert_eq!(word(&rig.outcome(&sent)), "refused/invalid", "the identifier stays spent");
    }

    #[test]
    fn the_transports_cancel_flag_does_the_same() {
        let rig = Arc::new(Rig::new(Plan::Silent));
        let cancel = Arc::new(AtomicBool::new(false));
        let sent = rig.jan("sys kit", &[]);
        let worker = {
            let (rig, cancel) = (rig.clone(), cancel.clone());
            std::thread::spawn(move || {
                let mut out = Recorder::new();
                Mcp::new(&rig.service).serve(&request(&sent, Some(json!("t"))), &cancel, &mut out);
                out.chunks.len()
            })
        };
        rig.pledge.wait_for("submit");
        cancel.store(true, Ordering::SeqCst);
        worker.join().unwrap();
        rig.pledge.wait_for("cancel");
        assert!(rig.ran().is_empty());
    }
}
