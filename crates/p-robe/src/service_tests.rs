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

/// The deadline the call carries, in seconds since the epoch.
fn deadline_of(sent: &Sent) -> i64 {
    Call::parse(base64::engine::general_purpose::STANDARD.decode(&sent.call).unwrap()).unwrap().deadline().unix()
}

/// The clock as the service reads it.
fn now_unix() -> i64 {
    Timestamp::now().unwrap().unix()
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

/// A count of the keepalive comments a test's client has seen, shared with a fake pledge or a runner that
/// holds back until enough have come.
#[derive(Clone, Default)]
struct Seen(Arc<std::sync::atomic::AtomicUsize>);

impl Seen {
    fn one_more(&self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// Waits for `n`; a minute at most, so that a stream that never sends one fails the test, not hangs it.
    fn wait_for(&self, n: usize) {
        let until = Instant::now() + Duration::from_secs(60);
        while self.0.load(std::sync::atomic::Ordering::SeqCst) < n && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

// ---- the fake pledge -----------------------------------------------------------

#[derive(Clone)]
enum Plan {
    Approve(PathBuf),
    ApproveAfter(Duration, PathBuf),
    /// Approves once `seen` has counted that many keepalive comments: what a test shows about the
    /// stream is then not a matter of how fast the machine is (it waits at most a minute).
    ApproveWhen(Seen, usize, PathBuf),
    /// Signs an approval over a request that is not the one submitted.
    OverOther(PathBuf),
    Decline,
    Refuse(PledgeReason),
    Expire,
    Silent,
    CloseAfterSubmit,
    /// The connection is dropped as soon as it is accepted, before anything is read (a peer whose credentials pledge
    /// cannot read): the service is told nothing.
    DropAtOnce,
    /// An answer whose `result` is not one, then (if a key) an approval.
    UnknownThen(Option<PathBuf>),
    /// An approval with clearance members, which stage 1 refuses.
    ApproveWithClearance(PathBuf),
    /// A valid approval of **another** request (another hash) first, then, if `then_own`, the real one.
    Foreign {
        key: PathBuf,
        then_own: bool,
    },
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
            assert!(started.elapsed() < Duration::from_secs(60), "no event {prefix}: {:?}", self.events());
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
    if matches!(plan, Plan::DropAtOnce) {
        return log("dropped-at-once".to_string());
    }
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
        Plan::ApproveWhen(seen, at_least, path) => {
            seen.wait_for(*at_least);
            answer(&stream, hash, Answered::Approved(approve(path, submit.request())), POLICY);
        }
        Plan::OverOther(path) => {
            let other =
                p_act::Request::compose(submit.request().call(), submit.request().call_sig(), Rating::WORST, false)
                    .unwrap();
            answer(&stream, hash, Answered::Approved(approve(path, &other)), POLICY);
        }
        Plan::Decline => answer(&stream, hash, Answered::Declined, POLICY),
        Plan::Refuse(reason) => answer(&stream, hash, Answered::Refused(Refused::Pledge(*reason)), POLICY),
        Plan::Expire => answer(&stream, hash, Answered::Expired(By::Pledge), POLICY),
        Plan::Silent => {}
        Plan::CloseAfterSubmit => return log(format!("closed-by-pledge {hash}")),
        Plan::DropAtOnce => unreachable!("dropped before anything was read"),
        Plan::UnknownThen(path) => {
            let _ = (&stream).write_all_line(format!(
                "{{\"schema_version\":1,\"type\":\"answer\",\"request\":\"{hash}\",\"result\":\"maybe\"}}\n"
            ));
            if let Some(path) = path {
                answer(&stream, hash, Answered::Approved(approve(path, submit.request())), POLICY);
            }
        }
        Plan::Foreign { key, then_own } => {
            let other =
                p_act::Request::compose(submit.request().call(), submit.request().call_sig(), Rating::WORST, false)
                    .unwrap();
            answer(&stream, other.hash(), Answered::Approved(approve(key, &other)), POLICY);
            if *then_own {
                std::thread::sleep(Duration::from_millis(200));
                answer(&stream, hash, Answered::Approved(approve(key, submit.request())), POLICY);
            }
        }
        Plan::ApproveWithClearance(path) => {
            let signed = sign_approval(&Signer::plain(path), submit.request()).unwrap();
            let clearance =
                Clearance::compose(hash, p_act::clearance::approval_hash(&signed), Timestamp::now().unwrap()).unwrap();
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
        use std::os::unix::fs::PermissionsExt;
        // Modes written out: under a umask of 0002 (an account with a group of its own name) `create_dir` would make
        // `open/` group-writable, and the rule that nothing is rated lower under a directory others can write would
        // then rightly keep the worst rating.
        let dir = std::fs::canonicalize(crate::testdir::new("sandbox")).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        for sub in ["open", "private"] {
            std::fs::create_dir(dir.join(sub)).unwrap();
            std::fs::set_permissions(dir.join(sub), std::fs::Permissions::from_mode(0o755)).unwrap();
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
    assert_eq!(rig.outcome(&sent), Outcome::Expired);
    // What this shows: the service does not answer `expired` before the deadline the call carries. The
    // clock is read as the service reads it (whole seconds since the epoch); no wall time is measured.
    assert!(now_unix() >= deadline_of(&sent), "answered expired before the deadline {}", deadline_of(&sent));
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
        (sign(&spec(a, "rt jitter", &[])), "unknown-action"),
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
fn an_answer_for_a_request_the_service_is_not_waiting_on_is_dropped_and_nothing_is_acted_on() {
    let rig = Rig::new(Plan::Silent);
    // A valid approval, but of another request's bytes, arrives for another hash: dropped and logged.
    rig.pledge.set(Plan::Foreign { key: rig.pki.confirmed.clone(), then_own: false });
    let sent = sign(&CallSpec { secs: 2, ..spec(&rig.pki.jan_agent, "sys kit", &[]) });
    assert_eq!(rig.outcome(&sent), Outcome::Expired, "the foreign answer did not end the wait");
    assert!(rig.log_has("a message for a request not held: ignored"), "{:?}", rig.log);
    assert!(rig.ran().is_empty(), "nothing ran on it");
    // The same, and then the real approval: only that one is acted on, once.
    rig.pledge.set(Plan::Foreign { key: rig.pki.confirmed.clone(), then_own: true });
    let sent = rig.jan("sys kit", &[]);
    assert_eq!(word(&rig.outcome(&sent)), "done");
    assert_eq!(rig.ran().iter().filter(|l| l.starts_with("event=start")).count(), 1);
    // The same identifier is spent: an answer cannot make it run twice.
    assert_eq!(word(&rig.outcome(&sent)), "refused/invalid");
    assert_eq!(rig.ran().iter().filter(|l| l.starts_with("event=start")).count(), 1);
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
fn a_connection_pledge_drops_without_a_word_is_unavailable_and_nothing_more_whenever_it_ends_and_nothing_runs() {
    let rig = Rig::new(Plan::DropAtOnce);
    // Dropped before pledge read anything (the credentials it could not read): the agent hears `unavailable`.
    let first = rig.outcome(&rig.jan("sys kit", &[]));
    assert_eq!(first, Outcome::Unavailable);
    assert_eq!((first.word(), first.reason()), ("unavailable", None), "nothing more specific");
    // Dropped after the submit was written: the same.
    rig.pledge.set(Plan::CloseAfterSubmit);
    let second = rig.outcome(&rig.jan("sys kit", &[]));
    assert_eq!((second.word(), second.reason()), ("unavailable", None));
    assert!(rig.ran().is_empty(), "nothing ran");
    assert!(rig.log_has("exact='no-route:") || rig.log_has("exact=no-route:"), "{:?}", rig.log);
    assert_eq!(rig.service.waiting(), 0);
}

#[test]
fn the_door_is_checked_from_this_side() {
    let rig = Rig::new(Plan::Decline);
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
    // At once, not at the deadline: the call (30 s) has most of its time left when the answer is there.
    assert!(now_unix() < deadline_of(&sent), "not at the deadline");
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

/// A runner that answers with a fixed exit code, and remembers what it was asked.
struct Fixed {
    rc: u8,
    asked: Arc<Mutex<Vec<(String, i64)>>>,
}

impl crate::runner::Runner for Fixed {
    fn run(
        &self,
        _: crate::table::Within,
        call_id: &str,
        until: i64,
        _: &str,
        _: &[String],
    ) -> Result<crate::runner::RunOutput, crate::runner::RunError> {
        self.asked.lock().unwrap().push((call_id.to_string(), until));
        Ok(crate::runner::RunOutput { rc: self.rc, timed_out: false, signal: None, stdout: String::new() })
    }
}

#[test]
fn the_dispatchers_exit_codes_reach_the_agent_as_the_documented_outcomes_and_the_deadline_goes_with_the_call() {
    let rig = Rig::new(Plan::Silent);
    rig.pledge.set(confirmed(&rig));
    for (rc, expected, exact) in [
        (75, "refused/try-later", "dispatcher-busy"),
        (76, "expired", "dispatcher-deadline"),
        (64, "refused/not-allowed", "dispatcher-refused"),
        (3, "unavailable", "dispatcher-unavailable"),
        (0, "done", "ran"),
        (70, "failed", "dispatcher-failed"),
        (2, "failed", "dispatcher-code:2"),
        (1, "unavailable", "sudo-refused"),
    ] {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let (mut service, log) = make_service(
            &rig.pki,
            rig.pledge.link(),
            &rig.used,
            InProcess { audit_file: rig.audit.clone(), lock_dir: rig.used.clone(), user: "probe".into(), before: None },
            16,
        );
        service.runner = Box::new(Fixed { rc, asked: asked.clone() });
        let sent = rig.jan("sys kit", &[]);
        match service.handle(&sent.tool(), &AtomicBool::new(false)) {
            Handled::Outcome { outcome, .. } => assert_eq!(word(&outcome), expected, "rc {rc}"),
            other => panic!("{other:?}"),
        }
        assert!(log.lock().unwrap().iter().any(|l| l.contains(exact)), "{exact}: {:?}", log.lock().unwrap());
        let (id, until) = asked.lock().unwrap()[0].clone();
        let call = Call::parse(base64::engine::general_purpose::STANDARD.decode(&sent.call).unwrap()).unwrap();
        assert_eq!(
            (id.as_str(), until),
            (sent.id.as_str(), call.deadline().unix()),
            "the dispatcher is told the call's deadline"
        );
    }
}

/// A runner that gives what it was told to, once.
struct Canned(Mutex<Option<Result<crate::runner::RunOutput, crate::runner::RunError>>>);

impl crate::runner::Runner for Canned {
    fn run(
        &self,
        _: crate::table::Within,
        _: &str,
        _: i64,
        _: &str,
        _: &[String],
    ) -> Result<crate::runner::RunOutput, crate::runner::RunError> {
        self.0.lock().unwrap().take().expect("asked once")
    }
}

#[test]
fn a_run_that_may_have_started_is_failed_and_only_a_certain_not_started_is_unavailable() {
    use crate::runner::{RunError, RunOutput};
    let rig = Rig::new(Plan::Silent);
    rig.pledge.set(confirmed(&rig));
    let output = |rc, timed_out, signal| RunOutput { rc, timed_out, signal, stdout: "{\"type\":\"header\"}\n".into() };
    for (given, expected, exact) in [
        (Err(RunError::NotStarted("cannot start sudo: nope".into())), "unavailable", "run:cannot start sudo"),
        (Err(RunError::Lost("answer over the limit".into())), "failed", "run-lost:answer over the limit"),
        (Ok(output(255, true, Some(9))), "failed", "run-limit"),
        (Ok(output(255, false, Some(11))), "failed", "dispatcher-signal:11"),
        (Ok(output(101, false, None)), "failed", "dispatcher-code:101"),
    ] {
        let (mut service, log) = make_service(
            &rig.pki,
            rig.pledge.link(),
            &rig.used,
            InProcess { audit_file: rig.audit.clone(), lock_dir: rig.used.clone(), user: "probe".into(), before: None },
            16,
        );
        service.runner = Box::new(Canned(Mutex::new(Some(given))));
        let sent = rig.jan("sys kit", &[]);
        match service.handle(&sent.tool(), &AtomicBool::new(false)) {
            Handled::Outcome { outcome, .. } => assert_eq!(word(&outcome), expected, "{exact}"),
            other => panic!("{other:?}"),
        }
        assert!(log.lock().unwrap().iter().any(|l| l.contains(exact)), "{exact}: {:?}", log.lock().unwrap());
    }
}

#[test]
fn a_call_whose_dispatcher_waits_past_the_deadline_for_the_lock_is_expired_and_nothing_runs() {
    let rig = Rig::new(Plan::Silent);
    rig.pledge.set(confirmed(&rig));
    // Something else holds the identity's lock for longer than the call has left.
    let held = crate::lock::take(&rig.dispatcher_dir.path().join("locks"), "probe").unwrap();
    let sent = sign(&CallSpec { secs: 3, ..spec(&rig.pki.jan_agent, "sys kit", &[]) });
    assert_eq!(rig.outcome(&sent), Outcome::Expired);
    // Expired at the deadline (the wait for the lock was cut there), not before it.
    assert!(now_unix() >= deadline_of(&sent), "expired before the deadline");
    drop(held);
    std::thread::sleep(Duration::from_millis(300));
    assert!(!rig.ran().iter().any(|l| l.starts_with("event=start")), "the verb did not start: {:?}", rig.ran());
    assert!(
        rig.ran().iter().any(|l| l.starts_with("event=expired ") && l.contains(&format!(" call={}", sent.id))),
        "{:?}",
        rig.ran()
    );
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
    fn a_verb_that_was_started_and_exits_with_a_code_is_failed_with_the_cause_under_the_calls_identifier() {
        let rig = Rig::new(Plan::Silent);
        rig.pledge.set(confirmed(&rig));
        let sent = rig.jan("test fail", &["2"]);
        assert_eq!(rig.outcome(&sent), Outcome::Failed);
        assert!(rig.log_has("dispatcher-failed"), "{:?}", rig.log);
        let line = rig.ran().into_iter().find(|l| l.starts_with("event=done ")).expect("a done line");
        assert!(line.contains(" rc=70 ") && line.contains("cause=verb-code:2") && line.contains(&sent.id), "{line}");
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
    fn an_mcp_message_with_a_repeated_key_at_any_depth_is_a_parse_error_and_nobody_is_asked() {
        use crate::mcp::{HttpRequest, Mcp};
        use serde_json::Value;
        let rig = Rig::new(Plan::Silent);
        let mcp = Mcp::new(&rig.service);
        let post = |body: &str| HttpRequest {
            method: "POST".into(),
            path: "/mcp".into(),
            headers: vec![
                ("Accept".into(), "application/json, text/event-stream".into()),
                ("Content-Type".into(), "application/json".into()),
            ],
            body: body.as_bytes().to_vec(),
        };
        let cancel = AtomicBool::new(false);
        let value = |resp: crate::mcp::HttpResponse| -> Value { serde_json::from_slice(&resp.body).unwrap() };
        // A clean one is answered.
        let clean = value(mcp.handle(&post(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#), &cancel));
        assert!(clean["result"]["tools"].is_array(), "{clean}");
        // A repeated key at the top, in `_meta` (where the signed call travels), in the arguments, and in a list of objects.
        for (what, body) in [
            ("top", r#"{"jsonrpc":"2.0","id":1,"id":2,"method":"tools/list"}"#),
            ("method", r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","method":"tools/call"}"#),
            (
                "_meta",
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"sys_kit","arguments":{"params":[]},"_meta":{"procession/call":"a","procession/call":"b","procession/call_sig":"c"}}}"#,
            ),
            (
                "arguments",
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"test_echo","arguments":{"params":[],"params":["x"]}}}"#,
            ),
            ("nested", r#"{"jsonrpc":"2.0","id":1,"method":"x","params":{"a":[{"b":1,"b":2}]}}"#),
        ] {
            let resp = value(mcp.handle(&post(body), &cancel));
            // As the other malformed messages: a JSON-RPC parse error, with no value from the message in it.
            assert_eq!(resp["error"]["code"], -32700, "{what}: {resp}");
            assert_eq!(resp["error"]["message"], "not a JSON object", "{what}: {resp}");
        }
        assert_eq!(rig.pledge.count("submit"), 0, "nobody was asked");
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
        assert!(
            names.contains(&"sys_kit")
                && names.contains(&"test_echo")
                && names.contains(&"rt_irq")
                && !names.contains(&"rt_jitter"),
            "{names:?}"
        );

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
        // `wait_seconds` is `pact`'s (it shows it to the model and strips it before it composes the call): a call that
        // carries it is refused like any argument the tool does not have, and nothing is asked of anybody.
        let carrying = post(json!({
            "jsonrpc": "2.0", "id": 7, "method": "tools/call",
            "params": {"name": "test_echo", "arguments": {"params": sent.params, "wait_seconds": 30},
                       "_meta": {"procession/call": c, "procession/call_sig": s}}
        }));
        let refused = value(mcp.handle(&carrying, &cancel));
        assert_eq!(refused["error"]["code"], -32602, "{refused}");
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
        let unknown = value(
            mcp.handle(&call(&sent, "rt_jitter", json!({"procession/call": c, "procession/call_sig": s})), &cancel),
        );
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
        seen: Seen,
    }

    impl Recorder {
        fn new() -> Recorder {
            Recorder {
                started: Instant::now(),
                head: None,
                chunks: Vec::new(),
                fail_after_head: false,
                seen: Seen::default(),
            }
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
            if bytes.starts_with(b": keepalive") {
                self.seen.one_more();
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
        let mut out = Recorder::new();
        // The person answers only after five comments have been seen: the order is what is shown, not
        // how many fit in a stretch of wall time.
        rig.pledge.set(Plan::ApproveWhen(out.seen.clone(), 5, rig.pki.confirmed.clone()));
        let mut mcp = Mcp::new(&rig.service);
        mcp.keepalive = Duration::from_millis(100);
        mcp.serve(&request(&rig.jan("sys kit", &[]), Some(json!("tok"))), &AtomicBool::new(false), &mut out);

        let (_, status, _) = out.head.clone().unwrap();
        assert_eq!(status, 200);
        assert_eq!(content_type(&out), "text/event-stream");
        // The head came first, then at least five comments, then the answer, which is the last thing.
        assert!(out.comments() >= 5, "{} comments while waiting for the person", out.comments());
        let messages = out.messages();
        assert_eq!(messages.len(), 1, "no notice of progress: only the answer");
        let last = messages.last().unwrap();
        assert_eq!(last["id"], 9);
        assert!(last["result"]["content"][0]["text"].as_str().unwrap().contains("\"outcome\":\"done\""));
        assert!(out.chunks.last().unwrap().1.starts_with("event: message"), "{:?}", out.chunks.last());
        assert!(out.chunks[..out.chunks.len() - 1].iter().all(|(_, c)| c.starts_with(": keepalive")));
        // Comments are not spammed: the keepalive interval (100 ms) is a lower bound on the spacing. (A slow
        // machine only widens the gaps, so this holds under load.)
        let times: Vec<_> = out.chunks.iter().map(|(t, _)| *t).collect();
        assert!(times.windows(2).take(4).all(|w| w[1] - w[0] >= Duration::from_millis(80)), "{times:?}");
    }

    #[test]
    fn something_is_written_while_a_verb_runs_too() {
        let rig = Rig::new(Plan::Silent);
        rig.pledge.set(confirmed(&rig));
        // The dispatcher is held up for a while just before it runs the verb.
        let mut out = Recorder::new();
        let seen = out.seen.clone();
        let runner = InProcess {
            audit_file: rig.audit.clone(),
            lock_dir: rig.dispatcher_dir.path().join("locks"),
            user: "probe".into(),
            // Held until five comments have been seen while it is held (not for a stretch of wall time).
            before: Some(Box::new(move || seen.wait_for(5))),
        };
        let (service, _) = make_service(&rig.pki, rig.pledge.link(), &rig.used, runner, 16);
        let mut mcp = Mcp::new(&service);
        mcp.keepalive = Duration::from_millis(100);
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

// ---- the HTTP transport: hyper over memory and over a Unix socket -------------------------------

mod http_tests {
    use super::*;
    use crate::http::{Limits, accept_loop, serve_connection};
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap()
    }

    /// A service on the rig's pledge, with its own dispatcher state.
    fn service_of(rig: &Rig) -> Arc<Service> {
        let runner = InProcess {
            audit_file: rig.audit.clone(),
            lock_dir: rig.dispatcher_dir.path().join("locks"),
            user: "probe".into(),
            before: None,
        };
        Arc::new(make_service(&rig.pki, rig.pledge.link(), &rig.used, runner, 16).0)
    }

    fn request(body: &Value, extra_headers: &str) -> Vec<u8> {
        let body = body.to_string();
        format!(
            "POST /mcp HTTP/1.1\r\nHost: probe\r\nAccept: application/json, text/event-stream\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{extra_headers}\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn call_body(sent: &Sent, token: Option<&str>) -> Value {
        let mut meta = json!({"procession/call": sent.call, "procession/call_sig": sent.call_sig});
        if let Some(token) = token {
            meta["progressToken"] = json!(token);
        }
        json!({"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": sent.name, "arguments": {"params": sent.params}, "_meta": meta}})
    }

    /// What arrived, and when: the status, the headers and the pieces of the chunked body.
    struct Reply {
        status: u16,
        headers: Vec<(String, String)>,
        head_at: Duration,
        chunks: Vec<(Duration, String)>,
    }

    impl Reply {
        fn comments(&self) -> usize {
            self.chunks.iter().filter(|(_, c)| c.starts_with(": keepalive")).count()
        }

        fn messages(&self) -> Vec<Value> {
            self.chunks
                .iter()
                .filter_map(|(_, c)| c.strip_prefix("event: message\ndata: "))
                .map(|d| serde_json::from_str(d.trim_end()).unwrap())
                .collect()
        }

        fn header(&self, name: &str) -> Option<&str> {
            self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
        }
    }

    /// Reads one response from `stream` as it arrives: the head, then the pieces of the chunked body or the
    /// whole body of a Content-Length response, until the server closes.
    async fn read_reply<S: AsyncReadExt + Unpin>(stream: &mut S) -> Reply {
        read_reply_counting(stream, None).await
    }

    /// As [`read_reply`], counting each keepalive comment in `seen` as it arrives.
    async fn read_reply_counting<S: AsyncReadExt + Unpin>(stream: &mut S, seen: Option<&Seen>) -> Reply {
        let started = Instant::now();
        let mut buffer = Vec::new();
        let mut byte = [0u8; 4096];
        let end = loop {
            if let Some(at) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                break at;
            }
            let n = stream.read(&mut byte).await.unwrap();
            assert!(n > 0, "closed before a head: {:?}", String::from_utf8_lossy(&buffer));
            buffer.extend_from_slice(&byte[..n]);
        };
        let head_at = started.elapsed();
        let head = String::from_utf8_lossy(&buffer[..end]).into_owned();
        let mut lines = head.split("\r\n");
        let status: u16 = lines.next().unwrap().split(' ').nth(1).unwrap().parse().unwrap();
        let headers: Vec<(String, String)> =
            lines.filter_map(|l| l.split_once(": ")).map(|(k, v)| (k.to_string(), v.to_string())).collect();
        let chunked = headers.iter().any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v == "chunked");
        let length: Option<usize> =
            headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("content-length")).and_then(|(_, v)| v.parse().ok());
        let mut rest = buffer[end + 4..].to_vec();
        let mut chunks = Vec::new();
        loop {
            if chunked {
                // size CRLF data CRLF ... 0 CRLF CRLF
                while let Some(line_end) = rest.windows(2).position(|w| w == b"\r\n") {
                    let size =
                        usize::from_str_radix(std::str::from_utf8(&rest[..line_end]).unwrap().trim(), 16).unwrap();
                    if size == 0 {
                        return Reply { status, headers, head_at, chunks };
                    }
                    if rest.len() < line_end + 2 + size + 2 {
                        break;
                    }
                    let data = String::from_utf8(rest[line_end + 2..line_end + 2 + size].to_vec()).unwrap();
                    if data.starts_with(": keepalive") {
                        seen.iter().for_each(|seen| seen.one_more());
                    }
                    chunks.push((started.elapsed(), data));
                    rest.drain(..line_end + 2 + size + 2);
                }
            } else if length.is_some_and(|l| rest.len() >= l) {
                chunks.push((started.elapsed(), String::from_utf8(rest).unwrap()));
                return Reply { status, headers, head_at, chunks };
            }
            let n = stream.read(&mut byte).await.unwrap();
            if n == 0 {
                if !chunked && length.is_none() && !rest.is_empty() {
                    chunks.push((started.elapsed(), String::from_utf8(rest).unwrap()));
                }
                return Reply { status, headers, head_at, chunks };
            }
            rest.extend_from_slice(&byte[..n]);
        }
    }

    /// One request over an in-memory connection.
    async fn exchange(service: &Arc<Service>, limits: Limits, bytes: &[u8]) -> Reply {
        exchange_counting(service, limits, bytes, None).await
    }

    async fn exchange_counting(service: &Arc<Service>, limits: Limits, bytes: &[u8], seen: Option<&Seen>) -> Reply {
        let (mut client, server) = tokio::io::duplex(1 << 16);
        tokio::spawn(serve_connection(server, service.clone(), limits));
        client.write_all(bytes).await.unwrap();
        read_reply_counting(&mut client, seen).await
    }

    #[test]
    fn a_plain_request_gets_a_plain_answer_and_what_is_not_allowed_gets_its_status() {
        let rig = Rig::new(Plan::Decline);
        let service = service_of(&rig);
        runtime().block_on(async {
            let ping = exchange(
                &service,
                Limits::default(),
                &request(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}), ""),
            )
            .await;
            assert_eq!(ping.status, 200);
            assert_eq!(ping.header("content-type"), Some("application/json"));
            assert_eq!(ping.chunks.len(), 1);
            assert_eq!(serde_json::from_str::<Value>(&ping.chunks[0].1).unwrap()["id"], 1);
            let origin = exchange(
                &service,
                Limits::default(),
                &request(&json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}), "Origin: http://evil\r\n"),
            )
            .await;
            assert_eq!(origin.status, 403);
            let get = exchange(&service, Limits::default(), b"GET /mcp HTTP/1.1\r\nHost: probe\r\n\r\n").await;
            assert_eq!(get.status, 405);
            // More than the layer's 64 KiB: refused, whatever the client does next.
            let big = json!({"jsonrpc": "2.0", "id": 1, "method": "ping", "pad": "x".repeat(70_000)});
            assert_eq!(exchange(&service, Limits::default(), &request(&big, "")).await.status, 413);
            // Not HTTP at all: hyper's own refusal, and the connection closes.
            let (mut client, server) = tokio::io::duplex(4096);
            tokio::spawn(serve_connection(server, service.clone(), Limits::default()));
            client.write_all(b"\x16\x03\x01 not http\r\n\r\n").await.unwrap();
            let mut rest = Vec::new();
            let _ = tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut rest)).await;
            assert!(
                String::from_utf8_lossy(&rest).starts_with("HTTP/1.1 400") || rest.is_empty(),
                "{:?}",
                String::from_utf8_lossy(&rest)
            );
        });
    }

    #[test]
    fn a_client_that_sends_no_head_is_dropped_at_the_header_timeout() {
        let rig = Rig::new(Plan::Decline);
        let service = service_of(&rig);
        runtime().block_on(async {
            let (mut client, server) = tokio::io::duplex(4096);
            let limits = Limits { header_timeout: Duration::from_millis(300), ..Limits::default() };
            let handler = tokio::spawn(serve_connection(server, service.clone(), limits));
            client.write_all(b"POST /mcp HTTP/1.1\r\nHost: pro").await.unwrap(); // and nothing more
            let ended = tokio::time::timeout(Duration::from_secs(3), handler).await;
            assert!(ended.is_ok(), "the connection was not dropped");
        });
    }

    #[test]
    fn the_stream_head_comes_at_acceptance_with_keepalive_comments_until_the_answer() {
        let rig = Rig::new(Plan::Silent);
        let seen = Seen::default();
        // Approved after five comments have arrived at the client: the order is shown, not a count in wall time.
        rig.pledge.set(Plan::ApproveWhen(seen.clone(), 5, rig.pki.confirmed.clone()));
        let service = service_of(&rig);
        let sent = rig.jan("sys kit", &[]);
        runtime().block_on(async {
            let limits = Limits { keepalive: Duration::from_millis(100), ..Limits::default() };
            let reply =
                exchange_counting(&service, limits, &request(&call_body(&sent, Some("tok")), ""), Some(&seen)).await;
            assert_eq!(reply.status, 200);
            assert_eq!(reply.header("content-type"), Some("text/event-stream"));
            assert_eq!(reply.header("transfer-encoding"), Some("chunked"));
            assert!(reply.comments() >= 5, "{} comments while the person was asked", reply.comments());
            let messages = reply.messages();
            assert_eq!(messages.len(), 1, "no notice of progress");
            assert!(messages[0]["result"]["content"][0]["text"].as_str().unwrap().contains("\"outcome\":\"done\""));
            // The head came before any comment and the answer after all of them.
            let last = reply.chunks.last().unwrap();
            assert!(last.1.starts_with("event: message"), "{last:?}");
            assert!(reply.chunks[..reply.chunks.len() - 1].iter().all(|(_, c)| c.starts_with(": keepalive")));
            assert!(reply.chunks.iter().all(|(t, _)| *t >= reply.head_at));
        });
    }

    #[test]
    fn a_client_that_goes_away_cancels_the_call_at_once_not_at_the_next_keepalive() {
        let rig = Rig::new(Plan::Silent);
        let service = service_of(&rig);
        let sent = rig.jan("sys kit", &[]);
        runtime().block_on(async {
            // The default keepalive is 15 seconds: noticing the client at the next comment would take that long.
            let (mut client, server) = tokio::io::duplex(1 << 16);
            tokio::spawn(serve_connection(server, service.clone(), Limits::default()));
            client.write_all(&request(&call_body(&sent, Some("tok")), "")).await.unwrap();
            let mut head = [0u8; 256];
            let n = client.read(&mut head).await.unwrap();
            assert!(String::from_utf8_lossy(&head[..n]).starts_with("HTTP/1.1 200"));
            drop(client); // the agent is gone
        });
        let started = Instant::now();
        rig.pledge.wait_for("cancel");
        assert!(started.elapsed() < Duration::from_secs(60), "{:?}", started.elapsed());
        assert!(rig.ran().is_empty(), "nothing ran");
        assert_eq!(service.waiting(), 0);
    }

    #[test]
    fn over_a_unix_socket_through_the_accept_loop_two_calls_at_once_and_a_clean_shutdown() {
        let rig = Rig::new(Plan::Silent);
        rig.pledge.set(Plan::Approve(rig.pki.automatic.clone()));
        let service = service_of(&rig);
        let socket = socket_dir().join("probe.sock");
        runtime().block_on(async {
            let listener = tokio::net::UnixListener::bind(&socket).unwrap();
            let (stop, shutdown) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(accept_loop(listener, service.clone(), Limits::default(), shutdown));
            let (a, b) = (rig.jan("sys kit", &[]), rig.jan("sys kit", &[]));
            let ask = |sent: Sent| {
                let socket = socket.clone();
                async move {
                    let mut stream = tokio::net::UnixStream::connect(&socket).await.unwrap();
                    stream.write_all(&request(&call_body(&sent, None), "")).await.unwrap();
                    read_reply(&mut stream).await
                }
            };
            let (first, second) = tokio::join!(ask(a), ask(b));
            for reply in [first, second] {
                assert_eq!(reply.status, 200);
                let body: Value = serde_json::from_str(&reply.chunks[0].1).unwrap();
                assert!(
                    body["result"]["content"][0]["text"].as_str().unwrap().contains("\"outcome\":\"done\""),
                    "{body}"
                );
            }
            stop.send(()).unwrap();
            tokio::time::timeout(Duration::from_secs(3), server).await.expect("the loop ended").unwrap();
        });
        assert_eq!(rig.pledge.count("submit"), 2);
    }
}
