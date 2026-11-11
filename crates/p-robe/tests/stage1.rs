//! The first run of the real parts against each other, without HTTP:
//! the real `pledge serve` (keys in files, a fresh state directory, the person
//! scripted on its standard input), the real `pledge agents start` (and the
//! control socket for a delegation that is never delivered), `pact`'s own
//! parser, composer, catalogue and in-process signer (`p_act::pact`), and
//! this crate's service core reached through `Mcp::handle` in-process, with
//! the verb run in this process through the test feature's override instead of
//! sudo. Everything is real except the HTTP between `pact` and `probe`, sudo,
//! and the person.
//!
//! Needs `ssh-keygen`, a built `pledge` (`cargo build --workspace --features p-robe/test-verbs`)
//! and a directory where Unix sockets can be bound (`/tmp/claude/` in the sandbox this was written in).

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p_act::exchange::{Answer, ClearancePolicy, LineReader, Message, Outcome as Answered, Submit, write_message};
use p_act::pact::bundle::Bundle;
use p_act::pact::catalogue::Catalogue;
use p_act::pact::mcp::{Context, call_once};
use p_act::pact::rt::{SystemClock, SystemRandomSource};
use p_act::pact::transport::{CancelToken, Transport, TransportError};
use p_act::pact::{Service as PactService, Settings};
use p_act::rating::Rating;
use p_act::sign::{PublicKey, Signer, sign_request, signature_from_base64};
use p_act::{Call, Request, Timestamp};
use serde_json::{Value, json};

use p_robe::mcp::{HttpRequest, Mcp};
use p_robe::runner::InProcess;
use p_robe::service::{Service, Settings as ServiceSettings};
use p_robe::store::UsedStore;
use p_robe::{pledge, rate, setup};

const HOST: &str = "a.example";

// ---- the world on disk -----------------------------------------------------------

fn dir_for(name: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let base = if Path::new("/tmp/claude").is_dir() { PathBuf::from("/tmp/claude") } else { std::env::temp_dir() };
    let dir = base.join(format!("s1-{}-{}-{name}", std::process::id() % 100_000, NEXT.fetch_add(1, Ordering::Relaxed)));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn keygen(args: &[&str]) {
    let out = Command::new("ssh-keygen").args(args).stdin(Stdio::null()).output().expect("ssh-keygen");
    assert!(out.status.success(), "ssh-keygen {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

/// `target/debug/pledge`, next to this test's `deps` directory.
fn pledge_binary() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let path = exe.parent().and_then(Path::parent).unwrap().join("pledge");
    assert!(
        path.exists(),
        "{} is not built: cargo build --workspace --offline --features p-robe/test-verbs",
        path.display()
    );
    path
}

struct Pledge {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    state: PathBuf,
    sockets: PathBuf,
    binary: PathBuf,
}

impl Pledge {
    fn start(dir: &Path) -> Pledge {
        let (state, sockets) = (dir.join("state"), dir.join("run"));
        fs::create_dir_all(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let host = fs::read_to_string(dir.join("host.pub")).unwrap();
        let config = json!({
            "person": "jan",
            "hosts": [{"host": HOST, "key": host.trim()}],
            "services": [{"host": HOST, "name": "probe", "url": "http://127.0.0.1:8443/mcp"}],
        });
        fs::write(state.join("config.json"), config.to_string()).unwrap();
        let binary = pledge_binary();
        let (child, stdin, lines) = Pledge::spawn(&binary, dir, &state, &sockets);
        Pledge { child, stdin, lines, state, sockets, binary }
    }

    fn spawn(binary: &Path, dir: &Path, state: &Path, sockets: &Path) -> (Child, ChildStdin, Receiver<String>) {
        let mut child = Command::new(binary)
            .args(["serve", "--state-dir"])
            .arg(state)
            .arg("--socket-dir")
            .arg(sockets)
            .arg("--known-hosts")
            .arg(dir.join("known_hosts"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("pledge serve");
        let stdin = child.stdin.take().unwrap();
        let (tx, lines) = mpsc::channel();
        let (out, err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
        let tx2 = tx.clone();
        std::thread::spawn(move || {
            BufReader::new(out).lines().map_while(Result::ok).for_each(|l| drop(tx.send(format!("out: {l}"))))
        });
        std::thread::spawn(move || {
            BufReader::new(err).lines().map_while(Result::ok).for_each(|l| drop(tx2.send(format!("err: {l}"))))
        });
        let started = Instant::now();
        while UnixStream::connect(sockets.join("service.sock")).is_err() {
            assert!(started.elapsed() < Duration::from_secs(10), "pledge serve did not start");
            std::thread::sleep(Duration::from_millis(50));
        }
        (child, stdin, lines)
    }

    /// Kills `pledge serve` (no chance to write anything) and starts it again on the same directories.
    fn restart(&mut self, dir: &Path) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let (child, stdin, lines) = Pledge::spawn(&self.binary, dir, &self.state, &self.sockets);
        (self.child, self.stdin, self.lines) = (child, stdin, lines);
    }

    /// Waits for a line of pledge's output that starts with `prefix` (a dialog is on screen).
    fn wait_for(&self, prefix: &str) -> String {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match self.lines.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
                Ok(line)
                    if line
                        .trim_start_matches("out: ")
                        .trim_start_matches("err: ")
                        .trim_start()
                        .starts_with(prefix) =>
                {
                    return line;
                }
                Ok(_) => {}
                Err(_) => panic!("pledge serve did not print a line starting {prefix:?}"),
            }
        }
    }

    /// The answers the dialogs will read, in order.
    fn answer(&mut self, text: &str) {
        self.stdin.write_all(text.as_bytes()).and_then(|()| self.stdin.flush()).unwrap();
    }

    fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(&self.binary)
            .args(args)
            .arg("--state-dir")
            .arg(&self.state)
            .arg("--socket-dir")
            .arg(&self.sockets)
            .output()
            .unwrap()
    }

    fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(out.status.success(), "pledge {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    fn history(&self) -> Vec<Value> {
        self.ok(&["history", "--format", "json", "--verify"])
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// `pledge agents start` into a file: the bundle's bytes and the delegation's identifier.
    fn start_agent(&mut self, dir: &Path, name: &str) -> (Vec<u8>, String) {
        self.answer("y\n");
        let file = dir.join(name);
        self.ok(&["agents", "start", "--groups", "admins", "--output", file.to_str().unwrap()]);
        let listed: Value = serde_json::from_str(&self.ok(&["agents", "list", "--format", "json"])).unwrap();
        let id = listed["delegations"].as_array().unwrap().last().unwrap()["delegation"].as_str().unwrap().to_owned();
        (fs::read(file).unwrap(), id)
    }
}

impl Drop for Pledge {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

// ---- pact's transport: this crate's MCP layer, in process ---------------------------

struct InProcessMcp {
    service: Arc<Service>,
    /// What `tools/call` requests were posted, in order.
    posted: Mutex<Vec<Value>>,
    /// While set, a `tools/call` is recorded and not sent: the call was signed and goes nowhere.
    hold_calls: AtomicBool,
}

impl Transport for InProcessMcp {
    fn post(&self, _: &PactService, request: &Value, cancel: &CancelToken) -> Result<Value, TransportError> {
        if request["method"] == "tools/call" {
            self.posted.lock().unwrap().push(request.clone());
            if self.hold_calls.load(Ordering::SeqCst) {
                return Err(TransportError::NotSent("held by the test".into()));
            }
        }
        let http = HttpRequest {
            method: "POST".into(),
            path: "/mcp".into(),
            headers: vec![
                ("Accept".into(), "application/json, text/event-stream".into()),
                ("Content-Type".into(), "application/json".into()),
                ("MCP-Protocol-Version".into(), "2025-06-18".into()),
            ],
            body: request.to_string().into_bytes(),
        };
        // The model's cancel closes the connection: here, it sets the flag the layer watches.
        let (gone, done) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        let watcher = {
            let (cancel, gone, done) = (cancel.clone(), gone.clone(), done.clone());
            std::thread::spawn(move || {
                while !done.load(Ordering::SeqCst) {
                    if cancel.is_cancelled() {
                        gone.store(true, Ordering::SeqCst);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            })
        };
        let response = Mcp::new(&self.service).handle(&http, &gone);
        done.store(true, Ordering::SeqCst);
        let _ = watcher.join();
        let content_type = response
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.clone())
            .unwrap_or_default();
        match response.status {
            200 if content_type.starts_with("text/event-stream") => {
                let text = String::from_utf8_lossy(&response.body).into_owned();
                text.split("\n\n")
                    .filter_map(|event| event.lines().find_map(|l| l.strip_prefix("data: ")))
                    .filter_map(|data| serde_json::from_str::<Value>(data).ok())
                    .find(|message| message["id"] == request["id"])
                    .ok_or_else(|| TransportError::Lost("no response in the stream".into()))
            }
            200 => serde_json::from_slice(&response.body).map_err(|e| TransportError::Lost(e.to_string())),
            503 => Err(TransportError::TryLater),
            status => Err(TransportError::Unavailable(format!("HTTP {status}"))),
        }
    }
}

/// `pact`, with a bundle: its own parser, its catalogue from this service's `tools/list`, its signer.
fn pact(bundle: &[u8], transport: &Arc<InProcessMcp>, settings: Settings) -> (Context, Vec<String>) {
    let bundle = Bundle::parse(bundle, Timestamp::now().unwrap()).expect("pact reads the bundle pledge wrote");
    let services = bundle.config.services.clone();
    let (catalogue, dropped) = Catalogue::build(&services, &settings, transport).expect("catalogue");
    let context = Context::new(
        services,
        catalogue,
        bundle.key,
        settings,
        Box::new(transport.clone()),
        Box::new(SystemClock),
        Box::new(SystemRandomSource::default()),
        Box::new(|_| {}),
    );
    (context, dropped)
}

/// What the model is told: the outcome word, the reason, and the rest of the texts.
#[derive(Debug, PartialEq, Eq)]
struct Told {
    outcome: String,
    reason: Option<String>,
    rc: Option<i64>,
    rest: Vec<String>,
}

fn told(result: &Value) -> Told {
    let texts: Vec<&str> = result["content"]
        .as_array()
        .unwrap_or_else(|| panic!("no content: {result}"))
        .iter()
        .filter_map(|c| c["text"].as_str())
        .collect();
    let line: Value = serde_json::from_str(texts[0]).unwrap_or_else(|_| panic!("not an outcome line: {result}"));
    Told {
        outcome: line["outcome"].as_str().unwrap().to_owned(),
        reason: line["reason"].as_str().map(str::to_owned),
        rc: line["rc"].as_i64(),
        rest: texts[1..].iter().map(|t| (*t).to_owned()).collect(),
    }
}

fn is(told: &Told, outcome: &str, reason: Option<&str>) -> bool {
    told.outcome == outcome && told.reason.as_deref() == reason
}

/// The request the service would have signed for a posted `tools/call`, rebuilt from its `_meta`.
fn request_of(sent: &Value, rating: Rating) -> Request {
    let meta = &sent["params"]["_meta"];
    let call_bytes = STANDARD.decode(meta["procession/call"].as_str().unwrap()).unwrap();
    let call_sig = signature_from_base64(meta["procession/call_sig"].as_str().unwrap()).unwrap();
    Request::compose(&Call::parse(call_bytes).unwrap(), &call_sig, rating).unwrap()
}

/// Submits `request` on `service.sock` as the service would, and returns pledge's answer.
fn submit(pledge: &Pledge, signer: &Signer, request: &Request) -> Answered {
    let mut stream = UnixStream::connect(pledge.sockets.join("service.sock")).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let sig = sign_request(signer, request).unwrap();
    write_message(&mut stream, &Message::Submit(Submit::new(request.clone(), &sig).unwrap()), ClearancePolicy::Refused)
        .unwrap();
    match LineReader::new(&stream).read_message(ClearancePolicy::Refused).unwrap().unwrap() {
        Message::Answer(Answer { outcome, .. }) => outcome,
        other => panic!("{other:?}"),
    }
}

// ---- the run ---------------------------------------------------------------------------------

#[test]
fn the_real_parts_against_each_other() {
    let dir = dir_for("run");
    let path = |name: &str| dir.join(name).to_string_lossy().into_owned();
    // A throwaway host key that pledge's configuration names, and the service's key and certificate
    // made by this crate's own setup.
    keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", &path("host")]);
    setup::run(&dir.join("host"), HOST, &dir.join("probe")).expect("probe setup");
    let mut pledge = Pledge::start(&dir);
    for purpose in ["delegation", "confirmed", "automatic"] {
        pledge.answer("y\n");
        pledge.ok(&["keys", "create", purpose]);
    }
    let keys: Value = serde_json::from_str(&pledge.ok(&["keys", "list", "--format", "json"])).unwrap();
    let key = |purpose: &str| {
        let entry = keys["keys"].as_array().unwrap().iter().find(|k| k["purpose"] == purpose).unwrap();
        PublicKey::parse(entry["public"].as_str().unwrap()).unwrap()
    };

    // The `test read` verb rates `<sandbox>/open/` harmless.
    let sandbox = fs::canonicalize(&dir).unwrap().join("sandbox");
    for sub in ["open", "private"] {
        fs::create_dir_all(sandbox.join(sub)).unwrap();
        fs::set_permissions(sandbox.join(sub), fs::Permissions::from_mode(0o755)).unwrap();
    }
    rate::SANDBOX.set(sandbox.clone()).unwrap();

    // The service: its key and certificate from setup, pledge's socket, the identifiers on disk,
    // the dispatcher in this process in place of sudo (a caller that is root: the sudo path does not run).
    type Hook = Arc<Mutex<Option<Box<dyn Fn() + Send + Sync>>>>;
    let hook: Hook = Arc::new(Mutex::new(None));
    let runner = {
        let hook = hook.clone();
        InProcess {
            audit_file: dir.join("dispatcher.log"),
            lock_dir: dir.join("locks"),
            user: "probe".into(),
            before: Some(Box::new(move || {
                if let Some(plant) = hook.lock().unwrap().as_ref() {
                    plant();
                }
            })),
        }
    };
    fs::create_dir_all(dir.join("locks")).unwrap();
    fs::create_dir_all(dir.join("used")).unwrap();
    let log = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = log.clone();
    let service = Arc::new(Service::new(
        ServiceSettings {
            host: HOST.into(),
            person: "jan".into(),
            confirmed: key("confirmed"),
            automatic: key("automatic"),
            max_waiting: 16,
        },
        Signer::certified(dir.join("probe/service-key")).unwrap(),
        UsedStore::new(dir.join("used")),
        pledge::PledgeLink { socket: pledge.sockets.join("service.sock"), uid: unsafe { libc::geteuid() } },
        Box::new(runner),
        Box::new(move |line| sink.lock().unwrap().push(line.to_string())),
    ));
    let transport =
        Arc::new(InProcessMcp { service, posted: Mutex::new(Vec::new()), hold_calls: AtomicBool::new(false) });

    let (bundle, _first_id) = pledge.start_agent(&dir, "bundle1");
    let (agent, dropped) = pact(&bundle, &transport, Settings::new(120, None));
    assert!(dropped.is_empty(), "pact dropped tools of this service: {dropped:?}");
    let names: Vec<String> = agent.catalogue.read().unwrap().tools.iter().map(|t| t.name.clone()).collect();
    for expected in ["test_echo", "test_peak", "test_read", "sys_kit"] {
        assert!(names.contains(&expected.to_string()), "{expected} not in {names:?}");
    }
    let call = |ctx: &Context, tool: &str, params: &[&str]| told(&call_once(ctx, tool, &json!({"params": params})));
    let mut expected: Vec<(&str, Option<&str>)> = Vec::new(); // what pledge's record must say, request by request

    // 1. `test echo` under a default delegation: harmless, automatic, done.
    let echo = call(&agent, "test_echo", &["a=1"]);
    assert!(is(&echo, "done", None) && echo.rc == Some(0), "{echo:?} {:?}", log.lock().unwrap());
    assert!(echo.rest[0].contains("\"args\":[\"a=1\"]"), "{echo:?}");
    expected.push(("approved", None));

    // 2. `test peak`: the top of a scale: asked, the presence check, the confirmed key, done.
    pledge.answer("y\ny\n");
    let peak = call(&agent, "test_peak", &[]);
    assert!(is(&peak, "done", None), "{peak:?} {:?}", log.lock().unwrap());
    assert!(log.lock().unwrap().iter().any(|l| l.contains("approval=confirmed")), "{:?}", log.lock().unwrap());
    expected.push(("approved", None));

    // 3. The same, the person declines.
    pledge.answer("n\n");
    let declined = call(&agent, "test_peak", &[]);
    assert!(is(&declined, "declined", None), "{declined:?}");
    expected.push(("declined", None));

    // 4. `test read` with a path whose rating differs between the two ratings: a link planted
    //    between the service's and the dispatcher's. `--within` refuses; the agent is told not-allowed.
    let (link, harmless, secret) = (sandbox.join("open/link"), sandbox.join("open/a"), sandbox.join("private/s"));
    fs::write(&harmless, "hello").unwrap();
    fs::write(&secret, "secret").unwrap();
    std::os::unix::fs::symlink(&harmless, &link).unwrap();
    let plain = call(&agent, "test_read", &[link.to_str().unwrap()]);
    assert!(is(&plain, "done", None) && plain.rest[0].contains("\"text\":\"hello\""), "{plain:?}");
    expected.push(("approved", None));
    {
        let (link, secret) = (link.clone(), secret.clone());
        *hook.lock().unwrap() = Some(Box::new(move || {
            let _ = fs::remove_file(&link);
            std::os::unix::fs::symlink(&secret, &link).unwrap();
        }));
    }
    let planted = call(&agent, "test_read", &[link.to_str().unwrap()]);
    *hook.lock().unwrap() = None;
    assert!(is(&planted, "refused", Some("not-allowed")), "{planted:?}");
    assert!(planted.rest.is_empty(), "the secret was not read: {planted:?}");
    expected.push(("approved", None)); // pledge approved what it was shown; the dispatcher refused later

    // 5. The same call sent twice: the service's identifier store refuses the second, pledge is not asked.
    let first_call = transport.posted.lock().unwrap().first().unwrap().clone();
    let before = pledge.history().iter().filter(|e| e["type"] == "request").count();
    let again = told(
        &transport
            .post(
                &PactService { host: HOST.into(), name: "probe".into(), url: String::new() },
                &first_call,
                &CancelToken::default(),
            )
            .unwrap()["result"],
    );
    assert!(is(&again, "refused", Some("invalid")), "{again:?}");
    assert_eq!(
        pledge.history().iter().filter(|e| e["type"] == "request").count(),
        before,
        "pledge was not asked again"
    );

    // 6. The same request bytes submitted twice to pledge: its answer store answers the second.
    transport.hold_calls.store(true, Ordering::SeqCst);
    let held = call(&agent, "test_echo", &["held=1"]);
    transport.hold_calls.store(false, Ordering::SeqCst);
    assert_eq!(held.outcome, "unavailable", "{held:?}");
    let sent = transport.posted.lock().unwrap().last().unwrap().clone();
    let meta = &sent["params"]["_meta"];
    let call_bytes = STANDARD.decode(meta["procession/call"].as_str().unwrap()).unwrap();
    let call_sig = signature_from_base64(meta["procession/call_sig"].as_str().unwrap()).unwrap();
    let request = Request::compose(&Call::parse(call_bytes).unwrap(), &call_sig, Rating::HARMLESS).unwrap();
    let service_signer = Signer::certified(dir.join("probe/service-key")).unwrap();
    let submit_twice = |_: ()| {
        let mut stream = UnixStream::connect(pledge.sockets.join("service.sock")).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let sig = sign_request(&service_signer, &request).unwrap();
        write_message(
            &mut stream,
            &Message::Submit(Submit::new(request.clone(), &sig).unwrap()),
            ClearancePolicy::Refused,
        )
        .unwrap();
        match LineReader::new(&stream).read_message(ClearancePolicy::Refused).unwrap().unwrap() {
            Message::Answer(Answer { outcome: Answered::Approved(a), .. }) => a.approval().to_owned(),
            other => panic!("{other:?}"),
        }
    };
    let (one, two) = (submit_twice(()), submit_twice(()));
    assert_eq!(one, two, "the same bytes got the same approval");
    expected.push(("approved", None)); // once, for both submissions

    // 7. A delegation withdrawn with `pledge agents withdraw`, then a call.
    let (bundle2, id2) = pledge.start_agent(&dir, "bundle2");
    let (second, _) = pact(&bundle2, &transport, Settings::new(120, None));
    pledge.ok(&["agents", "withdraw", &id2]);
    let withdrawn = call(&second, "test_echo", &[]);
    assert!(is(&withdrawn, "refused", Some("not-allowed")), "{withdrawn:?}");
    expected.push(("refused", Some("delegation-withdrawn")));

    // 8. A delegation issued but never delivered: `agents.start` on the control socket, the bundle taken, no `agents.delivered`.
    pledge.answer("y\n");
    let mut control = UnixStream::connect(pledge.sockets.join("control.sock")).unwrap();
    control.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    let command = json!({"schema_version": 1, "type": "command", "ref": "1", "name": "agents.start", "args": {
        "groups": ["admins"], "services": [{"host": HOST, "name": "probe", "url": "http://127.0.0.1:8443/mcp"}]}});
    writeln!(control, "{command}").unwrap();
    let mut reply = String::new();
    BufReader::new(&control).read_line(&mut reply).unwrap();
    let reply: Value = serde_json::from_str(&reply).unwrap();
    assert_eq!(reply["result"], "ok", "{reply}");
    let undelivered = STANDARD.decode(reply["data"]["bundle"].as_str().unwrap()).unwrap();
    let (third, _) = pact(&undelivered, &transport, Settings::new(120, None));
    let never = call(&third, "test_echo", &[]);
    assert!(is(&never, "refused", Some("not-allowed")), "{never:?}");
    expected.push(("refused", Some("unknown-delegation")));
    drop(control); // the connection ends: it never existed

    // 9. A deadline that passes with the dialog open (last: a dialog that is still reading stands in the way of the next answer).
    let (short, _) = pact(&bundle, &transport, Settings::new(3, Some(1)));
    let started = Instant::now();
    let expired = call(&short, "test_peak", &[]);
    assert!(is(&expired, "expired", None), "{expired:?}");
    assert!(
        started.elapsed() >= Duration::from_secs(2) && started.elapsed() < Duration::from_secs(8),
        "{:?}",
        started.elapsed()
    );
    expected.push(("expired", None));

    let peak_rating =
        Rating::new(p_act::rating::Exposure::Open, p_act::rating::Damage::None, p_act::rating::Disruption::Outage);
    let peak_starts =
        || fs::read_to_string(dir.join("dispatcher.log")).unwrap_or_default().matches("verb=peak").count();
    let hold = |on: bool| transport.hold_calls.store(on, Ordering::SeqCst);
    let (open_service, requests) =
        (PactService { host: HOST.into(), name: "probe".into(), url: String::new() }, |p: &Pledge| {
            p.history().iter().filter(|e| e["type"] == "request").count()
        });

    // 10. The agent goes away while the dialog is open. EXPECTED (service-sock.md section 4, connections
    //     3.4 and section 2): the service's connection closes, which cancels; pledge closes the dialog and
    //     records `cancelled`; no approval, the verb does not run.
    hold(true);
    let _ = call(&agent, "test_peak", &[]);
    hold(false);
    let signed = transport.posted.lock().unwrap().last().unwrap().clone();
    let (cancel, starts) = (CancelToken::default(), peak_starts());
    let worker = {
        let (transport, cancel, signed, service) =
            (transport.clone(), cancel.clone(), signed.clone(), open_service.clone());
        std::thread::spawn(move || transport.post(&service, &signed, &cancel))
    };
    pledge.wait_for("action:");
    cancel.cancel();
    let gone = worker.join().unwrap();
    assert!(gone.is_err(), "no answer is written to a client that went away: {gone:?}");
    let waited = Instant::now();
    while pledge.history().last().map(|e| e["result"].clone()) != Some(json!("cancelled")) {
        assert!(waited.elapsed() < Duration::from_secs(5), "pledge did not record the cancel");
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(peak_starts(), starts, "the verb did not run");
    expected.push(("cancelled", None));

    // 11. `pledge serve` is killed and started again with a request open. EXPECTED: the service's
    //     connection ends, so it tells the agent `unavailable` and does not submit again; pledge,
    //     killed, wrote nothing for the open request (no entry); after the restart pledge knows
    //     the request neither as used nor as answered (service-sock.md section 6: only approved and declined
    //     are stored), so the same bytes submitted by hand are asked about again; the same call
    //     through the service is refused by its own store (`call-used`); a new call works.
    hold(true);
    let _ = call(&agent, "test_peak", &[]);
    hold(false);
    let open_call = transport.posted.lock().unwrap().last().unwrap().clone();
    let worker = {
        let (transport, open_call, service) = (transport.clone(), open_call.clone(), open_service.clone());
        std::thread::spawn(move || transport.post(&service, &open_call, &CancelToken::default()))
    };
    pledge.wait_for("action:");
    let entries = requests(&pledge);
    pledge.restart(&dir);
    let after_kill = told(&worker.join().unwrap().expect("the service answered")["result"]);
    assert!(is(&after_kill, "unavailable", None), "{after_kill:?}");
    assert_eq!(requests(&pledge), entries, "the killed pledge wrote nothing for the open request");
    let used = told(&transport.post(&open_service, &open_call, &CancelToken::default()).unwrap()["result"]);
    assert!(is(&used, "refused", Some("invalid")), "the service's store: {used:?}");
    pledge.answer("y\ny\n");
    let again = submit(
        &pledge,
        &Signer::certified(dir.join("probe/service-key")).unwrap(),
        &request_of(&open_call, peak_rating),
    );
    assert!(matches!(again, Answered::Approved(_)), "the restarted pledge asked again: {again:?}");
    expected.push(("approved", None));
    let fresh = call(&agent, "test_echo", &["after=restart"]);
    assert!(is(&fresh, "done", None), "{fresh:?}");
    expected.push(("approved", None));
    assert!(log.lock().unwrap().iter().any(|l| l.contains("no-route:")), "{:?}", log.lock().unwrap());

    // 12. Parameters shown whole: 512 bytes each, all together at most 2000 characters (connections 3.7).
    //     Each is within the service's own limit; pledge refuses the call as not showable, the agent is told invalid.
    let long = "x".repeat(450);
    let five: Vec<&str> = std::iter::repeat_n(long.as_str(), 5).collect();
    let too_long = call(&agent, "test_echo", &five);
    assert!(is(&too_long, "refused", Some("invalid")), "{too_long:?}");
    assert!(log.lock().unwrap().iter().any(|l| l.contains("pledge:not-showable")), "{:?}", log.lock().unwrap());
    expected.push(("refused", Some("not-showable")));

    // The record, against what the agent was told. `--verify` checks the chain (it fails the command if broken).
    std::thread::sleep(Duration::from_millis(300));
    let history = pledge.history();
    let results: Vec<(String, Option<String>)> = history
        .iter()
        .filter(|e| e["type"] == "request")
        .map(|e| (e["result"].as_str().unwrap().to_owned(), e["reason"].as_str().map(str::to_owned)))
        .collect();
    let expected: Vec<(String, Option<String>)> =
        expected.iter().map(|(r, why)| ((*r).to_owned(), why.map(str::to_owned))).collect();
    assert_eq!(results, expected, "the record, request by request");
    let events: Vec<(String, String)> = history
        .iter()
        .filter_map(|e| e["event"].as_str().map(|ev| (ev.to_owned(), e["by"].as_str().unwrap_or("").to_owned())))
        .collect();
    assert!(events.contains(&("delegation-withdrawn".into(), "person".into())), "{events:?}");
    // A delegation never delivered never was one: `delegation-not-delivered`, and never "withdrawn" nor "issued".
    assert!(events.iter().any(|(e, _)| e == "delegation-not-delivered"), "{events:?}");
    assert_eq!(events.iter().filter(|(e, _)| e == "delegation-issued").count(), 2, "{events:?}");
    assert_eq!(events.iter().filter(|(e, _)| e == "delegation-withdrawn").count(), 1, "{events:?}");
    let record = fs::read_to_string(pledge.state.join("record.jsonl")).unwrap();
    assert!(!record.contains("PRIVATE KEY"));
    // What the service logged for each call, with the exact code.
    eprintln!("{}", log.lock().unwrap().join("\n"));
    let _ = fs::remove_dir_all(&dir);
}
