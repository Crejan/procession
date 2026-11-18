//! Shared by the stage-1 runs: the world on disk, the real `pledge serve`, `pact` over
//! this crate's MCP layer in process, and what the model is told.
#![allow(dead_code, unused_imports)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p_act::exchange::{
    Answer, ClearancePolicy, LineReader, Message, Outcome as Answered, PledgeReason, Refused, Submit, write_message,
};
use p_act::pact::bundle::Bundle;
use p_act::pact::catalogue::Catalogue;
use p_act::pact::mcp::{Context, call_once};
use p_act::pact::rt::{SystemClock, SystemRandomSource};
use p_act::pact::transport::{CancelToken, Transport, TransportError};
use p_act::pact::{Service as PactService, Settings};
use p_act::rating::Rating;
use p_act::sign::{PublicKey, Signer, sign_request, signature_from_base64};
use p_act::{Call, Request, Timestamp};
use p_robe::mcp::{HttpRequest, Mcp};
use p_robe::runner::InProcess;
use p_robe::service::{Service, Settings as ServiceSettings};
use p_robe::store::UsedStore;
use p_robe::{pledge, rate, setup};
use serde_json::{Value, json};
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

pub const HOST: &str = "a.example";

// ---- the world on disk -----------------------------------------------------------

pub fn dir_for(name: &str) -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let base = if Path::new("/tmp/claude").is_dir() { PathBuf::from("/tmp/claude") } else { std::env::temp_dir() };
    let dir = base.join(format!("s1-{}-{}-{name}", std::process::id() % 100_000, NEXT.fetch_add(1, Ordering::Relaxed)));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Writes a file that a program's rules will judge (pledge's `config.json`: no group or other write bit) with
/// mode 0600, created that way: **nothing here leans on the umask**, which is 0002 for an account that has a
/// group of its own name (Debian's default).
pub fn write_private(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    let _ = fs::remove_file(path);
    let mut file = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    file.write_all(bytes).unwrap();
    // `mode` is reduced by the umask but never raised: say it again.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

pub fn keygen(args: &[&str]) {
    let out = Command::new("ssh-keygen").args(args).stdin(Stdio::null()).output().expect("ssh-keygen");
    assert!(
        out.status.success(),
        "ssh-keygen {args:?}: {}\n  standard output: {}\n  standard error: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// `target/debug/pledge`, next to this test's `deps` directory.
pub fn pledge_binary() -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let path = exe.parent().and_then(Path::parent).unwrap().join("pledge");
    assert!(
        path.exists(),
        "{} is not built: cargo build --workspace --offline --features p-robe/test-verbs",
        path.display()
    );
    path
}

/// Panics with everything a program that did not start said: its exit status (or that it is still running)
/// and every line it wrote to standard output and standard error. A start failure always comes with the
/// program's own words.
pub fn start_failed(child: &mut Child, lines: &Receiver<String>, what: &str) -> ! {
    std::thread::sleep(Duration::from_millis(300)); // what it wrote last, and its readers, get a moment
    let status = match child.try_wait() {
        Ok(Some(status)) => format!("exited: {status}"),
        Ok(None) => "still running".to_string(),
        Err(e) => format!("status unknown: {e}"),
    };
    let written: Vec<String> = std::iter::from_fn(|| lines.try_recv().ok()).collect();
    panic!(
        "pledge serve did not start: {what}\n  the process: {status}\n  what it wrote ({} lines):\n{}",
        written.len(),
        if written.is_empty() {
            "    (nothing)".to_string()
        } else {
            written.iter().map(|l| format!("    {l}")).collect::<Vec<_>>().join("\n")
        }
    );
}

pub struct Pledge {
    pub child: Child,
    pub stdin: ChildStdin,
    pub lines: Receiver<String>,
    pub state: PathBuf,
    pub sockets: PathBuf,
    pub binary: PathBuf,
}

impl Pledge {
    pub fn start(dir: &Path) -> Pledge {
        let (state, sockets) = (dir.join("state"), dir.join("run"));
        fs::create_dir_all(&state).unwrap();
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        let host = fs::read_to_string(dir.join("host.pub")).unwrap();
        let config = json!({
            "person": "jan",
            "hosts": [{"host": HOST, "key": host.trim()}],
            "services": [{"host": HOST, "name": "probe", "url": std::env::var("PROBE_STAGE1_URL").unwrap_or_else(|_| "http://127.0.0.1:8443/mcp".into())}],
        });
        write_private(&state.join("config.json"), config.to_string().as_bytes());
        let binary = pledge_binary();
        let (child, stdin, lines) = Pledge::spawn(&binary, dir, &state, &sockets);
        Pledge { child, stdin, lines, state, sockets, binary }
    }

    pub fn spawn(binary: &Path, dir: &Path, state: &Path, sockets: &Path) -> (Child, ChildStdin, Receiver<String>) {
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
            .unwrap_or_else(|e| panic!("cannot start {}: {e}", binary.display()));
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
        // `pledge serve` binds agent.sock, control.sock and service.sock one after another and prints
        // "pledge: serving." only after all three: ready means all three answer (the CLI talks to control.sock,
        // the service to service.sock), not the first one that does.
        let started = Instant::now();
        for socket in ["agent.sock", "control.sock", "service.sock"] {
            while UnixStream::connect(sockets.join(socket)).is_err() {
                // If it has already gone, say so at once, with what it wrote; else after 10 seconds.
                let exited = child.try_wait().ok().flatten();
                if exited.is_some() || started.elapsed() > Duration::from_secs(10) {
                    start_failed(
                        &mut child,
                        &lines,
                        &format!("{socket} does not answer ({})", sockets.join(socket).display()),
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        (child, stdin, lines)
    }

    /// Kills `pledge serve` (no chance to write anything) and starts it again on the same directories.
    pub fn restart(&mut self, dir: &Path) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let (child, stdin, lines) = Pledge::spawn(&self.binary, dir, &self.state, &self.sockets);
        (self.child, self.stdin, self.lines) = (child, stdin, lines);
    }

    /// Forgets the lines printed so far, so that the next `wait_for` waits for a new one.
    pub fn drain(&self) {
        while self.lines.try_recv().is_ok() {}
    }

    /// Waits for a line of pledge's output that starts with `prefix` (a dialog is on screen).
    pub fn wait_for(&self, prefix: &str) -> String {
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
    pub fn answer(&mut self, text: &str) {
        self.stdin.write_all(text.as_bytes()).and_then(|()| self.stdin.flush()).unwrap();
    }

    pub fn run(&self, args: &[&str]) -> std::process::Output {
        Command::new(&self.binary)
            .args(args)
            .arg("--state-dir")
            .arg(&self.state)
            .arg("--socket-dir")
            .arg(&self.sockets)
            .output()
            .unwrap()
    }

    pub fn ok(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "pledge {args:?}: {}\n  standard output: {}\n  standard error: {}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).into_owned()
    }

    pub fn history(&self) -> Vec<Value> {
        self.ok(&["history", "--format", "json", "--verify"])
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// `pledge agents start` into a file: the bundle's bytes and the delegation's identifier.
    pub fn start_agent(&mut self, dir: &Path, name: &str) -> (Vec<u8>, String) {
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

pub struct InProcessMcp {
    pub service: Arc<Service>,
    /// What `tools/call` requests were posted, in order.
    pub posted: Mutex<Vec<Value>>,
    /// While set, a `tools/call` is recorded and not sent: the call was signed and goes nowhere.
    pub hold_calls: AtomicBool,
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
pub fn pact(bundle: &[u8], transport: &Arc<InProcessMcp>, settings: Settings) -> (Context, Vec<String>) {
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
pub struct Told {
    pub outcome: String,
    pub reason: Option<String>,
    pub rc: Option<i64>,
    pub rest: Vec<String>,
}

pub fn told(result: &Value) -> Told {
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

pub fn is(told: &Told, outcome: &str, reason: Option<&str>) -> bool {
    told.outcome == outcome && told.reason.as_deref() == reason
}

/// The request the service would have signed for a posted `tools/call`, rebuilt from its `_meta`.
pub fn request_of(sent: &Value, rating: Rating) -> Request {
    let meta = &sent["params"]["_meta"];
    let call_bytes = STANDARD.decode(meta["procession/call"].as_str().unwrap()).unwrap();
    let call_sig = signature_from_base64(meta["procession/call_sig"].as_str().unwrap()).unwrap();
    Request::compose(&Call::parse(call_bytes).unwrap(), &call_sig, rating).unwrap()
}

/// Submits `request` on `service.sock` as the service would, and returns pledge's answer.
pub fn submit(pledge: &Pledge, signer: &Signer, request: &Request) -> Answered {
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
