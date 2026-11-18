//! A site in a temporary directory, with real keys made by `ssh-keygen`, a broker over it, and clients
//! that speak the connections' lines over in-memory streams. Nothing here touches anything outside the
//! directory and nothing prompts.

#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p_act::broker::ConnectionDocument;
use p_act::exchange::{Answer, Approved, ClearancePolicy, Message, Outcome, Submit};
use p_act::rating::{Damage, Disruption, Exposure, Rating};
use p_act::sign::{Namespace, PublicKey, Signer, sign_call, sign_request, signature_to_base64};
use p_act::{Call, CallContent, CallId, Document, DocumentHash, Request, ServiceId, Timestamp};
use p_age::core::{Core, Settings};
use p_age::crypto::SshCrypto;
use p_age::log::MemoryLog;
use p_age::net::{Broker, Clock, Lines, Timeouts, serve_connection};
use p_age::site::Site;
use tempfile::TempDir;
use tokio::io::{AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf, duplex};

pub const VALID: &str = "20200101Z:20990101Z";

/// Where the tests make their directories. A Unix socket is bound in one of them (the administrator's), and some
/// sandboxes allow that only under one directory: `PAGE_TEST_DIR` if set, else `/tmp/claude` if it is there, else
/// the system's temporary directory.
pub fn socket_base() -> PathBuf {
    if let Some(dir) = std::env::var_os("PAGE_TEST_DIR") {
        return PathBuf::from(dir);
    }
    let sandbox = PathBuf::from("/tmp/claude");
    if sandbox.is_dir() { sandbox } else { std::env::temp_dir() }
}

pub struct Keys {
    pub dir: TempDir,
}

impl Keys {
    pub fn new() -> Keys {
        let dir = tempfile::Builder::new().tempdir_in(socket_base()).unwrap();
        std::fs::set_permissions(dir.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        Keys { dir }
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    pub fn keygen(&self, args: &[&str]) {
        let out =
            Command::new("ssh-keygen").args(args).stdin(Stdio::null()).output().expect("these tests need ssh-keygen");
        assert!(out.status.success(), "ssh-keygen {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    pub fn key(&self, name: &str) -> PathBuf {
        let path = self.path(name);
        self.keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", path.to_str().unwrap()]);
        path
    }

    /// A key certified by `ca`, issued as pledge does (`-O clear`, then `options`); the private key's path.
    pub fn certified(&self, name: &str, ca: &Path, principals: &str, validity: &str, options: &[&str]) -> PathBuf {
        let key = self.key(name);
        let pub_file = format!("{}.pub", key.display());
        let mut args =
            vec!["-q", "-s", ca.to_str().unwrap(), "-I", name, "-n", principals, "-V", validity, "-O", "clear"];
        for o in options {
            args.extend(["-O", o]);
        }
        args.push(&pub_file);
        self.keygen(&args);
        key
    }

    pub fn public(&self, key: &Path) -> PublicKey {
        PublicKey::read(&PathBuf::from(format!("{}.pub", key.display()))).unwrap()
    }

    /// The `-cert.pub` line of a certified key.
    pub fn cert_line(&self, key: &Path) -> String {
        std::fs::read_to_string(format!("{}-cert.pub", key.display())).unwrap().trim_end().to_owned()
    }
}

/// A clock that starts at the real time (certificates are checked against the real one) and moves on request.
pub struct TestClock(AtomicI64);

impl TestClock {
    pub fn new() -> Arc<TestClock> {
        let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
        Arc::new(TestClock(AtomicI64::new(i64::try_from(now).unwrap())))
    }

    pub fn unix(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }

    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now(&self) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(self.unix()).unwrap())
    }
}

pub struct World {
    pub keys: Keys,
    pub site_ca: PathBuf,
    pub broker_key: PathBuf,
    pub host_key: PathBuf,
    pub service: PathBuf,
    pub jan_connection: PathBuf,
    pub eva_connection: PathBuf,
    pub jan_delegation: PathBuf,
    pub jan_confirmed: PathBuf,
    pub agent: PathBuf,
    pub clock: Arc<TestClock>,
    pub log: MemoryLog,
    pub broker: Arc<Broker>,
    pub state: PathBuf,
}

impl World {
    pub fn new() -> World {
        World::with(Settings::default(), Timeouts::default())
    }

    pub fn with(settings: Settings, timeouts: Timeouts) -> World {
        let keys = Keys::new();
        let site_ca = keys.key("site-ca");
        let broker_key = keys.certified("broker", &site_ca, "broker", VALID, &[]);
        let host_key = keys.key("host");
        let service = keys.certified("service", &host_key, "probe@a.example", VALID, &[]);
        let (jan_connection, eva_connection) = (keys.key("jan-connection"), keys.key("eva-connection"));
        let (jan_delegation, eva_delegation) = (keys.key("jan-delegation"), keys.key("eva-delegation"));
        let jan_confirmed = keys.certified("jan-confirmed", &site_ca, "jan:confirmed", VALID, &[]);
        let agent = keys.certified("agent", &jan_delegation, "jan", "-5m:+8h", &["extension:groups@procession=ops"]);
        let (jan_automatic, eva_confirmed, eva_automatic) =
            (keys.key("jan-automatic"), keys.key("eva-confirmed"), keys.key("eva-automatic"));
        let row = |k: &Path| format!(r#"{{"key":"{}","verified_on":"2026-11-10"}}"#, keys.public(k));
        let person = |name: &str, conn: &Path, deleg: &Path, confirmed: &Path, automatic: &Path| {
            format!(
                r#"{{"name":"{name}","enabled":true,"groups":["ops"],"keys":{{"confirmed":{},"automatic":{},"delegation":{},"connection":{}}}}}"#,
                row(confirmed),
                row(automatic),
                row(deleg),
                row(conn)
            )
        };
        let json = format!(
            r#"{{"persons":[{},{}],"hosts":[{{"name":"a.example","key":"{}"}}]}}"#,
            person("jan", &jan_connection, &jan_delegation, &jan_confirmed, &jan_automatic),
            person("eva", &eva_connection, &eva_delegation, &eva_confirmed, &eva_automatic),
            keys.public(&host_key)
        );
        let site = Arc::new(Site::from_json(&json).unwrap());
        let clock = TestClock::new();
        let log = MemoryLog::default();
        let state = keys.path("register.json");
        let crypto = Arc::new(SshCrypto::new(&broker_key));
        let core = Core::new(
            Arc::clone(&site),
            settings,
            {
                Core::init_state(&state).unwrap();
                Core::read_state(&state).unwrap()
            },
            Some(state.clone()),
            crypto.clone(),
            Box::new(log.clone()),
        );
        let broker = Broker::new(core, crypto, site, clock.clone(), timeouts, 8);
        World {
            keys,
            site_ca,
            broker_key,
            host_key,
            service,
            jan_connection,
            eva_connection,
            jan_delegation,
            jan_confirmed,
            agent,
            clock,
            log,
            broker,
            state,
        }
    }

    pub fn ca(&self) -> PublicKey {
        self.keys.public(&self.site_ca)
    }

    /// A signed call under the agent, due `due` seconds from now, number `n`.
    pub fn call(&self, n: u32, due: i64, agent: &Path) -> (Call, String) {
        let content = CallContent {
            id: CallId::parse(&format!("3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f{n:04x}")).unwrap(),
            deadline: Timestamp::from_unix(self.clock.unix() + due).unwrap(),
            service: ServiceId { host: "a.example".into(), name: "probe".into() },
            action: "rt procs".into(),
            params: vec![format!("pid={n}")],
            claim: None,
        };
        let call = Call::compose(&content).unwrap();
        let sig = sign_call(&Signer::certified(agent).unwrap(), &call).unwrap();
        (call, sig)
    }

    /// The `submit` a service would send for call `n`, signed by `service`.
    pub fn submit(&self, n: u32, due: i64) -> Submit {
        self.submit_with(n, due, &self.agent, &self.service)
    }

    pub fn submit_with(&self, n: u32, due: i64, agent: &Path, service: &Path) -> Submit {
        let (call, call_sig) = self.call(n, due, agent);
        let rating = Rating::new(Exposure::Internal, Damage::None, Disruption::None);
        let request = Request::compose(&call, &call_sig, rating).unwrap();
        let sig = sign_request(&Signer::certified(service).unwrap(), &request).unwrap();
        Submit::new(request, &sig).unwrap()
    }
}

pub fn submit_line(s: &Submit) -> Vec<u8> {
    Message::Submit(s.clone()).encode(ClearancePolicy::Refused).unwrap()
}

/// The line pledge answers with: approved by `approval`.
pub fn approval_line(hash: DocumentHash, approval: &str) -> Vec<u8> {
    let a = Answer { request: hash, outcome: Outcome::Approved(Approved::new(approval, None).unwrap()) };
    Message::Answer(a).encode(ClearancePolicy::Refused).unwrap()
}

pub fn answer_line(hash: DocumentHash, outcome: Outcome) -> Vec<u8> {
    Message::Answer(Answer { request: hash, outcome }).encode(ClearancePolicy::Refused).unwrap()
}

/// One end of a connection, with what a test needs to say and hear.
pub struct Client {
    pub lines: Lines<ReadHalf<DuplexStream>>,
    pub wr: WriteHalf<DuplexStream>,
}

impl Client {
    fn new(stream: DuplexStream, timeouts: Timeouts) -> Client {
        let (rd, wr) = tokio::io::split(stream);
        Client { lines: Lines::new(rd, timeouts.line), wr }
    }

    pub async fn send(&mut self, line: &[u8]) {
        self.wr.write_all(line).await.unwrap();
        self.wr.flush().await.unwrap();
    }

    pub async fn send_json(&mut self, value: serde_json::Value) {
        let mut line = serde_json::to_vec(&value).unwrap();
        line.push(b'\n');
        self.send(&line).await;
    }

    /// The next line, or `None` when the peer closed. Fails the test after five seconds.
    pub async fn recv_raw(&mut self) -> Option<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(5), self.lines.read(None))
            .await
            .expect("no line in 5 s")
            .unwrap_or(None)
    }

    pub async fn recv(&mut self) -> serde_json::Value {
        let line = self.recv_raw().await.expect("the peer closed");
        serde_json::from_slice(&line).unwrap()
    }

    /// The `type` of the next line.
    pub async fn recv_type(&mut self) -> String {
        self.recv().await["type"].as_str().unwrap().to_owned()
    }

    /// Nothing more is coming: the peer closed.
    pub async fn expect_closed(&mut self) {
        assert_eq!(self.recv_raw().await, None);
    }
}

pub fn open_service(w: &World) -> Client {
    open_service_on(&w.broker, Timeouts::default())
}

pub fn open_service_on(broker: &Arc<Broker>, timeouts: Timeouts) -> Client {
    open_raw_on(broker, BINDING, timeouts)
}

pub const BINDING: [u8; 32] = [7; 32];

/// A connection to the broker that has not said what it is.
pub fn open_raw_on(broker: &Arc<Broker>, binding: [u8; 32], timeouts: Timeouts) -> Client {
    let (a, b) = duplex(1 << 20);
    tokio::spawn(serve_connection(b, binding, Arc::clone(broker)));
    Client::new(a, timeouts)
}

/// A pledge's connection: it has said `hello`; the challenge is next.
pub async fn open_pledge_on(broker: &Arc<Broker>, binding: [u8; 32], timeouts: Timeouts) -> Client {
    let mut c = open_raw_on(broker, binding, timeouts);
    c.send_json(serde_json::json!({"schema_version":1,"type":"hello"})).await;
    c
}

pub async fn open_pledge(w: &World) -> Client {
    open_pledge_on(&w.broker, BINDING, Timeouts::default()).await
}

/// The connection document for the nonce the broker sent (base64, 32 bytes) and the TLS binding.
pub fn connection_doc(person: &str, nonce_b64: &str, binding: [u8; 32]) -> ConnectionDocument {
    let nonce: [u8; 32] = STANDARD.decode(nonce_b64).unwrap().try_into().unwrap();
    ConnectionDocument::compose(person, &nonce, &binding).unwrap()
}

/// The sign-in message for `person`, signed with `key`, for the nonce and binding given.
pub fn signin_message(person: &str, key: &Path, nonce: &str, binding: [u8; 32]) -> serde_json::Value {
    let doc = connection_doc(person, nonce, binding);
    let sig = doc.sign(&Signer::plain(key)).unwrap();
    serde_json::json!({"schema_version":1,"type":"signin","doc":STANDARD.encode(doc.as_bytes()),"doc_sig":signature_to_base64(&sig)})
}

impl Client {
    /// Read the challenge, sign in as `person` with `key`; the nonce.
    pub async fn sign_in(&mut self, person: &str, key: &Path) -> String {
        let challenge = self.recv().await;
        assert_eq!(challenge["type"], "challenge");
        let nonce = challenge["nonce"].as_str().unwrap().to_owned();
        self.send_json(signin_message(person, key, &nonce, BINDING)).await;
        nonce
    }

    /// Sign in and read through `ready` and the standing; the standing's document.
    pub async fn connect_as(&mut self, person: &str, key: &Path) -> serde_json::Value {
        self.sign_in(person, key).await;
        assert_eq!(self.recv_type().await, "ready");
        let notice = self.recv().await;
        assert_eq!(notice["type"], "notice");
        let doc = STANDARD.decode(notice["doc"].as_str().unwrap()).unwrap();
        serde_json::from_slice(&doc).unwrap()
    }
}

/// Verify a signature of the broker's over `doc`, in the way pledge does, with a plain `ssh-keygen`.
pub fn verify_as_broker(w: &World, namespace: Namespace, doc: &[u8], sig_b64: &str) -> bool {
    let dir = tempfile::tempdir().unwrap();
    let (allowed, sig) = (dir.path().join("allowed"), dir.path().join("sig"));
    std::fs::write(&allowed, format!("broker cert-authority,namespaces=\"{}\" {}\n", namespace.as_str(), w.ca()))
        .unwrap();
    std::fs::write(&sig, p_act::sign::signature_from_base64(sig_b64).unwrap()).unwrap();
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&allowed)
        .args(["-I", "broker", "-n", namespace.as_str(), "-s"])
        .arg(&sig)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), doc).unwrap();
    child.wait().unwrap().success()
}

pub fn hash_of(s: &Submit) -> DocumentHash {
    s.request().hash()
}

/// Sign `data` in a namespace of the test's choosing, as another document type would.
pub fn raw_sign(key: &Path, namespace: Namespace, data: &[u8]) -> String {
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", namespace.as_str(), "-f"])
        .arg(key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    std::io::Write::write_all(&mut child.stdin.take().unwrap(), data).unwrap();
    String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap()
}

/// The fingerprint of a key file's public key, as `ssh-keygen -l` prints it.
pub fn fingerprint(w: &World, key: &Path) -> String {
    w.keys.public(key).fingerprint().to_string()
}

/// The identifier of the agent's delegation.
pub fn agent_fingerprint(w: &World) -> String {
    p_act::sign::agent_certificate(&w.keys.cert_line(&w.agent)).unwrap().delegation.to_string()
}

/// A configuration file that names the world's state directory, for the verbs (which find the socket by it).
pub fn config_file(w: &World) -> PathBuf {
    let dir = w.keys.dir.path().display();
    let text = format!(
        r#"{{"site":"{dir}/site.json","listen":["127.0.0.1:0"],"tls_cert":"{dir}/c.pem","tls_key":"{dir}/k.pem","broker_key":"{dir}/broker","state_dir":"{dir}","log":"{dir}/log.jsonl"}}"#
    );
    let path =
        std::env::temp_dir().join(format!("page-config-{}.json", std::process::id() as u64 * 1000 + rand_suffix()));
    std::fs::write(&path, text).unwrap();
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
    path
}

fn rand_suffix() -> u64 {
    use std::sync::atomic::AtomicU64;
    static N: AtomicU64 = AtomicU64::new(0);
    N.fetch_add(1, Ordering::SeqCst)
}

/// Bind the administrator's socket in the world's state directory and serve it; the socket's path.
pub fn serve_admin(w: &World) -> PathBuf {
    let listener = p_age::admin::bind(w.keys.dir.path()).unwrap();
    tokio::spawn(p_age::admin::serve(listener, Arc::clone(&w.broker)));
    p_age::admin::socket_path(w.keys.dir.path())
}

/// Run `page <args> --config <config>` as the verbs run: its exit code, what it printed and what it said.
pub async fn page(config: &Path, args: &[&str]) -> (i32, String, String) {
    let mut all: Vec<String> = args.iter().map(|s| (*s).to_owned()).collect();
    all.extend(["--config".to_owned(), config.display().to_string()]);
    tokio::task::spawn_blocking(move || {
        let out = Command::new(env!("CARGO_BIN_EXE_page")).args(&all).output().unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).trim_end().to_owned(),
            String::from_utf8_lossy(&out.stderr).trim_end().to_owned(),
        )
    })
    .await
    .unwrap()
}
