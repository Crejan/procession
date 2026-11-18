//! pledge's connection to the broker (`doc/approval-connections.md`, section 5; `proposals/broker-connection.md`).
//!
//! A dedicated thread with blocking rustls and no runtime. One thread owns the stream: every 50 ms it writes
//! what the outgoing channel holds and reads with a 50 ms timeout, so that no other thread ever touches the
//! stream. The **session** (what is said, in what order, and what it does) is a state machine over p-act's
//! message types, independent of the transport; the **transport** is TLS 1.3 over any `Read + Write` with
//! timeouts. A supervisor reconnects with a delay of 1 s, doubled to 60 s, with jitter; every connection
//! signs in anew and nothing carries over.
//!
//! What this program never does with what the broker says: act on a standing that does not verify as
//! `broker` against the site CA, is not for this person, is not for this connection (its nonce) or is not newer
//! (`n`); accept a certificate the CA did not sign for its own key; or treat a request as anything but a request
//! to check. `carried` is ignored in this step (stage 2 reads hosts from its own configuration).

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use p_act::Document;
use p_act::broker::{ConnectionDocument, FromPledge, NotRegisteredReason, Secret32, Signed, Standing, ToPledge};
use p_act::exchange::{Answer, ClearancePolicy, ExchangeError, LineBuffer, Message, PledgeReason};
use p_act::limits::{PING_INTERVAL_SECONDS, SIGNIN_SECONDS, TLS_EXPORTER_LABEL};
use p_act::sign::{Fingerprint, Namespace, PublicKey};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::json;

use crate::approvals::Responder;
use crate::broker_state::{Applied, Withdrawal};
use crate::shared::Shared;

/// How often the link thread looks at its outgoing channel and its timers.
pub const TICK: Duration = Duration::from_millis(50);
/// A registration that gets no answer in this long is `unavailable`.
pub const REGISTER_WAIT: Duration = Duration::from_secs(10);
/// A withdrawal the broker has not stored is sent again at most this often on a standing connection.
pub const RESEND_WITHDRAWALS: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// The transport
// ---------------------------------------------------------------------------

/// A stream with timeouts: what the link needs of a TCP or Unix socket.
pub trait Wire: Read + Write + Send + 'static {
    /// Reads wait at most this long (`None`: for ever).
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    /// Writes wait at most this long.
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl Wire for TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_read_timeout(self, timeout)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        TcpStream::set_write_timeout(self, timeout)
    }
}

impl Wire for UnixStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_read_timeout(self, timeout)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        UnixStream::set_write_timeout(self, timeout)
    }
}

/// What the session needs of a connection.
pub trait Transport {
    /// The 32 bytes both ends export from this connection (RFC 5705, `TLS_EXPORTER_LABEL`, no context).
    ///
    /// # Errors
    ///
    /// If the connection cannot export (it must be TLS 1.3 and finished).
    fn binding(&mut self) -> io::Result<Secret32>;
    /// Writes one line (with its `\n`).
    ///
    /// # Errors
    ///
    /// If the connection fails.
    fn write_line(&mut self, line: &[u8]) -> io::Result<()>;
    /// The next complete line, waiting at most `wait`; `Ok(None)` if none came yet.
    ///
    /// # Errors
    ///
    /// If the connection ended or failed, or a line was too long.
    fn read_line(&mut self, wait: Duration) -> io::Result<Option<Vec<u8>>>;
}

/// TLS 1.3 over `W`, with the line framing of the exchange.
pub struct TlsTransport<W: Wire> {
    stream: StreamOwned<ClientConnection, W>,
    lines: LineBuffer,
}

/// The TLS client configuration: TLS 1.3 only, the `ring` provider, the roots in `root_pem` and nothing else.
/// (A small copy of what p-age builds for its own use; what both ends must agree on, the exporter's label, its
/// 32 bytes and the version, comes from `p_act`.)
///
/// # Errors
///
/// A sentence if the roots do not read.
pub fn client_config(root_pem: &str) -> Result<Arc<ClientConfig>, String> {
    use rustls::pki_types::pem::PemObject as _;
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(root_pem.as_bytes()) {
        roots.add(cert.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| e.to_string())?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

impl<W: Wire> TlsTransport<W> {
    /// Runs the handshake on `wire`, within `handshake`.
    ///
    /// # Errors
    ///
    /// If the handshake fails or takes too long.
    pub fn connect(
        config: Arc<ClientConfig>,
        name: ServerName<'static>,
        mut wire: W,
        handshake: Duration,
    ) -> io::Result<Self> {
        wire.set_read_timeout(Some(handshake))?;
        wire.set_write_timeout(Some(handshake))?;
        let mut conn = ClientConnection::new(config, name).map_err(io::Error::other)?;
        while conn.is_handshaking() {
            conn.complete_io(&mut wire)?;
        }
        Ok(Self { stream: StreamOwned::new(conn, wire), lines: LineBuffer::new() })
    }
}

impl<W: Wire> Transport for TlsTransport<W> {
    fn binding(&mut self) -> io::Result<Secret32> {
        let mut out = [0_u8; 32];
        self.stream
            .conn
            .export_keying_material(&mut out, TLS_EXPORTER_LABEL.as_bytes(), None)
            .map_err(io::Error::other)?;
        Ok(out)
    }

    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        self.stream.sock.set_write_timeout(Some(Duration::from_secs(10)))?;
        self.stream.write_all(line)?;
        self.stream.flush()
    }

    fn read_line(&mut self, wait: Duration) -> io::Result<Option<Vec<u8>>> {
        loop {
            match self.lines.next_line() {
                Ok(Some(line)) => return Ok(Some(line)),
                Ok(None) => {}
                Err(e) => return Err(io::Error::other(e.to_string())),
            }
            self.stream.sock.set_read_timeout(Some(wait))?;
            let mut chunk = [0_u8; 8192];
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(n) => self.lines.push(&chunk[..n]),
                Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Ok(None),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The handle other threads use
// ---------------------------------------------------------------------------

/// A registration the broker did not take.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterError {
    /// No connection, no answer, or the broker said `unavailable`: try again.
    Unavailable,
    /// `not-registered` with this reason (a code of the closed list).
    Refused(&'static str),
}

#[derive(Debug)]
enum Registration {
    Registered,
    NotRegistered(NotRegisteredReason),
}

/// What the rest of pledge sees of the connection.
pub struct BrokerLink {
    out: Mutex<Sender<Vec<u8>>>,
    ready: AtomicBool,
    standing: AtomicBool,
    generation: AtomicU64,
    waiters: Mutex<HashMap<String, Sender<Registration>>>,
    stop: AtomicBool,
}

impl BrokerLink {
    pub(crate) fn new(out: Sender<Vec<u8>>) -> Arc<Self> {
        Arc::new(Self {
            out: Mutex::new(out),
            ready: AtomicBool::new(false),
            standing: AtomicBool::new(false),
            generation: AtomicU64::new(0),
            waiters: Mutex::new(HashMap::new()),
            stop: AtomicBool::new(false),
        })
    }

    /// Signed in on the current connection.
    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    /// Signed in, and a standing verified on **this** connection has been accepted: what issuing needs.
    #[must_use]
    pub fn can_issue(&self) -> bool {
        self.is_ready() && self.standing.load(Ordering::SeqCst)
    }

    /// Ends the link thread at its next tick.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    fn queue(&self, line: Vec<u8>) {
        if let Ok(out) = self.out.lock() {
            let _ = out.send(line);
        }
    }

    /// Registers a delegation with the broker and waits for the answer.
    ///
    /// # Errors
    ///
    /// [`RegisterError`] if the broker did not take it.
    pub fn register(&self, certificate: &str, id: &str) -> Result<(), RegisterError> {
        if !self.can_issue() {
            return Err(RegisterError::Unavailable);
        }
        let agent = p_act::sign::agent_certificate(certificate).map_err(|_| RegisterError::Unavailable)?;
        let line =
            FromPledge::Delegation(p_act::broker::DelegationMessage { certificate: certificate.to_owned(), agent })
                .encode()
                .map_err(|_| RegisterError::Unavailable)?;
        let (tx, rx) = mpsc::channel();
        self.waiters.lock().map_err(|_| RegisterError::Unavailable)?.insert(id.to_owned(), tx);
        self.queue(line);
        let answer = rx.recv_timeout(REGISTER_WAIT);
        if let Ok(mut waiters) = self.waiters.lock() {
            waiters.remove(id);
        }
        match answer {
            Ok(Registration::Registered) => Ok(()),
            Ok(Registration::NotRegistered(NotRegisteredReason::Unavailable))
            | Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => Err(RegisterError::Unavailable),
            Ok(Registration::NotRegistered(reason)) => Err(RegisterError::Refused(reason.wire())),
        }
    }

    /// Tells the broker about a withdrawal, if connected. Returns whether it was queued.
    pub fn send_withdraw(&self, id: &str) -> bool {
        if !self.is_ready() {
            return false;
        }
        let Ok(fingerprint) = id.parse::<Fingerprint>() else { return false };
        FromPledge::Withdraw(fingerprint).encode().map(|line| self.queue(line)).is_ok()
    }

    fn responder_send(self: &Arc<Self>, generation: u64) -> crate::approvals::Send {
        let link = Arc::clone(self);
        Arc::new(move |answer: &Answer| {
            // An answer made for an older connection is not written to this one: the request is submitted again and
            // is answered from the store.
            if link.generation.load(Ordering::SeqCst) != generation {
                return;
            }
            if let Ok(line) = FromPledge::Exchange(Box::new(Message::Answer(answer.clone()))).encode() {
                link.queue(line);
            }
        })
    }
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

/// What the session needs to know about its world.
pub struct SessionConfig {
    /// The person.
    pub person: String,
    /// The site CA's key: the anchor for the standing and the certificates.
    pub site_ca: PublicKey,
}

/// Why a connection ended.
#[derive(Debug)]
pub enum End {
    /// The stream failed or closed.
    Io(io::Error),
    /// The broker said `error` with this code, or said something that is not allowed here.
    Protocol(String),
    /// The broker refused the sign-in because the connection key or the person is blocked (`error blocked`
    /// before `ready`): not a fault to retry in a loop.
    Blocked,
    /// The link was stopped.
    Stopped,
}

#[derive(Debug, PartialEq, Eq)]
enum Phase {
    AwaitChallenge,
    AwaitReady,
    Ready,
}

/// One connection's conversation.
pub struct Session {
    shared: Arc<Shared>,
    link: Arc<BrokerLink>,
    cfg: Arc<SessionConfig>,
    binding: Secret32,
    phase: Phase,
    nonce: Option<Secret32>,
    last_n: Option<u64>,
    generation: u64,
    responder_id: u64,
    carried_noted: bool,
    /// What the session sends first: the lines of the sign-in.
    pub signed_in: bool,
}

fn sign_connection_document(shared: &Shared, document: &[u8]) -> Option<String> {
    let key = shared.key_with_purpose("connection")?;
    crate::seam::sign(shared, &key.blob, &key.blob, Namespace::Connection, document)
}

impl Session {
    /// A session for a connection whose binding is `binding`.
    #[must_use]
    pub fn new(shared: Arc<Shared>, link: Arc<BrokerLink>, cfg: Arc<SessionConfig>, binding: Secret32) -> Self {
        let generation = link.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let responder_id = shared.approvals.responder_id();
        Self {
            shared,
            link,
            cfg,
            binding,
            phase: Phase::AwaitChallenge,
            nonce: None,
            last_n: None,
            generation,
            responder_id,
            carried_noted: false,
            signed_in: false,
        }
    }

    /// The first line: `hello`.
    ///
    /// # Panics
    ///
    /// Never: `hello` always encodes.
    #[must_use]
    pub fn hello() -> Vec<u8> {
        Message::Hello.encode(ClearancePolicy::Refused).expect("hello encodes")
    }

    fn now(&self) -> i64 {
        self.shared.now().unix()
    }

    /// Handles one line from the broker; returns the lines to write.
    ///
    /// # Errors
    ///
    /// [`End`] if the broker said something that ends the connection.
    pub fn handle(&mut self, line: &[u8]) -> Result<Vec<Vec<u8>>, End> {
        let message = match ToPledge::parse(line) {
            Ok(message) => message,
            Err(error) => return self.unreadable(line, &error),
        };
        let mut out = Vec::new();
        match (message, &self.phase) {
            (ToPledge::Challenge(nonce), Phase::AwaitChallenge) => {
                self.nonce = Some(nonce);
                let doc = ConnectionDocument::compose(&self.cfg.person, &nonce, &self.binding)
                    .map_err(|e| End::Protocol(e.to_string()))?;
                let sig = sign_connection_document(&self.shared, doc.as_bytes())
                    .ok_or_else(|| End::Protocol("no connection key to sign in with".into()))?;
                out.push(
                    FromPledge::Signin(Signed { doc: doc.as_bytes().to_vec(), sig })
                        .encode()
                        .map_err(|e| End::Protocol(e.to_string()))?,
                );
                self.phase = Phase::AwaitReady;
            }
            (ToPledge::Ready, Phase::AwaitReady) => {
                self.phase = Phase::Ready;
                self.signed_in = true;
                self.link.ready.store(true, Ordering::SeqCst);
                self.shared.event("broker-signed-in", json!({}));
                out.extend(self.withdrawals());
            }
            (ToPledge::Notice(signed), Phase::Ready) => self.standing(&signed),
            (ToPledge::Registered(id), Phase::Ready) => self.registration(&id, Registration::Registered),
            (ToPledge::NotRegistered { delegation, reason }, Phase::Ready) => {
                self.registration(&delegation, Registration::NotRegistered(reason))
            }
            (ToPledge::Withdrawn { delegation, stored }, Phase::Ready) => self.withdrawn(delegation.as_str(), stored),
            // `error blocked` before `ready` is the broker refusing the sign-in.
            (ToPledge::Exchange(message), Phase::AwaitReady) if matches!(&*message, Message::Error(e) if e.error == p_act::exchange::ErrorCode::Blocked) =>
            {
                return Err(End::Blocked);
            }
            (ToPledge::Exchange(message), Phase::Ready) => self.exchange(*message)?,
            (other, phase) => {
                return Err(End::Protocol(format!("unexpected {:?} in {phase:?}", std::mem::discriminant(&other))));
            }
        }
        Ok(out)
    }

    /// A line `ToPledge` did not read: `carried` is ignored (once noted); anything else ends the connection.
    fn unreadable(&mut self, line: &[u8], error: &ExchangeError) -> Result<Vec<Vec<u8>>, End> {
        let kind =
            serde_json::from_slice::<serde_json::Value>(line).ok().and_then(|v| v["type"].as_str().map(str::to_owned));
        if kind.as_deref() == Some("carried") && self.phase == Phase::Ready {
            if !self.carried_noted {
                self.carried_noted = true;
                eprintln!(
                    "pledge: the broker sent a `carried` document; ignored in this version (hosts come from config.json)"
                );
            }
            return Ok(Vec::new());
        }
        Err(End::Protocol(format!("a line that cannot be read: {error}")))
    }

    fn exchange(&mut self, message: Message) -> Result<(), End> {
        match message {
            Message::Submit(submit) => {
                let responder = Responder {
                    id: self.responder_id,
                    send: self.link.responder_send(self.generation),
                    peer: None,
                    via_broker: true,
                };
                let shared = Arc::clone(&self.shared);
                thread::spawn(move || crate::approvals::submit(&shared, &submit, responder));
            }
            Message::Cancel(cancel) => self.shared.approvals.cancel(&cancel.request, self.responder_id, self.now()),
            Message::Error(error) => {
                if error.error == p_act::exchange::ErrorCode::Blocked && self.phase != Phase::Ready {
                    return Err(End::Blocked);
                }
                return Err(End::Protocol(format!("the broker sent error {}", error.error.wire())));
            }
            Message::Answer(_) | Message::Hello => {
                return Err(End::Protocol("a message the broker does not send".into()));
            }
        }
        Ok(())
    }

    fn registration(&self, id: &Fingerprint, what: Registration) {
        if let Ok(mut waiters) = self.link.waiters.lock()
            && let Some(waiter) = waiters.remove(id.as_str())
        {
            let _ = waiter.send(what);
        }
    }

    fn withdrawn(&self, id: &str, stored: bool) {
        let state = &self.shared.broker_state;
        let Some(before) = state.withdrawal(id) else { return };
        let now = if stored { Withdrawal::Stored } else { Withdrawal::InForce };
        if before != now && state.set_withdrawal(id, now).is_ok() {
            self.shared
                .event(if stored { "withdrawal-stored" } else { "withdrawal-not-stored" }, json!({"delegation": id}));
        }
    }

    /// The withdrawals the broker has not stored, as lines to send; they are then in force at the broker.
    fn withdrawals(&self) -> Vec<Vec<u8>> {
        let state = &self.shared.broker_state;
        state
            .unstored_withdrawals()
            .into_iter()
            .filter_map(|id| {
                let line = FromPledge::Withdraw(id.parse().ok()?).encode().ok()?;
                if state.withdrawal(&id) == Some(Withdrawal::NotTold) {
                    let _ = state.set_withdrawal(&id, Withdrawal::InForce);
                }
                Some(line)
            })
            .collect()
    }

    fn standing(&mut self, signed: &Signed) {
        let ignored = |why: &str| self.shared.event("standing-ignored", json!({"why": why}));
        let Ok(standing) = Standing::parse_verified(signed.doc.clone(), &signed.sig, &self.cfg.site_ca) else {
            return ignored("it does not verify as the broker's");
        };
        let Some(nonce) = self.nonce else { return ignored("no sign-in") };
        if !standing.accepted_by(&self.cfg.person, &nonce, self.last_n) {
            return ignored("not for this person and connection, or not newer");
        }
        let content = standing.content();
        self.last_n = Some(content.n);
        let strings = |list: &[Fingerprint]| list.iter().map(|f| f.as_str().to_owned()).collect::<Vec<_>>();
        let (person, ca, now) = (self.cfg.person.clone(), self.cfg.site_ca.clone(), self.now());
        let shared = Arc::clone(&self.shared);
        let verify = move |line: &str| {
            crate::certs::check(&shared, line, &person, &ca, now).ok().map(|good| good.role.to_owned())
        };
        let (blocked_keys, withdrawn) = (strings(&content.blocked_keys), strings(&content.withdrawn));
        let changes = match self.shared.broker_state.apply(
            &Applied {
                blocked: content.blocked,
                blocked_keys: &blocked_keys,
                withdrawn: &withdrawn,
                certificates: &content.certificates,
                groups: &content.groups,
                now,
            },
            &verify,
        ) {
            Ok(changes) => changes,
            Err(e) => return ignored(&format!("it could not be kept: {e}")),
        };
        self.link.standing.store(true, Ordering::SeqCst);
        self.shared.event("standing-accepted", json!({"n": content.n}));
        // What is waiting is refused now, with the reason that fits.
        if changes.newly_blocked {
            self.shared.approvals.refuse_waiting(|_| true, PledgeReason::Blocked);
        }
        for id in &changes.newly_withdrawn {
            self.shared.approvals.refuse_waiting(|agent| agent == id, PledgeReason::DelegationWithdrawn);
        }
        if changes.newly_blocked_keys.iter().any(|fp| {
            ["confirmed", "automatic"]
                .iter()
                .filter_map(|r| self.shared.key_with_purpose(r))
                .any(|k| &k.fingerprint == fp)
        }) {
            self.shared.approvals.refuse_waiting(|_| true, PledgeReason::Blocked);
        }
    }

    /// Runs the conversation on `transport` until it ends. `outgoing` holds what other threads want written.
    ///
    /// # Errors
    ///
    /// [`End`] when the connection is over.
    pub fn run<T: Transport>(&mut self, transport: &mut T, outgoing: &mpsc::Receiver<Vec<u8>>) -> Result<(), End> {
        let hello = Self::hello();
        transport.write_line(&hello).map_err(End::Io)?;
        let started = Instant::now();
        let mut last_sent = Instant::now();
        let mut last_resend = Instant::now();
        loop {
            if self.link.stop.load(Ordering::SeqCst) {
                return Err(End::Stopped);
            }
            while let Ok(line) = outgoing.try_recv() {
                transport.write_line(&line).map_err(End::Io)?;
                last_sent = Instant::now();
            }
            if let Some(line) = transport.read_line(TICK).map_err(End::Io)? {
                for reply in self.handle(&line)? {
                    transport.write_line(&reply).map_err(End::Io)?;
                    last_sent = Instant::now();
                }
            }
            if self.phase != Phase::Ready && started.elapsed() > Duration::from_secs(SIGNIN_SECONDS) {
                return Err(End::Protocol("the sign-in did not finish in time".into()));
            }
            if self.phase == Phase::Ready {
                if last_sent.elapsed() >= Duration::from_secs(PING_INTERVAL_SECONDS) {
                    transport
                        .write_line(&FromPledge::Ping.encode().map_err(|e| End::Protocol(e.to_string()))?)
                        .map_err(End::Io)?;
                    last_sent = Instant::now();
                }
                if last_resend.elapsed() >= RESEND_WITHDRAWALS {
                    for line in self.withdrawals() {
                        transport.write_line(&line).map_err(End::Io)?;
                    }
                    last_resend = Instant::now();
                }
            }
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.link.ready.store(false, Ordering::SeqCst);
        self.link.standing.store(false, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// The supervisor
// ---------------------------------------------------------------------------

/// The delay before the next connection attempt: 1 s after a connection that signed in, else the
/// previous delay doubled up to 60 s; `jitter` in `0.0..1.0` adds up to a quarter.
#[must_use]
pub fn backoff(previous: Duration, signed_in: bool, jitter: f64) -> Duration {
    let base = if signed_in {
        Duration::from_secs(1)
    } else {
        (previous * 2).clamp(Duration::from_secs(1), Duration::from_secs(60))
    };
    base.mul_f64(1.0 + 0.25 * jitter.clamp(0.0, 1.0))
}

fn jitter() -> f64 {
    use ring::rand::SecureRandom as _;
    let mut byte = [0_u8; 1];
    let _ = ring::rand::SystemRandom::new().fill(&mut byte);
    f64::from(byte[0]) / 256.0
}

/// A transport that can be used behind a pointer.
pub trait DynTransport: Transport + Send {}
impl<T: Transport + Send> DynTransport for T {}

impl Transport for Box<dyn DynTransport> {
    fn binding(&mut self) -> io::Result<Secret32> {
        (**self).binding()
    }
    fn write_line(&mut self, line: &[u8]) -> io::Result<()> {
        (**self).write_line(line)
    }
    fn read_line(&mut self, wait: Duration) -> io::Result<Option<Vec<u8>>> {
        (**self).read_line(wait)
    }
}

/// How long after a refused sign-in (blocked) pledge waits before it tries again.
const BLOCKED_RETRY: Duration = Duration::from_secs(600);

/// Starts the link: a supervisor thread that connects with `connect` (which returns a ready transport, the
/// handshake done), runs a session, and reconnects with [`backoff`]. Returns the handle.
pub fn start(
    shared: &Arc<Shared>,
    cfg: SessionConfig,
    connect: Box<dyn Fn() -> io::Result<Box<dyn DynTransport>> + Send + Sync>,
) -> Arc<BrokerLink> {
    let (tx, rx) = mpsc::channel();
    let link = BrokerLink::new(tx);
    let (shared, thread_link, cfg) = (Arc::clone(shared), Arc::clone(&link), Arc::new(cfg));
    thread::spawn(move || {
        let mut delay = Duration::from_secs(1);
        let mut refused_before = false;
        while !thread_link.stop.load(Ordering::SeqCst) {
            let mut signed_in = false;
            match connect() {
                Ok(mut transport) => {
                    // What was queued for an older connection is not for this one.
                    while rx.try_recv().is_ok() {}
                    match transport.binding() {
                        Ok(binding) => {
                            let mut session =
                                Session::new(Arc::clone(&shared), Arc::clone(&thread_link), Arc::clone(&cfg), binding);
                            let result = session.run(&mut transport, &rx);
                            signed_in = session.signed_in;
                            if matches!(result, Err(End::Blocked)) {
                                // Told once to the person (record and stderr); asked again only rarely, never in a loop.
                                if !refused_before {
                                    shared.event(
                                        "broker-signin-refused",
                                        json!({"why": "the broker refused the sign-in: the connection key or the person is blocked"}),
                                    );
                                    eprintln!(
                                        "pledge: the broker refused the sign-in: the connection key or the person is blocked; trying again every {} minutes",
                                        BLOCKED_RETRY.as_secs() / 60
                                    );
                                }
                                refused_before = true;
                                delay = BLOCKED_RETRY;
                            } else if let Err(end) = result {
                                shared.event(
                                    "broker-connection-ended",
                                    json!({"why": format!("{end:?}").chars().take(100).collect::<String>()}),
                                );
                            }
                        }
                        Err(e) => eprintln!("pledge: the broker connection cannot export its binding: {e}"),
                    }
                }
                Err(e) => eprintln!("pledge: cannot reach the broker: {e}"),
            }
            if signed_in {
                refused_before = false;
            }
            if delay != BLOCKED_RETRY || signed_in {
                delay = backoff(delay, signed_in, jitter());
            }
            let until = Instant::now() + delay;
            while Instant::now() < until && !thread_link.stop.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(100));
            }
        }
    });
    link
}
