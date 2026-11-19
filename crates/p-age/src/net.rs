//! The two connections, over any async byte stream: a service's
//! (`approval-connections.md` section 4) and a pledge's (section 5). TLS is
//! around them (`tls`); tests run them over in-memory streams.
//!
//! The rules are `core`'s. This module reads and writes lines, runs the
//! signatures that cost time off the async threads (bounded, so that a
//! stranger's line costs little), and carries out what `core` returns.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use p_act::broker::{ConnectionDocument, First, FromPledge, FromService, Secret32, ToPledge, first_kind};
use p_act::exchange::{ClearancePolicy, ErrorCode, ErrorMessage, ExchangeError, LineBuffer, Message};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};
use tokio_rustls::TlsAcceptor;

use crate::core::{ConnId, Core, Effect, PledgeOut, ServiceOut, StoreError, Stored, vet};
use crate::crypto::Crypto;
use crate::register::Actor;
use crate::site::Site;
use crate::tls;

/// The line for a message to a pledge. `None` for `Close`.
fn pledge_line(out: &PledgeOut) -> Option<Vec<u8>> {
    out.to_message()?.encode().ok()
}

/// The line for a message to a service. `None` for `Close`, or if the answer cannot be written.
fn service_line(out: &ServiceOut) -> Option<Vec<u8>> {
    let policy = ClearancePolicy::Required;
    match out {
        ServiceOut::Answer(a) => Message::Answer(a.clone()).encode(policy).ok(),
        ServiceOut::Error(code) => Message::Error(ErrorMessage { error: *code }).encode(policy).ok(),
        ServiceOut::Close => None,
    }
}

/// The waits of the connections. The defaults are the document's; tests shorten them.
#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// A line that is begun must be finished within this long (10 s).
    pub line: Duration,
    /// A service sends its `submit` within this long of connecting (10 s).
    pub first_line: Duration,
    /// A pledge answers the challenge within this long (10 s).
    pub signin: Duration,
    /// A pledge connection silent for this long is closed; pledge pings every 30 s (90 s).
    pub pledge_silence: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            line: Duration::from_secs(10),
            first_line: Duration::from_secs(10),
            signin: Duration::from_secs(10),
            pledge_silence: Duration::from_secs(90),
        }
    }
}

/// The time, replaceable in tests.
pub trait Clock: Send + Sync {
    fn now(&self) -> SystemTime;
}

/// The system's clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Why a line could not be read.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadError {
    TooLong,
    Truncated,
    Timeout,
    Io,
}

/// An async line reader on `p_act`'s framing ([`LineBuffer`]): at most `MAX_LINE` bytes in a line, and a begun
/// line is finished within the line timeout. Cancel-safe: a dropped `read` loses nothing.
#[derive(Debug)]
pub struct Lines<R> {
    inner: R,
    buf: LineBuffer,
    started: Option<Instant>,
    line_timeout: Duration,
}

impl<R: AsyncRead + Unpin> Lines<R> {
    pub fn new(inner: R, line_timeout: Duration) -> Lines<R> {
        Lines { inner, buf: LineBuffer::new(), started: None, line_timeout }
    }

    /// As [`Lines::new`] with another limit on a line, for a connection that is not the exchange.
    pub fn with_limit(inner: R, line_timeout: Duration, limit: usize) -> Lines<R> {
        Lines { inner, buf: LineBuffer::with_limit(limit), started: None, line_timeout }
    }

    /// The next line without its `\n`; `None` at the end between lines. `wait` bounds the wait for a line to begin.
    pub async fn read(&mut self, wait: Option<Duration>) -> Result<Option<Vec<u8>>, ReadError> {
        loop {
            match self.buf.next_line() {
                Ok(Some(line)) => {
                    self.started = (self.buf.pending() > 0).then(Instant::now);
                    return Ok(Some(line));
                }
                Ok(None) => {}
                Err(_) => return Err(ReadError::TooLong),
            }
            let limit = match self.started {
                Some(t0) => Some(self.line_timeout.saturating_sub(t0.elapsed())),
                None => wait,
            };
            let mut chunk = [0u8; 8192];
            let n = match limit {
                Some(d) => tokio::time::timeout(d, self.inner.read(&mut chunk))
                    .await
                    .map_err(|_| ReadError::Timeout)?
                    .map_err(|_| ReadError::Io)?,
                None => self.inner.read(&mut chunk).await.map_err(|_| ReadError::Io)?,
            };
            if n == 0 {
                return if self.buf.pending() == 0 { Ok(None) } else { Err(ReadError::Truncated) };
            }
            if self.buf.pending() == 0 {
                self.started = Some(Instant::now());
            }
            self.buf.push(&chunk[..n]);
        }
    }
}

async fn write_line<W: AsyncWrite + Unpin>(w: &mut W, line: &[u8]) -> bool {
    w.write_all(line).await.is_ok() && w.flush().await.is_ok()
}

fn read_error_code(e: &ReadError) -> Option<ErrorCode> {
    match e {
        ReadError::TooLong => Some(ErrorCode::LineTooLong),
        ReadError::Timeout => Some(ErrorCode::Timeout),
        ReadError::Truncated | ReadError::Io => None,
    }
}

#[derive(Debug)]
enum Out {
    Service(ServiceOut),
    Pledge(PledgeOut),
}

/// The broker: the state under one lock, and the channels to the connections.
pub struct Broker {
    core: Mutex<Core>,
    outs: Mutex<HashMap<ConnId, mpsc::UnboundedSender<Out>>>,
    crypto: Arc<dyn Crypto>,
    site: Arc<Site>,
    clock: Arc<dyn Clock>,
    timeouts: Timeouts,
    /// Bounds the `ssh-keygen` runs at once; above it a request is refused `busy`.
    keygen: Arc<Semaphore>,
    next: AtomicU64,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Broker {
    pub fn new(
        core: Core,
        crypto: Arc<dyn Crypto>,
        site: Arc<Site>,
        clock: Arc<dyn Clock>,
        timeouts: Timeouts,
        max_keygen: usize,
    ) -> Arc<Broker> {
        Arc::new(Broker {
            core: Mutex::new(core),
            outs: Mutex::new(HashMap::new()),
            crypto,
            site,
            clock,
            timeouts,
            keygen: Arc::new(Semaphore::new(max_keygen.max(1))),
            next: AtomicU64::new(1),
        })
    }

    fn new_conn(&self) -> ConnId {
        ConnId(self.next.fetch_add(1, Ordering::Relaxed))
    }

    fn attach(&self, id: ConnId) -> mpsc::UnboundedReceiver<Out> {
        let (tx, rx) = mpsc::unbounded_channel();
        lock(&self.outs).insert(id, tx);
        rx
    }

    fn detach(&self, id: ConnId) {
        lock(&self.outs).remove(&id);
    }

    /// Hand effects to their connections. Called with the core's lock held, so that two events cannot
    /// reorder what one connection receives.
    fn dispatch(&self, effects: Vec<Effect>) {
        let outs = lock(&self.outs);
        for effect in effects {
            let (id, out) = match effect {
                Effect::Service(id, o) => (id, Out::Service(o)),
                Effect::Pledge(id, o) => (id, Out::Pledge(o)),
            };
            if let Some(tx) = outs.get(&id) {
                let _ = tx.send(out);
            }
        }
    }

    /// Run `f` on the core off the async threads, then dispatch what it returns, in one critical section.
    pub(crate) async fn with_core<T: Send + 'static>(
        self: &Arc<Self>,
        f: impl FnOnce(&mut Core, SystemTime) -> (T, Vec<Effect>) + Send + 'static,
    ) -> Option<T> {
        let me = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let mut core = lock(&me.core);
            let (value, effects) = f(&mut core, me.clock.now());
            me.dispatch(effects);
            value
        })
        .await
        .ok()
    }

    /// Run signature work for a stranger's line, bounded. `None` if the bound is reached.
    async fn offload<T: Send + 'static>(&self, f: impl FnOnce() -> T + Send + 'static) -> Option<T> {
        let permit: OwnedSemaphorePermit = Arc::clone(&self.keygen).try_acquire_owned().ok()?;
        tokio::task::spawn_blocking(move || {
            let value = f();
            drop(permit);
            value
        })
        .await
        .ok()
    }

    /// The deadline sweep: unanswered requests past their deadline are answered `expired`, and forgotten.
    pub async fn sweep(self: &Arc<Self>) {
        self.with_core(|core, now| ((), core.sweep(now))).await;
    }

    /// Set the group whose members may use `admin.sock` (start, and tests).
    pub fn set_administrators(&self, group: Option<crate::admin::AdminGroup>) {
        lock(&self.core).set_administrators(group);
    }

    /// The group whose members may use `admin.sock`, if one is configured.
    pub fn administrators(&self) -> Option<crate::admin::AdminGroup> {
        lock(&self.core).administrators().cloned()
    }

    /// How many requests the broker holds.
    pub fn held_count(&self) -> usize {
        lock(&self.core).held_count()
    }

    /// An administrator blocks a person: in force at once; whether it is stored is the answer.
    pub async fn block_person(self: &Arc<Self>, person: String, by: Actor) -> Stored {
        let outcome = self
            .with_core(move |core, now| {
                let (effects, stored) = core.block_person(&person, by, now);
                (stored, effects)
            })
            .await;
        outcome.unwrap_or_else(unreachable_store)
    }

    /// An administrator blocks one key: in force at once; whether it is stored is the answer.
    pub async fn block_key(self: &Arc<Self>, fingerprint: String, by: Actor) -> Stored {
        let outcome = self
            .with_core(move |core, now| {
                let (effects, stored) = core.block_key(&fingerprint, by, now);
                (stored, effects)
            })
            .await;
        outcome.unwrap_or_else(unreachable_store)
    }

    /// An administrator lifts a block: refused while the register cannot be written.
    pub async fn unblock_person(self: &Arc<Self>, person: String) -> Result<(), StoreError> {
        let outcome = self
            .with_core(move |core, now| match core.unblock_person(&person, now) {
                Ok(effects) => (Ok(()), effects),
                Err(why) => (Err(why), Vec::new()),
            })
            .await;
        outcome.unwrap_or_else(|| Err(StoreError { code: "io", text: "the broker could not be reached".to_owned() }))
    }

    /// An administrator lifts a key's block: refused while the register cannot be written.
    pub async fn unblock_key(self: &Arc<Self>, fingerprint: String) -> Result<(), StoreError> {
        let outcome = self
            .with_core(move |core, now| match core.unblock_key(&fingerprint, now) {
                Ok(effects) => (Ok(()), effects),
                Err(why) => (Err(why), Vec::new()),
            })
            .await;
        outcome.unwrap_or_else(|| Err(StoreError { code: "io", text: "the broker could not be reached".to_owned() }))
    }

    /// An administrator withdraws a delegation: in force at once; whether it is stored is the answer.
    pub async fn admin_withdraw(self: &Arc<Self>, delegation: p_act::sign::Fingerprint, by: Actor) -> Stored {
        let outcome = self
            .with_core(move |core, now| {
                let (effects, stored) = core.admin_withdraw(&delegation, by, now);
                (stored, effects)
            })
            .await;
        outcome.unwrap_or_else(unreachable_store)
    }

    /// Look up the account's name for an administrator's uid and record it beside the uid, **off the path that
    /// answered the verb**: the lookup goes through the name service, which can be slow or never answer, so it runs on
    /// a thread of its own and the answer to the administrator never waits for it. An entry without a name is
    /// complete; nothing is decided by the name.
    pub fn name_administrator_later(self: &Arc<Self>, uid: u32) {
        self.name_administrator_later_with(uid, p_ermit::peer::account_of);
    }

    /// As [`Broker::name_administrator_later`], with the lookup given (a test's that never returns).
    pub fn name_administrator_later_with(
        self: &Arc<Self>,
        uid: u32,
        lookup: impl FnOnce(u32) -> Option<String> + Send + 'static,
    ) {
        let broker = Arc::clone(self);
        let spawned = std::thread::Builder::new().name("page-account-lookup".to_owned()).spawn(move || {
            if let Some(name) = lookup(uid) {
                let now = broker.clock.now();
                lock(&broker.core).name_administrator(uid, &name, now);
            }
        });
        if let Err(e) = spawned {
            eprintln!("page: cannot start the account lookup: {e}");
        }
    }

    /// Why the register cannot be stored, if it cannot: the broker is degraded.
    pub fn degraded(&self) -> Option<String> {
        lock(&self.core).degraded().map(str::to_owned)
    }
}

fn unreachable_store() -> Stored {
    Stored::No(StoreError { code: "io", text: "the broker could not be reached".to_owned() })
}

/// Send `error` and say so; the caller then ends the connection.
async fn send_service_error<W: AsyncWrite + Unpin>(w: &mut W, code: ErrorCode) {
    if let Some(line) = service_line(&ServiceOut::Error(code)) {
        write_line(w, &line).await;
    }
}

async fn send_pledge_error<W: AsyncWrite + Unpin>(w: &mut W, code: ErrorCode) {
    if let Some(line) = pledge_line(&PledgeOut::Error(code)) {
        write_line(w, &line).await;
    }
}

/// One service connection (section 4): one request, and its answer. `first` is the `submit` that began it.
async fn service_loop<R, W>(mut lines: Lines<R>, mut wr: W, first: Vec<u8>, broker: Arc<Broker>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let conn = broker.new_conn();
    let mut rx = broker.attach(conn);
    let mut pending = Some(first);
    let mut submitted = false;
    loop {
        tokio::select! {
            read = async {
                match pending.take() {
                    Some(line) => Ok(Some(line)),
                    None => lines.read(None).await,
                }
            } => {
                let line = match read {
                    Ok(Some(line)) => line,
                    Ok(None) => break,
                    Err(e) => {
                        if let Some(code) = read_error_code(&e) { send_service_error(&mut wr, code).await; }
                        break;
                    }
                };
                match FromService::parse(&line) {
                    Err(ExchangeError::BadRequest { hash, .. }) => {
                        submitted = true;
                        broker.with_core(move |c, now| ((), c.refuse_unparsed(conn, hash, now))).await;
                    }
                    Err(e) => {
                        if let Some(code) = e.code() { send_service_error(&mut wr, code).await; }
                        break;
                    }
                    Ok(FromService::Ack(request)) => {
                        broker.with_core(move |c, now| ((), c.ack(conn, request, now))).await;
                    }
                    Ok(FromService::Exchange(message)) => match *message {
                        Message::Cancel(c) => {
                            broker.with_core(move |core, now| ((), core.cancel(conn, c.request, now))).await;
                        }
                        Message::Submit(submit) => {
                            if submitted {
                                send_service_error(&mut wr, ErrorCode::TooManyOpen).await;
                                break;
                            }
                            submitted = true;
                            submit_from_service(&broker, conn, submit).await;
                        }
                        Message::Error(_) => break,
                        // A service sends no answer.
                        Message::Answer(_) | Message::Hello => {
                            send_service_error(&mut wr, ErrorCode::UnknownType).await;
                            break;
                        }
                    },
                }
            }
            out = rx.recv() => match out {
                Some(Out::Service(ServiceOut::Close)) | None => break,
                Some(Out::Service(o)) => {
                    if let Some(line) = service_line(&o)
                        && !write_line(&mut wr, &line).await
                    {
                        break;
                    }
                }
                Some(Out::Pledge(_)) => {}
            },
        }
    }
    let _ = wr.shutdown().await;
    broker.detach(conn);
    broker.with_core(move |c, _| (c.service_gone(conn), Vec::new())).await;
}

async fn submit_from_service(broker: &Arc<Broker>, conn: ConnId, submit: p_act::exchange::Submit) {
    let hash = submit.hash();
    let (crypto, site, now) = (Arc::clone(&broker.crypto), Arc::clone(&broker.site), broker.clock.now());
    let vetted = broker.offload(move || vet(&*crypto, &site, submit, now)).await;
    match vetted {
        Some(Ok(v)) => {
            broker.with_core(move |c, now| ((), c.submit(conn, v, now))).await;
        }
        Some(Err(refusal)) => {
            broker.with_core(move |c, now| ((), c.refuse(conn, &refusal, now))).await;
        }
        None => {
            // The bound on signature work is reached: the request was not looked at, so it is refused
            // `busy` and not logged against a host or a person.
            broker.with_core(move |c, _| ((), c.refuse_busy(conn, hash))).await;
        }
    }
}

/// One connection, of either kind. Its first message says which exchange it carries (section 4): `submit` is a
/// service's, `hello` a pledge's; anything else is `error` `malformed-line`. Where it arrived means nothing.
/// `binding` is what both ends exported from the TLS connection, for a pledge's sign-in.
pub async fn serve_connection<S>(stream: S, binding: [u8; 32], broker: Arc<Broker>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let mut lines = Lines::new(rd, broker.timeouts.line);
    // The broker never speaks first: silence is closed without a word, and a first line that is not a `hello` or
    // a `submit` (too long included) is `malformed-line` and nothing more.
    let first = match lines.read(Some(broker.timeouts.first_line)).await {
        Ok(Some(line)) => line,
        Ok(None) | Err(ReadError::Timeout | ReadError::Truncated | ReadError::Io) => return,
        Err(ReadError::TooLong) => {
            send_pledge_error(&mut wr, ErrorCode::MalformedLine).await;
            let _ = wr.shutdown().await;
            return;
        }
    };
    match first_kind(&first) {
        First::Service => service_loop(lines, wr, first, broker).await,
        First::Pledge => pledge_loop(lines, wr, binding, broker).await,
        First::Refuse(code) => {
            send_pledge_error(&mut wr, code).await;
            let _ = wr.shutdown().await;
        }
    }
}

fn random_nonce() -> Option<Secret32> {
    let mut bytes = [0u8; 32];
    SystemRandom::new().fill(&mut bytes).ok()?;
    Some(bytes)
}

/// One pledge connection (section 5), after its `hello`. `binding` is what both ends exported from the TLS
/// connection; it ties the sign-in to this connection.
async fn pledge_loop<R, W>(mut lines: Lines<R>, mut wr: W, binding: [u8; 32], broker: Arc<Broker>)
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Some(nonce) = random_nonce() else { return };
    let Ok(challenge) = ToPledge::Challenge(nonce).encode() else { return };
    if !write_line(&mut wr, &challenge).await {
        return;
    }
    let Some(person) = sign_in(&broker, &mut lines, &mut wr, &nonce, &binding).await else {
        let _ = wr.shutdown().await;
        return;
    };
    let conn = broker.new_conn();
    let mut rx = broker.attach(conn);
    let p = person.clone();
    broker.with_core(move |c, now| ((), c.pledge_signed_in(&p, conn, &nonce, now))).await;
    loop {
        tokio::select! {
            read = lines.read(Some(broker.timeouts.pledge_silence)) => {
                let line = match read {
                    Ok(Some(line)) => line,
                    Ok(None) => break,
                    Err(e) => {
                        if let Some(code) = read_error_code(&e) { send_pledge_error(&mut wr, code).await; }
                        break;
                    }
                };
                match FromPledge::parse(&line) {
                    Err(e) => {
                        if let Some(code) = e.code() { send_pledge_error(&mut wr, code).await; }
                        break;
                    }
                    Ok(FromPledge::Ping) => {}
                    Ok(FromPledge::Delegation(message)) => {
                        let p = person.clone();
                        broker.with_core(move |c, now| ((), c.register_delegation(&p, conn, &message, now))).await;
                    }
                    Ok(FromPledge::Withdraw(delegation)) => {
                        let p = person.clone();
                        broker.with_core(move |c, now| ((), c.withdraw(&p, conn, &delegation, now))).await;
                    }
                    Ok(FromPledge::Exchange(message)) => match *message {
                        Message::Answer(answer) => {
                            let p = person.clone();
                            broker.with_core(move |c, now| ((), c.pledge_answer(&p, answer, now))).await;
                        }
                        Message::Error(_) => break,
                        // pledge sends no submit and no cancel.
                        Message::Submit(_) | Message::Cancel(_) | Message::Hello => {
                            send_pledge_error(&mut wr, ErrorCode::UnknownType).await;
                            break;
                        }
                    },
                    // pledge signs in once.
                    Ok(FromPledge::Signin(_)) => {
                        send_pledge_error(&mut wr, ErrorCode::UnknownType).await;
                        break;
                    }
                }
            }
            out = rx.recv() => match out {
                Some(Out::Pledge(PledgeOut::Close)) | None => break,
                Some(Out::Pledge(o)) => {
                    if let Some(line) = pledge_line(&o)
                        && !write_line(&mut wr, &line).await
                    {
                        break;
                    }
                }
                Some(Out::Service(_)) => {}
            },
        }
    }
    let _ = wr.shutdown().await;
    broker.detach(conn);
    broker.with_core(move |c, _| (c.pledge_gone(&person, conn), Vec::new())).await;
}

/// The sign-in: the signed connection document, checked against the nonce, the TLS binding and the person's
/// connection key. Any failure is `error` `signin`, the same for an unknown person, a wrong key and a stale
/// nonce; `blocked` only after a signature verified.
async fn sign_in<R, W>(
    broker: &Arc<Broker>,
    lines: &mut Lines<R>,
    wr: &mut W,
    nonce: &Secret32,
    binding: &Secret32,
) -> Option<String>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let line = match lines.read(Some(broker.timeouts.signin)).await {
        Ok(Some(line)) => line,
        Ok(None) => return None,
        Err(e) => {
            if let Some(code) = read_error_code(&e) {
                send_pledge_error(wr, code).await;
            }
            return None;
        }
    };
    let signed = match FromPledge::parse(&line) {
        Ok(FromPledge::Signin(signed)) => signed,
        // A line that is too long, or of a version not spoken, is told so; everything else that is not a sign-in is
        // `signin`, whether or not it is a message the broker knows or one that is well formed, so that nothing
        // about the protocol is probed before sign-in.
        Err(e) if matches!(e.code(), Some(ErrorCode::LineTooLong | ErrorCode::UnsupportedVersion)) => {
            if let Some(code) = e.code() {
                send_pledge_error(wr, code).await;
            }
            return None;
        }
        _ => {
            send_pledge_error(wr, ErrorCode::Signin).await;
            return None;
        }
    };
    let (nonce, binding) = (*nonce, *binding);
    let verified = async {
        let doc = ConnectionDocument::parse_unverified(signed.doc).ok()?;
        if !doc.is_for(&nonce, &binding) {
            return None;
        }
        let person = broker.site.person(doc.person()).filter(|p| p.enabled)?;
        // A person without keys cannot sign in.
        let key = person.connection_key()?.clone();
        let (crypto, sig) = (Arc::clone(&broker.crypto), signed.sig);
        let name = doc.person().to_owned();
        let ok = broker.offload(move || crypto.verify_connection(&doc, &sig, &key).is_ok()).await?;
        ok.then_some(name)
    }
    .await;
    let Some(person) = verified else {
        send_pledge_error(wr, ErrorCode::Signin).await;
        return None;
    };
    let p = person.clone();
    if broker.with_core(move |c, _| (c.signin_blocked(&p), Vec::new())).await.unwrap_or(true) {
        send_pledge_error(wr, ErrorCode::Blocked).await;
        return None;
    }
    Some(person)
}

// ---------------------------------------------------------------------------
// Listening
// ---------------------------------------------------------------------------

/// Bounds on connections: in total, and from one address.
#[derive(Debug, Clone)]
pub struct ConnLimits {
    total: Arc<Semaphore>,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    max_per_ip: usize,
}

impl ConnLimits {
    #[must_use]
    pub fn new(total: usize, max_per_ip: usize) -> ConnLimits {
        ConnLimits { total: Arc::new(Semaphore::new(total)), per_ip: Arc::default(), max_per_ip }
    }

    /// A slot for a connection from `ip`, or `None` if either bound is reached.
    fn take(&self, ip: IpAddr) -> Option<Slot> {
        let permit = Arc::clone(&self.total).try_acquire_owned().ok()?;
        let mut map = lock(&self.per_ip);
        let count = map.entry(ip).or_insert(0);
        if *count >= self.max_per_ip {
            return None;
        }
        *count += 1;
        Some(Slot { _permit: permit, per_ip: Arc::clone(&self.per_ip), ip })
    }
}

struct Slot {
    _permit: OwnedSemaphorePermit,
    per_ip: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut map = lock(&self.per_ip);
        if let Some(count) = map.get_mut(&self.ip) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                map.remove(&self.ip);
            }
        }
    }
}

/// Accept connections for ever: TLS first (the handshake within 10 s), then the connection itself. An address
/// means nothing: a service and a pledge may use the same one, and a site may listen on several.
pub async fn listen(listener: TcpListener, acceptor: TlsAcceptor, broker: Arc<Broker>, limits: ConnLimits) {
    loop {
        let Ok((tcp, peer)) = listener.accept().await else {
            tokio::time::sleep(Duration::from_millis(100)).await;
            continue;
        };
        let Some(slot) = limits.take(peer.ip()) else { continue };
        let (acceptor, broker) = (acceptor.clone(), Arc::clone(&broker));
        tokio::spawn(async move {
            let _slot = slot;
            serve_tls(tcp, acceptor, broker).await;
        });
    }
}

/// One accepted connection: the TLS handshake within 10 s, then [`serve_connection`] with what both ends
/// export from the TLS connection.
pub async fn serve_tls<S>(stream: S, acceptor: TlsAcceptor, broker: Arc<Broker>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await else {
        return;
    };
    let Some(binding) = tls::exporter(stream.get_ref().1) else { return };
    serve_connection(stream, binding, broker).await;
}

/// Run the deadline sweep once a second for ever.
pub async fn sweep_forever(broker: Arc<Broker>) {
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    loop {
        tick.tick().await;
        broker.sweep().await;
    }
}
