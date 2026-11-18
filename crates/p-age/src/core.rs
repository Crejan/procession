//! The broker's state and rules, without any I/O: what is held, for whom, and
//! what follows from each event. Every method takes the time and returns the
//! messages to send ([`Effect`]); the connections (`net`) carry them out.
//!
//! The order of `SPEC.md` for a request from a service: 0 the deadline, 1 the
//! service's signature, 2 the delegation, 3 the person, then the limit. 0 to 2's
//! signatures are checked before the state is touched ([`vet`]), so that a
//! stranger's line costs no lock; the rest is here. Check 4 (R10) is stage 3.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use p_act::exchange::{
    Answer, Approved, BrokerReason, By, ClearanceAnswer, ErrorCode, Outcome, PledgeReason, Refused, Submit,
};
use p_act::limits::{CLOCK_TOLERANCE_SECONDS, MAX_DEADLINE_AHEAD_SECONDS, MAX_DELEGATION_SECONDS};
use p_act::sign::{self, Agent, Fingerprint, signature_person};
use p_act::{Clearance, DocumentHash, Timestamp};

use crate::crypto::Crypto;
use crate::log::{LogEntry, LogSink};
use crate::perm::{self, PermError};
use crate::register::{Register, Snapshot, Stopped};
use crate::site::Site;
use crate::wire::{NotRegistered, PledgeOut, ServiceOut, Standing};

/// Why the register on disk was not used.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    #[error(transparent)]
    Perm(#[from] PermError),
    #[error("cannot read {path}: {source}")]
    Read { path: String, source: std::io::Error },
    #[error("{path} is not a register: {source}")]
    Parse { path: String, source: serde_json::Error },
    #[error("{path} is version {v} of the register, which this broker does not know")]
    Version { path: String, v: u32 },
}

/// The broker's settings.
#[derive(Debug, Clone)]
pub struct Settings {
    /// How many requests of one agent may wait; further ones are refused (five by default).
    pub max_waiting_per_agent: usize,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { max_waiting_per_agent: 5 }
    }
}

/// One connection, of either kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnId(pub u64);

/// A message to send to a connection.
#[derive(Debug, Clone)]
pub enum Effect {
    Service(ConnId, ServiceOut),
    Pledge(ConnId, PledgeOut),
}

fn unix(t: SystemTime) -> i64 {
    t.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn at(secs: i64) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(secs).unwrap_or(0))
}

fn stamp(t: SystemTime) -> Timestamp {
    // Clamped into the years `Timestamp` supports (0000 to 9999), so the conversion cannot fail.
    Timestamp::from_unix(unix(t).clamp(0, 253_402_300_799)).expect("clamped into the supported years")
}

// ---------------------------------------------------------------------------
// Vetting: checks 0 to 2, which need signatures
// ---------------------------------------------------------------------------

/// A `submit` that passed checks 0 to 2's signatures.
#[derive(Debug, Clone)]
pub struct Vetted {
    pub submit: Submit,
    pub agent: Agent,
}

/// A `submit` that did not pass, and why: what the answer and the log need, not the request.
#[derive(Debug, Clone)]
pub struct Refusal {
    pub hash: DocumentHash,
    pub host: String,
    pub service: String,
    pub reason: BrokerReason,
}

/// Checks 0, 1 and the signature of 2, in that order; the first failure is the answer.
pub fn vet(crypto: &dyn Crypto, site: &Site, submit: Submit, now: SystemTime) -> Result<Vetted, Refusal> {
    let refuse = |submit: Submit, reason| {
        let service = &submit.request().call().service();
        Err(Refusal { hash: submit.hash(), host: service.host.clone(), service: service.name.clone(), reason })
    };
    let request = submit.request();
    let call = request.call();
    // 0. A limit that bounds what the broker holds. The tolerance applies to the bound ahead only.
    let (deadline, now_s) = (call.deadline().unix(), unix(now));
    if now_s >= deadline || deadline > now_s + MAX_DEADLINE_AHEAD_SECONDS + CLOCK_TOLERANCE_SECONDS {
        return refuse(submit, BrokerReason::Deadline);
    }
    // 1. Signed by a service key that a host of the site certified; host and service are the call's.
    let Some(host_key) = site.host_key(&call.service().host) else { return refuse(submit, BrokerReason::BadRequest) };
    if crypto.verify_request(request, submit.request_sig(), host_key).is_err() {
        return refuse(submit, BrokerReason::BadRequest);
    }
    // 2. The call is signed under a certificate of a delegation key of the person it names.
    let Ok(person) = signature_person(request.call_sig()) else { return refuse(submit, BrokerReason::Delegation) };
    let Some(key) = site.person(&person).map(|p| p.delegation_key.clone()) else {
        return refuse(submit, BrokerReason::Delegation);
    };
    match crypto.verify_call(call, request.call_sig(), &key) {
        Ok(agent) => Ok(Vetted { submit, agent }),
        Err(_) => refuse(submit, BrokerReason::Delegation),
    }
}

// ---------------------------------------------------------------------------
// The state
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct Held {
    submit: Submit,
    person: String,
    agent: Fingerprint,
    host: String,
    service: String,
    deadline: SystemTime,
    seq: u64,
    /// The service connection that waits for the answer.
    conn: Option<ConnId>,
    /// The answer, held in memory until the service's `ack` or the deadline.
    answer: Option<Answer>,
}

#[derive(Debug)]
struct Link {
    conn: ConnId,
    nonce: String,
    /// The counter of the next standing on this connection.
    next_n: u64,
}

/// What the broker knows and holds. Sync, with no I/O but the register's file and the log.
pub struct Core {
    site: Arc<Site>,
    settings: Settings,
    register: Register,
    state_path: Option<PathBuf>,
    held: HashMap<DocumentHash, Held>,
    links: HashMap<String, Link>,
    crypto: Arc<dyn Crypto>,
    log: Box<dyn LogSink>,
    seq: u64,
}

impl Core {
    pub fn new(
        site: Arc<Site>,
        settings: Settings,
        register: Register,
        state_path: Option<PathBuf>,
        crypto: Arc<dyn Crypto>,
        log: Box<dyn LogSink>,
    ) -> Core {
        Core { site, settings, register, state_path, held: HashMap::new(), links: HashMap::new(), crypto, log, seq: 0 }
    }

    /// The register as kept on disk. No file is a first start: an empty register. A file that cannot be read
    /// whole (not JSON, a version this broker does not know, readable by others, in a directory open to
    /// others) is an error: the broker does not start in its place with an empty register, which would drop
    /// the blocks without a word.
    pub fn read_state(path: &std::path::Path) -> Result<Register, StateError> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            perm::ensure_private_dir(dir)?;
        }
        if !path.exists() {
            return Ok(Register::default());
        }
        perm::check_private_file(path)?;
        let shown = path.display().to_string();
        let bytes = std::fs::read(path).map_err(|source| StateError::Read { path: shown.clone(), source })?;
        let snapshot: Snapshot =
            serde_json::from_slice(&bytes).map_err(|source| StateError::Parse { path: shown.clone(), source })?;
        if snapshot.v != 1 {
            return Err(StateError::Version { path: shown, v: snapshot.v });
        }
        Ok(Register::restore(snapshot))
    }

    fn persist(&self) {
        let Some(path) = &self.state_path else { return };
        let result = serde_json::to_vec(&self.register.snapshot())
            .map_err(std::io::Error::other)
            .and_then(|bytes| perm::replace_private_file(path, &bytes));
        // The broker goes on in memory, and says so: a refused request is worse than a register not yet on disk.
        if let Err(e) = result {
            eprintln!("page: cannot keep the register in {}: {e}", path.display());
        }
    }

    fn log(&mut self, now: SystemTime, h: &HeldInfo, result: &str) {
        self.log.write(&LogEntry {
            at: stamp(now),
            host: h.host.clone(),
            service: h.service.clone(),
            person: h.person.clone(),
            request: h.hash,
            result: result.to_owned(),
        });
    }

    /// Requests that are held and not answered, of one agent.
    fn waiting_of(&self, agent: &Fingerprint) -> usize {
        self.held.values().filter(|h| h.answer.is_none() && &h.agent == agent).count()
    }

    // --- services ---------------------------------------------------------

    /// A request that is refused before it is held: the answer, and the end of the connection.
    pub fn refuse(&mut self, conn: ConnId, refusal: &Refusal, now: SystemTime) -> Vec<Effect> {
        let info =
            HeldInfo { host: refusal.host.clone(), service: refusal.service.clone(), person: None, hash: refusal.hash };
        self.log(now, &info, &format!("refused:{}", refusal.reason.wire()));
        refused_to_service(conn, refusal.hash, refusal.reason)
    }

    /// A message about a request the receiver does not hold (or does not hold for the sender) is ignored and
    /// logged: the hash and the time, nothing else.
    fn ignore(&mut self, now: SystemTime, person: Option<&str>, hash: DocumentHash, what: &str) -> Vec<Effect> {
        let info = HeldInfo { host: "-".to_owned(), service: "-".to_owned(), person: person.map(str::to_owned), hash };
        self.log(now, &info, &format!("ignored:{what}"));
        Vec::new()
    }

    /// A `submit` whose request did not parse: refused for the hash of its bytes, logged without names.
    pub fn refuse_unparsed(&mut self, conn: ConnId, hash: DocumentHash, now: SystemTime) -> Vec<Effect> {
        let info = HeldInfo { host: "-".to_owned(), service: "-".to_owned(), person: None, hash };
        self.log(now, &info, "refused:bad-request");
        refused_to_service(conn, hash, BrokerReason::BadRequest)
    }

    /// The bound on signature work was reached: the request was not looked at, so it is refused `busy`.
    pub fn refuse_busy(&mut self, conn: ConnId, hash: DocumentHash) -> Vec<Effect> {
        refused_to_service(conn, hash, BrokerReason::Busy)
    }

    /// Whether the person is blocked.
    #[must_use]
    pub fn is_blocked(&self, person: &str) -> bool {
        self.register.is_blocked(person)
    }

    /// A request that passed [`vet`]: checks 2 (registered), 3 and the limit, then held and put to the pledge.
    pub fn submit(&mut self, conn: ConnId, vetted: Vetted, now: SystemTime) -> Vec<Effect> {
        let Vetted { submit, agent } = vetted;
        let hash = submit.hash();
        // The same bytes again: attach, do not check or count again.
        if let Some(h) = self.held.get_mut(&hash) {
            let mut fx = Vec::new();
            if let Some(old) = h.conn.replace(conn) {
                if old != conn {
                    fx.push(Effect::Service(old, ServiceOut::Error(ErrorCode::Superseded)));
                    fx.push(Effect::Service(old, ServiceOut::Close));
                }
            }
            if let Some(answer) = h.answer.clone() {
                fx.push(Effect::Service(conn, ServiceOut::Answer(answer)));
            }
            return fx;
        }
        let call = submit.request().call();
        let (host, service) = (call.service().host.clone(), call.service().name.clone());
        let deny = |core: &mut Core, person: Option<String>, reason: BrokerReason| {
            let info = HeldInfo { host: host.clone(), service: service.clone(), person, hash };
            core.log(now, &info, &format!("refused:{}", reason.wire()));
            refused_to_service(conn, hash, reason)
        };
        let fingerprint = agent.delegation.clone();
        let person = match self.register.person_for(fingerprint.as_str(), now) {
            Ok(person) if person == agent.person => person.to_owned(),
            Ok(_) | Err(Stopped::Unknown | Stopped::Ended | Stopped::Withdrawn) => {
                return deny(self, Some(agent.person.clone()), BrokerReason::Delegation);
            }
            Err(Stopped::PersonBlocked) => return deny(self, Some(agent.person.clone()), BrokerReason::Person),
        };
        if !self.site.person(&person).is_some_and(|p| p.enabled) {
            return deny(self, Some(person), BrokerReason::Person);
        }
        if self.waiting_of(&fingerprint) >= self.settings.max_waiting_per_agent {
            return deny(self, Some(person), BrokerReason::TooManyWaiting);
        }
        self.seq += 1;
        let deadline = at(call.deadline().unix());
        let mut fx = Vec::new();
        if let Some(link) = self.links.get(&person) {
            fx.push(Effect::Pledge(link.conn, PledgeOut::Submit(Box::new(submit.clone()))));
        }
        self.held.insert(
            hash,
            Held {
                submit,
                person,
                agent: fingerprint,
                host,
                service,
                deadline,
                seq: self.seq,
                conn: Some(conn),
                answer: None,
            },
        );
        fx
    }

    /// The service no longer wants an answer. Only the connection that holds the request may say so.
    pub fn cancel(&mut self, conn: ConnId, hash: DocumentHash, now: SystemTime) -> Vec<Effect> {
        let owned = self.held.get(&hash).is_some_and(|h| h.conn == Some(conn) && h.answer.is_none());
        if !owned {
            return self.ignore(now, None, hash, "cancel");
        }
        let Some(h) = self.held.remove(&hash) else { return Vec::new() };
        self.log(now, &HeldInfo::of(&h, hash), "cancelled");
        let mut fx = vec![Effect::Service(conn, ServiceOut::Close)];
        if let Some(link) = self.links.get(&h.person) {
            fx.push(Effect::Pledge(link.conn, PledgeOut::Cancel(hash)));
        }
        fx
    }

    /// The service has the answer: drop what was held.
    pub fn ack(&mut self, conn: ConnId, hash: DocumentHash, now: SystemTime) -> Vec<Effect> {
        match self.held.get(&hash) {
            Some(h) if h.conn == Some(conn) && h.answer.is_some() => {
                self.held.remove(&hash);
                vec![Effect::Service(conn, ServiceOut::Close)]
            }
            _ => self.ignore(now, None, hash, "ack"),
        }
    }

    /// A service connection ended. It does not cancel: the service may submit the same bytes again.
    pub fn service_gone(&mut self, conn: ConnId) {
        for h in self.held.values_mut().filter(|h| h.conn == Some(conn)) {
            h.conn = None;
        }
    }

    // --- pledges ----------------------------------------------------------

    fn standing(&mut self, person: &str, now: SystemTime) -> Result<Effect, ()> {
        let Some(link) = self.links.get_mut(person) else { return Err(()) };
        let n = link.next_n;
        link.next_n += 1;
        let (conn, nonce) = (link.conn, link.nonce.clone());
        let known = self.site.person(person);
        let standing = Standing::new(
            person,
            &nonce,
            n,
            self.register.is_blocked(person),
            Vec::new(),
            self.register.withdrawn_of(person, now),
            known.map(|p| p.certificates.clone()).unwrap_or_default(),
            known.map(|p| p.groups.clone()).unwrap_or_default(),
        );
        let bytes = standing.bytes();
        match self.crypto.sign_standing(&bytes) {
            Ok(sig) => Ok(Effect::Pledge(conn, PledgeOut::Notice { doc: bytes, sig })),
            Err(e) => {
                eprintln!("page: cannot sign the standing: {e}");
                Err(())
            }
        }
    }

    /// A pledge signed in: it is told it is ready, then the standing, then every request that waited.
    pub fn pledge_signed_in(&mut self, person: &str, conn: ConnId, nonce: &str, now: SystemTime) -> Vec<Effect> {
        let mut fx = Vec::new();
        if let Some(old) = self.links.insert(person.to_owned(), Link { conn, nonce: nonce.to_owned(), next_n: 0 }) {
            fx.push(Effect::Pledge(old.conn, PledgeOut::Error(ErrorCode::Superseded)));
            fx.push(Effect::Pledge(old.conn, PledgeOut::Close));
        }
        fx.push(Effect::Pledge(conn, PledgeOut::Ready));
        match self.standing(person, now) {
            Ok(notice) => fx.push(notice),
            Err(()) => {
                self.links.remove(person);
                fx.push(Effect::Pledge(conn, PledgeOut::Error(ErrorCode::Busy)));
                fx.push(Effect::Pledge(conn, PledgeOut::Close));
                return fx;
            }
        }
        let mut waiting: Vec<&Held> =
            self.held.values().filter(|h| h.person == person && h.answer.is_none() && now < h.deadline).collect();
        waiting.sort_by_key(|h| h.seq);
        fx.extend(waiting.into_iter().map(|h| Effect::Pledge(conn, PledgeOut::Submit(Box::new(h.submit.clone())))));
        fx
    }

    /// A pledge connection ended. Its requests stay waiting.
    pub fn pledge_gone(&mut self, person: &str, conn: ConnId) {
        if self.links.get(person).is_some_and(|l| l.conn == conn) {
            self.links.remove(person);
        }
    }

    /// The outcome of a request is final: held in memory for the service, and logged.
    fn finish(&mut self, hash: DocumentHash, outcome: Outcome, result: &str, now: SystemTime) -> Vec<Effect> {
        let Some(h) = self.held.get_mut(&hash) else { return Vec::new() };
        let answer = Answer { request: hash, outcome };
        h.answer = Some(answer.clone());
        let conn = h.conn;
        let info = HeldInfo::of(h, hash);
        self.log(now, &info, result);
        conn.map(|c| Effect::Service(c, ServiceOut::Answer(answer))).into_iter().collect()
    }

    /// An answer from the pledge of `person`. What it names must be a request the broker put to that person
    /// and still holds; anything else is ignored. The approval is not checked here: it is the service's.
    pub fn pledge_answer(&mut self, person: &str, answer: Answer, now: SystemTime) -> Vec<Effect> {
        let hash = answer.request;
        let held = self.held.get(&hash).is_some_and(|h| h.person == person && h.answer.is_none());
        if !held {
            return self.ignore(now, Some(person), hash, "answer");
        }
        let deadline = self.held.get(&hash).map_or(now, |h| h.deadline);
        match answer.outcome {
            Outcome::Approved(approved) => {
                if now >= deadline {
                    // An approval that comes late is worthless.
                    return self.finish(hash, Outcome::Expired(By::Broker), "expired", now);
                }
                match self.clearance_for(hash, approved.approval(), now) {
                    Ok(outcome) => self.finish(hash, outcome, "approval-returned", now),
                    Err(()) => {
                        self.finish(hash, Outcome::Refused(Refused::Broker(BrokerReason::Busy)), "refused:busy", now)
                    }
                }
            }
            Outcome::Declined => self.finish(hash, Outcome::Declined, "declined", now),
            Outcome::Refused(refused) => {
                // Built from what was parsed, never passed on: only pledge's own reasons count as pledge's.
                let reason = match refused {
                    Refused::Pledge(r) => r,
                    Refused::Broker(_) | Refused::Unknown => PledgeReason::Unknown,
                };
                self.finish(hash, Outcome::Refused(Refused::Pledge(reason)), &format!("refused:{}", reason.wire()), now)
            }
            Outcome::Expired(_) => self.finish(hash, Outcome::Expired(By::Pledge), "expired", now),
            Outcome::Unknown => self.ignore(now, Some(person), hash, "answer"),
        }
    }

    fn clearance_for(&self, hash: DocumentHash, approval: &str, now: SystemTime) -> Result<Outcome, ()> {
        let clearance = Clearance::compose(hash, stamp(now)).map_err(drop)?;
        let sig =
            self.crypto.sign_clearance(&clearance).map_err(|e| eprintln!("page: cannot sign a clearance: {e}"))?;
        let with = ClearanceAnswer::new(clearance, &sig).map_err(drop)?;
        let approved = Approved::new(approval, Some(with)).map_err(drop)?;
        Ok(Outcome::Approved(approved))
    }

    /// A delegation pledge registers. Authenticated by the sign-in alone; the certificate is what authorises it.
    pub fn register_delegation(&mut self, person: &str, conn: ConnId, cert: &str, now: SystemTime) -> Vec<Effect> {
        let reply = |out| vec![Effect::Pledge(conn, out)];
        let Ok(agent) = sign::agent_certificate(cert) else {
            // No identifier can be named for a certificate that cannot be read.
            return vec![
                Effect::Pledge(conn, PledgeOut::Error(ErrorCode::MalformedLine)),
                Effect::Pledge(conn, PledgeOut::Close),
            ];
        };
        let fp = agent.delegation.clone();
        let no = |why| reply(PledgeOut::NotRegistered(fp.clone(), why));
        if agent.person != person {
            return no(NotRegistered::NotYours);
        }
        if self.register.is_blocked(person) {
            return no(NotRegistered::Blocked);
        }
        let (from, until) = (
            i64::try_from(agent.valid_after).unwrap_or(i64::MAX),
            i64::try_from(agent.valid_before).unwrap_or(i64::MAX),
        );
        if until.saturating_sub(from) > MAX_DELEGATION_SECONDS {
            return no(NotRegistered::TooLong);
        }
        if unix(now) < from || unix(now) >= until {
            return no(NotRegistered::BadCertificate);
        }
        let Some(key) = self.site.person(person).map(|p| p.delegation_key.clone()) else {
            return no(NotRegistered::NotYours);
        };
        if self.crypto.check_agent_certificate(cert, &key).is_err() {
            return no(NotRegistered::BadCertificate);
        }
        self.register.register(fp.as_str(), person, at(until));
        self.persist();
        reply(PledgeOut::Registered(fp))
    }

    /// The person withdraws one of their own delegations. Requests waiting under it are refused.
    pub fn withdraw(&mut self, person: &str, delegation: &Fingerprint, now: SystemTime) -> Vec<Effect> {
        if self.register.person_of(delegation.as_str()) != Some(person) {
            return Vec::new();
        }
        self.register.withdraw(delegation.as_str());
        self.persist();
        let hashes: Vec<_> =
            self.held.iter().filter(|(_, h)| h.answer.is_none() && &h.agent == delegation).map(|(k, _)| *k).collect();
        self.refuse_held(hashes, BrokerReason::Delegation, now)
    }

    fn refuse_held(&mut self, hashes: Vec<DocumentHash>, reason: BrokerReason, now: SystemTime) -> Vec<Effect> {
        let mut fx = Vec::new();
        for hash in hashes {
            if let Some(link) = self.held.get(&hash).and_then(|h| self.links.get(&h.person)) {
                fx.push(Effect::Pledge(link.conn, PledgeOut::Cancel(hash)));
            }
            fx.extend(self.finish(
                hash,
                Outcome::Refused(Refused::Broker(reason)),
                &format!("refused:{}", reason.wire()),
                now,
            ));
        }
        fx
    }

    /// An administrator blocks a person: what waits for them is refused, and a connected pledge is told.
    pub fn block_person(&mut self, person: &str, now: SystemTime) -> Vec<Effect> {
        self.register.block(person);
        self.persist();
        let hashes: Vec<_> =
            self.held.iter().filter(|(_, h)| h.answer.is_none() && h.person == person).map(|(k, _)| *k).collect();
        let mut fx = self.refuse_held(hashes, BrokerReason::Person, now);
        fx.extend(self.standing(person, now));
        fx
    }

    /// An administrator lifts a block; a connected pledge is told.
    pub fn unblock_person(&mut self, person: &str, now: SystemTime) -> Vec<Effect> {
        self.register.unblock(person);
        self.persist();
        self.standing(person, now).into_iter().collect()
    }

    /// At the deadline the broker forgets the request: an unanswered one is answered `expired`, and an answer
    /// still held for an `ack` is dropped.
    pub fn sweep(&mut self, now: SystemTime) -> Vec<Effect> {
        let due: Vec<_> = self.held.iter().filter(|(_, h)| now >= h.deadline).map(|(k, _)| *k).collect();
        let mut fx = Vec::new();
        for hash in due {
            if self.held.get(&hash).is_some_and(|h| h.answer.is_none()) {
                fx.extend(self.finish(hash, Outcome::Expired(By::Broker), "expired", now));
            }
            if let Some(h) = self.held.remove(&hash) {
                fx.extend(h.conn.map(|c| Effect::Service(c, ServiceOut::Close)));
            }
        }
        self.register.forget_ended(now);
        fx
    }

    /// How many requests are held (for tests and the status).
    #[must_use]
    pub fn held_count(&self) -> usize {
        self.held.len()
    }
}

struct HeldInfo {
    host: String,
    service: String,
    person: Option<String>,
    hash: DocumentHash,
}

impl HeldInfo {
    fn of(h: &Held, hash: DocumentHash) -> HeldInfo {
        HeldInfo { host: h.host.clone(), service: h.service.clone(), person: Some(h.person.clone()), hash }
    }
}

fn refused_to_service(conn: ConnId, hash: DocumentHash, reason: BrokerReason) -> Vec<Effect> {
    vec![
        Effect::Service(
            conn,
            ServiceOut::Answer(Answer { request: hash, outcome: Outcome::Refused(Refused::Broker(reason)) }),
        ),
        Effect::Service(conn, ServiceOut::Close),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::CryptoError;
    use crate::log::MemoryLog;
    use p_act::rating::{Damage, Disruption, Exposure, Rating};
    use p_act::sign::{PublicKey, SignError};
    use p_act::{Call, CallContent, CallId, Request, ServiceId};

    const SIG: &str = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n";
    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";
    const AGENT_A: &str = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const AGENT_B: &str = "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
    const NOW: i64 = 1_800_000_000;

    fn now(plus: i64) -> SystemTime {
        at(NOW + plus)
    }

    /// Signatures that always succeed: the rules of `core` are tested here, the signatures in `tests/`.
    struct Fake;

    impl Crypto for Fake {
        fn verify_request(&self, _: &Request, _: &str, _: &PublicKey) -> Result<(), CryptoError> {
            Ok(())
        }
        fn verify_call(&self, _: &Call, _: &str, _: &PublicKey) -> Result<Agent, CryptoError> {
            Err(CryptoError::Sign(SignError::MalformedSignature))
        }
        fn verify_connection(&self, _: &[u8], _: &str, _: &str, _: &PublicKey) -> Result<(), CryptoError> {
            Ok(())
        }
        fn check_agent_certificate(&self, _: &str, _: &PublicKey) -> Result<Agent, CryptoError> {
            Err(CryptoError::Sign(SignError::MalformedSignature))
        }
        fn sign_clearance(&self, _: &Clearance) -> Result<String, CryptoError> {
            Ok(SIG.to_owned())
        }
        fn sign_standing(&self, _: &[u8]) -> Result<String, CryptoError> {
            Ok(SIG.to_owned())
        }
    }

    fn site() -> Arc<Site> {
        let person = |name: &str, enabled: bool| {
            format!(
                r#"{{"name":"{name}","enabled":{enabled},"connection_key":"{KEY}","delegation_key":"{KEY}","groups":["ops"]}}"#
            )
        };
        let json = format!(
            r#"{{"persons":[{},{},{}],"hosts":[{{"name":"a.example","key":"{KEY}"}}]}}"#,
            person("jan", true),
            person("off", false),
            person("eva", true)
        );
        Arc::new(Site::from_json(&json).unwrap())
    }

    struct Fixture {
        core: Core,
        log: MemoryLog,
    }

    fn fixture(max_waiting: usize) -> Fixture {
        let log = MemoryLog::default();
        let mut register = Register::default();
        let until = now(8 * 3600);
        for (fp, person) in [(AGENT_A, "jan"), (AGENT_B, "jan")] {
            register.register(fp, person, until);
        }
        register.register("SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", "off", until);
        register.register("SHA256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", "eva", until);
        let core = Core::new(
            site(),
            Settings { max_waiting_per_agent: max_waiting },
            register,
            None,
            Arc::new(Fake),
            Box::new(log.clone()),
        );
        Fixture { core, log }
    }

    fn agent(person: &str, fp: &str) -> Agent {
        Agent {
            person: person.to_owned(),
            groups: vec!["ops".to_owned()],
            key_id: "agent".to_owned(),
            delegation: fp.parse().unwrap(),
            valid_after: 0,
            valid_before: u64::MAX / 2,
        }
    }

    /// A vetted request under `fp`, for the person the agent names, with call id number `n`, due `due` seconds from NOW.
    fn vetted(person: &str, fp: &str, n: u32, due: i64) -> Vetted {
        let content = CallContent {
            id: CallId::parse(&format!("3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f{n:04x}")).unwrap(),
            deadline: Timestamp::from_unix(NOW + due).unwrap(),
            service: ServiceId { host: "a.example".into(), name: "probe".into() },
            action: "rt procs".into(),
            params: vec![format!("pid={n}")],
            claim: Some("a claim".into()),
        };
        let call = Call::compose(&content).unwrap();
        let rating = Rating::new(Exposure::Internal, Damage::None, Disruption::None);
        let request = Request::compose(&call, SIG, rating).unwrap();
        Vetted { submit: Submit::new(request, SIG).unwrap(), agent: agent(person, fp) }
    }

    const SVC: ConnId = ConnId(1);
    const PLEDGE: ConnId = ConnId(2);

    fn to_service(fx: &[Effect], conn: ConnId) -> Vec<ServiceOut> {
        fx.iter()
            .filter_map(|e| if let Effect::Service(c, o) = e { (*c == conn).then(|| o.clone()) } else { None })
            .collect()
    }

    fn to_pledge(fx: &[Effect], conn: ConnId) -> Vec<PledgeOut> {
        fx.iter()
            .filter_map(|e| if let Effect::Pledge(c, o) = e { (*c == conn).then(|| o.clone()) } else { None })
            .collect()
    }

    fn refusal_of(fx: &[Effect]) -> Option<BrokerReason> {
        to_service(fx, SVC).into_iter().find_map(|o| match o {
            ServiceOut::Answer(Answer { outcome: Outcome::Refused(Refused::Broker(r)), .. }) => Some(r),
            _ => None,
        })
    }

    fn submits(fx: &[Effect], conn: ConnId) -> Vec<DocumentHash> {
        to_pledge(fx, conn)
            .into_iter()
            .filter_map(|o| if let PledgeOut::Submit(s) = o { Some(s.hash()) } else { None })
            .collect()
    }

    fn sign_in(core: &mut Core, person: &str, conn: ConnId) -> Vec<Effect> {
        core.pledge_signed_in(person, conn, "nonce-1", now(0))
    }

    fn answer(hash: DocumentHash, outcome: Outcome) -> Answer {
        Answer { request: hash, outcome }
    }

    fn approved() -> Outcome {
        Outcome::Approved(Approved::new(SIG, None).unwrap())
    }

    #[test]
    fn a_request_for_a_pledge_that_is_not_connected_waits_and_is_delivered_at_sign_in() {
        let mut f = fixture(5);
        let v = vetted("jan", AGENT_A, 1, 120);
        let hash = v.submit.hash();
        assert!(f.core.submit(SVC, v, now(0)).is_empty());
        let fx = sign_in(&mut f.core, "jan", PLEDGE);
        let kinds: Vec<&str> = to_pledge(&fx, PLEDGE)
            .iter()
            .map(|o| match o {
                PledgeOut::Ready => "ready",
                PledgeOut::Notice { .. } => "notice",
                PledgeOut::Submit(_) => "submit",
                _ => "other",
            })
            .collect();
        assert_eq!(kinds, ["ready", "notice", "submit"], "ready, then the standing, then what waited");
        assert_eq!(submits(&fx, PLEDGE), [hash]);
    }

    #[test]
    fn requests_that_waited_come_in_the_order_they_arrived_and_not_past_their_deadline() {
        let mut f = fixture(5);
        let (a, b, c) = (vetted("jan", AGENT_A, 1, 120), vetted("jan", AGENT_B, 2, 10), vetted("jan", AGENT_A, 3, 120));
        let (ha, hc) = (a.submit.hash(), c.submit.hash());
        for v in [a, b, c] {
            f.core.submit(SVC, v, now(0));
        }
        let fx = f.core.pledge_signed_in("jan", PLEDGE, "n", now(30));
        assert_eq!(submits(&fx, PLEDGE), [ha, hc]);
    }

    #[test]
    fn a_connected_pledge_is_sent_the_request_at_once() {
        let mut f = fixture(5);
        sign_in(&mut f.core, "jan", PLEDGE);
        let v = vetted("jan", AGENT_A, 1, 120);
        let hash = v.submit.hash();
        assert_eq!(submits(&f.core.submit(SVC, v, now(0)), PLEDGE), [hash]);
    }

    #[test]
    fn the_first_failing_check_is_the_answer_and_names_its_reason() {
        let mut f = fixture(5);
        let cases = [
            (vetted("jan", "SHA256:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", 1, 120), BrokerReason::Delegation),
            (vetted("eva", AGENT_A, 2, 120), BrokerReason::Delegation), // the delegation is jan's, the certificate says eva
            (vetted("off", "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC", 3, 120), BrokerReason::Person),
        ];
        for (v, reason) in cases {
            assert_eq!(refusal_of(&f.core.submit(SVC, v, now(0))), Some(reason));
        }
        f.core.block_person("eva", now(0));
        let v = vetted("eva", "SHA256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD", 4, 120);
        assert_eq!(refusal_of(&f.core.submit(SVC, v, now(0))), Some(BrokerReason::Person));
        assert_eq!(f.core.held_count(), 0);
    }

    #[test]
    fn an_ended_or_withdrawn_delegation_is_refused_as_a_delegation() {
        let mut f = fixture(5);
        let v = vetted("jan", AGENT_A, 1, 120);
        assert_eq!(refusal_of(&f.core.submit(SVC, v, now(9 * 3600))), Some(BrokerReason::Delegation));
        let fp: Fingerprint = AGENT_B.parse().unwrap();
        f.core.withdraw("jan", &fp, now(0));
        let v = vetted("jan", AGENT_B, 2, 120);
        assert_eq!(refusal_of(&f.core.submit(SVC, v, now(0))), Some(BrokerReason::Delegation));
    }

    #[test]
    fn per_agent_the_limit_is_the_setting_and_a_resubmission_does_not_count_twice() {
        let mut f = fixture(2);
        let (a, b, c) =
            (vetted("jan", AGENT_A, 1, 120), vetted("jan", AGENT_A, 2, 120), vetted("jan", AGENT_A, 3, 120));
        assert!(f.core.submit(SVC, a.clone(), now(0)).is_empty());
        assert!(f.core.submit(SVC, b, now(0)).is_empty());
        assert_eq!(refusal_of(&f.core.submit(SVC, c, now(0))), Some(BrokerReason::TooManyWaiting));
        // the same bytes again: attached, not refused
        assert_eq!(refusal_of(&f.core.submit(ConnId(9), a, now(1))), None);
        // another agent of the same person has its own count
        assert!(f.core.submit(SVC, vetted("jan", AGENT_B, 4, 120), now(0)).is_empty());
    }

    #[test]
    fn the_default_limit_is_five() {
        assert_eq!(Settings::default().max_waiting_per_agent, 5);
    }

    #[test]
    fn an_approval_comes_back_with_the_clearance_and_is_held_until_the_ack() {
        let mut f = fixture(5);
        sign_in(&mut f.core, "jan", PLEDGE);
        let v = vetted("jan", AGENT_A, 1, 120);
        let hash = v.submit.hash();
        f.core.submit(SVC, v, now(0));
        let fx = f.core.pledge_answer("jan", answer(hash, approved()), now(5));
        let outs = to_service(&fx, SVC);
        let [ServiceOut::Answer(a)] = outs.as_slice() else { panic!("one answer") };
        let Outcome::Approved(ap) = &a.outcome else { panic!("approved") };
        let c = ap.clearance.as_ref().expect("the broker adds the clearance");
        assert_eq!(c.clearance.request(), hash);
        assert_eq!(c.clearance.at().unix(), NOW + 5, "at is when the approval came back");
        assert_eq!(f.core.held_count(), 1, "held in memory until the ack");
        // the connection is lost and the same bytes come again: the answer is there
        f.core.service_gone(SVC);
        let again = vetted("jan", AGENT_A, 1, 120);
        let fx = f.core.submit(ConnId(7), again, now(6));
        assert!(matches!(to_service(&fx, ConnId(7)).as_slice(), [ServiceOut::Answer(_)]));
        f.core.ack(ConnId(7), hash, now(7));
        assert_eq!(f.core.held_count(), 0);
    }

    #[test]
    fn the_log_says_approval_returned_never_approved_and_has_no_parameters() {
        let mut f = fixture(5);
        sign_in(&mut f.core, "jan", PLEDGE);
        let v = vetted("jan", AGENT_A, 1, 120);
        let hash = v.submit.hash();
        f.core.submit(SVC, v, now(0));
        f.core.pledge_answer("jan", answer(hash, approved()), now(5));
        let entries = f.log.entries();
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(
            (e.result.as_str(), e.person.as_deref(), e.host.as_str(), e.service.as_str()),
            ("approval-returned", Some("jan"), "a.example", "probe")
        );
        let shown = format!("{e:?}");
        assert!(!shown.contains("approved") && !shown.contains("pid=") && !shown.contains("a claim"), "{shown}");
    }

    #[test]
    fn an_approval_after_the_deadline_is_dropped_and_the_answer_is_expired() {
        let mut f = fixture(5);
        sign_in(&mut f.core, "jan", PLEDGE);
        let v = vetted("jan", AGENT_A, 1, 120);
        let hash = v.submit.hash();
        f.core.submit(SVC, v, now(0));
        let fx = f.core.pledge_answer("jan", answer(hash, approved()), now(120));
        assert!(matches!(
            to_service(&fx, SVC).as_slice(),
            [ServiceOut::Answer(Answer { outcome: Outcome::Expired(By::Broker), .. })]
        ));
    }

    #[test]
    fn a_decline_and_a_refusal_go_back_as_they_are_and_an_unknown_reason_stays_unknown() {
        let mut f = fixture(5);
        sign_in(&mut f.core, "jan", PLEDGE);
        let mut outcomes = Vec::new();
        for (n, outcome) in [
            (1, Outcome::Declined),
            (2, Outcome::Refused(Refused::Pledge(PledgeReason::Ceiling))),
            (3, Outcome::Refused(Refused::Pledge(PledgeReason::Unknown))),
            // a broker's reason in pledge's mouth is no reason of pledge's
            (4, Outcome::Refused(Refused::Broker(BrokerReason::NotEntitled))),
        ] {
            let v = vetted("jan", AGENT_A, n, 120);
            let hash = v.submit.hash();
            f.core.submit(SVC, v, now(0));
            let fx = f.core.pledge_answer("jan", answer(hash, outcome), now(1));
            let outs = to_service(&fx, SVC);
            let [ServiceOut::Answer(a)] = outs.as_slice() else { panic!("one answer") };
            outcomes.push(a.outcome.clone());
            f.core.ack(SVC, hash, now(2));
        }
        assert_eq!(
            outcomes,
            [
                Outcome::Declined,
                Outcome::Refused(Refused::Pledge(PledgeReason::Ceiling)),
                Outcome::Refused(Refused::Pledge(PledgeReason::Unknown)),
                Outcome::Refused(Refused::Pledge(PledgeReason::Unknown)),
            ]
        );
    }

    #[test]
    fn an_answer_for_a_request_the_broker_does_not_hold_for_that_person_is_ignored() {
        let mut f = fixture(5);
        let v = vetted("jan", AGENT_A, 1, 120);
        let hash = v.submit.hash();
        f.core.submit(SVC, v, now(0));
        assert!(f.core.pledge_answer("eva", answer(hash, approved()), now(1)).is_empty(), "another person's pledge");
        let unknown = vetted("jan", AGENT_A, 2, 120).submit.hash();
        assert!(f.core.pledge_answer("jan", answer(unknown, approved()), now(1)).is_empty(), "not held");
        assert!(f.core.pledge_answer("jan", answer(hash, Outcome::Unknown), now(1)).is_empty(), "no result known");
        let log: Vec<_> = f.log.entries().into_iter().map(|e| (e.result, e.host, e.person)).collect();
        assert_eq!(
            log,
            [
                ("ignored:answer".to_owned(), "-".to_owned(), Some("eva".to_owned())),
                ("ignored:answer".to_owned(), "-".to_owned(), Some("jan".to_owned())),
                ("ignored:answer".to_owned(), "-".to_owned(), Some("jan".to_owned())),
            ],
            "the hash and the time, no names of host or service"
        );
    }

    #[test]
    fn an_answer_is_given_once() {
        let mut f = fixture(5);
        let v = vetted("jan", AGENT_A, 1, 120);
        let hash = v.submit.hash();
        f.core.submit(SVC, v, now(0));
        assert_eq!(to_service(&f.core.pledge_answer("jan", answer(hash, Outcome::Declined), now(1)), SVC).len(), 1);
        assert!(f.core.pledge_answer("jan", answer(hash, approved()), now(2)).is_empty());
    }

    #[test]
    fn a_cancel_removes_the_request_and_is_passed_on_to_the_pledge() {
        let mut f = fixture(5);
        sign_in(&mut f.core, "jan", PLEDGE);
        let v = vetted("jan", AGENT_A, 1, 120);
        let hash = v.submit.hash();
        f.core.submit(SVC, v, now(0));
        assert!(f.core.cancel(ConnId(9), hash, now(1)).is_empty(), "only the connection that holds it");
        let fx = f.core.cancel(SVC, hash, now(1));
        assert!(matches!(to_pledge(&fx, PLEDGE).as_slice(), [PledgeOut::Cancel(h)] if *h == hash));
        assert_eq!(f.core.held_count(), 0);
        let log: Vec<_> = f.log.entries().into_iter().map(|e| e.result).collect();
        assert_eq!(log, ["ignored:cancel", "cancelled"]);
        // the same bytes again are a new request
        let fx = f.core.submit(SVC, vetted("jan", AGENT_A, 1, 120), now(2));
        assert_eq!(submits(&fx, PLEDGE), [hash]);
    }

    #[test]
    fn a_service_connection_that_ends_does_not_cancel() {
        let mut f = fixture(5);
        let v = vetted("jan", AGENT_A, 1, 120);
        f.core.submit(SVC, v, now(0));
        f.core.service_gone(SVC);
        assert_eq!(f.core.held_count(), 1);
        // resubmitting takes the old connection's place and does not reach the pledge twice
        sign_in(&mut f.core, "jan", PLEDGE);
        let fx = f.core.submit(ConnId(5), vetted("jan", AGENT_A, 1, 120), now(1));
        assert!(submits(&fx, PLEDGE).is_empty());
    }

    #[test]
    fn a_resubmission_on_a_new_connection_supersedes_the_old_one() {
        let mut f = fixture(5);
        f.core.submit(SVC, vetted("jan", AGENT_A, 1, 120), now(0));
        let fx = f.core.submit(ConnId(5), vetted("jan", AGENT_A, 1, 120), now(1));
        assert!(matches!(
            to_service(&fx, SVC).as_slice(),
            [ServiceOut::Error(ErrorCode::Superseded), ServiceOut::Close]
        ));
    }

    #[test]
    fn at_the_deadline_an_unanswered_request_is_expired_and_forgotten_and_an_answer_is_dropped() {
        let mut f = fixture(5);
        f.core.submit(SVC, vetted("jan", AGENT_A, 1, 60), now(0));
        f.core.submit(ConnId(3), vetted("jan", AGENT_B, 2, 60), now(0));
        let h2 = vetted("jan", AGENT_B, 2, 60).submit.hash();
        f.core.pledge_answer("jan", answer(h2, Outcome::Declined), now(1));
        assert!(f.core.sweep(now(59)).is_empty());
        let fx = f.core.sweep(now(60));
        assert!(matches!(
            to_service(&fx, SVC).as_slice(),
            [ServiceOut::Answer(Answer { outcome: Outcome::Expired(By::Broker), .. }), ServiceOut::Close]
        ));
        assert!(matches!(to_service(&fx, ConnId(3)).as_slice(), [ServiceOut::Close]));
        assert_eq!(f.core.held_count(), 0);
        let results: Vec<_> = f.log.entries().into_iter().map(|e| e.result).collect();
        assert_eq!(results, ["declined", "expired"]);
    }

    #[test]
    fn a_second_sign_in_of_a_person_supersedes_the_first_and_the_counter_starts_again() {
        let mut f = fixture(5);
        sign_in(&mut f.core, "jan", PLEDGE);
        let fx = f.core.pledge_signed_in("jan", ConnId(8), "nonce-2", now(1));
        assert!(matches!(
            to_pledge(&fx, PLEDGE).as_slice(),
            [PledgeOut::Error(ErrorCode::Superseded), PledgeOut::Close]
        ));
        let standing = notice_json(&to_pledge(&fx, ConnId(8)));
        assert_eq!((standing["nonce"].as_str(), standing["n"].as_u64()), (Some("nonce-2"), Some(0)));
    }

    fn notice_json(outs: &[PledgeOut]) -> serde_json::Value {
        let doc = outs
            .iter()
            .find_map(|o| if let PledgeOut::Notice { doc, .. } = o { Some(doc.clone()) } else { None })
            .unwrap();
        serde_json::from_slice(&doc).unwrap()
    }

    #[test]
    fn blocking_a_person_refuses_what_waits_and_sends_a_new_standing_with_a_higher_counter() {
        let mut f = fixture(5);
        sign_in(&mut f.core, "jan", PLEDGE);
        let v = vetted("jan", AGENT_A, 1, 120);
        let hash = v.submit.hash();
        f.core.submit(SVC, v, now(0));
        let fx = f.core.block_person("jan", now(1));
        assert_eq!(refusal_of(&fx), Some(BrokerReason::Person));
        let pledge = to_pledge(&fx, PLEDGE);
        assert!(matches!(pledge[0], PledgeOut::Cancel(h) if h == hash));
        let standing = notice_json(&pledge);
        assert_eq!(
            (standing["blocked"].as_bool(), standing["n"].as_u64(), standing["to"].as_str()),
            (Some(true), Some(1), Some("jan"))
        );
        let fx = f.core.unblock_person("jan", now(2));
        let standing = notice_json(&to_pledge(&fx, PLEDGE));
        assert_eq!((standing["blocked"].as_bool(), standing["n"].as_u64()), (Some(false), Some(2)));
        assert_eq!(f.core.held_count(), 1, "the refused request is held as an answer until its ack");
    }

    #[test]
    fn the_standing_names_withdrawn_delegations_and_carries_groups_but_no_keys_of_others() {
        let mut f = fixture(5);
        let fp: Fingerprint = AGENT_B.parse().unwrap();
        f.core.withdraw("jan", &fp, now(0));
        f.core.withdraw("eva", &AGENT_A.parse().unwrap(), now(0)); // not eva's: nothing happens
        let fx = sign_in(&mut f.core, "jan", PLEDGE);
        let standing = notice_json(&to_pledge(&fx, PLEDGE));
        assert_eq!(standing["withdrawn"], serde_json::json!([AGENT_B]));
        assert_eq!(standing["groups"], serde_json::json!(["ops"]));
        assert_eq!(standing["blocked"], serde_json::json!(false));
    }

    #[test]
    fn withdrawing_refuses_the_requests_waiting_under_the_delegation() {
        let mut f = fixture(5);
        f.core.submit(SVC, vetted("jan", AGENT_A, 1, 120), now(0));
        f.core.submit(ConnId(3), vetted("jan", AGENT_B, 2, 120), now(0));
        let fx = f.core.withdraw("jan", &AGENT_A.parse().unwrap(), now(1));
        assert_eq!(refusal_of(&fx), Some(BrokerReason::Delegation));
        assert!(to_service(&fx, ConnId(3)).is_empty());
    }

    #[test]
    fn an_unparsed_submit_is_refused_for_the_hash_of_its_bytes_and_logged_without_names() {
        let mut f = fixture(5);
        let hash = DocumentHash::of(b"garbage");
        let fx = f.core.refuse_unparsed(SVC, hash, now(0));
        assert_eq!(refusal_of(&fx), Some(BrokerReason::BadRequest));
        let e = &f.log.entries()[0];
        assert_eq!((e.host.as_str(), e.service.as_str(), e.result.as_str()), ("-", "-", "refused:bad-request"));
    }

    #[test]
    fn the_register_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::os::unix::fs::PermissionsExt::from_mode(0o700)).unwrap();
        let path = dir.path().join("register.json");
        let mut f = fixture(5);
        f.core.state_path = Some(path.clone());
        f.core.block_person("eva", now(0));
        f.core.withdraw("jan", &AGENT_A.parse().unwrap(), now(0));
        let register = Core::read_state(&path).unwrap();
        assert!(register.is_blocked("eva"));
        assert_eq!(register.person_for(AGENT_A, now(1)), Err(Stopped::Withdrawn));
        assert_eq!(register.person_for(AGENT_B, now(1)), Ok("jan"));
        // no file: a first start, an empty register
        assert!(!Core::read_state(&dir.path().join("none")).unwrap().is_blocked("eva"));
    }
}
