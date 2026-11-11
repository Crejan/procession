//! What pledge does with a request a service submitted (`SPEC.md`, section 4;
//! `doc/approval-connections.md`, 3.7): check, derive the mode, ask or sign,
//! **sign, record, store, send**.
//!
//! pledge's answer to a request is final until the call's deadline. The same
//! bytes submitted again get the same answer again from the store of answers
//! (`answers.rs`); a verdict, an approval and a decline are kept, a passing
//! condition (`limit`, `muted`, `unavailable`) is not. A call's identifier is
//! used once pledge approved or the person declined; a different request under
//! it is refused `call-used`. A request that was cancelled is over.
//!
//! The checks, in order: the delegation (pledge's own, not withdrawn, not
//! ended), the deadline by pledge's own clock, the identifier, the service's
//! signature and the host it names, that every field can be shown as it is, the
//! limits, and the mode from the ceilings. Nothing is signed that was not
//! recorded first.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p_act::exchange::{Answer, Approved, By, Outcome, PledgeReason, Refused, Submit};
use p_act::rating::{Mode, Rating};
use p_act::sign::{PublicKey, signature_agent, verify_call_agent, verify_request};
use p_act::{Document, DocumentHash, Request, Timestamp};
use serde_json::{Map, Value, json};

use crate::agent::text::is_showable;
use crate::answers::{Answers, Stored};
use crate::config::Config;
use crate::delegations::{Delegations, RatingWords};
use crate::dialog::{Description, Outcome as Dialog, Wait};
use crate::mute::Muter;
use crate::shared::{KeyInfo, Shared};
use crate::sshsig;

/// The namespace of an approval.
pub const APPROVAL_NAMESPACE: &str = "approval-v1@procession";
/// The tolerated clock difference, which applies only to "more than ten minutes ahead".
pub const TOLERANCE_SECONDS: i64 = p_act::limits::CLOCK_TOLERANCE_SECONDS;

/// Where an answer goes: one connection's writer.
pub type Send = Arc<dyn Fn(&Answer) + std::marker::Send + Sync>;

/// Whoever submitted, on one connection.
#[derive(Clone)]
pub struct Responder {
    /// Distinguishes the connections that submitted the same request.
    pub id: u64,
    /// Writes an answer to the connection.
    pub send: Send,
    /// Information for the record: the peer's user and process.
    pub peer: Option<(u32, Option<i32>)>,
}

struct Inflight {
    responders: Vec<Responder>,
    cancelled: Arc<AtomicBool>,
    agent: Option<String>,
}

/// The state of approvals: configuration, delegations, answers, what is open.
pub struct Approvals {
    /// What the person told pledge.
    pub config: Config,
    /// The delegations pledge issued.
    pub delegations: Delegations,
    /// The store of answers and used identifiers.
    pub answers: Answers,
    inflight: Mutex<HashMap<String, Inflight>>,
    muter: Mutex<Muter>,
    next_responder: AtomicU64,
}

impl Approvals {
    /// Assembles the state.
    #[must_use]
    pub fn new(config: Config, delegations: Delegations, answers: Answers) -> Self {
        Self {
            config,
            delegations,
            answers,
            inflight: Mutex::new(HashMap::new()),
            muter: Mutex::new(Muter::default()),
            next_responder: AtomicU64::new(1),
        }
    }

    /// A new responder identifier.
    pub fn responder_id(&self) -> u64 {
        self.next_responder.fetch_add(1, Ordering::Relaxed)
    }

    /// How many requests of this agent are open.
    fn waiting(&self, agent: &str, except: &str) -> usize {
        self.inflight.lock().map_or(0, |open| {
            open.iter().filter(|(hash, e)| *hash != except && e.agent.as_deref() == Some(agent)).count()
        })
    }

    fn set_agent(&self, hash: &str, agent: &str) {
        if let Ok(mut open) = self.inflight.lock() {
            if let Some(entry) = open.get_mut(hash) {
                entry.agent = Some(agent.to_owned());
            }
        }
    }

    /// The sender no longer wants an answer. If nobody else submitted the same
    /// bytes, the dialog closes and the request is over. Ignored, and said so,
    /// for a request pledge does not hold.
    pub fn cancel(&self, hash: &DocumentHash, responder: u64) {
        let key = hash.to_string();
        let Ok(mut open) = self.inflight.lock() else { return };
        match open.get_mut(&key) {
            Some(entry) => {
                entry.responders.retain(|r| r.id != responder);
                if entry.responders.is_empty() {
                    entry.cancelled.store(true, Ordering::SeqCst);
                }
            }
            None => eprintln!("pledge: cancel for a request it does not hold: {key}"),
        }
    }

    /// Every connection that has these requests open is gone.
    pub fn cancel_all(&self, hashes: &[DocumentHash], responder: u64) {
        for hash in hashes {
            self.cancel(hash, responder);
        }
    }
}

/// What a request turned out to be.
enum Ending {
    Approved(String),
    Declined,
    Refused(PledgeReason),
    Expired,
    Cancelled,
}

/// What the record says about a request, as far as it was found out.
#[derive(Default)]
struct Facts {
    person: Option<String>,
    delegation: Option<String>,
    agent: Option<String>,
    service: Option<(String, String)>,
    call: Option<String>,
    deadline: Option<Timestamp>,
    /// Fields that can be shown as they are.
    shown: Option<(String, Vec<String>, Option<String>)>,
    rating: Option<Rating>,
    mode: Option<&'static str>,
    key: Option<(&'static str, String)>,
    clamped: bool,
    peer: Option<(u32, Option<i32>)>,
}

/// Seconds from `now` that a stored entry is kept: to the call's deadline, but
/// not past the longest a deadline may be.
fn expiry(now: i64, deadline: Option<Timestamp>) -> i64 {
    let cap = now + p_act::limits::MAX_DEADLINE_AHEAD_SECONDS + TOLERANCE_SECONDS;
    deadline.map_or(cap, |d| d.unix().min(cap))
}

fn answer_for(hash: DocumentHash, outcome: Outcome) -> Answer {
    Answer { request: hash, outcome }
}

fn answer_from_stored(hash: DocumentHash, stored: Stored) -> Option<Answer> {
    let outcome = match stored {
        Stored::Approved { approval } => {
            let armoured = String::from_utf8(STANDARD.decode(approval).ok()?).ok()?;
            Outcome::Approved(Approved::new(&armoured, None).ok()?)
        }
        Stored::Declined => Outcome::Declined,
        Stored::Refused { reason } => Outcome::Refused(Refused::Pledge(PledgeReason::from_wire(&reason))),
    };
    Some(answer_for(hash, outcome))
}

/// A verdict is kept; a passing condition is not (`doc/approval-connections.md`, 3.7).
fn is_verdict(reason: PledgeReason) -> bool {
    matches!(
        reason,
        PledgeReason::UnknownDelegation
            | PledgeReason::DelegationEnded
            | PledgeReason::DelegationWithdrawn
            | PledgeReason::ServiceMismatch
            | PledgeReason::NotShowable
            | PledgeReason::Ceiling
            | PledgeReason::Malformed
            | PledgeReason::DeadlineTooFar
    )
}

/// A submitted request: the whole of what pledge does with it. Returns when
/// the answer has been sent, or when there is nobody left to send it to.
pub fn submit(shared: &Shared, submit: &Submit, responder: Responder) {
    let approvals = &shared.approvals;
    let hash = submit.hash();
    let key = hash.to_string();
    let now = shared.now().unix();
    if let Some(answer) = approvals.answers.answer(&key, now).and_then(|stored| answer_from_stored(hash, stored)) {
        (responder.send)(&answer);
        return;
    }
    let cancelled = {
        let Ok(mut open) = approvals.inflight.lock() else { return };
        if let Some(entry) = open.get_mut(&key) {
            // Already open: nothing is done, and this sender gets the answer too.
            if !entry.responders.iter().any(|r| r.id == responder.id) {
                entry.responders.push(responder);
            }
            return;
        }
        let cancelled = Arc::new(AtomicBool::new(false));
        open.insert(
            key.clone(),
            Inflight { responders: vec![responder.clone()], cancelled: Arc::clone(&cancelled), agent: None },
        );
        cancelled
    };
    let mut facts = Facts { peer: responder.peer, ..Facts::default() };
    let ending = process(shared, submit, &key, &cancelled, &mut facts);
    finish(shared, hash, ending, facts);
}

/// A request that does not parse is answered `refused` / `malformed`, as a
/// verdict, for the hash of the bytes received.
pub fn refuse_malformed(shared: &Shared, hash: DocumentHash, responder: &Responder) {
    let key = hash.to_string();
    let now = shared.now().unix();
    if let Some(answer) = shared.approvals.answers.answer(&key, now).and_then(|stored| answer_from_stored(hash, stored))
    {
        (responder.send)(&answer);
        return;
    }
    let facts = Facts { peer: responder.peer, ..Facts::default() };
    if let Ok(mut open) = shared.approvals.inflight.lock() {
        open.entry(key).or_insert_with(|| Inflight {
            responders: vec![responder.clone()],
            cancelled: Arc::new(AtomicBool::new(false)),
            agent: None,
        });
    }
    finish(shared, hash, Ending::Refused(PledgeReason::Malformed), facts);
}

fn refuse(reason: PledgeReason) -> Ending {
    Ending::Refused(reason)
}

fn holder_sign(shared: &Shared, key: &KeyInfo, request: &Request) -> Option<String> {
    let data = sshsig::signed_data(APPROVAL_NAMESPACE, request.as_bytes());
    let signature = shared.holder.lock().ok()?.sign(&key.blob, &data).ok()?;
    Some(sshsig::armour(&key.blob, APPROVAL_NAMESPACE, &signature))
}

fn description(facts: &Facts, request: &Request) -> Description {
    let mut fields: Vec<(&'static str, String)> = Vec::new();
    let (action, params, claim) = facts.shown.clone().unwrap_or_default();
    fields.push(("person", facts.person.clone().unwrap_or_default()));
    fields.push(("agent", facts.delegation.clone().unwrap_or_default()));
    if let Some((host, name)) = &facts.service {
        fields.push(("service", format!("{name} on {host}")));
    }
    fields.push(("action", action));
    for param in params {
        fields.push(("parameter", param));
    }
    if let Some(claim) = claim {
        fields.push(("the agent's claim", claim));
    }
    let rating = request.rating();
    let words = (RatingWords::of(rating).exposure, RatingWords::of(rating).damage, RatingWords::of(rating).disruption);
    fields.push(("exposure", words.0));
    fields.push(("damage", words.1));
    fields.push(("disruption", words.2));
    fields.push(("deadline", request.call().deadline().to_string()));
    Description { title: "an agent asks for this to be carried out".into(), fields }
}

#[allow(clippy::too_many_lines)]
fn process(shared: &Shared, submit: &Submit, hash: &str, cancelled: &Arc<AtomicBool>, facts: &mut Facts) -> Ending {
    let approvals = &shared.approvals;
    let request = submit.request();
    let call = request.call();
    let now = shared.now();
    let deadline = call.deadline();
    facts.call = Some(call.id().to_string());
    facts.deadline = Some(deadline);
    facts.service = Some((call.service().host.clone(), call.service().name.clone()));

    // 1. The call, under one of pledge's own delegations.
    let Ok(agent) = signature_agent(request.call_sig()) else { return refuse(PledgeReason::UnknownDelegation) };
    facts.person = Some(agent.person.clone());
    facts.delegation = Some(agent.delegation.as_str().to_owned());
    facts.agent = Some(agent.delegation.as_str().to_owned());
    let Some(delegation) = approvals.delegations.get(agent.delegation.as_str()) else {
        return refuse(PledgeReason::UnknownDelegation);
    };
    if approvals.config.person.as_deref() != Some(agent.person.as_str()) || delegation.person != agent.person {
        return refuse(PledgeReason::UnknownDelegation);
    }
    if delegation.withdrawn.is_some() {
        return refuse(PledgeReason::DelegationWithdrawn);
    }
    if now.unix() >= delegation.valid_until {
        return refuse(PledgeReason::DelegationEnded);
    }
    let Some(issuer) = shared.key_by_fingerprint(&delegation.issuer) else {
        return refuse(PledgeReason::UnknownDelegation);
    };
    let Ok(issuer_key) = PublicKey::parse(&issuer.public_line()) else {
        return refuse(PledgeReason::UnknownDelegation);
    };
    if verify_call_agent(call, request.call_sig(), &issuer_key).is_err() {
        return refuse(PledgeReason::UnknownDelegation);
    }
    let Some(ceilings) = delegation.ceilings() else { return refuse(PledgeReason::UnknownDelegation) };
    facts.clamped = delegation.automatic_was_raised();
    approvals.set_agent(hash, agent.delegation.as_str());
    let _ = approvals.delegations.touch(agent.delegation.as_str(), now.unix());

    // The deadline, by pledge's own clock. The tolerance never extends it.
    if deadline <= now {
        return refuse(PledgeReason::DeadlinePast);
    }
    if deadline.unix() - now.unix() > p_act::limits::MAX_DEADLINE_AHEAD_SECONDS + TOLERANCE_SECONDS {
        return refuse(PledgeReason::DeadlineTooFar);
    }
    // The identifier: used by another request?
    if approvals.answers.used_for(call.id().as_str(), now.unix()).is_some_and(|other| other != hash) {
        return refuse(PledgeReason::CallUsed);
    }

    // 2. The request: signed by a service key that a known host certified,
    // and host and service are the ones the call names.
    let Some(host_key) = approvals.config.host_key(&call.service().host) else {
        return refuse(PledgeReason::ServiceMismatch);
    };
    if verify_request(request, submit.request_sig(), &host_key).is_err() {
        return refuse(PledgeReason::ServiceMismatch);
    }

    // 3. Every field can be shown as it is.
    let mut texts: Vec<&str> = vec![call.action(), &call.service().host, &call.service().name, &agent.person];
    texts.extend(call.params().iter().map(String::as_str));
    texts.extend(call.claim());
    if !texts.into_iter().all(is_showable) {
        return refuse(PledgeReason::NotShowable);
    }
    facts.shown = Some((call.action().to_owned(), call.params().to_vec(), call.claim().map(str::to_owned)));
    facts.rating = Some(request.rating());

    // 5. The limits.
    let agent_id = agent.delegation.as_str();
    if approvals.muter.lock().is_ok_and(|muter| muter.is_muted(agent_id, u64::try_from(now.unix()).unwrap_or(0))) {
        return refuse(PledgeReason::Muted);
    }
    if approvals.waiting(agent_id, hash) >= approvals.config.max_waiting() {
        return refuse(PledgeReason::Limit);
    }

    // 6. The mode, from the rating and the two ceilings.
    let mode = ceilings.mode(request.rating());
    facts.mode = Some(match mode {
        Mode::Refuse => "refuse",
        Mode::Ask => "ask",
        Mode::Automatic => "automatic",
    });
    let expires = expiry(now.unix(), Some(deadline));
    let reserve = || approvals.answers.mark_used(call.id().as_str(), hash, expires).is_ok();
    match mode {
        Mode::Refuse => refuse(PledgeReason::Ceiling),
        Mode::Automatic => {
            let Some(key) = shared.key_with_purpose("automatic") else { return refuse(PledgeReason::Unavailable) };
            if !reserve() {
                return refuse(PledgeReason::Unavailable);
            }
            facts.key = Some(("automatic", key.fingerprint.clone()));
            holder_sign(shared, &key, request).map_or_else(|| refuse(PledgeReason::Unavailable), Ending::Approved)
        }
        Mode::Ask => {
            let Some(key) = shared.key_with_purpose("confirmed") else { return refuse(PledgeReason::Unavailable) };
            let what = description(facts, request);
            let left = |now: Timestamp| Duration::from_secs(u64::try_from(deadline.unix() - now.unix()).unwrap_or(0));
            let is_cancelled = || cancelled.load(Ordering::SeqCst);
            let wait = Wait { timeout: left(shared.now()), cancelled: &is_cancelled };
            let agreed = shared.dialogs.ask_request(&what, &wait).and_then(|yes| {
                if !yes {
                    return Dialog::Answer(false);
                }
                // The presence check, for this one signature.
                let wait = Wait { timeout: left(shared.now()), cancelled: &is_cancelled };
                shared.dialogs.confirm(&format!("sign the approval for the request: {}", call.action()), &wait)
            });
            match agreed {
                Dialog::Answer(true) => {
                    if !reserve() {
                        return refuse(PledgeReason::Unavailable);
                    }
                    facts.key = Some(("confirmed", key.fingerprint.clone()));
                    holder_sign(shared, &key, request)
                        .map_or_else(|| refuse(PledgeReason::Unavailable), Ending::Approved)
                }
                Dialog::Answer(false) => {
                    if !reserve() {
                        return refuse(PledgeReason::Unavailable);
                    }
                    let now = u64::try_from(shared.now().unix()).unwrap_or(0);
                    if approvals.muter.lock().is_ok_and(|mut muter| muter.declined(agent_id, now)) {
                        shared.event("agent-muted", json!({"delegation": agent_id}));
                        shared.dialogs.tell(&format!("the agent {agent_id} was declined {} times within ten minutes: its requests are refused for ten minutes", crate::mute::DECLINES));
                    }
                    Ending::Declined
                }
                Dialog::Timeout => Ending::Expired,
                Dialog::Cancelled => Ending::Cancelled,
                Dialog::Unavailable => refuse(PledgeReason::Unavailable),
            }
        }
    }
}

fn entry(hash: &str, ending: &Ending, facts: &Facts) -> Value {
    let mut entry = Map::new();
    entry.insert("type".into(), "request".into());
    let (result, reason) = match ending {
        Ending::Approved(_) => ("approved", None),
        Ending::Declined => ("declined", None),
        Ending::Refused(reason) => ("refused", Some(reason.wire())),
        Ending::Expired => ("expired", None),
        Ending::Cancelled => ("cancelled", None),
    };
    entry.insert("result".into(), result.into());
    if let Some(reason) = reason {
        entry.insert("reason".into(), reason.into());
    }
    entry.insert("request_hash".into(), hash.into());
    let mut put = |name: &str, value: Option<Value>| {
        if let Some(value) = value {
            entry.insert(name.into(), value);
        }
    };
    put("person", facts.person.clone().map(Value::from));
    put("delegation", facts.delegation.clone().map(Value::from));
    put("agent", facts.agent.clone().map(Value::from));
    put("service", facts.service.as_ref().map(|(host, name)| json!({"host": host, "name": name})));
    put("call", facts.call.clone().map(Value::from));
    put("deadline", facts.deadline.map(|d| Value::from(d.to_string())));
    if let Some((action, params, claim)) = &facts.shown {
        put("action", Some(action.clone().into()));
        put("params", Some(params.clone().into()));
        put("claim", claim.clone().map(Value::from));
    }
    put("rating", facts.rating.map(|r| json!(RatingWords::of(r))));
    put("mode", facts.mode.map(Value::from));
    if let Some((role, fingerprint)) = &facts.key {
        put("key", Some((*role).into()));
        put("key_fingerprint", Some(fingerprint.clone().into()));
    }
    if facts.clamped {
        put("automatic_ceiling_clamped", Some(true.into()));
    }
    put("peer", facts.peer.map(|(uid, pid)| json!({"uid": uid, "pid": pid})));
    Value::Object(entry)
}

/// Records the ending, keeps what is to be kept, and sends the answer.
fn finish(shared: &Shared, hash: DocumentHash, mut ending: Ending, facts: Facts) {
    let approvals = &shared.approvals;
    let key = hash.to_string();
    let now = shared.now().unix();
    // No record, no approval.
    if let Err(e) = shared.append(entry(&key, &ending, &facts)) {
        eprintln!("pledge: the record cannot be written, so nothing is signed: {e}");
        if matches!(ending, Ending::Approved(_)) {
            ending = Ending::Refused(PledgeReason::Unavailable);
        }
    }
    let stored = match &ending {
        Ending::Approved(armoured) => Some(Stored::Approved { approval: STANDARD.encode(armoured) }),
        Ending::Declined => Some(Stored::Declined),
        Ending::Refused(reason) if is_verdict(*reason) => Some(Stored::Refused { reason: reason.wire().to_owned() }),
        _ => None,
    };
    if let Some(stored) = stored {
        let expires = expiry(now, facts.deadline);
        if expires > now {
            if let Err(e) = approvals.answers.keep(&key, stored, expires) {
                eprintln!("pledge: the answer could not be stored: {e}");
            }
        }
    }
    let responders = approvals
        .inflight
        .lock()
        .ok()
        .and_then(|mut open| open.remove(&key))
        .map(|entry| entry.responders)
        .unwrap_or_default();
    let outcome = match ending {
        Ending::Approved(armoured) => match Approved::new(&armoured, None) {
            Ok(approved) => Outcome::Approved(approved),
            Err(_) => Outcome::Refused(Refused::Pledge(PledgeReason::Unavailable)),
        },
        Ending::Declined => Outcome::Declined,
        Ending::Refused(reason) => Outcome::Refused(Refused::Pledge(reason)),
        Ending::Expired => Outcome::Expired(By::Pledge),
        Ending::Cancelled => return,
    };
    let answer = answer_for(hash, outcome);
    for responder in responders {
        (responder.send)(&answer);
    }
}
