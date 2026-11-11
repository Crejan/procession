//! Delegations: `pledge agents start`, `list`, `withdraw` (`SPEC.md`, section
//! 4; `doc/approval-formats.md`, section 3.1; `proposals/review-pact-bundle.md`).
//!
//! `start` makes the agent's Ed25519 key in memory, has the key holder sign a
//! certificate for it with the delegation key (the person is its only
//! principal; no critical options; the extension `groups@procession`), checks
//! the certificate with the code that checks calls, and replies with the key
//! block and the certificate. The delegation is **pending** and signs nothing
//! until the command line reports the bundle written (`delivered`); a
//! connection that ends first withdraws it. pledge keeps the certificate and the
//! ceilings, not the key.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p_act::rating::{Ceilings, Rating};
use p_act::sign::{PublicKey, verify_call_agent};
use p_act::{Call, CallContent, CallId, Document, ServiceId, Timestamp};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::agent::host_key::fingerprint;
use crate::agent::text::is_showable;
use crate::config::is_name;
use crate::control::Code;
use crate::delegations::{Delegation, RatingWords, State};
use crate::dialog::{Outcome, Wait};
use crate::openssh::{AgentKey, CertificateParts, certificate_blob, certificate_line, certificate_to_sign};
use crate::shared::Shared;
use crate::sshsig;

/// A delegation's validity by default, in seconds: 8 hours.
pub const DEFAULT_VALID_SECONDS: u64 = 8 * 3600;
/// The shortest a delegation may last: a minute. (The certificate is checked
/// by `ssh-keygen` against the real clock; a shorter one could end between
/// being made and being checked.)
pub const MIN_VALID_SECONDS: u64 = 60;
/// The longest a delegation may last: 24 hours.
pub const MAX_VALID_SECONDS: u64 = 24 * 3600;
/// How far before now a certificate's validity starts, for clocks that differ.
const BACKDATE_SECONDS: i64 = 60;

/// The arguments of `agents.start`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartArgs {
    /// The delegation's groups.
    #[serde(default)]
    pub groups: Vec<String>,
    /// The automatic ceiling; harmless by default.
    pub automatic_ceiling: Option<RatingWords>,
    /// The ask ceiling; the worst by default.
    pub ask_ceiling: Option<RatingWords>,
    /// How long it lasts.
    pub valid_seconds: Option<u64>,
    /// A free label, for dialogs and the record.
    pub label: Option<String>,
}

fn random_uuid() -> Option<String> {
    let mut bytes = [0_u8; 16];
    SystemRandom::new().fill(&mut bytes).ok()?;
    bytes[6] = bytes[6] & 0x0F | 0x40;
    bytes[8] = bytes[8] & 0x3F | 0x80;
    let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
    Some(format!(
        "{}-{}-{}-{}-{}",
        hex[0..4].concat(),
        hex[4..6].concat(),
        hex[6..8].concat(),
        hex[8..10].concat(),
        hex[10..16].concat()
    ))
}

/// Checks the certificate just made with the code that checks calls: a probe
/// call signed with the agent's key and certificate must verify under the
/// delegation key, and name the person, the groups and the key's fingerprint.
fn self_check(
    key: &AgentKey,
    certificate: &[u8],
    issuer: &PublicKey,
    person: &str,
    groups: &[String],
    id: &str,
    now: Timestamp,
) -> bool {
    let (Some(uuid), Some(deadline)) = (random_uuid(), now.checked_add(60)) else { return false };
    let Ok(call_id) = CallId::parse(&uuid) else { return false };
    let content = CallContent {
        id: call_id,
        deadline,
        service: ServiceId { host: "localhost".into(), name: "probe".into() },
        action: "check".into(),
        params: Vec::new(),
        claim: None,
    };
    let Ok(call) = Call::compose(&content) else { return false };
    let Ok(signature) = key.sign(&sshsig::signed_data("call-v1@procession", call.as_bytes())) else { return false };
    let armoured = sshsig::armour(certificate, "call-v1@procession", &signature);
    verify_call_agent(&call, &armoured, issuer)
        .is_ok_and(|agent| agent.person == person && agent.groups == groups && agent.delegation.as_str() == id)
}

/// `agents.start`. Returns the reply's data and the new delegation's identifier.
///
/// # Errors
///
/// A [`Code`] for what is wrong: no person configured, no delegation key,
/// arguments outside what a person may set, the presence check.
pub fn start(shared: &Shared, args: StartArgs) -> Result<(Value, String), Code> {
    let person = shared.approvals.config.person.clone().ok_or(Code::Refused)?;
    let mut groups = args.groups;
    if !groups.iter().all(|g| is_name(g)) {
        return Err(Code::BadArguments);
    }
    groups.sort();
    groups.dedup();
    let rating = |words: Option<RatingWords>, default: Rating| {
        words.map_or(Some(default), |w| w.rating()).ok_or(Code::BadArguments)
    };
    let automatic = rating(args.automatic_ceiling, Rating::HARMLESS)?;
    let ask = rating(args.ask_ceiling, Rating::WORST)?;
    // A person cannot set an automatic ceiling above `HIGHEST_AUTOMATIC`, or above the ask ceiling.
    Ceilings::new(automatic, ask).ok_or(Code::Refused)?;
    let valid = args.valid_seconds.unwrap_or(DEFAULT_VALID_SECONDS);
    if valid < MIN_VALID_SECONDS {
        return Err(Code::BadArguments);
    }
    if valid > MAX_VALID_SECONDS {
        return Err(Code::Refused);
    }
    let label = args.label.unwrap_or_else(|| "pledge agent".to_owned());
    if label.is_empty() || !is_showable(&label) {
        return Err(Code::BadArguments);
    }
    let issuer = shared.key_with_purpose("delegation").ok_or(Code::Unavailable)?;
    let issuer_key = PublicKey::parse(&issuer.public_line()).map_err(|_| Code::Unavailable)?;
    let question = format!(
        "start an agent for {person}: groups {}; automatic up to {}/{}/{}, ask up to {}/{}/{}; valid {valid} seconds",
        if groups.is_empty() { "(none)".to_owned() } else { groups.join(",") },
        RatingWords::of(automatic).exposure,
        RatingWords::of(automatic).damage,
        RatingWords::of(automatic).disruption,
        RatingWords::of(ask).exposure,
        RatingWords::of(ask).damage,
        RatingWords::of(ask).disruption,
    );
    match shared.dialogs.confirm(&question, &Wait::up_to(crate::control::PRESENCE_TIMEOUT)) {
        Outcome::Answer(true) => {}
        Outcome::Answer(false) | Outcome::Timeout => return Err(Code::PresenceDenied),
        Outcome::Unavailable | Outcome::Cancelled => return Err(Code::Unavailable),
    }

    let now = shared.now();
    let now_secs = u64::try_from(now.unix()).map_err(|_| Code::Unavailable)?;
    let key = AgentKey::generate().map_err(|_| Code::Unavailable)?;
    let public: [u8; 32] =
        key.public_blob()[key.public_blob().len() - 32..].try_into().map_err(|_| Code::Unavailable)?;
    let parts = CertificateParts {
        person: &person,
        groups: &groups,
        label: &label,
        valid_after: now_secs.saturating_sub(BACKDATE_SECONDS.unsigned_abs()),
        valid_before: now_secs + valid,
        serial: now_secs,
    };
    let to_sign = certificate_to_sign(&public, &parts, &issuer.blob).map_err(|_| Code::Unavailable)?;
    let signature = shared
        .holder
        .lock()
        .map_err(|_| Code::Unavailable)?
        .sign(&issuer.blob, &to_sign)
        .map_err(|_| Code::Unavailable)?;
    let blob = certificate_blob(&to_sign, &signature);
    let line = certificate_line(&blob);
    let id = fingerprint(&key.public_blob());
    if !self_check(&key, &blob, &issuer_key, &person, &groups, &id, now) {
        return Err(Code::Unavailable);
    }
    let valid_until = now.unix() + i64::try_from(valid).map_err(|_| Code::BadArguments)?;
    let delegation = Delegation {
        id: id.clone(),
        agent_public: key.public_line(),
        certificate: line.clone(),
        person: person.clone(),
        groups: groups.clone(),
        automatic: RatingWords::of(automatic),
        ask: RatingWords::of(ask),
        issuer: issuer.fingerprint.clone(),
        issued: now.unix(),
        valid_until,
        state: State::Pending,
        withdrawn: None,
        last_asked: None,
    };
    shared.approvals.delegations.add(delegation).map_err(|_| Code::Unavailable)?;
    shared.event(
        "delegation-issued",
        json!({"delegation": id, "person": person, "groups": groups, "automatic": RatingWords::of(automatic), "ask": RatingWords::of(ask), "valid_until": Timestamp::from_unix(valid_until).map(|t| t.to_string())}),
    );
    let block = key.private_block(&label);
    let data = json!({
        "delegation": id,
        "key_block": STANDARD.encode(block.expose()),
        "certificate": STANDARD.encode(line.as_bytes()),
        "valid_until": Timestamp::from_unix(valid_until).map(|t| t.to_string()),
    });
    Ok((data, id))
}

/// `agents.delivered`: the bundle is written; the delegation signs from now on.
///
/// # Errors
///
/// [`Code::NotFound`] if no such delegation is pending.
pub fn delivered(shared: &Shared, id: &str) -> Result<Value, Code> {
    match shared.approvals.delegations.activate(id) {
        Ok(true) => Ok(json!({})),
        Ok(false) => Err(Code::NotFound),
        Err(_) => Err(Code::Unavailable),
    }
}

/// Withdraws a delegation and records it. `by` is `person` or `delivery-failed`.
///
/// # Errors
///
/// [`Code::NotFound`] if there is none, or it was withdrawn already.
pub fn withdraw(shared: &Shared, id: &str, by: &str) -> Result<Value, Code> {
    match shared.approvals.delegations.withdraw(id, shared.now().unix()) {
        Ok(true) => {
            shared.event("delegation-withdrawn", json!({"delegation": id, "by": by}));
            Ok(json!({}))
        }
        Ok(false) => Err(Code::NotFound),
        Err(_) => Err(Code::Unavailable),
    }
}

/// `agents.list`.
#[must_use]
pub fn list(shared: &Shared) -> Value {
    let now = shared.now().unix();
    let delegations: Vec<Value> = shared
        .approvals
        .delegations
        .all()
        .iter()
        .map(|d| {
            let state = if d.withdrawn.is_some() {
                "withdrawn"
            } else if d.state == State::Pending {
                "pending"
            } else if now >= d.valid_until {
                "ended"
            } else {
                "active"
            };
            let time = |t: i64| Timestamp::from_unix(t).map(|t| t.to_string());
            json!({
                "delegation": d.id, "person": d.person, "groups": d.groups, "automatic": d.automatic, "ask": d.ask,
                "valid_until": time(d.valid_until), "state": state,
                "withdrawn": d.withdrawn.and_then(time), "last_asked": d.last_asked.and_then(time),
            })
        })
        .collect();
    json!({"delegations": delegations})
}
