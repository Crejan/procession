//! Delegations: `pledge agents start`, `list`, `withdraw` (`SPEC.md`, section
//! 4; `doc/approval-formats.md`, section 3.1; `proposals/review-pact-bundle.md`).
//!
//! `start` has the agent's key pair and certificate made by OpenSSH through
//! the one seam, [`issue`](crate::issue), composes the bundle with p-act, and
//! replies with its bytes. A delegation **exists** for pledge only from
//! `agents.delivered`: until then it is held on the connection that started
//! it, signs for no call, and has been written nowhere; a connection that ends
//! first leaves only a record entry. pledge keeps the certificate and the
//! ceilings, never the key.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p_act::Timestamp;
use p_act::limits::{DEFAULT_DELEGATION_SECONDS, MAX_DELEGATION_SECONDS};
use p_act::pact::Service;
use p_act::pact::bundle::{Bundle, Config as BundleConfig};
use p_act::rating::{Ceilings, Rating};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::agent::text::is_showable;
use crate::config::{DEFAULT_DEADLINE_SECONDS, ServiceEntry, is_name};
use crate::control::Code;
use crate::delegations::{Delegation, RatingWords};
use crate::dialog::{Outcome, Wait};
use crate::issue::{Issuing, issue};
use crate::shared::Shared;

/// The shortest a delegation may last: a minute.
pub const MIN_VALID_SECONDS: u64 = 60;

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
    /// The services the bundle names: the person's own, from a file or options; never the broker's word.
    pub services: Vec<ServiceEntry>,
    /// The TLS root for `https` services (PEM).
    pub tls_root: Option<String>,
    /// The deadline the agent is told to give its calls.
    pub deadline_seconds: Option<u32>,
}

/// Starts a delegation. Returns the reply's data and the delegation, which the
/// caller holds until it is delivered.
///
/// # Errors
///
/// A [`Code`] for what is wrong: no person configured, no delegation key,
/// arguments outside what a person may set, the presence check, issuing.
pub fn start(shared: &Shared, args: StartArgs) -> Result<(Value, Delegation), Code> {
    let person = shared.approvals.config.person.clone().ok_or(Code::Refused)?;
    // With a broker configured, issuing needs the connection and a standing verified on it: nothing is
    // issued otherwise, and never a local-only delegation.
    let link = shared.link();
    if shared.approvals.config.broker.is_some() && !link.as_ref().is_some_and(|l| l.can_issue()) {
        eprintln!("pledge: the broker cannot be reached (or has not sent its standing yet): nothing issued");
        return Err(Code::BrokerUnavailable);
    }
    // A delegation key the broker blocks issues nothing: said to the person, in the record.
    if let Some(key) = shared.key_with_purpose("delegation")
        && shared.broker_state.is_key_blocked(&key.fingerprint)
    {
        eprintln!("pledge: the delegation key is blocked by the broker: nothing issued");
        shared.event("issuing-refused", json!({"why": "the delegation key is blocked by the broker"}));
        return Err(Code::Refused);
    }
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
    let valid = args.valid_seconds.unwrap_or(u64::try_from(DEFAULT_DELEGATION_SECONDS).unwrap_or(0));
    if valid < MIN_VALID_SECONDS {
        return Err(Code::BadArguments);
    }
    if valid > u64::try_from(MAX_DELEGATION_SECONDS).unwrap_or(0) {
        return Err(Code::Refused);
    }
    let label = args.label.unwrap_or_else(|| "pledge agent".to_owned());
    if label.is_empty() || !is_showable(&label) {
        return Err(Code::BadArguments);
    }
    let bundle_config = BundleConfig {
        services: args
            .services
            .iter()
            .map(|s| Service { host: s.host.clone(), name: s.name.clone(), url: s.url.clone() })
            .collect(),
        deadline_seconds: args.deadline_seconds.unwrap_or(DEFAULT_DEADLINE_SECONDS),
        tls_root: args.tls_root,
    };
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
    let issuer = shared.key_with_purpose("delegation").ok_or(Code::Unavailable)?;
    let now = shared.now();
    let issued = issue(
        shared,
        &shared.work_dir,
        &Issuing { person: &person, groups: &groups, label: &label, valid_seconds: valid, now: now.unix() },
    )
    .map_err(|e| {
        eprintln!("pledge: issuing a certificate failed: {e}");
        Code::Unavailable
    })?;
    // Registered with the broker before the bundle is handed over.
    if let Some(link) = &link {
        link.register(&issued.certificate, issued.agent.delegation.as_str()).map_err(|e| match e {
            crate::broker_link::RegisterError::Unavailable => Code::BrokerUnavailable,
            crate::broker_link::RegisterError::Refused(reason) => {
                eprintln!("pledge: the broker did not register the delegation: {reason}");
                Code::BrokerRefused
            }
        })?;
    }
    // Written once, and read back with `pact`'s own parser before it is handed out.
    let bundle = Bundle::write(&bundle_config, &issued.key, &issued.certificate, now).map_err(|e| {
        eprintln!("pledge: the bundle is refused: {e}");
        if link.is_some() {
            withdraw_at_broker(shared, issued.agent.delegation.as_str());
        }
        Code::BadArguments
    })?;
    let id = issued.agent.delegation.as_str().to_owned();
    let valid_until = i64::try_from(issued.agent.valid_before).map_err(|_| Code::Unavailable)?;
    let delegation = Delegation {
        id: id.clone(),
        agent_public: issued.agent_public.clone(),
        certificate: issued.certificate.clone(),
        person,
        groups,
        automatic: RatingWords::of(automatic),
        ask: RatingWords::of(ask),
        issuer: issuer.fingerprint,
        issued: now.unix(),
        valid_until,
        withdrawn: None,
        last_asked: None,
    };
    let data = json!({
        "delegation": id,
        "bundle": STANDARD.encode(bundle.as_bytes()),
        "valid_until": Timestamp::from_unix(valid_until).map(|t| t.to_string()),
    });
    Ok((data, delegation))
}

/// `agents.delivered`: the bundle is written; the delegation exists from now on.
///
/// # Errors
///
/// [`Code::Unavailable`] if it cannot be stored.
pub fn delivered(shared: &Shared, delegation: Delegation) -> Result<Value, Code> {
    let (id, person, groups) = (delegation.id.clone(), delegation.person.clone(), delegation.groups.clone());
    let (automatic, ask, until) = (delegation.automatic.clone(), delegation.ask.clone(), delegation.valid_until);
    shared.approvals.delegations.add(delegation).map_err(|_| Code::Unavailable)?;
    shared.event(
        "delegation-issued",
        json!({"delegation": id, "person": person, "groups": groups, "automatic": automatic, "ask": ask, "valid_until": Timestamp::from_unix(until).map(|t| t.to_string())}),
    );
    Ok(json!({}))
}

/// A delegation whose bundle was not delivered: it never existed for pledge, so it is not
/// "withdrawn" (which in the record always means something that could sign was stopped);
/// the record has an event of its own.
pub fn abandoned(shared: &Shared, id: &str) {
    shared.event("delegation-not-delivered", json!({"delegation": id}));
    // A registration that succeeded for a bundle that was never delivered is withdrawn at the broker,
    // through the same path as any withdrawal (re-sent until stored).
    if shared.approvals.config.broker.is_some() {
        withdraw_at_broker(shared, id);
    }
}

/// Tells the broker about a withdrawal and follows it: noted at once, sent if connected, re-sent at every
/// sign-in and at most once a minute until the broker says it stored it. Returns where it stands.
pub fn withdraw_at_broker(shared: &Shared, id: &str) -> crate::broker_state::Withdrawal {
    use crate::broker_state::Withdrawal;
    let _ = shared.broker_state.note_withdrawal(id);
    if shared.link().is_some_and(|link| link.send_withdraw(id))
        && shared.broker_state.withdrawal(id) == Some(Withdrawal::NotTold)
    {
        let _ = shared.broker_state.set_withdrawal(id, Withdrawal::InForce);
    }
    shared.broker_state.withdrawal(id).unwrap_or(Withdrawal::NotTold)
}

/// Withdraws a delegation and records it.
///
/// # Errors
///
/// [`Code::NotFound`] if there is none, or it was withdrawn already.
pub fn withdraw(shared: &Shared, id: &str) -> Result<Value, Code> {
    match shared.approvals.delegations.withdraw(id, shared.now().unix()) {
        Ok(true) => {
            let broker = shared.approvals.config.broker.is_some().then(|| withdraw_at_broker(shared, id).words());
            shared.event("delegation-withdrawn", json!({"delegation": id, "by": "person", "broker": broker}));
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
                "broker": shared.broker_state.withdrawal(&d.id).map(|w| w.words()),
            })
        })
        .collect();
    json!({"delegations": delegations, "broker_as_of": shared.broker_state.as_of()})
}
