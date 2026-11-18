//! What `probe serve` does with a call, in the order of `SPEC.md`, "What the
//! service does with a call". No HTTP here: the call arrives parsed out of its
//! tool call (`mcp.rs`), the answer goes back as an [`Outcome`].
//!
//! The service holds no rule about who may what. It checks what is its to
//! check, signs requests with a key of its own, and acts only on an approval it
//! has verified itself.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use p_act::exchange::{Outcome as Answered, Submit};
use p_act::sign::{
    ApprovalKind, ApprovalTrust, PublicKey, SignError, Signer, sign_request, signature_from_base64, signature_person,
    verify_approval,
};
use p_act::{Call, Document, Request, Timestamp};

use crate::outcome::{self, Outcome, Why};
use crate::pledge::{PledgeLink, Waited};
use crate::rate::{self, Mode};
use crate::rules::{ARG_MAX, check_argument};
use crate::runner::{RunError, Runner};
use crate::store::{StoreError, UsedStore};
use crate::table::{self, Availability};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// The most a call's deadline may lie ahead, and the tolerated difference of
/// clocks that applies **only** to this bound: after the deadline nothing starts.
use p_act::limits::{
    CLOCK_TOLERANCE_SECONDS as SKEW_SECS, MAX_CALL_BYTES as CALL_MAX, MAX_DEADLINE_AHEAD_SECONDS as MAX_AHEAD_SECS,
};
/// A signature is at most 4 KiB (p-act has no limit of its own for it yet); a call's limit is p-act's.
const SIG_MAX: usize = 4 * 1024;

/// What the service is, and whose approval it accepts (stage 1: one person,
/// their two approval keys listed directly, no clearance).
pub struct Settings {
    /// `service.host` of the calls this service takes.
    pub host: String,
    /// The one person whose approvals count.
    pub person: String,
    pub confirmed: PublicKey,
    pub automatic: PublicKey,
    /// How many calls may wait at once.
    pub max_waiting: usize,
}

/// The service's own name in a call: the type's name in the catalogue.
pub const SERVICE_NAME: &str = "probe";

/// The tool call as the MCP layer parsed it.
#[derive(Debug)]
pub struct ToolCall<'a> {
    pub name: &'a str,
    pub params: &'a [String],
    pub claim: Option<&'a str>,
    /// `_meta."procession/call"`, base64 of the call's bytes.
    pub call: &'a str,
    /// `_meta."procession/call_sig"`, base64 of the armoured signature.
    pub call_sig: &'a str,
}

/// What came of a tool call.
#[derive(Debug, PartialEq, Eq)]
pub enum Handled {
    /// The agent is told this.
    Outcome { outcome: Outcome, id: String },
    /// Too many calls wait: a transport decision, no outcome (HTTP 503).
    Busy,
    /// The agent went away: nobody to tell.
    Cancelled,
    /// The tool call itself is malformed (a signer bug): a JSON-RPC error.
    BadParams(&'static str),
}

/// What a waiting call has reached, for the stream the agent reads. Only
/// acceptance: there is no notice of a request's progress (the designer's
/// decision); the stream is a head and keepalive comments until the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// The first checks passed and there is a place to wait: from here the call is going to be decided.
    Accepted,
}

/// The service.
pub struct Service {
    pub settings: Settings,
    pub signer: Signer,
    pub store: UsedStore,
    pub pledge: PledgeLink,
    pub runner: Box<dyn Runner>,
    /// One line per call, with the exact code. Never shown to an agent.
    pub log: Box<dyn Fn(&str) + Send + Sync>,
    waiting: AtomicUsize,
    /// The dispatcher's lock is per identity, and every call of the service has
    /// the service's: runs go one at a time here instead of meeting "busy".
    run_lock: Mutex<()>,
}

struct Slot<'a>(&'a AtomicUsize);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// An end of the call's handling: what the agent is told, the exact code for the log.
type Ended = (Outcome, String);

fn invalid(exact: impl Into<String>) -> Ended {
    (Outcome::Refused(Why::Invalid), exact.into())
}

fn unavailable(exact: impl Into<String>) -> Ended {
    (Outcome::Unavailable, exact.into())
}

fn now() -> Timestamp {
    Timestamp::now().unwrap_or_else(|| Timestamp::from_unix(0).expect("the epoch"))
}

impl Service {
    #[must_use]
    pub fn new(
        settings: Settings,
        signer: Signer,
        store: UsedStore,
        pledge: PledgeLink,
        runner: Box<dyn Runner>,
        log: Box<dyn Fn(&str) + Send + Sync>,
    ) -> Self {
        Self { settings, signer, store, pledge, runner, log, waiting: AtomicUsize::new(0), run_lock: Mutex::new(()) }
    }

    /// How many calls wait now.
    #[must_use]
    pub fn waiting(&self) -> usize {
        self.waiting.load(Ordering::SeqCst)
    }

    /// Handles one tool call to its end. `cancel` is set when the agent's
    /// connection goes away.
    pub fn handle(&self, tool: &ToolCall<'_>, cancel: &AtomicBool) -> Handled {
        self.handle_with(tool, cancel, &|_| {})
    }

    /// As [`Service::handle`], telling `events` what the call has reached.
    pub fn handle_with(&self, tool: &ToolCall<'_>, cancel: &AtomicBool, events: &dyn Fn(Event)) -> Handled {
        let Ok(call_bytes) = STANDARD.decode(tool.call) else {
            return Handled::BadParams("procession/call is not base64");
        };
        if call_bytes.len() > CALL_MAX || tool.call_sig.len() > SIG_MAX * 4 / 3 + 4 {
            return Handled::BadParams("the call or its signature is too large");
        }
        let Ok(armoured) = signature_from_base64(tool.call_sig) else {
            return Handled::BadParams("procession/call_sig is not an armoured signature");
        };
        // From here the call parses or it is refused as invalid; its identifier is known only if it parses.
        let call = match Call::parse(call_bytes) {
            Ok(call) => call,
            Err(error) => {
                let exact = format!("malformed:{error}");
                (self.log)(&format!("call id=- outcome=refused/invalid exact={}", crate::audit::quote(&exact)));
                return Handled::Outcome { outcome: Outcome::Refused(Why::Invalid), id: String::new() };
            }
        };
        let id = call.id().as_str().to_string();
        let (outcome, exact, hash) = match self.decide(tool, &call, &armoured, cancel, events) {
            Ok(done) => done,
            Err(Stop::Busy) => return Handled::Busy,
            Err(Stop::Cancelled(hash)) => {
                (self.log)(&format!("call id={id} hash={hash} outcome=cancelled"));
                return Handled::Cancelled;
            }
            Err(Stop::Ended(outcome, exact, hash)) => (outcome, exact, hash),
        };
        let person = signature_person(&armoured).unwrap_or_else(|_| "-".into());
        (self.log)(&format!(
            "call id={id} hash={} person={} action={} outcome={}{} exact={}",
            if hash.is_empty() { "-" } else { &hash },
            crate::audit::quote(&person),
            crate::audit::quote(call.action()),
            outcome.word(),
            outcome.reason().map_or(String::new(), |r| format!("/{r}")),
            crate::audit::quote(&exact),
        ));
        Handled::Outcome { outcome, id }
    }

    /// Steps 1 to 5 of the SPEC. `Ok` carries the end of a call that was asked
    /// about; an `Err(Stop::Ended)` is a call that ended before or without that.
    fn decide(
        &self,
        tool: &ToolCall<'_>,
        call: &Call,
        armoured: &str,
        cancel: &AtomicBool,
        events: &dyn Fn(Event),
    ) -> Result<(Outcome, String, String), Stop> {
        let early = |(outcome, exact): Ended| Stop::Ended(outcome, exact, String::new());
        // 1. The call names this host and this service, has not ended, names a verb of the table
        //    with arguments the verb accepts, and the tool call says what the call says.
        if call.service().host != self.settings.host || call.service().name != SERVICE_NAME {
            return Err(early(invalid("wrong-service")));
        }
        let (at, deadline) = (now(), call.deadline());
        if deadline.unix() <= at.unix() {
            return Err(early(invalid("deadline-past")));
        }
        if deadline.unix() - at.unix() > MAX_AHEAD_SECS + SKEW_SECS {
            return Err(early(invalid("deadline-too-far")));
        }
        let verb = {
            let mut words = call.action().split(' ');
            match (words.next(), words.next(), words.next()) {
                (Some(noun), Some(verb), None) => table::find(noun, verb),
                _ => None,
            }
        };
        let Some(verb) = verb.filter(|row| matches!(row.availability, Availability::Ready(_))) else {
            return Err(early(invalid("unknown-action")));
        };
        if call.params().len() > ARG_MAX
            || call.params().iter().any(|p| check_argument(p).is_err())
            || (!verb.args.takes_any() && !call.params().is_empty())
        {
            return Err(early(invalid("params-not-accepted")));
        }
        if tool.name != call.action().replace(' ', "_") || tool.params != call.params() || tool.claim != call.claim() {
            return Err(early(invalid("mismatch")));
        }
        // Whether it can be shown (every field whole, all parameters together at most 2000 characters) is
        // decided here, before anybody is asked; pledge checks again and is the authority.
        call.showable().map_err(|e| early(invalid(format!("not-showable:{e}"))))?;
        // 2. Rate the call, and sign a request with the service's own key.
        let rating = rate::rate(verb, call.params(), Mode::Name)
            .map_err(|e| early(invalid(format!("params-not-accepted:{}", e.0))))?
            .rating;
        // The request says whether the verb's output can carry text that is not the service's, signed with the rating.
        let request = Request::compose(call, armoured, rating, verb.host_text)
            .map_err(|e| early(unavailable(format!("compose:{e}"))))?;
        let request_sig = sign_request(&self.signer, &request).map_err(|e| early(unavailable(format!("sign:{e}"))))?;
        let hash = request.hash().to_string();
        let ended = |(outcome, exact): Ended| Stop::Ended(outcome, exact, hash.clone());
        // A place to wait, and the identifier taken **before** anything is sent.
        if self.waiting.fetch_add(1, Ordering::SeqCst) >= self.settings.max_waiting {
            self.waiting.fetch_sub(1, Ordering::SeqCst);
            return Err(Stop::Busy);
        }
        let _slot = Slot(&self.waiting);
        events(Event::Accepted);
        match self.store.record(call.id(), deadline) {
            Ok(()) => {}
            Err(StoreError::Used) => return Err(ended(invalid("call-used"))),
            Err(StoreError::Io(why)) => return Err(ended(unavailable(format!("store:{why}")))),
        }
        // 3. Send it to pledge and wait until the deadline.
        let submit =
            Submit::new(request.clone(), &request_sig).map_err(|e| ended(unavailable(format!("submit:{e}"))))?;
        let note = |text: &str| {
            (self.log)(&format!("call id={} hash={hash} note={}", call.id().as_str(), crate::audit::quote(text)))
        };
        let approval = match self.pledge.submit_and_wait(&submit, deadline, cancel, &note) {
            Waited::Cancelled => return Err(Stop::Cancelled(hash.clone())),
            Waited::Deadline => return Err(ended((Outcome::Expired, "deadline".into()))),
            Waited::Broken(why) => return Err(ended(unavailable(format!("no-route:{why}")))),
            Waited::Answer(Answered::Declined) => return Err(ended((Outcome::Declined, "declined".into()))),
            Waited::Answer(Answered::Expired(by)) => {
                return Err(ended((Outcome::Expired, format!("expired-by-{}", by.wire()))));
            }
            Waited::Answer(Answered::Refused(refused)) => {
                let (outcome, exact) = outcome::refusal(refused);
                return Err(ended((outcome, exact)));
            }
            Waited::Answer(Answered::Approved(approved)) => approved.approval().to_string(),
            Waited::Answer(Answered::Unknown) => unreachable!("an unknown result is not an answer"),
        };
        // 4. Before it runs: the approval is over exactly this request, by the person the call's
        //    delegation names, with the confirmed key if the rating is at the top of any scale.
        let kind = self.verify(&request, &approval).map_err(&ended)?;
        // ... the deadline has not passed by our own clock, and nothing was run for this identifier
        //     (it was taken at submit: this handler is the only one that got this far).
        if now().unix() >= deadline.unix() {
            return Err(ended((Outcome::Expired, "approval-after-deadline".into())));
        }
        if cancel.load(Ordering::SeqCst) {
            return Err(Stop::Cancelled(hash.clone()));
        }
        // 5. Run the dispatcher, refusing above what was approved.
        // What was approved is what the request said: the rating and whether the output may carry host text.
        let approved = crate::table::Within { rating: request.rating(), host_text: request.host_text() };
        let (outcome, exact) = self.run(approved, call.id().as_str(), deadline.unix(), call.action(), call.params());
        Ok((outcome, format!("{exact} approval={}", ApprovalKindWord(kind)), hash.clone()))
    }

    fn verify(&self, request: &Request, approval: &str) -> Result<ApprovalKind, Ended> {
        // The person is passed to p-act, which refuses a request whose call belongs to another.
        let trust = ApprovalTrust::PersonKeys {
            person: &self.settings.person,
            confirmed: &self.settings.confirmed,
            automatic: &self.settings.automatic,
        };
        verify_approval(request, approval, trust).map_err(|e| match e {
            SignError::AutomaticNotAcceptable => unavailable("approval-invalid:automatic-at-the-top"),
            SignError::ApprovalForAnotherPerson => unavailable("approval-invalid:person-mismatch"),
            other => unavailable(format!("approval-invalid:{other}")),
        })
    }

    fn run(&self, within: crate::table::Within, call_id: &str, until: i64, action: &str, params: &[String]) -> Ended {
        let _one_at_a_time = self.run_lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        match self.runner.run(within, call_id, until, action, params) {
            Err(RunError::NotStarted(why)) => unavailable(format!("run:{why}")),
            Err(RunError::Lost(why)) => (Outcome::Failed, format!("run-lost:{why}")),
            Ok(out) => crate::outcome::dispatcher(&out),
        }
    }
}

struct ApprovalKindWord(ApprovalKind);

impl std::fmt::Display for ApprovalKindWord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.0 {
            ApprovalKind::Confirmed => "confirmed",
            ApprovalKind::Automatic => "automatic",
        })
    }
}

enum Stop {
    Busy,
    Cancelled(String),
    Ended(Outcome, String, String),
}
