//! What an agent is told (`proposals/agent-to-service.md`, section 6): a coarse
//! closed list. The exact code, with who said it, goes to the service's log.
//! The mapping from pledge's and the broker's codes is here, in one place; a
//! string received is never copied into what an agent reads.

use p_act::exchange::{BrokerReason, PledgeReason, Refused};

/// What a refusal means to an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// The delegation, the site's rules or the person's ceilings do not allow it.
    NotAllowed,
    /// The call itself is wrong.
    Invalid,
    /// Wait, then ask again.
    TryLater,
}

impl Why {
    #[must_use]
    pub fn word(self) -> &'static str {
        match self {
            Why::NotAllowed => "not-allowed",
            Why::Invalid => "invalid",
            Why::TryLater => "try-later",
        }
    }
}

/// What an agent is told of how its call ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The verb ran. `answer` is what the dispatcher wrote, one JSON object per line.
    Done {
        rc: u8,
        answer: String,
    },
    Declined,
    Expired,
    Refused(Why),
    /// Nobody could be asked, or nothing was done for a reason on this side: **certainly nothing was
    /// started**.
    Unavailable,
    /// The call was carried out and did not complete: no result. The exact cause is in the service's log and
    /// the host's audit lines under the call's identifier.
    Failed,
}

impl Outcome {
    #[must_use]
    pub fn word(&self) -> &'static str {
        match self {
            Outcome::Done { .. } => "done",
            Outcome::Declined => "declined",
            Outcome::Expired => "expired",
            Outcome::Refused(_) => "refused",
            Outcome::Unavailable => "unavailable",
            Outcome::Failed => "failed",
        }
    }

    /// The reason the agent sees, if the outcome has one.
    #[must_use]
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            Outcome::Refused(why) => Some(why.word()),
            _ => None,
        }
    }
}

/// What an agent is told of how the dispatcher ended, and the exact cause for the log.
///
/// `unavailable` only where the verb certainly did not start (sudo refused, the dispatcher refused, was
/// busy or found the deadline past, or said it could not write its audit line); `failed` wherever it
/// may have: the dispatcher's 70, a signal, the run limit, a code nobody defined.
#[must_use]
pub fn dispatcher(run: &crate::runner::RunOutput) -> (Outcome, String) {
    use crate::dispatch::{RC_BUSY, RC_EXPIRED, RC_FAILED, RC_REFUSED, RC_UNAVAILABLE};
    let said = |outcome: Outcome, exact: &str| (outcome, exact.to_string());
    if run.timed_out {
        return said(Outcome::Failed, "run-limit");
    }
    if let Some(signal) = run.signal {
        return (Outcome::Failed, format!("dispatcher-signal:{signal}"));
    }
    match run.rc {
        0 => said(Outcome::Done { rc: 0, answer: run.stdout.clone() }, "ran"),
        RC_REFUSED => said(Outcome::Refused(Why::NotAllowed), "dispatcher-refused"),
        RC_UNAVAILABLE => said(Outcome::Unavailable, "dispatcher-unavailable"),
        RC_BUSY => said(Outcome::Refused(Why::TryLater), "dispatcher-busy"),
        // Could not start before the deadline: nothing ran, and the call is over: expired, not try-later.
        RC_EXPIRED => said(Outcome::Expired, "dispatcher-deadline"),
        RC_FAILED => said(Outcome::Failed, "dispatcher-failed"),
        // sudo's own exit code when it will not run the program (no rule, no password): the dispatcher
        // never gives 1.
        1 => said(Outcome::Unavailable, "sudo-refused"),
        rc => (Outcome::Failed, format!("dispatcher-code:{rc}")),
    }
}

/// pledge's exact codes to what an agent sees.
#[must_use]
pub fn pledge(reason: PledgeReason) -> Outcome {
    use PledgeReason as P;
    match reason {
        P::Ceiling | P::UnknownDelegation | P::DelegationEnded | P::DelegationWithdrawn | P::Blocked | P::Unknown => {
            Outcome::Refused(Why::NotAllowed)
        }
        P::Malformed | P::DeadlinePast | P::DeadlineTooFar | P::CallUsed | P::NotShowable => {
            Outcome::Refused(Why::Invalid)
        }
        P::Limit | P::Muted => Outcome::Refused(Why::TryLater),
        // This service's own key or certificate is wrong, or pledge could not ask or record.
        P::ServiceMismatch | P::Unavailable => Outcome::Unavailable,
    }
}

/// The broker's exact codes to what an agent sees (stage 2).
#[must_use]
pub fn broker(reason: BrokerReason) -> Outcome {
    use BrokerReason as B;
    match reason {
        B::NotEntitled | B::Person | B::Delegation | B::Unknown => Outcome::Refused(Why::NotAllowed),
        B::BadRequest | B::Deadline => Outcome::Refused(Why::Invalid),
        B::TooManyWaiting | B::Busy => Outcome::Refused(Why::TryLater),
    }
}

/// A refusal, with the exact code for the log: `"pledge:ceiling"`.
#[must_use]
pub fn refusal(refused: Refused) -> (Outcome, String) {
    match refused {
        Refused::Pledge(reason) => (pledge(reason), format!("pledge:{}", reason.wire())),
        Refused::Broker(reason) => (broker(reason), format!("broker:{}", reason.wire())),
        Refused::Unknown => (Outcome::Refused(Why::NotAllowed), "unknown".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(outcome: &Outcome) -> String {
        match outcome.reason() {
            Some(reason) => format!("{}/{reason}", outcome.word()),
            None => outcome.word().to_string(),
        }
    }

    #[test]
    fn every_pledge_code_has_the_documented_meaning_for_an_agent() {
        let expected = [
            ("malformed", "refused/invalid"),
            ("unknown-delegation", "refused/not-allowed"),
            ("delegation-ended", "refused/not-allowed"),
            ("delegation-withdrawn", "refused/not-allowed"),
            ("deadline-past", "refused/invalid"),
            ("deadline-too-far", "refused/invalid"),
            ("call-used", "refused/invalid"),
            ("service-mismatch", "unavailable"),
            ("not-showable", "refused/invalid"),
            ("limit", "refused/try-later"),
            ("muted", "refused/try-later"),
            ("ceiling", "refused/not-allowed"),
            ("unavailable", "unavailable"),
            ("blocked", "refused/not-allowed"),
        ];
        assert_eq!(PledgeReason::ALL.len(), expected.len(), "a code was added: say what an agent sees");
        for (wire, agent) in expected {
            assert_eq!(word(&pledge(PledgeReason::from_wire(wire))), agent, "{wire}");
        }
        assert_eq!(word(&pledge(PledgeReason::Unknown)), "refused/not-allowed");
    }

    #[test]
    fn every_broker_code_has_a_meaning_and_an_unknown_one_is_not_allowed() {
        let expected = [
            ("bad-request", "refused/invalid"),
            ("deadline", "refused/invalid"),
            ("delegation", "refused/not-allowed"),
            ("person", "refused/not-allowed"),
            ("not-entitled", "refused/not-allowed"),
            ("too-many-waiting", "refused/try-later"),
            ("busy", "refused/try-later"),
        ];
        assert_eq!(BrokerReason::ALL.len(), expected.len(), "a code was added: say what an agent sees");
        for (wire, agent) in expected {
            assert_eq!(word(&broker(BrokerReason::from_wire(wire))), agent, "{wire}");
        }
        assert_eq!(word(&broker(BrokerReason::Unknown)), "refused/not-allowed");
        assert_eq!(word(&refusal(Refused::Unknown).0), "refused/not-allowed");
    }

    fn ran(rc: u8) -> crate::runner::RunOutput {
        crate::runner::RunOutput { rc, timed_out: false, signal: None, stdout: "{\"type\":\"header\"}\n".into() }
    }

    #[test]
    fn what_the_dispatcher_did_is_unavailable_only_where_nothing_was_started() {
        for (rc, agent, exact) in [
            (0, "done", "ran"),
            (3, "unavailable", "dispatcher-unavailable"),
            (64, "refused/not-allowed", "dispatcher-refused"),
            (70, "failed", "dispatcher-failed"),
            (75, "refused/try-later", "dispatcher-busy"),
            (76, "expired", "dispatcher-deadline"),
            (1, "unavailable", "sudo-refused"),
            (2, "failed", "dispatcher-code:2"),
            (101, "failed", "dispatcher-code:101"),
            (255, "failed", "dispatcher-code:255"),
        ] {
            let (outcome, said) = dispatcher(&ran(rc));
            assert_eq!((word(&outcome).as_str(), said.as_str()), (agent, exact), "rc {rc}");
        }
        let killed = crate::runner::RunOutput { rc: 255, signal: Some(9), ..ran(255) };
        assert_eq!(dispatcher(&killed), (Outcome::Failed, "dispatcher-signal:9".to_string()));
        let slow = crate::runner::RunOutput { timed_out: true, signal: Some(9), ..ran(255) };
        assert_eq!(dispatcher(&slow), (Outcome::Failed, "run-limit".to_string()));
    }

    #[test]
    fn the_exact_code_names_who_said_it() {
        assert_eq!(refusal(Refused::Pledge(PledgeReason::Ceiling)).1, "pledge:ceiling");
        assert_eq!(refusal(Refused::Broker(BrokerReason::Busy)).1, "broker:busy");
    }
}
