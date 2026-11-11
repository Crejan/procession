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
    /// Nobody could be asked, or nothing was done for a reason on this side.
    Unavailable,
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

    #[test]
    fn the_exact_code_names_who_said_it() {
        assert_eq!(refusal(Refused::Pledge(PledgeReason::Ceiling)).1, "pledge:ceiling");
        assert_eq!(refusal(Refused::Broker(BrokerReason::Busy)).1, "broker:busy");
    }
}
