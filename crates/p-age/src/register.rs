//! The delegations the broker knows.
//!
//! A delegation is registered when a person's pledge issues it. A request is
//! passed on only under a delegation that is registered, not past its end,
//! not withdrawn, and whose person is not blocked. Withdrawing and blocking
//! take effect with the next request, because every request is checked here.

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

/// Why a request is not passed on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stopped {
    /// No delegation with this fingerprint was registered.
    Unknown,
    /// The delegation's validity is over.
    Ended,
    /// The person or an administrator withdrew the delegation.
    Withdrawn,
    /// An administrator blocked the person.
    PersonBlocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    person: String,
    until: SystemTime,
    withdrawn: bool,
}

/// Registered delegations, by the fingerprint of the agent's certificate.
#[derive(Debug, Clone, Default)]
pub struct Register {
    delegations: BTreeMap<String, Entry>,
    blocked: BTreeSet<String>,
}

impl Register {
    /// Register a delegation `person` issued, valid until `until`.
    /// Registering a fingerprint again changes nothing: a delegation that was
    /// withdrawn cannot be brought back, and its end cannot be moved.
    pub fn register(&mut self, fingerprint: impl Into<String>, person: impl Into<String>, until: SystemTime) {
        self.delegations.entry(fingerprint.into()).or_insert(Entry { person: person.into(), until, withdrawn: false });
    }

    /// The person a request under this delegation is passed on to, or why it
    /// is stopped.
    pub fn person_for(&self, fingerprint: &str, now: SystemTime) -> Result<&str, Stopped> {
        let entry = self.delegations.get(fingerprint).ok_or(Stopped::Unknown)?;
        if entry.withdrawn {
            Err(Stopped::Withdrawn)
        } else if self.blocked.contains(&entry.person) {
            Err(Stopped::PersonBlocked)
        } else if now >= entry.until {
            Err(Stopped::Ended)
        } else {
            Ok(&entry.person)
        }
    }

    /// Withdraw one delegation. Returns whether it was registered.
    pub fn withdraw(&mut self, fingerprint: &str) -> bool {
        match self.delegations.get_mut(fingerprint) {
            Some(entry) => {
                entry.withdrawn = true;
                true
            }
            None => false,
        }
    }

    /// Block a person: nothing is passed on under any of their delegations,
    /// present or future, until [`Register::unblock`].
    pub fn block(&mut self, person: impl Into<String>) {
        self.blocked.insert(person.into());
    }

    pub fn unblock(&mut self, person: &str) {
        self.blocked.remove(person);
    }

    /// Drop the delegations whose validity ended before `now`. A withdrawn
    /// one is kept until its end, so that it stays withdrawn.
    pub fn forget_ended(&mut self, now: SystemTime) {
        self.delegations.retain(|_, entry| entry.until > now);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    const HOUR: Duration = Duration::from_secs(3600);

    fn t(hours: u32) -> SystemTime {
        SystemTime::UNIX_EPOCH + hours * HOUR
    }

    fn register() -> Register {
        let mut register = Register::default();
        register.register("SHA256:agent1", "jan", t(8));
        register
    }

    #[test]
    fn a_registered_delegation_leads_to_its_person_until_it_ends() {
        let register = register();
        assert_eq!(register.person_for("SHA256:agent1", t(1)), Ok("jan"));
        assert_eq!(register.person_for("SHA256:agent1", t(8)), Err(Stopped::Ended));
    }

    #[test]
    fn an_unregistered_delegation_leads_nowhere() {
        assert_eq!(register().person_for("SHA256:other", t(1)), Err(Stopped::Unknown));
    }

    #[test]
    fn a_withdrawn_delegation_stays_withdrawn_even_if_registered_again() {
        let mut register = register();
        assert!(register.withdraw("SHA256:agent1"));
        assert_eq!(register.person_for("SHA256:agent1", t(1)), Err(Stopped::Withdrawn));
        register.register("SHA256:agent1", "jan", t(24));
        assert_eq!(register.person_for("SHA256:agent1", t(1)), Err(Stopped::Withdrawn));
    }

    #[test]
    fn registering_again_cannot_move_a_delegations_end() {
        let mut register = register();
        register.register("SHA256:agent1", "jan", t(24));
        assert_eq!(register.person_for("SHA256:agent1", t(9)), Err(Stopped::Ended));
    }

    #[test]
    fn blocking_a_person_stops_all_their_delegations_until_unblocked() {
        let mut register = register();
        register.register("SHA256:agent2", "jan", t(8));
        register.block("jan");
        assert_eq!(register.person_for("SHA256:agent1", t(1)), Err(Stopped::PersonBlocked));
        assert_eq!(register.person_for("SHA256:agent2", t(1)), Err(Stopped::PersonBlocked));
        register.unblock("jan");
        assert_eq!(register.person_for("SHA256:agent1", t(1)), Ok("jan"));
    }

    #[test]
    fn a_withdrawn_delegation_is_kept_until_its_end_and_dropped_after() {
        let mut register = register();
        register.withdraw("SHA256:agent1");
        register.forget_ended(t(4));
        assert_eq!(register.person_for("SHA256:agent1", t(4)), Err(Stopped::Withdrawn));
        register.forget_ended(t(9));
        assert_eq!(register.person_for("SHA256:agent1", t(9)), Err(Stopped::Unknown));
    }
}
