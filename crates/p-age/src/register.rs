//! The delegations the broker knows.
//!
//! A delegation is registered when a person's pledge issues it. A request is
//! passed on only under a delegation that is registered, not past its end,
//! not withdrawn, and whose person is not blocked. Withdrawing and blocking
//! take effect with the next request, because every request is checked here.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

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

/// One delegation as it is kept on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub fingerprint: String,
    pub person: String,
    /// Seconds since the Unix epoch.
    pub until: u64,
    pub withdrawn: bool,
}

/// The register as it is kept on disk: delegations until their end, and blocks until lifted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// The version of the file's format: 1.
    pub v: u32,
    pub delegations: Vec<SnapshotEntry>,
    pub blocked: Vec<String>,
    /// Keys an administrator blocked, as `SHA256:...` fingerprints. A file without the member has none.
    #[serde(default)]
    pub blocked_keys: Vec<String>,
}

/// Registered delegations, by the SHA-256 fingerprint of the agent's public key.
#[derive(Debug, Clone, Default)]
pub struct Register {
    delegations: BTreeMap<String, Entry>,
    blocked: BTreeSet<String>,
    blocked_keys: BTreeSet<String>,
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

    /// Block one key (a fingerprint): a connection key, an approval key, a delegation key or an agent's key.
    pub fn block_key(&mut self, fingerprint: impl Into<String>) {
        self.blocked_keys.insert(fingerprint.into());
    }

    pub fn unblock_key(&mut self, fingerprint: &str) {
        self.blocked_keys.remove(fingerprint);
    }

    /// Whether the key is blocked.
    #[must_use]
    pub fn is_key_blocked(&self, fingerprint: &str) -> bool {
        self.blocked_keys.contains(fingerprint)
    }

    /// Whether a delegation is registered (in any state).
    #[must_use]
    pub fn knows_delegation(&self, fingerprint: &str) -> bool {
        self.delegations.contains_key(fingerprint)
    }

    /// Whether any delegation of this person is registered.
    #[must_use]
    pub fn knows_person(&self, person: &str) -> bool {
        self.delegations.values().any(|e| e.person == person)
    }

    /// The blocked persons, sorted.
    #[must_use]
    pub fn blocked_persons(&self) -> Vec<String> {
        self.blocked.iter().cloned().collect()
    }

    /// The blocked keys, sorted.
    #[must_use]
    pub fn blocked_keys(&self) -> Vec<String> {
        self.blocked_keys.iter().cloned().collect()
    }

    /// How many delegations are registered, and how many of them are withdrawn.
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        (self.delegations.len(), self.delegations.values().filter(|e| e.withdrawn).count())
    }

    /// Whether the person is blocked.
    #[must_use]
    pub fn is_blocked(&self, person: &str) -> bool {
        self.blocked.contains(person)
    }

    /// The person a delegation belongs to, whatever its state.
    #[must_use]
    pub fn person_of(&self, fingerprint: &str) -> Option<&str> {
        self.delegations.get(fingerprint).map(|e| e.person.as_str())
    }

    /// The person's delegations that were withdrawn and have not ended: what a
    /// pledge is told so that it stops signing for them.
    #[must_use]
    pub fn withdrawn_of(&self, person: &str, now: SystemTime) -> Vec<String> {
        self.delegations
            .iter()
            .filter(|(_, e)| e.person == person && e.withdrawn && now < e.until)
            .map(|(fp, _)| fp.clone())
            .collect()
    }

    /// The register as data, to be kept across a restart.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            v: 1,
            delegations: self
                .delegations
                .iter()
                .map(|(fp, e)| SnapshotEntry {
                    fingerprint: fp.clone(),
                    person: e.person.clone(),
                    until: e.until.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs()),
                    withdrawn: e.withdrawn,
                })
                .collect(),
            blocked: self.blocked.iter().cloned().collect(),
            blocked_keys: self.blocked_keys.iter().cloned().collect(),
        }
    }

    /// The register from what [`Register::snapshot`] wrote.
    ///
    /// # Errors
    /// The name of the member that has an entry that is not valid: a person's name that is not a name, a fingerprint
    /// that is not one. The value is not in the error. What the broker acts on and prints is validated when it is read.
    pub fn restore(snapshot: Snapshot) -> Result<Register, &'static str> {
        use crate::site::valid_name;
        use p_act::sign::Fingerprint;
        let fingerprint = |s: &str| s.parse::<Fingerprint>().is_ok();
        if !snapshot.delegations.iter().all(|e| fingerprint(&e.fingerprint)) {
            return Err("delegations (fingerprint)");
        }
        if !snapshot.delegations.iter().all(|e| valid_name(&e.person)) {
            return Err("delegations (person)");
        }
        if !snapshot.blocked.iter().all(|n| valid_name(n)) {
            return Err("blocked");
        }
        if !snapshot.blocked_keys.iter().all(|k| fingerprint(k)) {
            return Err("blocked_keys");
        }
        Ok(Register {
            delegations: snapshot
                .delegations
                .into_iter()
                .map(|e| {
                    let until = SystemTime::UNIX_EPOCH + Duration::from_secs(e.until);
                    (e.fingerprint, Entry { person: e.person, until, withdrawn: e.withdrawn })
                })
                .collect(),
            blocked: snapshot.blocked.into_iter().collect(),
            blocked_keys: snapshot.blocked_keys.into_iter().collect(),
        })
    }

    /// Drop the delegations whose validity ended before `now`, and say how many. A withdrawn
    /// one is kept until its end, so that it stays withdrawn.
    pub fn forget_ended(&mut self, now: SystemTime) -> usize {
        let before = self.delegations.len();
        self.delegations.retain(|_, entry| entry.until > now);
        before - self.delegations.len()
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
