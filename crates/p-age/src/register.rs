//! The delegations the broker knows.
//!
//! A delegation is registered when a person's pledge issues it. A request is
//! passed on only under a delegation that is registered, not past its end,
//! not withdrawn, and whose person is not blocked. Withdrawing and blocking
//! take effect with the next request, because every request is checked here.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// An account name as the register keeps it: what the system gave, shown and never decided on; bounded, and without a
/// control character or a bidirectional mark (`p_ermit::text`).
#[must_use]
pub fn valid_account(name: &str) -> bool {
    !name.is_empty() && name.chars().count() <= 64 && crate::util::is_clean(name)
}

/// A group's name as a certificate carries it.
fn valid_group(name: &str) -> bool {
    !name.is_empty() && name.chars().count() <= 64 && crate::util::is_clean(name)
}

/// A key's label: free text of the certificate's key identity, so bounded and clean.
fn valid_label(label: &str) -> bool {
    label.chars().count() <= 256 && crate::util::is_clean(label)
}

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

/// Who made a block or a withdrawal. The **uid is the record**: what the kernel said of the peer on `admin.sock`
/// (`p_act::peer`), which means something after the account is renamed or deleted. The account's **name** is for a
/// reader: the name the system gave that uid when it was looked up (after the verb was answered, so it may be
/// missing), never used to decide anything. Nothing else about the caller is read (not `SUDO_USER`: through `sudo`
/// the uid is 0 and the record says 0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Actor {
    /// The person's own pledge.
    Pledge { person: String },
    /// An administrator, by the user id the peer lookup read.
    Administrator {
        uid: u32,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account: Option<String>,
    },
}

/// When and by whom a block or a withdrawal was made.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mark {
    /// Seconds since the Unix epoch, UTC.
    pub at: u64,
    pub by: Actor,
}

impl Mark {
    /// A mark made at `at` by `by`.
    #[must_use]
    pub fn new(at: SystemTime, by: Actor) -> Mark {
        Mark { at: secs(at), by }
    }
}

fn secs(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

/// What a delegation is known by besides its fingerprint, from the certificate the person registered it with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registration {
    /// The groups of the certificate's `groups@procession`.
    pub groups: Vec<String>,
    /// The key's label: the certificate's key identity.
    pub label: String,
    /// When the broker registered it.
    pub registered: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Entry {
    person: String,
    until: SystemTime,
    withdrawn: bool,
    details: Registration,
    /// When and by whom it was withdrawn (absent in a register that was written before this was kept).
    withdrawal: Option<Mark>,
}

/// One delegation as it is kept on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEntry {
    pub fingerprint: String,
    pub person: String,
    /// Seconds since the Unix epoch.
    pub until: u64,
    pub withdrawn: bool,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub label: String,
    /// Seconds since the Unix epoch.
    #[serde(default)]
    pub registered: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawal: Option<Mark>,
}

/// A block as it is kept on disk: the person's name or the key's fingerprint, and when and by whom.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockEntry {
    pub name: String,
    #[serde(flatten)]
    pub mark: Mark,
}

/// The register as it is kept on disk: delegations until their end, and blocks until lifted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// The version of the file's format: 1.
    pub v: u32,
    pub delegations: Vec<SnapshotEntry>,
    pub blocked: Vec<BlockEntry>,
    /// Keys an administrator blocked, as `SHA256:...` fingerprints. A file without the member has none.
    #[serde(default)]
    pub blocked_keys: Vec<BlockEntry>,
}

/// Registered delegations, by the SHA-256 fingerprint of the agent's public key.
#[derive(Debug, Clone, Default)]
pub struct Register {
    delegations: BTreeMap<String, Entry>,
    blocked: BTreeMap<String, Mark>,
    blocked_keys: BTreeMap<String, Mark>,
}

impl Register {
    /// Register a delegation `person` issued, valid until `until`.
    /// Registering a fingerprint again changes nothing: a delegation that was
    /// withdrawn cannot be brought back, and its end cannot be moved.
    pub fn register(
        &mut self,
        fingerprint: impl Into<String>,
        person: impl Into<String>,
        until: SystemTime,
        details: Registration,
    ) {
        self.delegations.entry(fingerprint.into()).or_insert(Entry {
            person: person.into(),
            until,
            withdrawn: false,
            details,
            withdrawal: None,
        });
    }

    /// The person a request under this delegation is passed on to, or why it
    /// is stopped.
    pub fn person_for(&self, fingerprint: &str, now: SystemTime) -> Result<&str, Stopped> {
        let entry = self.delegations.get(fingerprint).ok_or(Stopped::Unknown)?;
        if entry.withdrawn {
            Err(Stopped::Withdrawn)
        } else if self.blocked.contains_key(&entry.person) {
            Err(Stopped::PersonBlocked)
        } else if now >= entry.until {
            Err(Stopped::Ended)
        } else {
            Ok(&entry.person)
        }
    }

    /// Withdraw one delegation, made as `mark` says. Returns whether it was registered. A delegation that is withdrawn
    /// already keeps its first mark.
    pub fn withdraw(&mut self, fingerprint: &str, mark: Mark) -> bool {
        match self.delegations.get_mut(fingerprint) {
            Some(entry) => {
                entry.withdrawn = true;
                entry.withdrawal.get_or_insert(mark);
                true
            }
            None => false,
        }
    }

    /// Block a person: nothing is passed on under any of their delegations,
    /// present or future, until [`Register::unblock`].
    /// A block that is there keeps its first mark.
    pub fn block(&mut self, person: impl Into<String>, mark: Mark) {
        self.blocked.entry(person.into()).or_insert(mark);
    }

    pub fn unblock(&mut self, person: &str) {
        self.blocked.remove(person);
    }

    /// Block one key (a fingerprint): a connection key, an approval key, a delegation key or an agent's key.
    pub fn block_key(&mut self, fingerprint: impl Into<String>, mark: Mark) {
        self.blocked_keys.entry(fingerprint.into()).or_insert(mark);
    }

    pub fn unblock_key(&mut self, fingerprint: &str) {
        self.blocked_keys.remove(fingerprint);
    }

    /// Whether the key is blocked.
    #[must_use]
    pub fn is_key_blocked(&self, fingerprint: &str) -> bool {
        self.blocked_keys.contains_key(fingerprint)
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
        self.blocked.keys().cloned().collect()
    }

    /// The blocked keys, sorted.
    #[must_use]
    pub fn blocked_keys(&self) -> Vec<String> {
        self.blocked_keys.keys().cloned().collect()
    }

    /// How many delegations are registered, and how many of them are withdrawn.
    #[must_use]
    pub fn counts(&self) -> (usize, usize) {
        (self.delegations.len(), self.delegations.values().filter(|e| e.withdrawn).count())
    }

    /// Whether the person is blocked.
    #[must_use]
    pub fn is_blocked(&self, person: &str) -> bool {
        self.blocked.contains_key(person)
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
                    until: secs(e.until),
                    withdrawn: e.withdrawn,
                    groups: e.details.groups.clone(),
                    label: e.details.label.clone(),
                    registered: e.details.registered.map_or(0, secs),
                    withdrawal: e.withdrawal.clone(),
                })
                .collect(),
            blocked: Self::entries(&self.blocked),
            blocked_keys: Self::entries(&self.blocked_keys),
        }
    }

    fn entries(blocks: &BTreeMap<String, Mark>) -> Vec<BlockEntry> {
        blocks.iter().map(|(name, mark)| BlockEntry { name: name.clone(), mark: mark.clone() }).collect()
    }

    /// Give the account `name` to every mark made by the administrator with this uid that has none yet. The name is
    /// for a reader and is looked up after the verb was answered; a name that is not valid is not recorded. Returns
    /// whether anything changed (and so needs storing).
    pub fn name_administrator(&mut self, uid: u32, name: &str) -> bool {
        if !valid_account(name) {
            return false;
        }
        let mut changed = false;
        let marks = self
            .blocked
            .values_mut()
            .chain(self.blocked_keys.values_mut())
            .chain(self.delegations.values_mut().filter_map(|e| e.withdrawal.as_mut()));
        for mark in marks {
            if let Actor::Administrator { uid: u, account: account @ None } = &mut mark.by
                && *u == uid
            {
                *account = Some(name.to_owned());
                changed = true;
            }
        }
        changed
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
        let mark_ok = |m: &Mark| match &m.by {
            Actor::Pledge { person } => valid_name(person),
            Actor::Administrator { account, .. } => account.as_deref().is_none_or(valid_account),
        };
        for e in &snapshot.delegations {
            if !fingerprint(&e.fingerprint) {
                return Err("delegations (fingerprint)");
            }
            if !valid_name(&e.person) {
                return Err("delegations (person)");
            }
            if !e.groups.iter().all(|g| valid_group(g)) {
                return Err("delegations (groups)");
            }
            if !valid_label(&e.label) {
                return Err("delegations (label)");
            }
            if !e.withdrawal.as_ref().is_none_or(mark_ok) {
                return Err("delegations (withdrawal)");
            }
        }
        if !snapshot.blocked.iter().all(|b| valid_name(&b.name) && mark_ok(&b.mark)) {
            return Err("blocked");
        }
        if !snapshot.blocked_keys.iter().all(|b| fingerprint(&b.name) && mark_ok(&b.mark)) {
            return Err("blocked_keys");
        }
        let marks = |v: Vec<BlockEntry>| v.into_iter().map(|b| (b.name, b.mark)).collect();
        Ok(Register {
            delegations: snapshot
                .delegations
                .into_iter()
                .map(|e| {
                    let until = SystemTime::UNIX_EPOCH + Duration::from_secs(e.until);
                    let registered =
                        (e.registered > 0).then(|| SystemTime::UNIX_EPOCH + Duration::from_secs(e.registered));
                    let details = Registration { groups: e.groups, label: e.label, registered };
                    (
                        e.fingerprint,
                        Entry { person: e.person, until, withdrawn: e.withdrawn, details, withdrawal: e.withdrawal },
                    )
                })
                .collect(),
            blocked: marks(snapshot.blocked),
            blocked_keys: marks(snapshot.blocked_keys),
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

    fn mark() -> Mark {
        Mark::new(t(1), Actor::Pledge { person: "jan".to_owned() })
    }

    fn register() -> Register {
        let mut register = Register::default();
        register.register("SHA256:agent1", "jan", t(8), Registration::default());
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
        assert!(register.withdraw("SHA256:agent1", mark()));
        assert_eq!(register.person_for("SHA256:agent1", t(1)), Err(Stopped::Withdrawn));
        register.register("SHA256:agent1", "jan", t(24), Registration::default());
        assert_eq!(register.person_for("SHA256:agent1", t(1)), Err(Stopped::Withdrawn));
    }

    #[test]
    fn registering_again_cannot_move_a_delegations_end() {
        let mut register = register();
        register.register("SHA256:agent1", "jan", t(24), Registration::default());
        assert_eq!(register.person_for("SHA256:agent1", t(9)), Err(Stopped::Ended));
    }

    #[test]
    fn blocking_a_person_stops_all_their_delegations_until_unblocked() {
        let mut register = register();
        register.register("SHA256:agent2", "jan", t(8), Registration::default());
        register.block("jan", mark());
        assert_eq!(register.person_for("SHA256:agent1", t(1)), Err(Stopped::PersonBlocked));
        assert_eq!(register.person_for("SHA256:agent2", t(1)), Err(Stopped::PersonBlocked));
        register.unblock("jan");
        assert_eq!(register.person_for("SHA256:agent1", t(1)), Ok("jan"));
    }

    #[test]
    fn a_withdrawn_delegation_is_kept_until_its_end_and_dropped_after() {
        let mut register = register();
        register.withdraw("SHA256:agent1", mark());
        register.forget_ended(t(4));
        assert_eq!(register.person_for("SHA256:agent1", t(4)), Err(Stopped::Withdrawn));
        register.forget_ended(t(9));
        assert_eq!(register.person_for("SHA256:agent1", t(9)), Err(Stopped::Unknown));
    }
}
