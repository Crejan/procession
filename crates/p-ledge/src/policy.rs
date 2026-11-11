//! Whether a local program may use a key.
//!
//! Every signing request on the SSH agent socket is answered by
//! [`Policy::decide`] with a [`Verdict`]. The order is fixed and the first
//! match wins:
//!
//! 1. data the SSH agent could not interpret is refused, whoever asks;
//! 2. a key is offered only for its purpose, and a signing request for any
//!    other key is refused without a dialog;
//! 3. a bound key signs without a dialog, for its program and for the one
//!    login it was made for;
//! 4. for a shared key, a blocked program is refused, an unknown one is put
//!    to the person, and an admitted one gets a presence check for each
//!    signature.
//!
//! Admitting a program means it may ask. It never means a shared key signs
//! unseen: the only path without the person is a bound key.

use std::collections::BTreeMap;

/// What happens to one signing request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Sign, without a dialog.
    Sign,
    /// Sign after a presence check for this one signature.
    CheckPresence,
    /// Ask the person whether this program may use keys at all; see
    /// [`Policy::admit`].
    AskAdmission,
    /// Refuse, without a dialog.
    Refuse(Reason),
}

/// Why a signing request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The data is not a login or a signature the SSH agent can read.
    NotUnderstood,
    /// The key is unknown, serves a purpose this program is not part of, or
    /// is bound to another use than the one asked for.
    KeyNotOffered,
    /// The person blocked this program.
    Blocked,
}

/// What a key on the SSH agent socket is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purpose {
    /// One program's key for one use (a backup program's login to its
    /// repository server). It signs without a dialog for exactly that, and is
    /// offered to no other program and for nothing else.
    Bound { program: String, use_: String },
    /// A key for every other program. Each signature gets a presence check.
    Shared,
}

/// One signing request: one use of one key by one program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningRequest {
    /// Who asks: the verified identity of the connecting program (its code
    /// signing identity on macOS).
    pub program: String,
    /// The key asked for, by fingerprint.
    pub key: String,
    /// What the SSH agent read out of the data: a login as a user on a
    /// verified host, or a signature in a namespace. `None` when it could not
    /// read it.
    pub use_: Option<String>,
}

/// What the person answered when asked about a program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Refuse this program from now on, without asking again.
    Block,
    /// Refuse this signing request; ask again next time.
    DeclineOnce,
    /// Let this signing request through to its presence check; ask again
    /// next time.
    AdmitOnce,
    /// Let this program ask from now on. Each signature still gets a
    /// presence check.
    AdmitGenerally,
}

/// What the person decided about a program for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Standing {
    /// The program may ask; each signature still gets a presence check.
    Admitted,
    /// The program is refused without a dialog.
    Blocked,
}

/// The namespaces a shared key signs SSHSIG in (`SPEC.md`, section 3).
pub const SHARED_NAMESPACES: [&str; 2] = ["git", "file"];

/// The form of [`SigningRequest::use_`] for an SSHSIG signature.
#[must_use]
pub fn sshsig_use(namespace: &str) -> String {
    format!("sshsig {namespace}")
}

/// The keys with their purposes, and the standing of each program.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    purposes: BTreeMap<String, Purpose>,
    standing: BTreeMap<String, Standing>,
}

impl Policy {
    /// Declare `key` with its purpose. A key the policy has not been told
    /// about is offered to nobody.
    pub fn set_purpose(&mut self, key: impl Into<String>, purpose: Purpose) {
        self.purposes.insert(key.into(), purpose);
    }

    /// Whether `program` has a key of its own, and so is not offered the
    /// shared ones.
    fn has_bound_key(&self, program: &str) -> bool {
        self.purposes
            .values()
            .any(|purpose| matches!(purpose, Purpose::Bound { program: owner, .. } if owner == program))
    }

    /// The keys (by the fingerprints they were declared under) offered to
    /// `program`: its own bound keys, and the shared ones unless it has a
    /// bound key.
    #[must_use]
    pub fn offered(&self, program: &str) -> Vec<&str> {
        let has_bound = self.has_bound_key(program);
        self.purposes
            .iter()
            .filter(|(_, purpose)| match purpose {
                Purpose::Bound { program: owner, .. } => owner == program,
                Purpose::Shared => !has_bound,
            })
            .map(|(key, _)| key.as_str())
            .collect()
    }

    /// Forget a key: it is offered to nobody from now on.
    pub fn remove_purpose(&mut self, key: &str) {
        self.purposes.remove(key);
    }

    /// What was decided about each program, in program order.
    pub fn programs(&self) -> impl Iterator<Item = (&str, Standing)> {
        self.standing.iter().map(|(program, standing)| (program.as_str(), *standing))
    }

    /// Set what was decided about `program` (used when state is loaded).
    pub fn set_standing(&mut self, program: impl Into<String>, standing: Standing) {
        self.standing.insert(program.into(), standing);
    }

    /// The verdict for `request`.
    pub fn decide(&self, request: &SigningRequest) -> Verdict {
        let Some(asked) = &request.use_ else {
            return Verdict::Refuse(Reason::NotUnderstood);
        };
        match self.purposes.get(&request.key) {
            None => return Verdict::Refuse(Reason::KeyNotOffered),
            Some(Purpose::Bound { program, use_ }) => {
                return if *program == request.program && use_ == asked {
                    Verdict::Sign
                } else {
                    Verdict::Refuse(Reason::KeyNotOffered)
                };
            }
            Some(Purpose::Shared) if self.has_bound_key(&request.program) => {
                return Verdict::Refuse(Reason::KeyNotOffered);
            }
            Some(Purpose::Shared) => {}
        }
        // A shared key signs SSHSIG only in the namespaces it is offered for.
        if let Some(namespace) = asked.strip_prefix("sshsig ") {
            if !SHARED_NAMESPACES.contains(&namespace) {
                return Verdict::Refuse(Reason::KeyNotOffered);
            }
        }
        match self.standing.get(&request.program) {
            Some(Standing::Blocked) => Verdict::Refuse(Reason::Blocked),
            None => Verdict::AskAdmission,
            Some(Standing::Admitted) => Verdict::CheckPresence,
        }
    }

    /// Record the person's answer about `program` and return whether the
    /// signing request that raised the question goes on to its presence
    /// check.
    pub fn admit(&mut self, program: &str, answer: Admission) -> bool {
        match answer {
            Admission::Block => {
                self.standing.insert(program.to_string(), Standing::Blocked);
                false
            }
            Admission::DeclineOnce => false,
            Admission::AdmitOnce => true,
            Admission::AdmitGenerally => {
                self.standing.insert(program.to_string(), Standing::Admitted);
                true
            }
        }
    }

    /// Forget what was decided about `program`. Its next signing request asks
    /// again.
    pub fn forget(&mut self, program: &str) {
        self.standing.remove(program);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BACKUP_KEY: &str = "SHA256:backup";
    const SHARED_KEY: &str = "SHA256:shared";
    const REPOSITORY_LOGIN: &str = "login u1@backup.example";

    fn policy() -> Policy {
        let mut policy = Policy::default();
        policy.set_purpose(BACKUP_KEY, Purpose::Bound { program: "preserve".into(), use_: REPOSITORY_LOGIN.into() });
        policy.set_purpose(SHARED_KEY, Purpose::Shared);
        policy
    }

    fn login(program: &str, key: &str, use_: &str) -> SigningRequest {
        SigningRequest { program: program.into(), key: key.into(), use_: Some(use_.into()) }
    }

    #[test]
    fn a_shared_key_signs_sshsig_in_git_and_file_only() {
        let policy = policy();
        let mut admitted = policy;
        admitted.admit("git", Admission::AdmitGenerally);
        for (namespace, verdict) in [
            ("git", Verdict::CheckPresence),
            ("file", Verdict::CheckPresence),
            ("other", Verdict::Refuse(Reason::KeyNotOffered)),
            ("approval-v1@procession", Verdict::Refuse(Reason::KeyNotOffered)),
        ] {
            assert_eq!(admitted.decide(&login("git", SHARED_KEY, &sshsig_use(namespace))), verdict, "{namespace}");
        }
    }

    #[test]
    fn offered_keys_follow_the_purposes() {
        let policy = policy();
        assert_eq!(policy.offered("preserve"), [BACKUP_KEY]);
        assert_eq!(policy.offered("git"), [SHARED_KEY]);
    }

    #[test]
    fn a_bound_key_signs_without_a_dialog_for_its_program_and_its_login_only() {
        let policy = policy();
        assert_eq!(policy.decide(&login("preserve", BACKUP_KEY, REPOSITORY_LOGIN)), Verdict::Sign);
        assert_eq!(policy.decide(&login("git", BACKUP_KEY, REPOSITORY_LOGIN)), Verdict::Refuse(Reason::KeyNotOffered));
        assert_eq!(
            policy.decide(&login("preserve", BACKUP_KEY, "login root@other.example")),
            Verdict::Refuse(Reason::KeyNotOffered)
        );
    }

    #[test]
    fn a_program_with_its_own_key_is_not_offered_the_shared_one() {
        assert_eq!(
            policy().decide(&login("preserve", SHARED_KEY, REPOSITORY_LOGIN)),
            Verdict::Refuse(Reason::KeyNotOffered)
        );
    }

    #[test]
    fn an_undeclared_key_is_offered_to_nobody() {
        assert_eq!(
            policy().decide(&login("git", "SHA256:other", REPOSITORY_LOGIN)),
            Verdict::Refuse(Reason::KeyNotOffered)
        );
    }

    #[test]
    fn unreadable_data_is_refused_even_for_the_bound_program() {
        let opaque = SigningRequest { use_: None, ..login("preserve", BACKUP_KEY, REPOSITORY_LOGIN) };
        assert_eq!(policy().decide(&opaque), Verdict::Refuse(Reason::NotUnderstood));
    }

    #[test]
    fn an_unknown_program_is_put_to_the_person() {
        assert_eq!(policy().decide(&login("git", SHARED_KEY, "login jan@box.example")), Verdict::AskAdmission);
    }

    #[test]
    fn admitting_or_declining_once_remembers_nothing() {
        let mut policy = policy();
        let request = login("git", SHARED_KEY, "login jan@box.example");
        assert!(policy.admit("git", Admission::AdmitOnce));
        assert_eq!(policy.decide(&request), Verdict::AskAdmission);
        assert!(!policy.admit("git", Admission::DeclineOnce));
        assert_eq!(policy.decide(&request), Verdict::AskAdmission);
    }

    #[test]
    fn an_admitted_program_still_gets_a_presence_check_per_signature() {
        let mut policy = policy();
        let request = login("git", SHARED_KEY, "login jan@box.example");
        assert!(policy.admit("git", Admission::AdmitGenerally));
        assert_eq!(policy.decide(&request), Verdict::CheckPresence);
        assert_eq!(policy.decide(&request), Verdict::CheckPresence);
    }

    #[test]
    fn a_blocked_program_is_refused_without_a_dialog_until_forgotten() {
        let mut policy = policy();
        let request = login("curl", SHARED_KEY, "login jan@box.example");
        assert!(!policy.admit("curl", Admission::Block));
        assert_eq!(policy.decide(&request), Verdict::Refuse(Reason::Blocked));
        policy.forget("curl");
        assert_eq!(policy.decide(&request), Verdict::AskAdmission);
    }
}
