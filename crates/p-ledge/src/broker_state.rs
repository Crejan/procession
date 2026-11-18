//! What pledge keeps of the broker across restarts (`proposals/broker-connection.md`, section 4;
//! the designer's rules): `broker-state.json` in the state directory.
//!
//! - **Restrictions** (anything in a standing that takes something away: `blocked`, `blocked_keys`,
//!   `withdrawn`): kept, and in force after a restart until a newer verified standing says otherwise.
//!   A restart must not lift a restriction.
//! - **Certificates** of the person's approval keys: kept, but verified again when loaded; what does not
//!   verify, or has ended, is dropped.
//! - **What permits** (the person's groups): shown from disk marked as of when, never trusted: nothing is
//!   issued on them; issuing needs a standing verified on the current connection.
//! - pledge's own withdrawals and whether the broker stored each.
//!
//! The file is owner-only, written to a temporary file and renamed, carries a `v`, and is refused whole
//! rather than read in part (`p_act::settings` does the reading).

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Where one of pledge's own withdrawals stands at the broker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Withdrawal {
    /// Withdrawn here; the broker has not been told (no connection yet).
    NotTold,
    /// Told; the broker has it in force but did not store it.
    InForce,
    /// The broker stored it.
    Stored,
}

impl Withdrawal {
    /// How `pledge agents list` says it.
    #[must_use]
    pub fn words(self) -> &'static str {
        match self {
            Self::NotTold => "not told",
            Self::InForce => "not stored yet",
            Self::Stored => "stored",
        }
    }
}

/// The file's content.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Persisted {
    /// The format's version: 1.
    pub v: u32,
    /// An administrator blocked the person.
    #[serde(default)]
    pub blocked: bool,
    /// Fingerprints of the person's keys an administrator blocked.
    #[serde(default)]
    pub blocked_keys: Vec<String>,
    /// Identifiers of delegations an administrator withdrew.
    #[serde(default)]
    pub withdrawn: Vec<String>,
    /// The approval keys' certificates that verified, as `-cert.pub` lines.
    #[serde(default)]
    pub certificates: Vec<Cert>,
    /// The person's groups as the last verified standing gave them.
    #[serde(default)]
    pub groups: Vec<String>,
    /// When that standing came (Unix time).
    #[serde(default)]
    pub groups_as_of: Option<i64>,
    /// pledge's own withdrawals.
    #[serde(default)]
    pub withdrawals: BTreeMap<String, Withdrawal>,
}

/// A certificate that verified, and for which role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cert {
    /// `confirmed` or `automatic`.
    pub role: String,
    /// The `-cert.pub` line.
    pub line: String,
}

/// What a standing changed, for the record and for what is waiting.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changes {
    /// The person became blocked.
    pub newly_blocked: bool,
    /// Delegations newly withdrawn.
    pub newly_withdrawn: Vec<String>,
    /// Keys newly blocked.
    pub newly_blocked_keys: Vec<String>,
}

/// The broker's word as pledge holds it, in memory and in `broker-state.json`.
pub struct BrokerState {
    path: PathBuf,
    inner: Mutex<Persisted>,
}

impl BrokerState {
    /// Reads the file (a missing one is empty), re-verifying every certificate with `verify` and dropping
    /// what does not verify.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupt`] if the file is refused: it is not read in part, and pledge does not start on it,
    /// because it could hold restrictions that cannot then be known.
    pub fn open(path: PathBuf, verify: &dyn Fn(&str) -> Option<String>) -> Result<Self> {
        let read = p_act::settings::read_optional::<Persisted>(&path)
            .map_err(|e| Error::Corrupt { path: path.clone(), problem: e.to_string() })?;
        let mut persisted = read.unwrap_or(Persisted { v: 1, ..Persisted::default() });
        if persisted.v != 1 {
            return Err(Error::Corrupt { path, problem: "the file's version is not 1".into() });
        }
        let before = persisted.certificates.len();
        persisted.certificates.retain(|cert| verify(&cert.line).as_deref() == Some(cert.role.as_str()));
        let state = Self { path, inner: Mutex::new(persisted) };
        if state.get().certificates.len() != before {
            state.save()?;
        }
        Ok(state)
    }

    /// A copy of what is held.
    #[must_use]
    pub fn get(&self) -> Persisted {
        self.inner.lock().map(|p| p.clone()).unwrap_or_default()
    }

    fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.get()).map_err(|e| Error::Refused(e.to_string()))?;
        let temp = self.path.with_extension("json.new");
        let context = format!("writing {}", self.path.display());
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp)
            .map_err(Error::io(context.clone()))?;
        file.write_all(&bytes).and_then(|()| file.sync_all()).map_err(Error::io(context.clone()))?;
        fs::rename(&temp, &self.path).map_err(Error::io(context))
    }

    /// Whether the person is blocked.
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        self.get().blocked
    }

    /// Whether the key with this fingerprint is blocked.
    #[must_use]
    pub fn is_key_blocked(&self, fingerprint: &str) -> bool {
        self.get().blocked_keys.iter().any(|k| k == fingerprint)
    }

    /// Whether an administrator withdrew this delegation, or pledge did and it is not forgotten.
    #[must_use]
    pub fn is_withdrawn(&self, delegation: &str) -> bool {
        let p = self.get();
        p.withdrawn.iter().any(|d| d == delegation)
    }

    /// The certificate line held for a role (`confirmed` or `automatic`).
    #[must_use]
    pub fn certificate_for(&self, role: &str) -> Option<String> {
        self.get().certificates.into_iter().find(|cert| cert.role == role).map(|cert| cert.line)
    }

    /// Replaces the restrictions, the certificates and the groups with those of a verified standing: a
    /// restriction that is absent lifts. Certificates are kept only if `verify` accepts them.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if it cannot be saved.
    pub fn apply(
        &self,
        blocked: bool,
        blocked_keys: &[String],
        withdrawn: &[String],
        certificates: &[String],
        groups: &[String],
        now: i64,
        verify: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Changes> {
        let kept: Vec<Cert> =
            certificates.iter().filter_map(|line| verify(line).map(|role| Cert { role, line: line.clone() })).collect();
        let changes = {
            let mut p = self.inner.lock().map_err(|_| Error::Refused("poisoned".into()))?;
            let changes = Changes {
                newly_blocked: blocked && !p.blocked,
                newly_withdrawn: withdrawn.iter().filter(|d| !p.withdrawn.contains(d)).cloned().collect(),
                newly_blocked_keys: blocked_keys.iter().filter(|k| !p.blocked_keys.contains(k)).cloned().collect(),
            };
            p.blocked = blocked;
            p.blocked_keys = blocked_keys.to_vec();
            p.withdrawn = withdrawn.to_vec();
            p.certificates = kept;
            p.groups = groups.to_vec();
            p.groups_as_of = Some(now);
            changes
        };
        self.save()?;
        Ok(changes)
    }

    /// Notes a withdrawal pledge made itself (not told yet), unless already noted.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if it cannot be saved.
    pub fn note_withdrawal(&self, delegation: &str) -> Result<()> {
        {
            let mut p = self.inner.lock().map_err(|_| Error::Refused("poisoned".into()))?;
            p.withdrawals.entry(delegation.to_owned()).or_insert(Withdrawal::NotTold);
        }
        self.save()
    }

    /// Sets where a withdrawal stands.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if it cannot be saved.
    pub fn set_withdrawal(&self, delegation: &str, state: Withdrawal) -> Result<()> {
        {
            let mut p = self.inner.lock().map_err(|_| Error::Refused("poisoned".into()))?;
            p.withdrawals.insert(delegation.to_owned(), state);
        }
        self.save()
    }

    /// The withdrawals the broker has not stored.
    #[must_use]
    pub fn unstored_withdrawals(&self) -> Vec<String> {
        self.get().withdrawals.into_iter().filter(|(_, s)| *s != Withdrawal::Stored).map(|(d, _)| d).collect()
    }

    /// Where a withdrawal stands, if pledge made one.
    #[must_use]
    pub fn withdrawal(&self, delegation: &str) -> Option<Withdrawal> {
        self.get().withdrawals.get(delegation).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestDir;

    /// Accepts every certificate; its role is its comment's part after the colon.
    const ALWAYS: &dyn Fn(&str) -> Option<String> = &|line| line.rsplit(':').next().map(str::to_owned);
    const NEVER: &dyn Fn(&str) -> Option<String> = &|_| None;

    fn state(dir: &TestDir) -> BrokerState {
        BrokerState::open(dir.path().join("broker-state.json"), ALWAYS).expect("open")
    }

    fn mode(dir: &TestDir) -> u32 {
        std::os::unix::fs::PermissionsExt::mode(
            &fs::metadata(dir.path().join("broker-state.json")).expect("meta").permissions(),
        ) & 0o777
    }

    #[test]
    fn a_standing_replaces_the_restrictions_and_the_absence_of_one_lifts_it() {
        let dir = TestDir::new("bstate");
        let s = state(&dir);
        let strings = |a: &[&str]| a.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>();
        let changes = s
            .apply(true, &strings(&["SHA256:k"]), &strings(&["SHA256:d"]), &[], &strings(&["ops"]), 100, ALWAYS)
            .expect("apply");
        assert_eq!(
            changes,
            Changes {
                newly_blocked: true,
                newly_withdrawn: strings(&["SHA256:d"]),
                newly_blocked_keys: strings(&["SHA256:k"])
            }
        );
        assert!(s.is_blocked() && s.is_key_blocked("SHA256:k") && s.is_withdrawn("SHA256:d"));
        // The same again: no change. A newer one that no longer lists them lifts them.
        let again =
            s.apply(true, &strings(&["SHA256:k"]), &strings(&["SHA256:d"]), &[], &[], 101, ALWAYS).expect("apply");
        assert_eq!(again, Changes::default());
        s.apply(false, &[], &[], &[], &[], 102, ALWAYS).expect("apply");
        assert!(!s.is_blocked() && !s.is_key_blocked("SHA256:k") && !s.is_withdrawn("SHA256:d"));
        assert_eq!(mode(&dir), 0o600);
    }

    #[test]
    fn a_restart_does_not_lift_a_restriction_and_certificates_are_verified_again() {
        let dir = TestDir::new("bstate-restart");
        let s = state(&dir);
        let cert = "ssh-ed25519-cert-v01@openssh.com AAAA jan:confirmed".to_owned();
        s.apply(true, &["SHA256:k".into()], &["SHA256:d".into()], &[cert.clone()], &["ops".into()], 100, ALWAYS)
            .expect("apply");
        assert_eq!(s.certificate_for("confirmed").as_deref(), Some(cert.as_str()));
        drop(s);
        let again = state(&dir);
        assert!(again.is_blocked() && again.is_withdrawn("SHA256:d") && again.is_key_blocked("SHA256:k"));
        assert_eq!(again.get().groups_as_of, Some(100), "groups come back marked as of when");
        drop(again);
        // A certificate that no longer verifies is dropped (and the file says so); the restrictions stay.
        let dropped = BrokerState::open(dir.path().join("broker-state.json"), NEVER).expect("open");
        assert!(dropped.certificate_for("confirmed").is_none());
        assert!(dropped.is_blocked());
        let reread = state(&dir);
        assert!(reread.get().certificates.is_empty(), "written without it");
    }

    #[test]
    fn a_certificate_that_does_not_verify_is_not_kept_from_a_standing() {
        let dir = TestDir::new("bstate-cert");
        let s = state(&dir);
        let lines = ["a AAAA jan:confirmed".to_owned(), "b AAAA jan:automatic".to_owned()];
        s.apply(false, &[], &[], &lines, &[], 1, &|line| line.starts_with('b').then(|| "automatic".to_owned()))
            .expect("apply");
        assert!(s.certificate_for("confirmed").is_none());
        assert!(s.certificate_for("automatic").is_some());
    }

    #[test]
    fn the_file_is_refused_whole_not_read_in_part() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new("bstate-bad");
        let path = dir.path().join("broker-state.json");
        for (what, text, mode) in [
            ("an unknown member", r#"{"v":1,"surprise":true}"#, 0o600),
            ("a version that is not 1", r#"{"v":2}"#, 0o600),
            ("not an object", "[]", 0o600),
            ("a member twice", r#"{"v":1,"blocked":false,"blocked":true}"#, 0o600),
            ("a file others can write", r#"{"v":1}"#, 0o666),
        ] {
            fs::write(&path, text).expect("write");
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");
            assert!(matches!(BrokerState::open(path.clone(), ALWAYS), Err(Error::Corrupt { .. })), "{what}");
        }
    }

    #[test]
    fn withdrawals_are_noted_and_followed_until_the_broker_stores_them() {
        let dir = TestDir::new("bstate-w");
        let s = state(&dir);
        s.note_withdrawal("SHA256:a").expect("note");
        s.note_withdrawal("SHA256:b").expect("note");
        s.set_withdrawal("SHA256:a", Withdrawal::InForce).expect("set");
        assert_eq!(s.unstored_withdrawals(), ["SHA256:a", "SHA256:b"]);
        s.set_withdrawal("SHA256:a", Withdrawal::Stored).expect("set");
        s.note_withdrawal("SHA256:a").expect("noting again changes nothing");
        assert_eq!(s.withdrawal("SHA256:a"), Some(Withdrawal::Stored));
        assert_eq!(s.unstored_withdrawals(), ["SHA256:b"]);
        assert_eq!(Withdrawal::InForce.words(), "not stored yet");
    }
}
