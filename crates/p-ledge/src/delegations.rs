//! The delegations pledge issued: who, which groups, the two ceilings, how
//! long, and whether withdrawn. They are kept in `delegations.json` in the
//! state directory and are the only thing that makes a call count: pledge
//! checks itself that a call is under one of them (R8). The agent's private key
//! is not kept.

use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::sync::Mutex;

use p_act::rating::{Ceilings, Damage, Disruption, Exposure, Rating};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A rating as it is written in files and commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RatingWords {
    /// `open`, `internal` or `secret`.
    pub exposure: String,
    /// `none`, `recoverable` or `lasting`.
    pub damage: String,
    /// `none`, `brief` or `outage`.
    pub disruption: String,
}

impl RatingWords {
    /// The words for `rating`.
    #[must_use]
    pub fn of(rating: Rating) -> Self {
        Self {
            exposure: match rating.exposure {
                Exposure::Open => "open",
                Exposure::Internal => "internal",
                Exposure::Secret => "secret",
            }
            .into(),
            damage: match rating.damage {
                Damage::None => "none",
                Damage::Recoverable => "recoverable",
                Damage::Lasting => "lasting",
            }
            .into(),
            disruption: match rating.disruption {
                Disruption::None => "none",
                Disruption::Brief => "brief",
                Disruption::Outage => "outage",
            }
            .into(),
        }
    }

    /// The rating, or `None` if a word is not one of the scale.
    #[must_use]
    pub fn rating(&self) -> Option<Rating> {
        let exposure = match self.exposure.as_str() {
            "open" => Exposure::Open,
            "internal" => Exposure::Internal,
            "secret" => Exposure::Secret,
            _ => return None,
        };
        let damage = match self.damage.as_str() {
            "none" => Damage::None,
            "recoverable" => Damage::Recoverable,
            "lasting" => Damage::Lasting,
            _ => return None,
        };
        let disruption = match self.disruption.as_str() {
            "none" => Disruption::None,
            "brief" => Disruption::Brief,
            "outage" => Disruption::Outage,
            _ => return None,
        };
        Some(Rating::new(exposure, damage, disruption))
    }
}

/// Where a delegation is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    /// Issued, but its bundle was not yet reported written. It signs nothing.
    Pending,
    /// In use.
    Active,
}

/// One delegation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Delegation {
    /// The fingerprint of the agent's public key.
    pub id: String,
    /// The agent's public key line.
    pub agent_public: String,
    /// The certificate line.
    pub certificate: String,
    /// The person.
    pub person: String,
    /// The groups, sorted.
    pub groups: Vec<String>,
    /// The automatic ceiling.
    pub automatic: RatingWords,
    /// The ask ceiling.
    pub ask: RatingWords,
    /// The fingerprint of the delegation key that issued the certificate.
    pub issuer: String,
    /// When it was issued (Unix time).
    pub issued: i64,
    /// When it ends (Unix time).
    pub valid_until: i64,
    /// Pending or active.
    pub state: State,
    /// When it was withdrawn (Unix time), if it was.
    #[serde(default)]
    pub withdrawn: Option<i64>,
    /// When it last asked (Unix time).
    #[serde(default)]
    pub last_asked: Option<i64>,
}

impl Delegation {
    /// The two ceilings pledge honours, as ratings. What a file says is not
    /// taken at its word: an automatic ceiling above what a person can set
    /// (`Ceilings::HIGHEST_AUTOMATIC`) is cut down to it on every scale, and
    /// above the ask ceiling to that. `None` if a word is not one of the
    /// scales: such a delegation is not used.
    fn honoured(&self) -> Option<(Rating, Rating)> {
        let (automatic, ask) = (self.automatic.rating()?, self.ask.rating()?);
        let top = Ceilings::HIGHEST_AUTOMATIC;
        let automatic = Rating::new(
            automatic.exposure.min(top.exposure).min(ask.exposure),
            automatic.damage.min(top.damage).min(ask.damage),
            automatic.disruption.min(top.disruption).min(ask.disruption),
        );
        Some((automatic, ask))
    }

    /// The ceilings pledge honours: the stored ones, with an automatic ceiling above what a person may set cut down.
    #[must_use]
    pub fn ceilings(&self) -> Option<Ceilings> {
        let (automatic, ask) = self.honoured()?;
        Ceilings::new(automatic, ask)
    }

    /// Whether the stored automatic ceiling is above what pledge honours.
    #[must_use]
    pub fn automatic_was_raised(&self) -> bool {
        self.honoured().zip(self.automatic.rating()).is_some_and(|((honoured, _), stored)| honoured != stored)
    }
}

#[derive(Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct File {
    delegations: Vec<Delegation>,
}

/// The delegations, in memory and in `delegations.json`.
pub struct Delegations {
    path: PathBuf,
    list: Mutex<Vec<Delegation>>,
}

impl Delegations {
    /// Loads `path` (missing is empty).
    ///
    /// # Errors
    ///
    /// [`Error::Corrupt`] if the file does not parse.
    pub fn open(path: PathBuf) -> Result<Self> {
        let list = match fs::read(&path) {
            Ok(bytes) => {
                serde_json::from_slice::<File>(&bytes)
                    .map_err(|e| Error::Corrupt { path: path.clone(), problem: e.to_string() })?
                    .delegations
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(Error::io(format!("reading {}", path.display()))(e)),
        };
        Ok(Self { path, list: Mutex::new(list) })
    }

    fn save(&self, list: &[Delegation]) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&File { delegations: list.to_vec() })
            .map_err(|e| Error::Refused(e.to_string()))?;
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

    fn with<T>(&self, change: impl FnOnce(&mut Vec<Delegation>) -> Result<T>) -> Result<T> {
        let mut list = self.list.lock().map_err(|_| Error::Refused("the delegations' lock is poisoned".into()))?;
        let result = change(&mut list)?;
        self.save(&list)?;
        Ok(result)
    }

    /// The delegation with this identifier.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<Delegation> {
        self.list.lock().ok()?.iter().find(|d| d.id == id).cloned()
    }

    /// Every delegation.
    #[must_use]
    pub fn all(&self) -> Vec<Delegation> {
        self.list.lock().map(|list| list.clone()).unwrap_or_default()
    }

    /// Adds a delegation.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] if the identifier exists; [`Error::Io`] if it cannot be saved.
    pub fn add(&self, delegation: Delegation) -> Result<()> {
        self.with(|list| {
            if list.iter().any(|d| d.id == delegation.id) {
                return Err(Error::Refused("a delegation with this identifier exists".into()));
            }
            list.push(delegation);
            Ok(())
        })
    }

    /// Makes a pending delegation active. `false` if there is none pending.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if it cannot be saved.
    pub fn activate(&self, id: &str) -> Result<bool> {
        self.with(|list| {
            match list.iter_mut().find(|d| d.id == id && d.state == State::Pending && d.withdrawn.is_none()) {
                Some(d) => {
                    d.state = State::Active;
                    Ok(true)
                }
                None => Ok(false),
            }
        })
    }

    /// Withdraws a delegation. `false` if there is none, or it was withdrawn already.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if it cannot be saved.
    pub fn withdraw(&self, id: &str, now: i64) -> Result<bool> {
        self.with(|list| match list.iter_mut().find(|d| d.id == id && d.withdrawn.is_none()) {
            Some(d) => {
                d.withdrawn = Some(now);
                Ok(true)
            }
            None => Ok(false),
        })
    }

    /// Notes that the delegation asked at `now`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] if it cannot be saved.
    pub fn touch(&self, id: &str, now: i64) -> Result<()> {
        self.with(|list| {
            if let Some(d) = list.iter_mut().find(|d| d.id == id) {
                d.last_asked = Some(now);
            }
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TestDir;

    fn words(e: &str, d: &str, s: &str) -> RatingWords {
        RatingWords { exposure: e.into(), damage: d.into(), disruption: s.into() }
    }

    pub fn sample(id: &str) -> Delegation {
        Delegation {
            id: id.into(),
            agent_public: "ssh-ed25519 AAAA".into(),
            certificate: "ssh-ed25519-cert-v01@openssh.com AAAA".into(),
            person: "jan".into(),
            groups: vec!["admins".into()],
            automatic: words("open", "none", "none"),
            ask: words("secret", "lasting", "outage"),
            issuer: "SHA256:x".into(),
            issued: 1000,
            valid_until: 2000,
            state: State::Active,
            withdrawn: None,
            last_asked: None,
        }
    }

    #[test]
    fn ratings_round_trip_through_words_and_unknown_words_are_none() {
        for rating in
            [Rating::HARMLESS, Rating::WORST, Rating::new(Exposure::Internal, Damage::Recoverable, Disruption::Brief)]
        {
            assert_eq!(RatingWords::of(rating).rating(), Some(rating));
        }
        assert_eq!(words("secrets", "none", "none").rating(), None);
    }

    #[test]
    fn a_tampered_automatic_ceiling_is_cut_down_and_never_reaches_the_top_of_a_scale() {
        let mut delegation = sample("a");
        assert!(!delegation.automatic_was_raised());
        delegation.automatic = words("secret", "lasting", "outage");
        let ceilings = delegation.ceilings().expect("usable");
        assert!(delegation.automatic_was_raised());
        assert_eq!(ceilings, Ceilings::new(Ceilings::HIGHEST_AUTOMATIC, Rating::WORST).expect("ceilings"));
        assert_eq!(
            ceilings.mode(Rating::new(Exposure::Secret, Damage::None, Disruption::None)),
            p_act::rating::Mode::Ask
        );
        assert_eq!(
            ceilings.mode(Rating::new(Exposure::Internal, Damage::Recoverable, Disruption::Brief)),
            p_act::rating::Mode::Automatic
        );
        // And above the ask ceiling it is cut to the ask ceiling.
        delegation.ask = words("open", "none", "none");
        assert_eq!(
            delegation.ceilings().expect("usable"),
            Ceilings::new(Rating::HARMLESS, Rating::HARMLESS).expect("ceilings")
        );
    }

    #[test]
    fn a_ceiling_in_words_that_are_not_the_scale_makes_the_delegation_unusable() {
        let mut delegation = sample("a");
        delegation.ask = words("everything", "none", "none");
        assert_eq!(delegation.ceilings(), None);
    }

    #[test]
    fn delegations_are_added_activated_withdrawn_and_kept_on_disk() {
        let dir = TestDir::new("delegations");
        let path = dir.path().join("delegations.json");
        let store = Delegations::open(path.clone()).expect("open");
        let mut pending = sample("p");
        pending.state = State::Pending;
        store.add(pending.clone()).expect("add");
        assert!(store.add(pending).is_err(), "no duplicates");
        assert!(store.activate("p").expect("activate"));
        assert!(!store.activate("p").expect("again"), "only a pending one");
        store.touch("p", 1500).expect("touch");
        assert!(store.withdraw("p", 1600).expect("withdraw"));
        assert!(!store.withdraw("p", 1700).expect("again"));
        let again = Delegations::open(path.clone()).expect("reopen");
        let kept = again.get("p").expect("kept");
        assert_eq!((kept.state, kept.withdrawn, kept.last_asked), (State::Active, Some(1600), Some(1500)));
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&path).expect("meta").permissions()) & 0o777,
            0o600
        );
        assert!(again.get("none").is_none());
    }

    #[test]
    fn a_withdrawn_pending_delegation_cannot_be_activated() {
        let dir = TestDir::new("delegations-w");
        let store = Delegations::open(dir.path().join("d.json")).expect("open");
        let mut pending = sample("p");
        pending.state = State::Pending;
        store.add(pending).expect("add");
        store.withdraw("p", 5).expect("withdraw");
        assert!(!store.activate("p").expect("activate"));
    }
}
