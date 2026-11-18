//! What the broker knows about the site: persons with their keys, hosts with
//! theirs, and the broker's own settings. Read from files in stage 2; from the
//! site's data (`page load`) in stage 3. The broker holds a copy and makes no
//! rule of it.

use std::collections::BTreeMap;
use std::path::Path;

use p_act::broker::{Standing, StandingContent};
use p_act::sign::{PublicKey, SignError};
use serde::Deserialize;
use thiserror::Error;

use crate::util::{shown, shown_error};

/// Why the site file was refused.
#[derive(Debug, Error)]
pub enum SiteError {
    #[error(transparent)]
    Settings(#[from] p_act::settings::SettingsError),
    #[error("the groups of `{}` are not what a standing may carry: {source}", shown(name))]
    BadStanding { name: String, source: p_act::ParseError },
    #[error("`{}` is not a name ([A-Za-z0-9._-]+, at most 64 characters)", shown(.0))]
    BadName(String),
    #[error("{what} of `{}`: {}", shown(name), shown_error(source))]
    BadKey { what: &'static str, name: String, source: SignError },
    #[error("`{}` appears twice", shown(.0))]
    Duplicate(String),
    #[error("the site file is version {0}, which this broker does not know")]
    Version(u32),
    #[error("members of group `{}`: {}", shown(group), shown(why))]
    BadMembers { group: String, why: String },
    #[error("`verified_on` of `{}` is not a date (YYYY-MM-DD): {}", shown(name), shown(value))]
    BadDate { name: String, value: String },
    #[error("`{}` is not enabled and has keys: the view the broker is given has none for a person who is not enabled", shown(.0))]
    KeysOnDisabled(String),
    #[error("`{}`'s keys: {}", shown(name), shown(why))]
    KeysClash { name: String, why: String },
}

/// A person's name or a host's name: `[A-Za-z0-9._-]+`, at most 64 characters.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// One of a person's four keys, as the fundament note has the row: `{key, verified_on?}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRow {
    key: String,
    /// A calendar date, `YYYY-MM-DD`. Checked for its shape and not used.
    #[serde(default)]
    verified_on: Option<String>,
}

/// The four keys, as one object with exactly these members: a partial set is refused (by `serde`: a member is
/// missing).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeysFile {
    confirmed: KeyRow,
    automatic: KeyRow,
    delegation: KeyRow,
    connection: KeyRow,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersonFile {
    name: String,
    enabled: bool,
    /// The person's four keys. Absent for a person who has no approval keys at all (they can neither sign in nor
    /// approve); never partial, and never on a person who is not enabled (the view the broker is given has none).
    #[serde(default)]
    keys: Option<KeysFile>,
    /// The names of the person's groups, to be offered to the person; they decide nothing.
    #[serde(default)]
    groups: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFile {
    name: String,
    key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteFile {
    /// The version of the file's format: 1. An unknown one is refused.
    v: u32,
    persons: Vec<PersonFile>,
    hosts: Vec<HostFile>,
    /// Who is in which group: group -> logins. **Absent is not empty**: absent means the members are the
    /// directory's, to come from the sync job; `{}` means nobody is in any group. `null` is refused, so that the
    /// two cannot be confused by a writer.
    #[serde(default, deserialize_with = "present")]
    members: Option<BTreeMap<String, Vec<String>>>,
}

/// A member that is there is read as what it is; one that is not there stays `None`. `null` is an error (it would
/// otherwise read as absent).
fn present<'de, D, T>(d: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    T::deserialize(d).map(Some)
}

/// A person's four keys: the purposes are a closed vocabulary, each exactly once, and four different keys.
#[derive(Debug, Clone)]
pub struct PersonKeys {
    /// Signs approvals the person was asked for.
    pub confirmed: PublicKey,
    /// Signs approvals in mode `automatic`.
    pub automatic: PublicKey,
    /// What the person's delegations are certified by.
    pub delegation: PublicKey,
    /// What pledge signs in with.
    pub connection: PublicKey,
}

/// A person of the site.
#[derive(Debug, Clone)]
pub struct Person {
    /// `enabled` in the site project.
    pub enabled: bool,
    /// The four keys, if the person has any.
    pub keys: Option<PersonKeys>,
    pub groups: Vec<String>,
}

/// The site's persons and hosts.
#[derive(Debug, Clone, Default)]
pub struct Site {
    persons: BTreeMap<String, Person>,
    hosts: BTreeMap<String, PublicKey>,
    /// Who is in which group, in **three states**: `None` (the file has no `members`: the directory's, to come from
    /// the sync job), `Some` of an empty map (nobody is in any group) and `Some` of groups with logins.
    members: Option<BTreeMap<String, Vec<String>>>,
}

fn key(what: &'static str, name: &str, line: &str) -> Result<PublicKey, SiteError> {
    PublicKey::parse(line).map_err(|source| SiteError::BadKey { what, name: name.to_owned(), source })
}

impl Site {
    /// Read the site file: JSON, one object, an unknown member refused, the file refused if anyone but its owner or
    /// root can write it (`p_act::settings`). `{"v":1,"persons":[{"name","enabled","keys":{"confirmed":{"key"},"automatic":…,
    /// "delegation":…,"connection":…}}],"hosts":[{"name","key"}]}`.
    pub fn read(path: &Path) -> Result<Site, SiteError> {
        Site::from_file(p_act::settings::read(path)?)
    }

    /// From JSON text, for tests.
    pub fn from_json(text: &str) -> Result<Site, SiteError> {
        Site::from_file(p_act::settings::parse(text.as_bytes())?)
    }

    fn from_file(file: SiteFile) -> Result<Site, SiteError> {
        if file.v != 1 {
            return Err(SiteError::Version(file.v));
        }
        let mut site = Site::default();
        for p in file.persons {
            if !valid_name(&p.name) {
                return Err(SiteError::BadName(p.name));
            }
            // What is carried to pledge is a set: sorted, each entry once. Whatever a standing may not carry is refused
            // here, when the file is read, and not when a pledge signs in.
            let sorted = |mut v: Vec<String>| {
                v.sort_unstable();
                v.dedup();
                v
            };
            let groups = sorted(p.groups);
            let probe = StandingContent {
                to: p.name.clone(),
                nonce: [0; 32],
                n: 0,
                at: crate::core::stamp(std::time::SystemTime::UNIX_EPOCH),
                blocked: false,
                blocked_keys: Vec::new(),
                withdrawn: Vec::new(),
                certificates: Vec::new(),
                groups: groups.clone(),
            };
            Standing::compose(&probe).map_err(|source| SiteError::BadStanding { name: p.name.clone(), source })?;
            let keys = match p.keys {
                None => None,
                Some(_) if !p.enabled => return Err(SiteError::KeysOnDisabled(p.name)),
                Some(k) => {
                    for row in [&k.confirmed, &k.automatic, &k.delegation, &k.connection] {
                        if let Some(date) = &row.verified_on
                            && !is_date(date)
                        {
                            return Err(SiteError::BadDate { name: p.name, value: date.clone() });
                        }
                    }
                    let parsed = PersonKeys {
                        confirmed: key("confirmed key", &p.name, &k.confirmed.key)?,
                        automatic: key("automatic key", &p.name, &k.automatic.key)?,
                        delegation: key("delegation key", &p.name, &k.delegation.key)?,
                        connection: key("connection key", &p.name, &k.connection.key)?,
                    };
                    // One key under two names would make a confirmed approval of an automatic one (and a
                    // delegation of a sign-in): the four are four different keys.
                    let fingerprints: Vec<_> =
                        [&parsed.confirmed, &parsed.automatic, &parsed.delegation, &parsed.connection]
                            .iter()
                            .map(|k| k.fingerprint())
                            .collect();
                    for (i, a) in fingerprints.iter().enumerate() {
                        if fingerprints[i + 1..].contains(a) {
                            return Err(SiteError::KeysClash {
                                name: p.name,
                                why: "two of the four are the same key".to_owned(),
                            });
                        }
                    }
                    Some(parsed)
                }
            };
            let person = Person { enabled: p.enabled, keys, groups };
            if site.persons.insert(p.name.clone(), person).is_some() {
                return Err(SiteError::Duplicate(p.name));
            }
        }
        for h in file.hosts {
            if !valid_name(&h.name) {
                return Err(SiteError::BadName(h.name));
            }
            let k = key("host key", &h.name, &h.key)?;
            if site.hosts.insert(h.name.clone(), k).is_some() {
                return Err(SiteError::Duplicate(h.name));
            }
        }
        if let Some(members) = file.members {
            let mut checked = BTreeMap::new();
            for (group, logins) in members {
                let bad = |why: &str| SiteError::BadMembers { group: group.clone(), why: why.to_owned() };
                // A group name is whatever a standing may carry as one, and a member is a person of the file.
                let probe = StandingContent {
                    to: "probe".to_owned(),
                    nonce: [0; 32],
                    n: 0,
                    at: crate::core::stamp(std::time::SystemTime::UNIX_EPOCH),
                    blocked: false,
                    blocked_keys: Vec::new(),
                    withdrawn: Vec::new(),
                    certificates: Vec::new(),
                    groups: vec![group.clone()],
                };
                Standing::compose(&probe).map_err(|_| bad("not a group name"))?;
                let mut logins = logins;
                logins.sort_unstable();
                logins.dedup();
                if let Some(unknown) = logins.iter().find(|l| !site.persons.contains_key(*l)) {
                    return Err(bad(&format!("`{unknown}` is not a person of the file")));
                }
                checked.insert(group, logins);
            }
            site.members = Some(checked);
        }
        // No key is another person's, and none is a host's.
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        for (name, person) in &site.persons {
            for fp in person.key_fingerprints() {
                if let Some(other) = seen.insert(fp.to_string(), name.clone()) {
                    return Err(SiteError::KeysClash { name: name.clone(), why: format!("a key is also `{other}`'s") });
                }
            }
        }
        for (host, k) in &site.hosts {
            if let Some(owner) = seen.get(&k.fingerprint().to_string()) {
                return Err(SiteError::KeysClash {
                    name: owner.clone(),
                    why: format!("a key is also host `{host}`'s"),
                });
            }
        }
        Ok(site)
    }

    /// Who is in which group, if the file says: `None` is **absent** (the directory's, from the sync job), `Some` of an
    /// empty map is **nobody in any group**. They are never the same.
    #[must_use]
    pub fn members(&self) -> Option<&BTreeMap<String, Vec<String>>> {
        self.members.as_ref()
    }

    /// Whether `person` is in `group`. **No when the file has no `members` part** (and no sync result exists yet):
    /// a broker that does not know who is in a group answers no (R10).
    #[must_use]
    pub fn in_group(&self, person: &str, group: &str) -> bool {
        self.members.as_ref().and_then(|m| m.get(group)).is_some_and(|logins| logins.iter().any(|l| l == person))
    }

    /// Every person's name.
    pub fn person_names(&self) -> impl Iterator<Item = &str> {
        self.persons.keys().map(String::as_str)
    }

    /// The person whose key this is (connection, delegation or an approval key), if the site file says.
    #[must_use]
    pub fn owner_of_key(&self, fingerprint: &str) -> Option<&str> {
        self.persons
            .iter()
            .find(|(_, p)| p.key_fingerprints().iter().any(|f| f.as_str() == fingerprint))
            .map(|(n, _)| n.as_str())
    }

    #[must_use]
    pub fn person(&self, name: &str) -> Option<&Person> {
        self.persons.get(name)
    }

    /// The public key of a host, which certifies its services' keys.
    #[must_use]
    pub fn host_key(&self, host: &str) -> Option<&PublicKey> {
        self.hosts.get(host)
    }
}

impl Person {
    /// The fingerprints of the person's keys: the four, or none.
    #[must_use]
    pub fn key_fingerprints(&self) -> Vec<p_act::sign::Fingerprint> {
        self.keys
            .iter()
            .flat_map(|k| [&k.confirmed, &k.automatic, &k.delegation, &k.connection])
            .map(PublicKey::fingerprint)
            .collect()
    }

    /// What pledge signs in with, if the person has keys.
    #[must_use]
    pub fn connection_key(&self) -> Option<&PublicKey> {
        self.keys.as_ref().map(|k| &k.connection)
    }

    /// What the person's delegations are certified by, if the person has keys.
    #[must_use]
    pub fn delegation_key(&self) -> Option<&PublicKey> {
        self.keys.as_ref().map(|k| &k.delegation)
    }
}

/// A calendar date as `YYYY-MM-DD`: the shape and the ranges of month and day (not the month's length).
fn is_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && b.iter().enumerate().all(|(i, c)| matches!(i, 4 | 7) || c.is_ascii_digit())
        && (1..=12).contains(&s[5..7].parse::<u8>().unwrap_or(0))
        && (1..=31).contains(&s[8..10].parse::<u8>().unwrap_or(0))
}
