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

/// A person of the site file: the name and the four approval keys. **Nothing else**: whether the person is enabled and
/// which groups they are in come from `directory.json`, never from here.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersonFile {
    name: String,
    keys: KeysFile,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFile {
    name: String,
    key: String,
}

/// The site file. It carries neither `enabled` nor `members`, on any kind of site.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SiteFile {
    /// The version of the file's format: 1. An unknown one is refused.
    v: u32,
    persons: Vec<PersonFile>,
    hosts: Vec<HostFile>,
    /// The groups the site names: the keys `directory.json`'s `members` must have, no more and no fewer.
    #[serde(default)]
    groups: Vec<String>,
}

/// `directory.json`: who is active and who is in which group, from the model, a directory or a hosted provider. The
/// same on every kind of site.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryFile {
    v: u32,
    /// `model`, `freeipa` or `hosted-ldap`. Shown by `page status`; decides nothing.
    source: String,
    /// When the writer made it, UTC to the second. Shown; stage 2 does not age the file.
    as_of: String,
    active: Vec<String>,
    members: BTreeMap<String, Vec<String>>,
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
    /// In the site file **and** in `active` of `directory.json`. A person who is not active has no sign-in and no
    /// clearance, as `enabled: false` once meant.
    pub enabled: bool,
    /// The four keys (the site file's: every person of the file has them).
    pub keys: Option<PersonKeys>,
    /// The groups the person is in, from `members` of `directory.json`; offered to the person, they decide nothing.
    pub groups: Vec<String>,
}

/// Where the directory part of the broker's view came from, as `page status` shows it. It decides nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryInfo {
    /// `model`, `freeipa` or `hosted-ldap`.
    pub source: String,
    /// The writer's time, UTC to the second.
    pub as_of: String,
}

/// The broker's view of the site: the site file and `directory.json`, **together** (both or neither).
#[derive(Debug, Clone, Default)]
pub struct Site {
    persons: BTreeMap<String, Person>,
    hosts: BTreeMap<String, PublicKey>,
    /// Who is in which group, from `directory.json`: every group the site file names is a key.
    members: Option<BTreeMap<String, Vec<String>>>,
    directory: Option<DirectoryInfo>,
}

/// Why the pair of files was not used: which of the two, and why.
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("the site file: {0}")]
    Site(#[from] SiteError),
    #[error("directory.json: {0}")]
    Directory(#[from] DirectoryError),
}

/// Why `directory.json` was refused. The file the broker holds stands.
#[derive(Debug, Error)]
pub enum DirectoryError {
    #[error(transparent)]
    Settings(#[from] p_act::settings::SettingsError),
    #[error("it is version {0}, which this broker does not know")]
    Version(u32),
    #[error("`source` is `{}`, not one of model, freeipa, hosted-ldap", shown(.0))]
    Source(String),
    #[error("`as_of` is not a UTC time to the second: `{}`", shown(.0))]
    AsOf(String),
    #[error("`as_of` is more than 60 seconds ahead of the clock")]
    AsOfAhead,
    #[error("the site file names the group `{}` and `members` has no key for it", shown(.0))]
    GroupMissing(String),
    #[error("`members` has a key `{}` that is no group of the site file", shown(.0))]
    GroupUnknown(String),
    #[error("`{}` in {place} is not a person of the site file", shown(name))]
    UnknownName { place: &'static str, name: String },
    #[error("`{}` is repeated in {place}", shown(name))]
    Repeated { place: &'static str, name: String },
    #[error("`{}` is in `members` of `{}` and not in `active`", shown(name), shown(group))]
    NotActive { group: String, name: String },
}

fn key(what: &'static str, name: &str, line: &str) -> Result<PublicKey, SiteError> {
    PublicKey::parse(line).map_err(|source| SiteError::BadKey { what, name: name.to_owned(), source })
}

/// A name a standing may carry as a group's (and that the site file may name).
fn group_name_ok(name: &str) -> bool {
    let probe = StandingContent {
        to: "probe".to_owned(),
        nonce: [0; 32],
        n: 0,
        at: crate::core::stamp(std::time::SystemTime::UNIX_EPOCH),
        blocked: false,
        blocked_keys: Vec::new(),
        withdrawn: Vec::new(),
        certificates: Vec::new(),
        groups: vec![name.to_owned()],
    };
    Standing::compose(&probe).is_ok()
}

impl Site {
    /// Read the pair: the site file and `directory.json`, each with the usual file checks (`p_act::settings`: JSON,
    /// one object, an unknown member refused, nobody but the owner or root can write it). **Both or neither**: if
    /// either is refused there is no `Site`, and the caller keeps the one it holds. `now` judges `as_of`.
    pub fn read_pair(site: &Path, directory: &Path, now: std::time::SystemTime) -> Result<Site, LoadError> {
        let site_file: SiteFile = p_act::settings::read(site).map_err(SiteError::from)?;
        let directory_file: DirectoryFile = p_act::settings::read(directory).map_err(DirectoryError::from)?;
        Site::from_files(site_file, directory_file, now)
    }

    /// From the texts of the two files (tests, and the checks of `page load`).
    pub fn from_texts(site: &str, directory: &str, now: std::time::SystemTime) -> Result<Site, LoadError> {
        let site_file: SiteFile = p_act::settings::parse(site.as_bytes()).map_err(SiteError::from)?;
        let directory_file: DirectoryFile =
            p_act::settings::parse(directory.as_bytes()).map_err(DirectoryError::from)?;
        Site::from_files(site_file, directory_file, now)
    }

    /// Where `directory.json` is: beside the site file.
    #[must_use]
    pub fn directory_path(site: &Path) -> std::path::PathBuf {
        site.with_file_name("directory.json")
    }

    fn from_files(file: SiteFile, directory: DirectoryFile, now: std::time::SystemTime) -> Result<Site, LoadError> {
        let mut site = Site::from_site_file(file)?;
        site.apply_directory(directory, now)?;
        Ok(site)
    }

    fn from_site_file(file: SiteFile) -> Result<Site, SiteError> {
        if file.v != 1 {
            return Err(SiteError::Version(file.v));
        }
        let mut site = Site::default();
        for p in file.persons {
            if !valid_name(&p.name) {
                return Err(SiteError::BadName(p.name));
            }
            let k = p.keys;
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
            // One key under two names would make a confirmed approval of an automatic one (and a delegation of a
            // sign-in): the four are four different keys.
            let fingerprints: Vec<_> = [&parsed.confirmed, &parsed.automatic, &parsed.delegation, &parsed.connection]
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
            let person = Person { enabled: false, keys: Some(parsed), groups: Vec::new() };
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
        let mut groups = BTreeMap::new();
        for g in file.groups {
            // A group name is whatever a standing may carry as one.
            if !group_name_ok(&g) {
                return Err(SiteError::BadMembers { group: g, why: "not a group name".to_owned() });
            }
            if groups.insert(g.clone(), Vec::new()).is_some() {
                return Err(SiteError::Duplicate(g));
            }
        }
        site.members = Some(groups);
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

    /// Put `directory.json` over the site file: who is enabled, who is in which group. Every refusal leaves nothing
    /// half applied: the caller holds the old `Site` and this one is dropped.
    fn apply_directory(&mut self, d: DirectoryFile, now: std::time::SystemTime) -> Result<(), DirectoryError> {
        if d.v != 1 {
            return Err(DirectoryError::Version(d.v));
        }
        if !matches!(d.source.as_str(), "model" | "freeipa" | "hosted-ldap") {
            return Err(DirectoryError::Source(d.source));
        }
        let as_of: p_act::Timestamp = d.as_of.parse().map_err(|_| DirectoryError::AsOf(d.as_of.clone()))?;
        let ahead = as_of.unix()
            - i64::try_from(now.duration_since(std::time::UNIX_EPOCH).map_or(0, |t| t.as_secs())).unwrap_or(0);
        if ahead > 60 {
            return Err(DirectoryError::AsOfAhead);
        }
        // `active`: persons of the site file, each once.
        let mut active = std::collections::BTreeSet::new();
        for name in &d.active {
            if !self.persons.contains_key(name) {
                return Err(DirectoryError::UnknownName { place: "`active`", name: name.clone() });
            }
            if !active.insert(name.as_str()) {
                return Err(DirectoryError::Repeated { place: "`active`", name: name.clone() });
            }
        }
        // `members`: exactly the groups the site file names; persons of the file, each once per group, all active.
        let named: Vec<String> = self.members.iter().flat_map(|m| m.keys().cloned()).collect();
        for group in &named {
            if !d.members.contains_key(group) {
                return Err(DirectoryError::GroupMissing(group.clone()));
            }
        }
        let mut members = BTreeMap::new();
        for (group, logins) in &d.members {
            if !named.contains(group) {
                return Err(DirectoryError::GroupUnknown(group.clone()));
            }
            let mut seen = std::collections::BTreeSet::new();
            for login in logins {
                if !self.persons.contains_key(login) {
                    return Err(DirectoryError::UnknownName { place: "`members`", name: login.clone() });
                }
                if !seen.insert(login.as_str()) {
                    return Err(DirectoryError::Repeated { place: "`members`", name: login.clone() });
                }
                if !active.contains(login.as_str()) {
                    return Err(DirectoryError::NotActive { group: group.clone(), name: login.clone() });
                }
            }
            let mut logins = logins.clone();
            logins.sort_unstable();
            members.insert(group.clone(), logins);
        }
        for (name, person) in &mut self.persons {
            person.enabled = active.contains(name.as_str());
            person.groups = members.iter().filter(|(_, l)| l.contains(name)).map(|(g, _)| g.clone()).collect();
        }
        self.members = Some(members);
        self.directory = Some(DirectoryInfo { source: d.source, as_of: d.as_of });
        Ok(())
    }

    /// Where the directory part came from and when it was made, as `page status` shows it.
    #[must_use]
    pub fn directory(&self) -> Option<&DirectoryInfo> {
        self.directory.as_ref()
    }

    /// Who is in which group: every group the site file names is a key (possibly with nobody).
    #[must_use]
    pub fn members(&self) -> Option<&BTreeMap<String, Vec<String>>> {
        self.members.as_ref()
    }

    /// Whether `person` is in `group` (R10).
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
