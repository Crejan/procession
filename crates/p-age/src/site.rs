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
    /// group -> names. A key repeated is refused by the reader (`p_act::settings`, which uses `p_ermit::json`).
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

/// What the two files say that the other does not know. Each only **restricts** (the broker decides from the
/// intersection), so nothing here is a refusal; it is shown, so that a writer's fault is not hidden by the tolerance.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Mismatch {
    /// Names in `active` or under `members` that are no person of the site file: ignored.
    pub names_not_in_site: Vec<String>,
    /// Keys of `members` that are no group of the site file: ignored.
    pub groups_not_in_site: Vec<String>,
    /// Groups of the site file that have no key in `members`: treated as empty.
    pub groups_without_members: Vec<String>,
}

impl Mismatch {
    /// Whether the two files agree on every name.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names_not_in_site.is_empty()
            && self.groups_not_in_site.is_empty()
            && self.groups_without_members.is_empty()
    }
}

/// The site file, checked **on its own**: persons with their four keys, hosts, the groups the site names.
#[derive(Debug, Clone, Default)]
pub struct SiteBase {
    persons: BTreeMap<String, PersonKeysRow>,
    hosts: BTreeMap<String, PublicKey>,
    groups: std::collections::BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct PersonKeysRow(PersonKeys);

/// `directory.json`, checked **on its own**: it contradicts neither itself nor its form. It says nothing of the site
/// file, which it is never refused for.
#[derive(Debug, Clone)]
pub struct Directory {
    info: DirectoryInfo,
    active: std::collections::BTreeSet<String>,
    members: BTreeMap<String, Vec<String>>,
}

/// The broker's view of the site: the site file and `directory.json` **intersected** at load.
#[derive(Debug, Clone, Default)]
pub struct Site {
    persons: BTreeMap<String, Person>,
    hosts: BTreeMap<String, PublicKey>,
    /// Who is in which group: every group the site file names is a key, with the names under it that are enabled
    /// persons (so a group `directory.json` does not know is empty).
    members: Option<BTreeMap<String, Vec<String>>>,
    directory: Option<DirectoryInfo>,
    mismatch: Mismatch,
    /// Why there is no `directory.json` in this view (missing, or refused on its own), if that is so.
    directory_problem: Option<String>,
}

/// Why a file was not used: which of the two, and why.
#[derive(Debug, Error)]
pub enum LoadError {
    #[error("the site file: {0}")]
    Site(#[from] SiteError),
    #[error("directory.json: {0}")]
    Directory(#[from] DirectoryError),
}

/// Why `directory.json` was refused: it contradicts itself or its form. The file the broker holds stands.
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
    #[error("`{}` in {place} is not a name the character rules take", shown(name))]
    BadName { place: &'static str, name: String },
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

impl SiteBase {
    /// Read the site file with the usual file checks (`p_act::settings`). Refused whole on its own faults.
    pub fn read(path: &Path) -> Result<SiteBase, SiteError> {
        SiteBase::from_file(p_act::settings::read(path)?)
    }

    /// From the text of the file.
    pub fn from_text(text: &str) -> Result<SiteBase, SiteError> {
        SiteBase::from_file(p_act::settings::parse(text.as_bytes())?)
    }

    fn from_file(file: SiteFile) -> Result<SiteBase, SiteError> {
        if file.v != 1 {
            return Err(SiteError::Version(file.v));
        }
        let mut base = SiteBase::default();
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
            if base.persons.insert(p.name.clone(), PersonKeysRow(parsed)).is_some() {
                return Err(SiteError::Duplicate(p.name));
            }
        }
        for h in file.hosts {
            if !valid_name(&h.name) {
                return Err(SiteError::BadName(h.name));
            }
            let k = key("host key", &h.name, &h.key)?;
            if base.hosts.insert(h.name.clone(), k).is_some() {
                return Err(SiteError::Duplicate(h.name));
            }
        }
        for g in file.groups {
            // A group name is whatever a standing may carry as one.
            if !group_name_ok(&g) {
                return Err(SiteError::BadMembers { group: g, why: "not a group name".to_owned() });
            }
            if !base.groups.insert(g.clone()) {
                return Err(SiteError::Duplicate(g));
            }
        }
        // No key is another person's, and none is a host's.
        let mut seen: BTreeMap<String, String> = BTreeMap::new();
        for (name, row) in &base.persons {
            let keys = &row.0;
            for k in [&keys.confirmed, &keys.automatic, &keys.delegation, &keys.connection] {
                if let Some(other) = seen.insert(k.fingerprint().to_string(), name.clone()) {
                    return Err(SiteError::KeysClash { name: name.clone(), why: format!("a key is also `{other}`'s") });
                }
            }
        }
        for (host, k) in &base.hosts {
            if let Some(owner) = seen.get(&k.fingerprint().to_string()) {
                return Err(SiteError::KeysClash {
                    name: owner.clone(),
                    why: format!("a key is also host `{host}`'s"),
                });
            }
        }
        Ok(base)
    }
}

impl Directory {
    /// Read `directory.json` with the usual file checks. `now` judges `as_of`.
    pub fn read(path: &Path, now: std::time::SystemTime) -> Result<Directory, DirectoryError> {
        Directory::from_file(p_act::settings::read(path)?, now)
    }

    /// From the text of the file.
    pub fn from_text(text: &str, now: std::time::SystemTime) -> Result<Directory, DirectoryError> {
        Directory::from_file(p_act::settings::parse(text.as_bytes())?, now)
    }

    /// The checks a file makes **on its own**: its version and form, its names under the character rules, no name
    /// twice in a list, and every member of a group active. Nothing about the site file.
    fn from_file(d: DirectoryFile, now: std::time::SystemTime) -> Result<Directory, DirectoryError> {
        if d.v != 1 {
            return Err(DirectoryError::Version(d.v));
        }
        if !matches!(d.source.as_str(), "model" | "freeipa" | "hosted-ldap") {
            return Err(DirectoryError::Source(d.source));
        }
        let as_of: p_act::Timestamp = d.as_of.parse().map_err(|_| DirectoryError::AsOf(d.as_of.clone()))?;
        let now_secs = i64::try_from(now.duration_since(std::time::UNIX_EPOCH).map_or(0, |t| t.as_secs())).unwrap_or(0);
        if as_of.unix() - now_secs > 60 {
            return Err(DirectoryError::AsOfAhead);
        }
        let mut active = std::collections::BTreeSet::new();
        for name in d.active {
            if !valid_name(&name) {
                return Err(DirectoryError::BadName { place: "`active`", name });
            }
            if !active.insert(name.clone()) {
                return Err(DirectoryError::Repeated { place: "`active`", name });
            }
        }
        let mut members = BTreeMap::new();
        for (group, logins) in d.members {
            if !group_name_ok(&group) {
                return Err(DirectoryError::BadName { place: "the keys of `members`", name: group });
            }
            let mut seen = std::collections::BTreeSet::new();
            for login in &logins {
                if !valid_name(login) {
                    return Err(DirectoryError::BadName { place: "`members`", name: login.clone() });
                }
                if !seen.insert(login.as_str()) {
                    return Err(DirectoryError::Repeated { place: "`members`", name: login.clone() });
                }
                if !active.contains(login) {
                    return Err(DirectoryError::NotActive { group: group.clone(), name: login.clone() });
                }
            }
            let mut logins = logins;
            logins.sort_unstable();
            members.insert(group, logins);
        }
        Ok(Directory { info: DirectoryInfo { source: d.source, as_of: d.as_of }, active, members })
    }
}

impl Site {
    /// Where `directory.json` is: beside the site file.
    #[must_use]
    pub fn directory_path(site: &Path) -> std::path::PathBuf {
        site.with_file_name("directory.json")
    }

    /// The view **at start**: the site file is required (refused or missing, there is no broker). `directory.json` is
    /// not: without a valid one nobody is active, the broker starts, and `page status` says why. That only restricts:
    /// no sign-in and no clearance for anyone until a good file arrives.
    pub fn load(site: &Path, directory: &Path, now: std::time::SystemTime) -> Result<Site, SiteError> {
        let base = SiteBase::read(site)?;
        Ok(match Directory::read(directory, now) {
            Ok(d) => Site::combine(&base, Some(&d)),
            Err(e) => {
                let mut view = Site::combine(&base, None);
                view.directory_problem = Some(shown(&format!("directory.json: {e}")));
                view
            }
        })
    }

    /// Both files from their texts, each refused on its own faults (tests, and the checks of `page load`).
    pub fn from_texts(site: &str, directory: &str, now: std::time::SystemTime) -> Result<Site, LoadError> {
        let base = SiteBase::from_text(site)?;
        let d = Directory::from_text(directory, now)?;
        Ok(Site::combine(&base, Some(&d)))
    }

    /// The **intersection**, computed at load. A person is enabled if the site file has the row and `active` has the
    /// name; a group's members are the names under its key that are enabled persons; a name that is no person of the
    /// site file, and a key of `members` that is no group of the site file, are ignored; a group of the site file with
    /// no key in `members` is empty. Each only restricts, so no order of arrival admits what neither file admits.
    #[must_use]
    pub fn combine(base: &SiteBase, directory: Option<&Directory>) -> Site {
        let mut mismatch = Mismatch::default();
        let mut persons: BTreeMap<String, Person> = base
            .persons
            .iter()
            .map(|(n, k)| (n.clone(), Person { enabled: false, keys: Some(k.0.clone()), groups: Vec::new() }))
            .collect();
        let mut members: BTreeMap<String, Vec<String>> = base.groups.iter().map(|g| (g.clone(), Vec::new())).collect();
        if let Some(d) = directory {
            let mut strangers = std::collections::BTreeSet::new();
            for name in &d.active {
                match persons.get_mut(name) {
                    Some(p) => p.enabled = true,
                    None => {
                        strangers.insert(name.clone());
                    }
                }
            }
            for (group, logins) in &d.members {
                let Some(slot) = members.get_mut(group) else {
                    mismatch.groups_not_in_site.push(group.clone());
                    continue;
                };
                for login in logins {
                    match persons.get(login) {
                        Some(p) if p.enabled => slot.push(login.clone()),
                        Some(_) => {}
                        None => {
                            strangers.insert(login.clone());
                        }
                    }
                }
            }
            mismatch.names_not_in_site = strangers.into_iter().collect();
            mismatch.groups_without_members =
                base.groups.iter().filter(|g| !d.members.contains_key(*g)).cloned().collect();
        }
        for (name, person) in &mut persons {
            person.groups = members.iter().filter(|(_, l)| l.contains(name)).map(|(g, _)| g.clone()).collect();
        }
        Site {
            persons,
            hosts: base.hosts.clone(),
            members: Some(members),
            directory: directory.map(|d| d.info.clone()),
            mismatch,
            directory_problem: None,
        }
    }

    /// Where the directory part came from and when it was made, as `page status` shows it.
    #[must_use]
    pub fn directory(&self) -> Option<&DirectoryInfo> {
        self.directory.as_ref()
    }

    /// What the two files say that the other does not know.
    #[must_use]
    pub fn mismatch(&self) -> &Mismatch {
        &self.mismatch
    }

    /// Why this view has no `directory.json`, if it has none.
    #[must_use]
    pub fn directory_problem(&self) -> Option<&str> {
        self.directory_problem.as_deref()
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
