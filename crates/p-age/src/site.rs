//! What the broker knows about the site: persons with their keys, hosts with
//! theirs, and the broker's own settings. Read from files in stage 2; from the
//! site's data (`page load`) in stage 3. The broker holds a copy and makes no
//! rule of it.

use std::collections::BTreeMap;
use std::path::Path;

use p_act::sign::{PublicKey, SignError};
use serde::Deserialize;
use thiserror::Error;

/// Why the site file was refused.
#[derive(Debug, Error)]
pub enum SiteError {
    #[error("cannot read {path}: {source}")]
    Read { path: String, source: std::io::Error },
    #[error("{path} is not a site file: {source}")]
    Parse { path: String, source: serde_json::Error },
    #[error("`{0}` is not a name ([A-Za-z0-9._-]+, at most 64 characters)")]
    BadName(String),
    #[error("{what} of `{name}`: {source}")]
    BadKey { what: &'static str, name: String, source: SignError },
    #[error("`{0}` appears twice")]
    Duplicate(String),
    #[error(transparent)]
    Perm(#[from] crate::perm::PermError),
}

/// A person's name or a host's name: `[A-Za-z0-9._-]+`, at most 64 characters.
#[must_use]
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersonFile {
    name: String,
    enabled: bool,
    connection_key: String,
    delegation_key: String,
    /// Certificates of the person's approval keys as the issuer made them, to be carried to pledge.
    #[serde(default)]
    certificates: Vec<String>,
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
    persons: Vec<PersonFile>,
    hosts: Vec<HostFile>,
}

/// A person of the site.
#[derive(Debug, Clone)]
pub struct Person {
    /// `enabled` in the site project.
    pub enabled: bool,
    /// What pledge signs in with.
    pub connection_key: PublicKey,
    /// What the person's delegations are certified by.
    pub delegation_key: PublicKey,
    pub certificates: Vec<String>,
    pub groups: Vec<String>,
}

/// The site's persons and hosts.
#[derive(Debug, Clone, Default)]
pub struct Site {
    persons: BTreeMap<String, Person>,
    hosts: BTreeMap<String, PublicKey>,
}

fn key(what: &'static str, name: &str, line: &str) -> Result<PublicKey, SiteError> {
    PublicKey::parse(line).map_err(|source| SiteError::BadKey { what, name: name.to_owned(), source })
}

impl Site {
    /// Read the site file (JSON): `{"persons":[{"name","enabled","connection_key","delegation_key"}],"hosts":[{"name","key"}]}`.
    pub fn read(path: &Path) -> Result<Site, SiteError> {
        let shown = path.display().to_string();
        crate::perm::check_config_file(path)?;
        let text = std::fs::read(path).map_err(|source| SiteError::Read { path: shown.clone(), source })?;
        let file: SiteFile =
            serde_json::from_slice(&text).map_err(|source| SiteError::Parse { path: shown, source })?;
        Site::from_file(file)
    }

    /// From JSON text, for tests and for `read`.
    pub fn from_json(text: &str) -> Result<Site, SiteError> {
        let file: SiteFile =
            serde_json::from_str(text).map_err(|source| SiteError::Parse { path: "<text>".to_owned(), source })?;
        Site::from_file(file)
    }

    fn from_file(file: SiteFile) -> Result<Site, SiteError> {
        let mut site = Site::default();
        for p in file.persons {
            if !valid_name(&p.name) {
                return Err(SiteError::BadName(p.name));
            }
            let person = Person {
                enabled: p.enabled,
                connection_key: key("connection key", &p.name, &p.connection_key)?,
                delegation_key: key("delegation key", &p.name, &p.delegation_key)?,
                certificates: p.certificates,
                groups: p.groups,
            };
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
        Ok(site)
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
