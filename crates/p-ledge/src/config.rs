//! What the person tells pledge about the world around it: `config.json` in
//! the state directory. In stage 1 (one machine, no broker, no site) this is
//! where pledge learns who the person is, which host key certifies the
//! services' keys, and where the agents reach their services.
//!
//! Every member is optional; without `person` no delegation can be issued, and
//! without the host a service's request is refused.

use std::path::Path;

use p_act::sign::PublicKey;
use serde::Deserialize;

use crate::error::{Error, Result};

/// Calls an agent may have waiting at once, by default (`doc/approvals.md`, section 7).
pub const DEFAULT_MAX_WAITING: usize = 5;
/// The call deadline an agent is told to use, by default, in seconds.
pub const DEFAULT_DEADLINE_SECONDS: u32 = 120;

/// A host and the key that certifies its services' keys.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEntry {
    /// The host's name, as a call names it.
    pub host: String,
    /// The host's public key line.
    pub key: String,
}

/// Where an agent reaches a service.
#[derive(Debug, Clone, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceEntry {
    /// The host's name, as a call names it.
    pub host: String,
    /// The service's name.
    pub name: String,
    /// `http` or `https`, no credentials.
    pub url: String,
}

/// The configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Who this pledge is for.
    #[serde(default)]
    pub person: Option<String>,
    /// The hosts pledge knows, with their keys.
    #[serde(default)]
    pub hosts: Vec<HostEntry>,
    /// The services an agent started here may reach.
    #[serde(default)]
    pub services: Vec<ServiceEntry>,
    /// The TLS root for `https` services, a PEM certificate.
    #[serde(default)]
    pub tls_root: Option<String>,
    /// The deadline an agent is told to give its calls.
    #[serde(default)]
    pub deadline_seconds: Option<u32>,
    /// Requests of one agent that may wait at once.
    #[serde(default)]
    pub max_waiting: Option<usize>,
    /// A group (of the operating system) that may use `service.sock`.
    #[serde(default)]
    pub service_group: Option<String>,
}

/// Whether `name` is a person's or host's name: `[A-Za-z0-9._-]+`, at most 64.
#[must_use]
pub fn is_name(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

impl Config {
    /// Reads `path`; a missing file is the empty configuration.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupt`] if the file does not parse or a member is not valid.
    pub fn load(path: &Path) -> Result<Self> {
        // One reader for the shared settings rules (`p_act::settings`): a regular file, owned by root or the
        // running user, not writable by others, one JSON object, no member twice, no trailing text, no byte
        // order mark, at most 1 MiB. Unknown members are refused by `deny_unknown_fields` on these types.
        let config: Self = match p_act::settings::read(path) {
            Ok(config) => config,
            Err(p_act::settings::SettingsError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(e) => return Err(Error::Corrupt { path: path.to_owned(), problem: e.to_string() }),
        };
        config.check().map_err(|problem| Error::Corrupt { path: path.to_owned(), problem })?;
        Ok(config)
    }

    fn check(&self) -> std::result::Result<(), String> {
        if self.person.as_deref().is_some_and(|p| !is_name(p)) {
            return Err("person is not a name ([A-Za-z0-9._-], at most 64)".into());
        }
        for host in &self.hosts {
            if !is_name(&host.host) {
                return Err(format!("host {:?} is not a name", host.host));
            }
            PublicKey::parse(&host.key).map_err(|e| format!("the key of host {}: {e}", host.host))?;
        }
        for service in &self.services {
            if !is_name(&service.host) || service.name.is_empty() {
                return Err(format!("service {}/{} is not valid", service.host, service.name));
            }
            let rest = service.url.strip_prefix("http://").or_else(|| service.url.strip_prefix("https://"));
            if rest.is_none_or(|rest| {
                rest.is_empty() || rest.split('/').next().is_some_and(|authority| authority.contains('@'))
            }) {
                return Err(format!(
                    "the url of {}/{} must be http or https without credentials",
                    service.host, service.name
                ));
            }
        }
        if self
            .deadline_seconds
            .is_some_and(|d| !(1..=p_act::limits::MAX_DEADLINE_AHEAD_SECONDS).contains(&i64::from(d)))
        {
            return Err(format!("deadline_seconds must be 1 to {}", p_act::limits::MAX_DEADLINE_AHEAD_SECONDS));
        }
        if self.max_waiting == Some(0) {
            return Err("max_waiting must be at least 1".into());
        }
        Ok(())
    }

    /// The key of `host`, if pledge knows it.
    #[must_use]
    pub fn host_key(&self, host: &str) -> Option<PublicKey> {
        let entry = self.hosts.iter().find(|entry| entry.host == host)?;
        PublicKey::parse(&entry.key).ok()
    }

    /// Requests of one agent that may wait.
    #[must_use]
    pub fn max_waiting(&self) -> usize {
        self.max_waiting.unwrap_or(DEFAULT_MAX_WAITING)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::testing::TestDir;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINrrY2cYwa0G4rWvXYKuvNuJfJTwXhBsGMjR8XF5SU9N";

    fn load(text: &str) -> Result<Config> {
        let dir = TestDir::new("config");
        let path = dir.path().join("config.json");
        fs::write(&path, text).expect("write");
        Config::load(&path)
    }

    #[test]
    fn a_missing_file_is_the_empty_configuration() {
        let dir = TestDir::new("config-none");
        let config = Config::load(&dir.path().join("none.json")).expect("loads");
        assert!(config.person.is_none() && config.hosts.is_empty());
        assert_eq!(config.max_waiting(), 5);
        assert!(config.host_key("a.example").is_none());
    }

    #[test]
    fn a_full_configuration_loads_and_finds_the_host_key() {
        let config = load(&format!(
            r#"{{"person":"jan","hosts":[{{"host":"a.example","key":"{KEY}"}}],"services":[{{"host":"a.example","name":"probe","url":"http://127.0.0.1:8443/mcp"}}],"deadline_seconds":120,"max_waiting":3}}"#
        ))
        .expect("loads");
        assert_eq!(config.person.as_deref(), Some("jan"));
        assert!(config.host_key("a.example").is_some());
        assert_eq!(config.max_waiting(), 3);
    }

    #[test]
    fn a_file_others_can_write_is_refused_and_one_object_is_required() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new("config-mode");
        let path = dir.path().join("config.json");
        fs::write(&path, r#"{"person":"jan"}"#).expect("write");
        for (mode, ok) in [(0o600, true), (0o644, true), (0o664, false), (0o646, false), (0o666, false), (0o620, false)]
        {
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");
            assert_eq!(Config::load(&path).is_ok(), ok, "mode {mode:o}");
        }
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
        for text in [
            "[]",
            r#"[{"person":"jan"}]"#,
            "\"jan\"",
            r#"{"person":"jan"} {"person":"bob"}"#,
            "{\"person\":\"jan\"} // comment",
            "// c\n{}",
        ] {
            fs::write(&path, text).expect("write");
            assert!(matches!(Config::load(&path), Err(Error::Corrupt { .. })), "{text}");
        }
    }

    #[test]
    fn what_the_shared_reader_refuses_that_was_read_before() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new("config-shared");
        let path = dir.path().join("config.json");
        let big = format!(r#"{{"person":"jan","tls_root":"{}"}}"#, "x".repeat(1024 * 1024));
        for (what, bytes) in [
            ("a member twice", br#"{"person":"jan","person":"bob"}"#.to_vec()),
            ("a byte order mark", b"\xEF\xBB\xBF{}".to_vec()),
            ("more than 1 MiB", big.into_bytes()),
        ] {
            fs::write(&path, bytes).expect("write");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");
            assert!(matches!(Config::load(&path), Err(Error::Corrupt { .. })), "{what}");
        }
        // Not a regular file.
        let directory = dir.path().join("dir.json");
        fs::create_dir(&directory).expect("dir");
        assert!(matches!(Config::load(&directory), Err(Error::Corrupt { .. })), "a directory");
        // What it says never holds a value from the file.
        fs::write(&path, r#"{"person":"top-secret-value","unknown":"also-secret"}"#).expect("write");
        let Err(Error::Corrupt { problem, .. }) = Config::load(&path) else { panic!("refused") };
        assert!(!problem.contains("also-secret") && !problem.contains("top-secret-value"), "{problem}");
    }

    #[test]
    fn anything_that_is_not_valid_is_an_error() {
        for text in [
            r#"{"person":"j an"}"#.to_owned(),
            r#"{"unknown":1}"#.to_owned(),
            r#"{"hosts":[{"host":"a","key":"nonsense"}]}"#.to_owned(),
            r#"{"hosts":[{"host":"a","key":"ssh-rsa AAAAB3NzaC1yc2E"}]}"#.to_owned(),
            r#"{"services":[{"host":"a","name":"p","url":"ftp://x"}]}"#.to_owned(),
            r#"{"services":[{"host":"a","name":"p","url":"http://user:pw@x/"}]}"#.to_owned(),
            r#"{"deadline_seconds":601}"#.to_owned(),
            r#"{"max_waiting":0}"#.to_owned(),
            "not json".to_owned(),
        ] {
            assert!(matches!(load(&text), Err(Error::Corrupt { .. })), "{text}");
        }
    }
}
