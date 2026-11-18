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

/// The broker (stage 2). Without it, stage 1 is unchanged: no connection, nothing registered.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerEntry {
    /// `host:port`.
    pub address: String,
    /// The name the broker's certificate must have; the host part of `address` if absent.
    #[serde(default)]
    pub server_name: Option<String>,
    /// The site's TLS root, a PEM certificate: the only anchor for *reaching* the broker.
    pub tls_root: String,
    /// The site CA's public key line: the anchor for *who signed what* (the broker's signature on the
    /// standing, the certificates of the person's keys).
    pub site_ca: String,
}

impl BrokerEntry {
    /// The name the broker's certificate is checked for.
    #[must_use]
    pub fn name(&self) -> &str {
        self.server_name
            .as_deref()
            .unwrap_or_else(|| self.address.rsplit_once(':').map_or(&self.address, |(host, _)| host))
    }

    fn check(&self) -> std::result::Result<(), String> {
        let host_port =
            self.address.rsplit_once(':').filter(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
        if host_port.is_none() {
            return Err("broker.address is host:port".into());
        }
        let name = self.name();
        if name.is_empty() || name.contains(char::is_whitespace) {
            return Err("broker.server_name is not a name".into());
        }
        use rustls_pki_types::pem::PemObject as _;
        let roots: Vec<Vec<u8>> = rustls_pki_types::CertificateDer::pem_slice_iter(self.tls_root.as_bytes())
            .map(|cert| cert.map(|der| der.as_ref().to_vec()))
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| "broker.tls_root is not a PEM certificate".to_owned())?;
        if roots.is_empty() {
            return Err("broker.tls_root holds no certificate".into());
        }
        let site_ca = PublicKey::parse(&self.site_ca).map_err(|e| format!("broker.site_ca: {e}"))?;
        // `site_ca` and `tls_root` must never stand in for each other: the same key material in both is refused.
        // An SSH public key and an X.509 certificate are different encodings, so they are compared by the key's
        // raw bytes (32 for Ed25519, the 65-byte uncompressed point for P-256) occurring inside the
        // certificate's DER, which holds its public key as one run of bytes. Not compared: the same key
        // re-encoded (a compressed P-256 point), and a certificate whose key merely *signed* the SSH key's
        // certificate.
        let raw =
            raw_key_bytes(&site_ca).ok_or_else(|| "broker.site_ca is not an Ed25519 or ECDSA P-256 key".to_owned())?;
        if roots.iter().any(|der| der.windows(raw.len()).any(|window| window == raw.as_slice())) {
            return Err("broker.tls_root and broker.site_ca hold the same key material: they must never stand in for each other".into());
        }
        Ok(())
    }
}

/// The raw public key bytes inside an SSH public key line: the 32 bytes of an Ed25519 key, or the
/// uncompressed point of a P-256 key.
fn raw_key_bytes(key: &PublicKey) -> Option<Vec<u8>> {
    use base64::Engine as _;
    let blob = base64::engine::general_purpose::STANDARD.decode(key.to_string().split_whitespace().nth(1)?).ok()?;
    let mut reader = crate::agent::wire::Reader::new(&blob);
    let kind = reader.utf8()?;
    match kind {
        "ssh-ed25519" => reader.string().map(<[u8]>::to_vec),
        "ecdsa-sha2-nistp256" => {
            reader.utf8()?;
            reader.string().map(<[u8]>::to_vec)
        }
        _ => None,
    }
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
    /// The broker, if there is one (stage 2).
    #[serde(default)]
    pub broker: Option<BrokerEntry>,
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
        // Only absence is the empty configuration; anything else wrong with the file is an error.
        let config: Self = match p_act::settings::read_optional(path) {
            Ok(Some(config)) => config,
            Ok(None) => return Ok(Self::default()),
            Err(e) => {
                return Err(Error::Corrupt {
                    path: path.to_owned(),
                    problem: crate::outside::bounded(&e.to_string(), 200),
                });
            }
        };
        config.check().map_err(|problem| Error::Corrupt { path: path.to_owned(), problem })?;
        Ok(config)
    }

    fn check(&self) -> std::result::Result<(), String> {
        if let Some(broker) = &self.broker {
            broker.check()?;
        }
        if self.person.as_deref().is_some_and(|p| !is_name(p)) {
            return Err("person is not a name ([A-Za-z0-9._-], at most 64)".into());
        }
        for host in &self.hosts {
            if !is_name(&host.host) {
                return Err(format!("host {:?} is not a name", host.host));
            }
            PublicKey::parse(&host.key)
                .map_err(|e| format!("the key of host {}: {e}", crate::outside::bounded(&host.host, 64)))?;
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
        crate::testing::write_settings(&path, text);
        Config::load(&path)
    }

    /// The premise of the umask tests: under `umask 002` a plain `fs::write` is 0664.
    #[test]
    fn umask_child_premise() {
        if std::env::var_os("PLEDGE_UMASK_CHILD").is_none() {
            return;
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new("config-umask");
        let path = dir.path().join("plain");
        fs::write(&path, "{}").expect("write");
        assert_eq!(fs::metadata(&path).expect("meta").permissions().mode() & 0o777, 0o664);
        assert!(matches!(Config::load(&path), Err(Error::Corrupt { .. })), "and that file is refused");
    }

    #[test]
    fn the_files_the_tests_write_do_not_lean_on_the_umask() {
        if std::env::var_os("PLEDGE_UMASK_CHILD").is_some() {
            return;
        }
        crate::testing::run_under_umask_002(&[
            "config::tests::umask_child_premise",
            "config::tests::a_full_configuration_loads_and_finds_the_host_key",
            "approvals_tests::a_harmless_request_is_approved_with_the_automatic_key_and_without_asking",
        ]);
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

    fn broker(root: &str, site_ca: &str) -> String {
        format!(
            r#"{{"broker":{{"address":"broker.example:8443","tls_root":{},"site_ca":"{site_ca}"}}}}"#,
            serde_json::to_string(root).expect("json")
        )
    }

    #[test]
    fn a_broker_needs_a_root_and_a_site_ca_that_are_not_the_same_key_material() {
        let root = include_str!("../testdata/tls_root.pem");
        let same = include_str!("../testdata/tls_root_key.pub").trim();
        let other = include_str!("../testdata/other_key.pub").trim();
        let config = load(&broker(root, other)).expect("a broker with two different anchors");
        let entry = config.broker.expect("broker");
        assert_eq!(entry.name(), "broker.example", "the host part of the address");
        // The same key material as the root's key, as an SSH key: refused.
        let result = load(&broker(root, same));
        let Err(Error::Corrupt { problem, .. }) = result else { panic!("refused: {result:?}") };
        assert!(problem.contains("same key material"), "{problem}");
        // And the other ways it can be wrong.
        for (what, text) in [
            ("no PEM", broker("not a certificate", other)),
            (
                "a root that holds no certificate",
                broker("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", other),
            ),
            ("a site CA that is not a key", broker(root, "nonsense")),
            ("an RSA site CA", broker(root, "ssh-rsa AAAAB3NzaC1yc2E")),
            (
                "an address without a port",
                r#"{"broker":{"address":"broker.example","tls_root":"x","site_ca":"y"}}"#.to_owned(),
            ),
            ("an unknown member", r#"{"broker":{"address":"a:1","tls_root":"x","site_ca":"y","extra":1}}"#.to_owned()),
        ] {
            assert!(matches!(load(&text), Err(Error::Corrupt { .. })), "{what}");
        }
        assert!(load("{}").expect("no broker").broker.is_none(), "stage 1: no broker, nothing changes");
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
