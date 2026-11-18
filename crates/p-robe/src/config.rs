//! `/etc/probe.json`: the service's settings, one JSON object (settings files are JSON for all
//! programs). An unknown member is refused, and so is a file that anyone but its owner or root can
//! write. Every member but `person`, `confirmed_key`, `automatic_key` and `pledge_socket` has a default.

use std::path::{Path, PathBuf};

/// Where `probe` reads its settings.
pub const DEFAULT_FILE: &str = "/etc/probe.json";
/// The host key of a Linux host that has an Ed25519 one.
pub const DEFAULT_HOST_KEY: &str = "/etc/ssh/ssh_host_ed25519_key";
/// Where the service's key and its certificate are when nothing says otherwise.
pub const DEFAULT_SERVICE_KEY: &str = "/etc/probe/service-key";

fn default_service_key() -> PathBuf {
    DEFAULT_SERVICE_KEY.into()
}
fn default_used_dir() -> PathBuf {
    "/var/lib/probe/used".into()
}
fn default_listen() -> String {
    "127.0.0.1:8765".into()
}
fn default_max_waiting() -> usize {
    16
}
fn default_probe() -> PathBuf {
    "/usr/local/bin/probe".into()
}
fn default_host_key() -> PathBuf {
    DEFAULT_HOST_KEY.into()
}

/// The service's settings as a file gives them. Read by `p_act::settings` (one JSON object, no member twice,
/// no trailing text, a regular file owned by root or the running user that nobody else can write); an unknown
/// member is refused by `deny_unknown_fields`, which is this type's to say.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub host: Option<String>,
    pub person: String,
    pub confirmed_key: PathBuf,
    pub automatic_key: PathBuf,
    #[serde(default = "default_service_key")]
    pub service_key: PathBuf,
    pub pledge_socket: PathBuf,
    /// The uid of the person on the machine the socket is on; the default is the uid that owns the socket's directory.
    #[serde(default)]
    pub pledge_uid: Option<u32>,
    #[serde(default = "default_used_dir")]
    pub used_dir: PathBuf,
    #[serde(default = "default_listen")]
    pub listen: String,
    #[serde(default = "default_max_waiting")]
    pub max_waiting: usize,
    #[serde(default = "default_probe")]
    pub probe: PathBuf,
    /// The host key `probe setup` certifies the service's key with.
    #[serde(default = "default_host_key")]
    pub host_key: PathBuf,
}

impl Config {
    /// Parses a settings document in memory, with the same rules as a file.
    ///
    /// # Errors
    /// What `p_act::settings` says, or what is wrong with a value.
    pub fn parse(text: &str) -> Result<Config, String> {
        p_act::settings::parse::<Config>(text.as_bytes()).map_err(|e| e.to_string()).and_then(Config::checked)
    }

    /// Reads the settings file at `path` with `p_act::settings::read`.
    ///
    /// # Errors
    /// Why not, with the path.
    pub fn load(path: &Path) -> Result<Config, String> {
        Config::load_optional(path)?.ok_or(format!("{}: no such file", path.display()))
    }

    /// As [`Config::load`], and `None` if there is no such file.
    ///
    /// # Errors
    /// The file is there and refused.
    pub fn load_optional(path: &Path) -> Result<Option<Config>, String> {
        match p_act::settings::read_optional::<Config>(path) {
            Ok(Some(config)) => config.checked().map(Some).map_err(|e| format!("{}: {e}", path.display())),
            Ok(None) => Ok(None),
            Err(e) => Err(format!("{}: {e}", path.display())),
        }
    }

    /// What the types do not say: a person's name.
    fn checked(self) -> Result<Config, String> {
        if self.person.is_empty() || !self.person.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) {
            return Err("person: not a person's name".into());
        }
        Ok(self)
    }
}

/// The certificate beside the service's key (`<key>-cert.pub`), where `config` (if there is one) says the key is,
/// else the default.
#[must_use]
pub fn certificate_path(config: Option<&Config>) -> PathBuf {
    let key = config.map_or_else(|| PathBuf::from(DEFAULT_SERVICE_KEY), |c| c.service_key.clone());
    let mut cert = key.into_os_string();
    cert.push("-cert.pub");
    PathBuf::from(cert)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const MINIMAL: &str = r#"{"person":"jan","confirmed_key":"/k/c.pub","automatic_key":"/k/a.pub","pledge_socket":"/run/p/service.sock"}"#;

    fn with(extra: &str) -> String {
        format!("{}, {extra}}}", MINIMAL.trim_end_matches('}'))
    }

    #[test]
    fn a_minimal_file_gets_the_defaults() {
        let config = Config::parse(MINIMAL).unwrap();
        assert_eq!((config.max_waiting, config.listen.as_str(), config.host.as_deref()), (16, "127.0.0.1:8765", None));
        assert_eq!(config.used_dir, PathBuf::from("/var/lib/probe/used"));
    }

    #[test]
    fn the_certificate_is_beside_the_key_the_file_names_or_the_default() {
        assert_eq!(certificate_path(None), PathBuf::from("/etc/probe/service-key-cert.pub"));
        let config = Config::parse(&with(r#""service_key":"/k/svc","host_key":"/k/host""#)).unwrap();
        assert_eq!(certificate_path(Some(&config)), PathBuf::from("/k/svc-cert.pub"));
        assert_eq!(config.host_key, PathBuf::from("/k/host"));
        assert_eq!(Config::parse(MINIMAL).unwrap().host_key, PathBuf::from(DEFAULT_HOST_KEY));
    }

    #[test]
    fn what_is_wrong_is_named_and_no_value_is_echoed() {
        for (text, needle) in [
            ("", "not one JSON object"),
            ("{}", "missing field `person`"),
            ("[]", "not one JSON object"),
            ("# a comment", "not one JSON object"),
            (&with(r#""x":1"#), "unknown field `x`"),
            (&with(r#""max_waiting":"many""#), "wrong kind"),
            (&with(r#""max_waiting":-1"#), "wrong kind"),
            (&with(r#""pledge_uid":99999999999"#), "wrong kind"),
            (&with(r#""listen":5"#), "wrong kind"),
            (r#"{"person":"j an","confirmed_key":"a","automatic_key":"b","pledge_socket":"c"}"#, "not a person's name"),
            // What p_act::settings refuses and the old reader let through:
            (&with(r#""listen":"a", "listen":"b""#), "not one JSON object"),
            (&format!("{MINIMAL} trailing"), "not one JSON object"),
            (&format!("\u{feff}{MINIMAL}"), "byte order mark"),
        ] {
            let error = Config::parse(text).unwrap_err();
            assert!(error.contains(needle), "{text:?}: {error}");
        }
        let error = Config::parse(&with(r#""listen":"a-secret-value-123", "bogus":1"#)).unwrap_err();
        assert!(!error.contains("a-secret-value-123"), "{error}");
    }

    #[test]
    fn a_file_is_read_with_p_acts_rules_a_missing_one_is_none() {
        let dir = crate::testdir::new("config");
        let file = dir.join("probe.json");
        std::fs::write(&file, MINIMAL).unwrap();
        for (mode, ok) in [
            (0o600, true),
            (0o644, true),
            (0o640, true),
            (0o660, false),
            (0o666, false),
            (0o602, false),
            (0o620, false),
        ] {
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            assert_eq!(Config::load(&file).is_ok(), ok, "{mode:o}");
        }
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(Config::load(&file).unwrap_err().contains("can be written by someone other than its owner"));
        assert_eq!(Config::load_optional(&dir.join("absent")), Ok(None));
        assert!(Config::load(&dir.join("absent")).unwrap_err().contains("no such file"));
        assert!(Config::load_optional(&dir).is_err(), "a directory is not a settings file");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Config::load(&file).is_ok());
        std::fs::write(&file, "{").unwrap();
        assert!(Config::load(&file).unwrap_err().starts_with(&file.display().to_string()));
        // A member twice at the top: refused (the old reader kept the last).
        std::fs::write(&file, with(r#""listen":"a", "listen":"b""#)).unwrap();
        assert!(Config::load(&file).is_err());
    }
}
