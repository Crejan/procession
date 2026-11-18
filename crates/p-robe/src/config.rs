//! `/etc/probe.json`: the service's settings, one JSON object (settings files are JSON for all
//! programs). An unknown member is refused, and so is a file that anyone but its owner or root can
//! write. Every member but `person`, `confirmed_key`, `automatic_key` and `pledge_socket` has a default.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// Where `probe` reads its settings.
pub const DEFAULT_FILE: &str = "/etc/probe.json";
/// The host key of a Linux host that has an Ed25519 one.
pub const DEFAULT_HOST_KEY: &str = "/etc/ssh/ssh_host_ed25519_key";
/// Where the service's key and its certificate are when nothing says otherwise.
pub const DEFAULT_SERVICE_KEY: &str = "/etc/probe/service-key";

/// The service's settings as a file gives them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub host: Option<String>,
    pub person: String,
    pub confirmed_key: PathBuf,
    pub automatic_key: PathBuf,
    pub service_key: PathBuf,
    pub pledge_socket: PathBuf,
    /// The uid of the person on the machine the socket is on; the default is the uid that owns the socket's directory.
    pub pledge_uid: Option<u32>,
    pub used_dir: PathBuf,
    pub listen: String,
    pub max_waiting: usize,
    pub probe: PathBuf,
    /// The host key `probe setup` certifies the service's key with.
    pub host_key: PathBuf,
}

impl Config {
    /// Parses the text of the file: one JSON object, an unknown member refused.
    ///
    /// # Errors
    /// The first problem, in words.
    pub fn parse(text: &str) -> Result<Config, String> {
        let serde_json::Value::Object(mut members) =
            serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?
        else {
            return Err("the file is one JSON object".into());
        };
        let mut string = |key: &str| -> Result<Option<String>, String> {
            match members.remove(key) {
                None => Ok(None),
                Some(serde_json::Value::String(text)) => Ok(Some(text)),
                Some(_) => Err(format!("{key}: a string")),
            }
        };
        let need = |value: Option<String>, key: &str| value.ok_or(format!("{key} is needed"));
        let host = string("host")?;
        let person = need(string("person")?, "person")?;
        let confirmed_key = need(string("confirmed_key")?, "confirmed_key")?;
        let automatic_key = need(string("automatic_key")?, "automatic_key")?;
        let service_key = string("service_key")?;
        let pledge_socket = need(string("pledge_socket")?, "pledge_socket")?;
        let used_dir = string("used_dir")?;
        let listen = string("listen")?;
        let probe = string("probe")?;
        let host_key = string("host_key")?;
        let mut number = |key: &str| -> Result<Option<u64>, String> {
            match members.remove(key) {
                None => Ok(None),
                Some(value) => value.as_u64().map(Some).ok_or(format!("{key}: a non-negative whole number")),
            }
        };
        let pledge_uid = number("pledge_uid")?
            .map(|n| u32::try_from(n).map_err(|_| "pledge_uid: too large".to_string()))
            .transpose()?;
        let max_waiting = number("max_waiting")?
            .map_or(Ok(16), |n| usize::try_from(n).map_err(|_| "max_waiting: too large".to_string()))?;
        if let Some(unknown) = members.keys().next() {
            return Err(format!("unknown member {unknown}"));
        }
        if !person.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) || person.is_empty() {
            return Err("person: not a person's name".into());
        }
        Ok(Config {
            host,
            person,
            confirmed_key: confirmed_key.into(),
            automatic_key: automatic_key.into(),
            service_key: service_key.unwrap_or_else(|| DEFAULT_SERVICE_KEY.into()).into(),
            pledge_socket: pledge_socket.into(),
            pledge_uid,
            used_dir: used_dir.unwrap_or_else(|| "/var/lib/probe/used".into()).into(),
            listen: listen.unwrap_or_else(|| "127.0.0.1:8765".into()),
            max_waiting,
            probe: probe.unwrap_or_else(|| "/usr/local/bin/probe".into()).into(),
            host_key: host_key.unwrap_or_else(|| DEFAULT_HOST_KEY.into()).into(),
        })
    }

    /// Reads and parses the settings file at `path`, after checking that nobody but its owner or
    /// root can write it.
    ///
    /// # Errors
    /// Why not, with the path.
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = read_checked(path)?.ok_or(format!("{}: no such file", path.display()))?;
        Config::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
    }
}

/// The text of the settings file at `path`, or `None` if there is none. A file that anyone but its
/// owner or root can write is refused: what it says is what the service signs for.
///
/// # Errors
/// The file is there and is writable by group or others, or cannot be read.
pub fn read_checked(path: &Path) -> Result<Option<String>, String> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    if !meta.is_file() {
        return Err(format!("{}: not a regular file", path.display()));
    }
    if meta.mode() & 0o022 != 0 {
        return Err(format!(
            "{}: writable by its group or by others (mode {:04o}); only its owner or root may write it",
            path.display(),
            meta.mode() & 0o7777
        ));
    }
    std::fs::read_to_string(path).map(Some).map_err(|e| format!("{}: {e}", path.display()))
}

/// The certificate beside the service's key (`<key>-cert.pub`), as `text` (the file's contents, if
/// there is one and it parses) says where the key is, else the default.
#[must_use]
pub fn certificate_path(text: Option<&str>) -> PathBuf {
    let key =
        text.and_then(|t| Config::parse(t).ok()).map_or_else(|| PathBuf::from(DEFAULT_SERVICE_KEY), |c| c.service_key);
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
        assert_eq!(certificate_path(Some("not a config")), PathBuf::from("/etc/probe/service-key-cert.pub"));
        let text = with(r#""service_key":"/k/svc","host_key":"/k/host""#);
        assert_eq!(certificate_path(Some(&text)), PathBuf::from("/k/svc-cert.pub"));
        assert_eq!(Config::parse(&text).unwrap().host_key, PathBuf::from("/k/host"));
        assert_eq!(Config::parse(MINIMAL).unwrap().host_key, PathBuf::from(DEFAULT_HOST_KEY));
    }

    #[test]
    fn what_is_wrong_is_named() {
        for (text, needle) in [
            ("", "not JSON"),
            ("{}", "person is needed"),
            ("[]", "one JSON object"),
            ("# a comment", "not JSON"),
            (&with(r#""x":1"#), "unknown member x"),
            (&with(r#""max_waiting":"many""#), "non-negative whole number"),
            (&with(r#""max_waiting":-1"#), "non-negative whole number"),
            (&with(r#""pledge_uid":99999999999"#), "too large"),
            (&with(r#""listen":5"#), "listen: a string"),
            (r#"{"person":"j an","confirmed_key":"a","automatic_key":"b","pledge_socket":"c"}"#, "not a person's name"),
        ] {
            let error = Config::parse(text).unwrap_err();
            assert!(error.contains(needle), "{text:?}: {error}");
        }
        // A member given twice: serde_json keeps the last; a duplicate is not an error of JSON, and not allowed to matter.
        assert_eq!(Config::parse(&with(r#""max_waiting":3, "max_waiting":4"#)).unwrap().max_waiting, 4);
    }

    #[test]
    fn a_file_that_group_or_others_can_write_is_refused_and_a_missing_one_is_none() {
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
            assert_eq!(read_checked(&file).is_ok(), ok, "{mode:o}");
        }
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(Config::load(&file).unwrap_err().contains("writable by its group or by others"));
        assert_eq!(read_checked(&dir.join("absent")), Ok(None));
        assert!(Config::load(&dir.join("absent")).unwrap_err().contains("no such file"));
        assert!(read_checked(&dir).is_err(), "a directory is not a settings file");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::write(&file, "{").unwrap();
        assert!(Config::load(&file).unwrap_err().starts_with(&file.display().to_string()));
    }
}
