//! `/etc/probe.toml`: the service's settings. A small subset of TOML (`key =
//! "string"` or `key = 123`, `#` comments); every key but `person`,
//! `confirmed_key`, `automatic_key` and `pledge_socket` has a default.

use std::path::PathBuf;

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
}

impl Config {
    /// Parses the text of the file.
    ///
    /// # Errors
    /// The first problem, with its line.
    pub fn parse(text: &str) -> Result<Config, String> {
        let mut values = std::collections::BTreeMap::new();
        for (index, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let at = index + 1;
            let (key, value) = line.split_once('=').ok_or(format!("line {at}: expected key = value"))?;
            let value = value.trim();
            let value = match value.strip_prefix('"') {
                Some(rest) => rest
                    .strip_suffix('"')
                    .filter(|v| !v.contains('"'))
                    .ok_or(format!("line {at}: bad string"))?
                    .to_string(),
                None if value.chars().all(|c| c.is_ascii_digit()) && !value.is_empty() => value.to_string(),
                None => return Err(format!("line {at}: a value is a quoted string or a number")),
            };
            if values.insert(key.trim().to_string(), value).is_some() {
                return Err(format!("line {at}: {} given twice", key.trim()));
            }
        }
        let mut take = |key: &str| values.remove(key);
        let need = |value: Option<String>, key: &str| value.ok_or(format!("{key} is needed"));
        let number = |value: Option<String>, key: &str| {
            value.map(|v| v.parse::<u64>().map_err(|_| format!("{key}: not a number"))).transpose()
        };
        let config = Config {
            host: take("host"),
            person: need(take("person"), "person")?,
            confirmed_key: need(take("confirmed_key"), "confirmed_key")?.into(),
            automatic_key: need(take("automatic_key"), "automatic_key")?.into(),
            service_key: take("service_key").unwrap_or_else(|| "/etc/probe/service-key".into()).into(),
            pledge_socket: need(take("pledge_socket"), "pledge_socket")?.into(),
            pledge_uid: number(take("pledge_uid"), "pledge_uid")?
                .map(|n| u32::try_from(n).map_err(|_| "pledge_uid: too large".to_string()))
                .transpose()?,
            used_dir: take("used_dir").unwrap_or_else(|| "/var/lib/probe/used".into()).into(),
            listen: take("listen").unwrap_or_else(|| "127.0.0.1:8765".into()),
            max_waiting: number(take("max_waiting"), "max_waiting")?
                .map_or(Ok(16), |n| usize::try_from(n).map_err(|_| "max_waiting: too large".to_string()))?,
            probe: take("probe").unwrap_or_else(|| "/usr/local/bin/probe".into()).into(),
        };
        if let Some(unknown) = values.keys().next() {
            return Err(format!("unknown key {unknown}"));
        }
        if !crate::rules::is_token(&config.person)
            && !config.person.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
        {
            return Err("person: not a person's name".into());
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "person = \"jan\"\nconfirmed_key = \"/k/c.pub\"\nautomatic_key = \"/k/a.pub\"\npledge_socket = \"/run/p/service.sock\"\n";

    #[test]
    fn a_minimal_file_gets_the_defaults() {
        let config = Config::parse(MINIMAL).unwrap();
        assert_eq!((config.max_waiting, config.listen.as_str(), config.host.as_deref()), (16, "127.0.0.1:8765", None));
        assert_eq!(config.used_dir, PathBuf::from("/var/lib/probe/used"));
    }

    #[test]
    fn what_is_wrong_is_named() {
        for (text, needle) in [
            ("", "person is needed"),
            (&format!("{MINIMAL}x = 1"), "unknown key x"),
            (&format!("{MINIMAL}person = \"eva\""), "given twice"),
            (&format!("{MINIMAL}max_waiting = many"), "quoted string or a number"),
            (&format!("{MINIMAL}pledge_uid = 99999999999"), "too large"),
            ("person", "expected key = value"),
        ] {
            let error = Config::parse(text).unwrap_err();
            assert!(error.contains(needle), "{text:?}: {error}");
        }
    }
}
