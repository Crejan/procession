//! `/etc/p-reserve.toml`: a file a person writes by hand. Every key optional,
//! an absent file is all defaults.
//!
//! Strictness is that of the JSON settings files (README, Conventions): a
//! regular file, owned by root or the running user, no group or other write
//! bit, an unknown key refused, a key given twice refused (the TOML parser
//! does that), a size limit, and error texts that carry no value from the
//! file. Secrets are never in it: a path to a 0600 file, or the key store.
//!
//! The owner and mode rule is `p_act::settings::check_owner_and_mode`, not a
//! copy; [`read_checked`] is the one function to point at p-act's TOML
//! reading when that exists.
//!
//! Provisional: the keys below are what `preserve health` needs. The full
//! shape (sources, targets, schedule) is not designed yet.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use p_reserve_core::textfile::DEFAULT_PREFIX;
use p_reserve_core::{Pair, Thresholds};
use serde::Deserialize;

pub const DEFAULT_CONFIG: &str = "/etc/p-reserve.toml";
pub const DEFAULT_LEDGER: &str = "/var/lib/p-reserve/ledger.prom";
/// A configuration file is at most this long.
pub const MAX_BYTES: u64 = 1024 * 1024;

/// The limits when the file names none. Provisional, and they assume a daily
/// schedule: fresh within 26 hours, stale after 72 hours, one hour of grace
/// for a pair that never succeeded. A pair on another schedule sets its own.
pub const DEFAULT_LIMITS: Thresholds = Thresholds {
    fresh_within: Duration::from_secs(26 * 3600),
    stale_after: Duration::from_secs(72 * 3600),
    first_run_grace: Duration::from_secs(3600),
};

#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub ledger: Option<PathBuf>,
    pub metric_prefix: Option<String>,
    pub freshness: FreshnessConfig,
    /// The declared (source, target) pairs. Without any, `health` reports
    /// every pair the ledger has.
    pub pair: Vec<PairConfig>,
    /// The repositories `snapshots`, `ls` and `restore` read.
    pub target: Vec<TargetConfig>,
}

/// A repository. The password is never here: `password_file` names a file of
/// mode 0600 that holds it.
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    pub name: String,
    /// A local path, or `opendal:sftp`, `rest:https://...`.
    pub repository: String,
    pub password_file: PathBuf,
    /// The backend's options (for `opendal:sftp`: `endpoint`, `root`, `user`,
    /// `key`, `known_hosts_strategy`).
    #[serde(default)]
    pub options: std::collections::BTreeMap<String, String>,
}

/// Limits as text (`"90m"`, `"3days"`); a key left out takes the default.
#[derive(Debug, Default, Deserialize, PartialEq, Eq, Clone)]
#[serde(default, deny_unknown_fields)]
pub struct FreshnessConfig {
    pub fresh_within: Option<String>,
    pub stale_after: Option<String>,
    pub first_run_grace: Option<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PairConfig {
    pub source: String,
    pub target: String,
    /// This pair's own limits; a key left out takes the file's `[freshness]`,
    /// then the default.
    #[serde(default)]
    pub freshness: FreshnessConfig,
}

/// Why the configuration was refused. Never holds a value from the file.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} does not exist")]
    NotFound(String),
    #[error("cannot read {0}")]
    Io(String),
    #[error("{0} is not a regular file")]
    NotARegularFile(String),
    #[error("{0}: {1}")]
    Untrusted(String, String),
    #[error("{0} is larger than the limit")]
    TooLarge(String),
    #[error("{0} is not UTF-8")]
    NotUtf8(String),
    #[error("{0}: {1}")]
    Invalid(String, String),
}

/// The text of the file at `path` if it may be trusted: a regular file, owned
/// by root or the running user, not writable by group or others, within
/// [`MAX_BYTES`], UTF-8. The checks are on the open file.
pub fn read_checked(path: &Path) -> Result<String, ConfigError> {
    let shown = path.display().to_string();
    let mut file = File::open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => ConfigError::NotFound(shown.clone()),
        _ => ConfigError::Io(shown.clone()),
    })?;
    let meta = file.metadata().map_err(|_| ConfigError::Io(shown.clone()))?;
    if !meta.is_file() {
        return Err(ConfigError::NotARegularFile(shown));
    }
    p_act::settings::check_owner_and_mode(&shown, meta.uid(), meta.permissions().mode(), p_act::peer::own_uid())
        .map_err(|e| ConfigError::Untrusted(shown.clone(), e.to_string()))?;
    let mut bytes = Vec::new();
    (&mut file).take(MAX_BYTES + 1).read_to_end(&mut bytes).map_err(|_| ConfigError::Io(shown.clone()))?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(ConfigError::TooLarge(shown));
    }
    String::from_utf8(bytes).map_err(|_| ConfigError::NotUtf8(shown))
}

/// The secret in the file at `path`, for a password: a regular file owned by
/// the running user or root, with no permission for group or others (0600 or
/// 0400), at most 4 KiB, UTF-8; one trailing newline is dropped. Errors name
/// the file and never its content.
pub fn read_secret(path: &Path) -> Result<String, ConfigError> {
    let shown = path.display().to_string();
    let mut file = File::open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => ConfigError::NotFound(shown.clone()),
        _ => ConfigError::Io(shown.clone()),
    })?;
    let meta = file.metadata().map_err(|_| ConfigError::Io(shown.clone()))?;
    if !meta.is_file() {
        return Err(ConfigError::NotARegularFile(shown));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(ConfigError::Untrusted(
            shown,
            "a password file must not be accessible to group or others: run chmod 600 on it".to_owned(),
        ));
    }
    if meta.uid() != 0 && meta.uid() != p_act::peer::own_uid() {
        return Err(ConfigError::Untrusted(
            shown,
            "a password file must be owned by root or by the user running this program".to_owned(),
        ));
    }
    let mut bytes = Vec::new();
    (&mut file).take(4097).read_to_end(&mut bytes).map_err(|_| ConfigError::Io(shown.clone()))?;
    if bytes.len() > 4096 {
        return Err(ConfigError::TooLarge(shown));
    }
    let mut text = String::from_utf8(bytes).map_err(|_| ConfigError::NotUtf8(shown.clone()))?;
    if text.ends_with('\n') {
        text.pop();
    }
    if text.is_empty() {
        return Err(ConfigError::Invalid(shown, "the password file is empty".to_owned()));
    }
    Ok(text)
}

/// What is wrong with a TOML document, without any value from it: the parser's
/// message can quote the offending value, so only messages that name a key
/// are kept (a key is what tells a person which one to remove), and the rest
/// is reduced to the line.
fn describe(text: &str, e: &toml::de::Error) -> String {
    let line = e.span().map_or(0, |span| text[..span.start.min(text.len())].matches('\n').count() + 1);
    let message = e.message();
    let first = message.lines().next().unwrap_or("");
    let names_only = ["unknown field `", "missing field `", "duplicate key `", "duplicate field `"];
    if names_only.iter().any(|prefix| first.starts_with(prefix)) {
        format!("{first}, line {line}")
    } else {
        format!("a value of the wrong kind or out of range, or not TOML, near line {line}")
    }
}

/// A source or target name as it will appear in the ledger, which anyone on
/// the machine may read: a short label, not an address and not a path into
/// somebody's home. Letters, digits and `. _ - : + /` only, 1 to 128 bytes;
/// no `@`, no `://`, no `..`, no leading `/` or `~`.
pub fn check_name(what: &str, name: &str) -> Result<(), String> {
    let plain = name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':' | b'+' | b'/'));
    if name.is_empty()
        || name.len() > 128
        || !plain
        || name.contains("://")
        || name.contains("..")
        || name.starts_with('/')
    {
        return Err(format!(
            "a {what} name is a short label (letters, digits and . _ - : + /, at most 128, not a path or an address)"
        ));
    }
    Ok(())
}

fn duration(key: &str, text: &str) -> Result<Duration, String> {
    humantime::parse_duration(text)
        .map_err(|_| format!("freshness.{key} is not a duration such as \"90m\" or \"3days\""))
}

/// `own` over `base` over `default`, per key, validated.
fn limits(own: &FreshnessConfig, base: &FreshnessConfig) -> Result<Thresholds, String> {
    let pick = |key: &str, own: &Option<String>, base: &Option<String>, default: Duration| match own
        .as_ref()
        .or(base.as_ref())
    {
        None => Ok(default),
        Some(text) => duration(key, text),
    };
    let limits = Thresholds {
        fresh_within: pick("fresh_within", &own.fresh_within, &base.fresh_within, DEFAULT_LIMITS.fresh_within)?,
        stale_after: pick("stale_after", &own.stale_after, &base.stale_after, DEFAULT_LIMITS.stale_after)?,
        first_run_grace: pick(
            "first_run_grace",
            &own.first_run_grace,
            &base.first_run_grace,
            DEFAULT_LIMITS.first_run_grace,
        )?,
    };
    if limits.fresh_within > limits.stale_after {
        return Err("freshness.fresh_within is longer than freshness.stale_after".to_owned());
    }
    Ok(limits)
}

impl Config {
    /// The file at `path`, checked (see the module); `None` if there is none.
    pub fn load(path: &Path) -> Result<Option<Config>, ConfigError> {
        let text = match read_checked(path) {
            Ok(text) => text,
            Err(ConfigError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(e),
        };
        let shown = path.display().to_string();
        let config: Config =
            toml::from_str(&text).map_err(|e| ConfigError::Invalid(shown.clone(), describe(&text, &e)))?;
        config.check().map_err(|problem| ConfigError::Invalid(shown, problem))?;
        Ok(Some(config))
    }

    /// Everything that can be checked without the ledger.
    fn check(&self) -> Result<(), String> {
        self.default_limits()?;
        self.declared()?;
        let mut seen = std::collections::BTreeSet::new();
        for target in &self.target {
            check_name("target", &target.name)?;
            if !seen.insert(&target.name) {
                return Err("two targets have the same name".to_owned());
            }
        }
        Ok(())
    }

    /// The target called `name`.
    pub fn target(&self, name: &str) -> Option<&TargetConfig> {
        self.target.iter().find(|t| t.name == name)
    }

    pub fn ledger_path(&self) -> &Path {
        self.ledger.as_deref().unwrap_or(Path::new(DEFAULT_LEDGER))
    }

    pub fn prefix(&self) -> &str {
        self.metric_prefix.as_deref().unwrap_or(DEFAULT_PREFIX)
    }

    /// The limits of a pair that sets none of its own.
    pub fn default_limits(&self) -> Result<Thresholds, String> {
        limits(&FreshnessConfig::default(), &self.freshness)
    }

    /// The declared pairs, each with its limits.
    pub fn declared(&self) -> Result<Vec<(Pair, Thresholds)>, String> {
        self.pair
            .iter()
            .map(|p| {
                check_name("source", &p.source)?;
                check_name("target", &p.target)?;
                Ok((Pair::new(&p.source, &p.target), limits(&p.freshness, &self.freshness)?))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, text: &str, mode: u32) -> PathBuf {
        let path = dir.join("p-reserve.toml");
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn every_key_is_optional_and_a_missing_file_is_none() {
        assert_eq!(toml::from_str::<Config>("").unwrap(), Config::default());
        assert_eq!(Config::default().default_limits().unwrap(), DEFAULT_LIMITS);
        assert_eq!(Config::load(Path::new("/nonexistent/p-reserve.toml")), Ok(None));
    }

    #[test]
    fn keys_parse_and_a_pair_may_set_its_own_limits() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(
            dir.path(),
            "ledger = \"/x/l.prom\"\n[freshness]\nfresh_within = \"90m\"\n\
             [[pair]]\nsource = \"a\"\ntarget = \"b\"\n\
             [[pair]]\nsource = \"w\"\ntarget = \"b\"\n[pair.freshness]\nfresh_within = \"8days\"\nstale_after = \"14days\"\n",
            0o644,
        );
        let config = Config::load(&path).unwrap().unwrap();
        let declared = config.declared().unwrap();
        assert_eq!(declared[0].0, Pair::new("a", "b"));
        assert_eq!(declared[0].1.fresh_within, Duration::from_secs(5400));
        assert_eq!(declared[0].1.stale_after, DEFAULT_LIMITS.stale_after);
        assert_eq!(declared[1].1.fresh_within, Duration::from_secs(8 * 86_400));
        assert_eq!(declared[1].1.stale_after, Duration::from_secs(14 * 86_400));
    }

    #[test]
    fn a_file_others_can_write_or_a_stranger_owns_is_refused_before_it_is_parsed() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o664, 0o646, 0o666, 0o620, 0o602] {
            let path = write(dir.path(), "x = [", mode);
            assert!(matches!(Config::load(&path), Err(ConfigError::Untrusted(..))), "{mode:o}");
        }
        // the owner check is p-act's `check_owner_and_mode`; a file of this user's passes it
        for mode in [0o600, 0o644, 0o400] {
            let path = write(dir.path(), "", mode);
            assert!(Config::load(&path).unwrap().is_some(), "{mode:o}");
        }
    }

    #[test]
    fn unknown_and_doubled_keys_a_directory_and_a_big_file_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        for text in [
            "lederg = 1",
            "[freshness]\nfresh = 1",
            "ledger = \"a\"\nledger = \"b\"",
            "[[pair]]\nsource = \"a\"\ntarget = \"b\"\nx = 1",
        ] {
            let path = write(dir.path(), text, 0o600);
            assert!(matches!(Config::load(&path), Err(ConfigError::Invalid(..))), "{text}");
        }
        assert!(matches!(Config::load(dir.path()), Err(ConfigError::NotARegularFile(_))));
        let big = write(dir.path(), &"#".repeat(MAX_BYTES as usize + 1), 0o600);
        assert!(matches!(Config::load(&big), Err(ConfigError::TooLarge(_))));
    }

    #[test]
    fn error_texts_carry_no_value_from_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let secret = "hunter2-SECRET";
        for text in [
            format!("ledger = 5\nmetric_prefix = {secret}"),
            format!("metric_prefix = 7\nledger = [\"{secret}\"]"),
            format!("[freshness]\nfresh_within = \"{secret}\""),
            format!("[[pair]]\nsource = \"{secret}@host\"\ntarget = \"b\""),
            format!("{secret} = 1"),
            format!("[[pair]]\nsource = \"a\"\ntarget = \"b\"\nfresh = \"{secret}\""),
        ] {
            let path = write(dir.path(), &text, 0o600);
            let err = Config::load(&path).unwrap_err().to_string();
            assert!(!err.contains(secret) || text.starts_with(secret), "{err}");
        }
        // a key's name may appear (it tells a person which to remove); a value never does
        let path = write(dir.path(), &format!("ledger = \"{secret}\"\nmetric_prefix = 3"), 0o600);
        assert!(!Config::load(&path).unwrap_err().to_string().contains(secret));
    }

    #[test]
    fn bad_durations_inverted_limits_and_names_that_do_not_belong_in_the_ledger_are_errors() {
        let bad: Config = toml::from_str("[freshness]\nfresh_within = \"soon\"").unwrap();
        assert!(bad.default_limits().unwrap_err().contains("fresh_within"));
        let inverted: Config = toml::from_str("[freshness]\nfresh_within = \"3d\"\nstale_after = \"1d\"").unwrap();
        assert!(inverted.default_limits().is_err());
        for good in ["home", "tank/home", "off-site.1", "db:main+x"] {
            assert!(check_name("source", good).is_ok(), "{good}");
        }
        for bad in ["", "/home/alice/docs", "alice@host", "sftp://u:pw@h/p", "../x", "a b", "é", &"x".repeat(129)] {
            assert!(check_name("source", bad).is_err(), "{bad}");
        }
    }
}
