//! `/etc/p-reserve.toml`: every key optional, an absent file is all defaults.
//!
//! Provisional: the keys below are what `preserve health` needs. The file's
//! full shape (sources, targets, schedule) is not designed yet.

use std::path::{Path, PathBuf};
use std::time::Duration;

use p_reserve_core::textfile::DEFAULT_PREFIX;
use p_reserve_core::{Pair, Thresholds};
use serde::Deserialize;

pub const DEFAULT_CONFIG: &str = "/etc/p-reserve.toml";
pub const DEFAULT_LEDGER: &str = "/var/lib/p-reserve/ledger.prom";

/// The limits when the file names none. Provisional: nothing in the SPEC says
/// what they are.
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
}

#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
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
}

impl Config {
    /// The file at `path`; `None` if there is none.
    pub fn load(path: &Path) -> Result<Option<Config>, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
        };
        toml::from_str(&text).map(Some).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn ledger_path(&self) -> &Path {
        self.ledger.as_deref().unwrap_or(Path::new(DEFAULT_LEDGER))
    }

    pub fn prefix(&self) -> &str {
        self.metric_prefix.as_deref().unwrap_or(DEFAULT_PREFIX)
    }

    pub fn declared(&self) -> Vec<Pair> {
        self.pair.iter().map(|p| Pair::new(&p.source, &p.target)).collect()
    }

    pub fn limits(&self) -> Result<Thresholds, String> {
        let get = |key: &str, value: &Option<String>, default: Duration| match value {
            None => Ok(default),
            Some(text) => humantime::parse_duration(text).map_err(|e| format!("freshness.{key}: {e}")),
        };
        let limits = Thresholds {
            fresh_within: get("fresh_within", &self.freshness.fresh_within, DEFAULT_LIMITS.fresh_within)?,
            stale_after: get("stale_after", &self.freshness.stale_after, DEFAULT_LIMITS.stale_after)?,
            first_run_grace: get("first_run_grace", &self.freshness.first_run_grace, DEFAULT_LIMITS.first_run_grace)?,
        };
        if limits.fresh_within > limits.stale_after {
            return Err("freshness.fresh_within is longer than freshness.stale_after".to_owned());
        }
        Ok(limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_key_is_optional_and_a_missing_file_is_none() {
        assert_eq!(toml::from_str::<Config>("").unwrap(), Config::default());
        assert_eq!(Config::default().limits().unwrap(), DEFAULT_LIMITS);
        assert_eq!(Config::load(Path::new("/nonexistent/p-reserve.toml")), Ok(None));
    }

    #[test]
    fn keys_parse_and_unknown_ones_are_refused() {
        let config: Config = toml::from_str(
            "ledger = \"/x/l.prom\"\n[freshness]\nfresh_within = \"90m\"\nstale_after = \"2days\"\n[[pair]]\nsource = \"a\"\ntarget = \"b\"\n",
        )
        .unwrap();
        let limits = config.limits().unwrap();
        assert_eq!(
            (limits.fresh_within, limits.stale_after),
            (Duration::from_secs(5400), Duration::from_secs(172_800))
        );
        assert_eq!(config.declared(), vec![Pair::new("a", "b")]);
        assert!(toml::from_str::<Config>("lederg = 1").is_err());
        assert!(toml::from_str::<Config>("[freshness]\nfresh = 1").is_err());
    }

    #[test]
    fn bad_durations_and_inverted_limits_are_errors() {
        let bad: Config = toml::from_str("[freshness]\nfresh_within = \"soon\"").unwrap();
        assert!(bad.limits().unwrap_err().contains("fresh_within"));
        let inverted: Config = toml::from_str("[freshness]\nfresh_within = \"3d\"\nstale_after = \"1d\"").unwrap();
        assert!(inverted.limits().is_err());
    }
}
