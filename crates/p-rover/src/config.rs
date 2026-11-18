//! `/etc/p-rover.toml`. Every key is optional; without the file every
//! observe subcommand runs with defaults.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobMatcher};
use p_roc::CpuSet;
use serde::Deserialize;

use crate::error::Error;

/// Default location of the configuration.
pub const DEFAULT_PATH: &str = "/etc/p-rover.toml";

/// The configuration.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Interface name globs of the fieldbus.
    pub fieldbus_interfaces: Vec<String>,
    /// What the command line should say; otherwise read from the bootloader config.
    pub declared_cmdline: Option<String>,
    /// `[irq]`.
    pub irq: IrqConfig,
    /// `[probe]` (only the keys observe subcommands need).
    pub probe: ProbeConfig,
}

/// `[irq]`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub struct IrqConfig {
    /// IRQ name glob to the expected affinity (a CPU list).
    pub expected: BTreeMap<String, String>,
}

/// `[probe]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default)]
pub struct ProbeConfig {
    /// Where probe ledgers live; an unrestored one is a finding of every subcommand.
    pub ledger_dir: PathBuf,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self { ledger_dir: PathBuf::from("/run/p-rover/probe") }
    }
}

/// One entry of `[irq] expected`, compiled.
#[derive(Clone, Debug)]
pub struct IrqExpectation {
    /// The glob as written.
    pub pattern: String,
    matcher: GlobMatcher,
    /// The expected affinity.
    pub cpus: CpuSet,
}

impl IrqExpectation {
    /// Whether the glob matches an IRQ name.
    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        self.matcher.is_match(name)
    }
}

impl Config {
    /// Loads `path`, or [`DEFAULT_PATH`] when `None`. A missing default file
    /// is the default configuration; a missing explicit file is an error.
    ///
    /// # Errors
    /// When the file cannot be read, is not valid TOML, or holds an invalid glob or CPU list.
    pub fn load(path: Option<&Path>) -> Result<Self, Error> {
        let (p, explicit) = path.map_or((Path::new(DEFAULT_PATH), false), |p| (p, true));
        let fail = |detail: String| Error::Config { path: p.display().to_string(), detail };
        let text = match std::fs::read_to_string(p) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !explicit => return Ok(Self::default()),
            Err(e) => return Err(fail(e.to_string())),
        };
        let cfg: Self = toml::from_str(&text).map_err(|e| fail(e.to_string()))?;
        cfg.irq_expectations().map_err(fail)?;
        Ok(cfg)
    }

    /// The compiled `[irq] expected` table.
    ///
    /// # Errors
    /// With the offending pattern when a glob or a CPU list is invalid.
    pub fn irq_expectations(&self) -> Result<Vec<IrqExpectation>, String> {
        self.irq
            .expected
            .iter()
            .map(|(pattern, cpus)| {
                let matcher = GlobBuilder::new(pattern)
                    .literal_separator(true)
                    .build()
                    .map_err(|e| format!("[irq] expected {pattern:?}: {e}"))?
                    .compile_matcher();
                let cpus = CpuSet::parse_list(cpus).map_err(|e| format!("[irq] expected {pattern:?}: {e}"))?;
                Ok(IrqExpectation { pattern: pattern.clone(), matcher, cpus })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load(text: &str) -> Result<Config, Error> {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("c.toml");
        std::fs::write(&p, text).unwrap();
        Config::load(Some(&p))
    }

    #[test]
    fn empty_and_full() {
        let c = load("").unwrap();
        assert!(c.fieldbus_interfaces.is_empty());
        assert_eq!(c.probe.ledger_dir, PathBuf::from("/run/p-rover/probe"));
        let c = load(
            "fieldbus_interfaces=[\"lab*\"]\n[irq]\nexpected={\"lan0-TxRx-*\"=\"4-7\"}\n[probe.jitter]\npriority=80\n",
        )
        .unwrap();
        let e = c.irq_expectations().unwrap();
        assert!(e[0].matches("lan0-TxRx-3") && !e[0].matches("lan1-TxRx-3"));
        assert_eq!(e[0].cpus.to_string(), "4-7");
    }

    #[test]
    fn bad_values_are_errors() {
        assert!(load("[irq]\nexpected={\"a\"=\"x\"}").is_err());
        assert!(load("fieldbus_interfaces = 3").is_err());
        assert!(Config::load(Some(Path::new("/nonexistent/p-rover.toml"))).is_err());
    }
}
