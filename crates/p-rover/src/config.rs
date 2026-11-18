//! `/etc/p-rover.toml`. Every key is optional; without the file every
//! observe subcommand runs with defaults.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobMatcher};
use p_roc::CpuSet;
use serde::Deserialize;

use crate::error::Error;

/// The one place the settings file is read: through `p_act::settings`.
fn read_toml(p: &Path) -> Result<Config, Error> {
    p_act::settings::read_toml(p).map_err(|e| Error::Config { path: p.display().to_string(), detail: e.to_string() })
}

fn read_toml_optional(p: &Path) -> Result<Option<Config>, Error> {
    p_act::settings::read_toml_optional(p).map_err(|e| Error::Config { path: p.display().to_string(), detail: e.to_string() })
}

/// Default location of the configuration.
pub const DEFAULT_PATH: &str = "/etc/p-rover.toml";

/// The configuration.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
#[serde(default, deny_unknown_fields)]
pub struct IrqConfig {
    /// IRQ name glob to the expected affinity (a CPU list).
    pub expected: BTreeMap<String, String>,
}

/// `[probe]`. Only `ledger_dir` is used by the observe subcommands; the rest is
/// read and checked now so a configuration written for the probes is not refused.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProbeConfig {
    /// Comm regexes that make every probe refuse.
    pub guard_processes: Vec<String>,
    /// Paths whose existence makes every probe refuse.
    pub guard_paths: Vec<PathBuf>,
    /// Where probe ledgers live; an unrestored one is a finding of every subcommand.
    pub ledger_dir: PathBuf,
    /// `[probe.jitter]`.
    pub jitter: JitterConfig,
    /// `[probe.nic_sweep]`.
    pub nic_sweep: NicSweepConfig,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            guard_processes: Vec::new(),
            guard_paths: Vec::new(),
            ledger_dir: PathBuf::from("/run/p-rover/probe"),
            jitter: JitterConfig::default(),
            nic_sweep: NicSweepConfig::default(),
        }
    }
}

/// `[probe.jitter]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct JitterConfig {
    /// Longest run accepted (`"5m"`).
    pub max_duration: String,
    /// SCHED_FIFO priority.
    pub priority: u8,
    /// cyclictest interval.
    pub interval_us: u32,
    /// Count samples over this latency.
    pub threshold_us: u32,
}

impl Default for JitterConfig {
    fn default() -> Self {
        Self { max_duration: "5m".into(), priority: 80, interval_us: 1000, threshold_us: 100 }
    }
}

/// `[probe.nic_sweep]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NicSweepConfig {
    /// `[sender, receiver]`; empty: the probe refuses.
    pub pair: Vec<String>,
    /// Longest whole sweep.
    pub max_duration: String,
    /// One cell.
    pub cell_duration: String,
    /// Longest one cell.
    pub cell_max_duration: String,
    /// `quick` or `full`.
    pub matrix: String,
    /// RT hog priority.
    pub hog_priority: u8,
    /// The small ring size.
    pub ring_small: u32,
    /// The coalescing setting under test.
    pub coalesce_us: u32,
    /// Frames per second.
    pub freq_hz: u32,
    /// Frames per burst.
    pub burst: u32,
    /// Frame size.
    pub frame_bytes: u32,
}

impl Default for NicSweepConfig {
    fn default() -> Self {
        Self {
            pair: Vec::new(),
            max_duration: "10m".into(),
            cell_duration: "5s".into(),
            cell_max_duration: "30s".into(),
            matrix: "quick".into(),
            hog_priority: 90,
            ring_small: 256,
            coalesce_us: 50,
            freq_hz: 2000,
            burst: 16,
            frame_bytes: 128,
        }
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
    /// is the default configuration; a missing explicit file is an error. The
    /// file is read by `p_act::settings`: a regular file, owned by root or
    /// the running user, not writable by group or others, no unknown key.
    ///
    /// # Errors
    /// When the file is refused, is not valid TOML, or holds an invalid glob or CPU list.
    pub fn load(path: Option<&Path>) -> Result<Self, Error> {
        let (p, explicit) = path.map_or((Path::new(DEFAULT_PATH), false), |p| (p, true));
        let fail = |detail: String| Error::Config { path: p.display().to_string(), detail };
        let cfg = if explicit { read_toml(p)? } else { read_toml_optional(p)?.unwrap_or_default() };
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
        // The reader refuses a file others can write: set the mode, do not lean on the umask.
        std::fs::set_permissions(&p, std::os::unix::fs::PermissionsExt::from_mode(0o644)).unwrap();
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
        assert!(load("typo_key = 1").is_err(), "unknown keys are refused");
        assert!(Config::load(Some(Path::new("/nonexistent/p-rover.toml"))).is_err());
    }
}
