//! The broker's configuration file (JSON), and the broker built from it.
//!
//! Every setting that has a sensible default is optional. The file's format is
//! an interim one: the workspace convention is TOML, which needs a dependency
//! the owner has not approved.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use thiserror::Error;

use crate::core::{Core, Settings};
use crate::crypto::SshCrypto;
use crate::log::FileLog;
use crate::net::{Broker, SystemClock, Timeouts};
use crate::site::{Site, SiteError};

/// Why the configuration could not be used.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error(transparent)]
    Settings(#[from] p_act::settings::SettingsError),
    #[error(transparent)]
    Site(#[from] SiteError),
    #[error(transparent)]
    Perm(#[from] crate::perm::PermError),
    #[error(transparent)]
    State(#[from] crate::core::StateError),
    #[error("`listen` names no address")]
    NoAddress,
    #[error("cannot open the log {path}: {source}")]
    Log { path: String, source: std::io::Error },
}

fn five() -> usize {
    5
}

fn sixteen() -> usize {
    16
}

fn max_connections() -> usize {
    512
}

/// The configuration file: one JSON object, an unknown member refused, the file refused if anyone but its owner
/// or root can write it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The site file: persons, hosts, keys.
    pub site: PathBuf,
    /// Where to listen, `host:port`, one or several. A service and a pledge may use the same address; all
    /// addresses behave the same.
    pub listen: Vec<String>,
    /// The TLS certificate chain and key (PEM), from the site's TLS root.
    pub tls_cert: PathBuf,
    pub tls_key: PathBuf,
    /// The broker's private key; its certificate (`broker`, from the site CA) is `<key>-cert.pub` beside it.
    pub broker_key: PathBuf,
    /// Where the register is kept across restarts.
    pub state_dir: PathBuf,
    /// The log: a JSON line per request.
    pub log: PathBuf,
    /// How many requests of one agent may wait (five by default).
    #[serde(default = "five")]
    pub max_waiting_per_agent: usize,
    /// Connections in total, and from one address.
    #[serde(default = "max_connections")]
    pub max_connections: usize,
    #[serde(default = "sixteen")]
    pub max_connections_per_address: usize,
}

impl Config {
    /// Read the file with `p_act::settings`: one JSON object, no duplicate member, no unknown member, a regular file
    /// that nobody but its owner (or root) can write. At least one address to listen on.
    pub fn read(path: &Path) -> Result<Config, ConfigError> {
        let config: Config = p_act::settings::read(path)?;
        if config.listen.is_empty() {
            return Err(ConfigError::NoAddress);
        }
        Ok(config)
    }

    /// The broker this configuration describes, not yet listening.
    pub fn build(&self) -> Result<Arc<Broker>, ConfigError> {
        let site = Arc::new(Site::read(&self.site)?);
        let register = Core::read_state(&self.state_dir.join("register.json"))?;
        let log = FileLog::open(&self.log)
            .map_err(|source| ConfigError::Log { path: self.log.display().to_string(), source })?;
        let crypto = Arc::new(SshCrypto::new(&self.broker_key));
        let core = Core::new(
            Arc::clone(&site),
            Settings { max_waiting_per_agent: self.max_waiting_per_agent },
            register,
            Some(self.state_dir.join("register.json")),
            crypto.clone(),
            Box::new(log),
        );
        Ok(Broker::new(core, crypto, site, Arc::new(SystemClock), Timeouts::default(), 8))
    }
}
