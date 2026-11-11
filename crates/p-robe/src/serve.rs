//! `probe serve` and `probe setup`: the commands around the service.
//!
//! **The HTTP transport is not built** (no HTTP server crate can be built in
//! the environment this was written in; see `proposals/REPORT.md`). Everything
//! up to it is: the settings, the service and the MCP layer as a function from
//! an HTTP request to a response (`mcp::Mcp::handle`).

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use p_act::sign::{PublicKey, Signer};

use crate::audit::{Audit, Syslog};
use crate::config::Config;
use crate::pledge::PledgeLink;
use crate::runner::SudoRunner;
use crate::service::{Service, Settings};
use crate::store::UsedStore;

const DEFAULT_CONFIG: &str = "/etc/probe.toml";

/// Builds the service a configuration describes.
///
/// # Errors
/// What is missing or wrong, in words.
pub fn build(config: &Config) -> Result<Service, String> {
    let key = |path: &Path| PublicKey::read(path).map_err(|e| format!("{}: {e}", path.display()));
    let signer =
        Signer::certified(&config.service_key).map_err(|e| format!("{}: {e}", config.service_key.display()))?;
    let uid = match config.pledge_uid {
        Some(uid) => uid,
        None => config
            .pledge_socket
            .parent()
            .and_then(|dir| dir.metadata().ok())
            .map(|meta| meta.uid())
            .ok_or("pledge_uid is not set and the socket's directory cannot be read")?,
    };
    let store = UsedStore::new(&config.used_dir);
    store.ensure().map_err(|e| format!("{}: {e}", config.used_dir.display()))?;
    if let Some(now) = p_act::Timestamp::now() {
        store.purge(now);
    }
    let syslog = Syslog::new();
    let log = Box::new(move |line: &str| {
        let _ = syslog.write(line);
    });
    Ok(Service::new(
        Settings {
            host: config.host.clone().unwrap_or_else(crate::kit::hostname),
            person: config.person.clone(),
            confirmed: key(&config.confirmed_key)?,
            automatic: key(&config.automatic_key)?,
            max_waiting: config.max_waiting,
        },
        signer,
        store,
        PledgeLink { socket: config.pledge_socket.clone(), uid },
        Box::new(SudoRunner { sudo: PathBuf::from("/usr/bin/sudo"), probe: config.probe.clone() }),
        log,
    ))
}

/// `probe serve [--config <file>]`. Returns the exit code.
pub fn serve(args: &[&str]) -> u8 {
    let path = match args {
        [] => DEFAULT_CONFIG,
        ["--config", path] => path,
        _ => {
            eprintln!("usage: probe serve [--config <file>]");
            return 64;
        }
    };
    let built = std::fs::read_to_string(path)
        .map_err(|e| format!("{path}: {e}"))
        .and_then(|text| Config::parse(&text).map_err(|e| format!("{path}: {e}")))
        .and_then(|config| build(&config).map(|service| (config, service)));
    match built {
        Ok((config, service)) => {
            let reachable = crate::pledge::reachable(&service.pledge);
            eprintln!(
                "probe serve: the service is built for {} (pledge {}); the HTTP transport on {} is not built yet",
                config.person,
                if reachable { "reachable" } else { "not reachable" },
                config.listen
            );
            2
        }
        Err(why) => {
            eprintln!("probe serve: {why}");
            64
        }
    }
}

/// `probe setup --host-key <file> [--host <name>] [--out <dir>]`.
pub fn setup(args: &[&str]) -> u8 {
    let (mut host_key, mut host, mut out) = (None, None, "/etc/probe");
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        match (*flag, rest.next()) {
            ("--host-key", Some(value)) => host_key = Some(*value),
            ("--host", Some(value)) => host = Some((*value).to_string()),
            ("--out", Some(value)) => out = value,
            _ => {
                eprintln!("usage: probe setup --host-key <file> [--host <name>] [--out <dir>]");
                return 64;
            }
        }
    }
    let Some(host_key) = host_key else {
        eprintln!("usage: probe setup --host-key <file> [--host <name>] [--out <dir>]");
        return 64;
    };
    let host = host.unwrap_or_else(crate::kit::hostname);
    match crate::setup::run(Path::new(host_key), &host, Path::new(out)) {
        Ok(()) => {
            println!("{}", crate::setup::NOTE);
            0
        }
        Err(why) => {
            eprintln!("probe setup: {why}");
            1
        }
    }
}
