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

/// What `probe setup` does with no arguments: the settings of `/etc/probe.toml` if it is there (and
/// valid), else the defaults. This is what the root timer runs.
///
/// # Errors
/// A settings file that exists and does not parse: a renewal does not guess then.
pub fn setup_defaults(config_text: Option<&str>, hostname: &str) -> Result<(PathBuf, String, PathBuf), String> {
    let Some(text) = config_text else {
        return Ok((PathBuf::from(crate::config::DEFAULT_HOST_KEY), hostname.to_string(), PathBuf::from("/etc/probe")));
    };
    let config = Config::parse(text)?;
    let out = config.service_key.parent().map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    if config.service_key.file_name().and_then(|n| n.to_str()) != Some("service-key") {
        return Err(
            "service_key must be named service-key: setup keeps the key and the certificate beside each other".into()
        );
    }
    Ok((config.host_key, config.host.unwrap_or_else(|| hostname.to_string()), out))
}

/// `probe setup [--host-key <file>] [--host <name>] [--out <dir>]`. With no arguments it renews, from
/// `/etc/probe.toml` or the defaults (the root timer's form).
pub fn setup(args: &[&str]) -> u8 {
    const USAGE: &str = "usage: probe setup [--if-due] [--host-key <file>] [--host <name>] [--out <dir>]   (no arguments: renew now, from /etc/probe.toml)";
    let (mut host_key, mut host, mut out, mut if_due) = (None, None, None, false);
    let mut rest = args.iter();
    while let Some(flag) = rest.next() {
        if *flag == "--if-due" {
            if_due = true;
            continue;
        }
        match (*flag, rest.next()) {
            ("--host-key", Some(value)) => host_key = Some(PathBuf::from(value)),
            ("--host", Some(value)) => host = Some((*value).to_string()),
            ("--out", Some(value)) => out = Some(PathBuf::from(value)),
            _ => {
                eprintln!("{USAGE}");
                return 64;
            }
        }
    }
    let hostname = crate::kit::hostname();
    let text = std::fs::read_to_string(crate::config::DEFAULT_FILE).ok();
    let (default_key, default_host, default_out) = match setup_defaults(text.as_deref(), &hostname) {
        Ok(defaults) => defaults,
        Err(why) => {
            eprintln!("probe setup: {}: {why}", crate::config::DEFAULT_FILE);
            return 64;
        }
    };
    let (host_key, host, out) =
        (host_key.unwrap_or(default_key), host.unwrap_or(default_host), out.unwrap_or(default_out));
    if if_due {
        let now = p_act::Timestamp::now().map_or(0, p_act::Timestamp::unix);
        return match crate::setup::run_if_due(&host_key, &host, &out, now) {
            Ok(crate::setup::IfDue::NotDue(days)) => {
                println!(
                    "Not due: {days} days left of the service's certificate (renewed when {} or fewer remain).",
                    crate::setup::RENEW_WHEN_DAYS_LEFT
                );
                0
            }
            Ok(crate::setup::IfDue::Did(done, reason)) => {
                println!("Due ({reason:?}). {}", crate::setup::note(done));
                0
            }
            Err(why) => {
                eprintln!("probe setup --if-due: {why}");
                1
            }
        };
    }
    match crate::setup::run(&host_key, &host, &out) {
        Ok(done) => {
            println!("{}", crate::setup::note(done));
            0
        }
        Err(why) => {
            eprintln!("probe setup: {why}");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = "person = \"jan\"\nconfirmed_key = \"/k/c.pub\"\nautomatic_key = \"/k/a.pub\"\npledge_socket = \"/run/p/service.sock\"\n";

    #[test]
    fn with_no_arguments_setup_takes_the_settings_file_or_the_defaults() {
        let (key, host, out) = setup_defaults(None, "h.example").unwrap();
        assert_eq!(
            (key, host.as_str(), out),
            (PathBuf::from("/etc/ssh/ssh_host_ed25519_key"), "h.example", PathBuf::from("/etc/probe"))
        );
        let text = format!(
            "{MINIMAL}host = \"a.example\"\nhost_key = \"/k/host\"\nservice_key = \"/srv/probe/service-key\"\n"
        );
        let (key, host, out) = setup_defaults(Some(&text), "h.example").unwrap();
        assert_eq!((key, host.as_str(), out), (PathBuf::from("/k/host"), "a.example", PathBuf::from("/srv/probe")));
        assert_eq!(setup_defaults(Some(MINIMAL), "h.example").unwrap().2, PathBuf::from("/etc/probe"));
    }

    #[test]
    fn a_settings_file_that_does_not_parse_or_names_the_key_oddly_is_not_guessed_around() {
        assert!(setup_defaults(Some("person"), "h").is_err());
        assert!(setup_defaults(Some(&format!("{MINIMAL}service_key = \"/etc/probe/other\"\n")), "h").is_err());
    }
}
