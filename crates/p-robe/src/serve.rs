//! `probe serve` and `probe setup`: the commands around the service.
//!
//! `probe serve` builds the service from `/etc/probe.json` and serves MCP over HTTP on `listen`
//! (`http.rs`: `hyper`, one request per connection). Nothing of the HTTP has run over a TCP
//! socket in the environment this was written in (no port can be bound there); it is tested over
//! memory and over a Unix socket.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use p_act::sign::{PublicKey, Signer};

use crate::audit::{Audit, Syslog};
use crate::config::Config;
use crate::pledge::PledgeLink;
use crate::runner::SudoRunner;
use crate::service::{Service, Settings};
use crate::store::UsedStore;

const DEFAULT_CONFIG: &str = crate::config::DEFAULT_FILE;

/// An error message for a person: paths and words that came from files and arguments are made visible by the rule for
/// strings from outside (`text_rule`), and cut at a bound.
fn shown(message: &str) -> String {
    crate::text_rule::visible(message, 600).0
}

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
        Box::new(SudoRunner {
            sudo: PathBuf::from("/usr/bin/sudo"),
            probe: config.probe.clone(),
            limit: crate::runner::RUN_LIMIT,
        }),
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
    let built = Config::load(Path::new(path)).and_then(|config| build(&config).map(|service| (config, service)));
    let (config, service) = match built {
        Ok(built) => built,
        Err(why) => {
            eprintln!("probe serve: {}", shown(&why));
            return 64;
        }
    };
    eprintln!(
        "probe serve: for {}, pledge {}",
        config.person,
        if crate::pledge::reachable(&service.pledge) {
            "reachable"
        } else {
            "not reachable (calls will be unavailable until it is)"
        }
    );
    match run(&config.listen, Arc::new(service)) {
        Ok(()) => 0,
        Err(why) => {
            eprintln!("probe serve: {}", shown(&why));
            1
        }
    }
}

/// Listens on `listen` (an address like `127.0.0.1:8765`) and serves until the process ends.
///
/// # Errors
/// The address cannot be used.
pub fn run(listen: &str, service: Arc<Service>) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let listener =
            tokio::net::TcpListener::bind(listen).await.map_err(|e| format!("cannot listen on {listen}: {e}"))?;
        eprintln!("probe serve: listening on {}", shown(listen));
        // The sender is kept for as long as the process runs: dropping it would stop the loop.
        let (_keep, shutdown) = tokio::sync::oneshot::channel();
        crate::http::accept_loop(listener, service, crate::http::Limits::default(), shutdown).await;
        Ok(())
    })
}

/// What `probe setup` does with no arguments: the settings of `/etc/probe.json` if it is there (and
/// valid), else the defaults. This is what the root timer runs.
///
/// # Errors
/// A settings file that exists and does not parse: a renewal does not guess then.
pub fn setup_defaults(config: Option<&Config>, hostname: &str) -> Result<(PathBuf, String, PathBuf), String> {
    let Some(config) = config else {
        return Ok((PathBuf::from(crate::config::DEFAULT_HOST_KEY), hostname.to_string(), PathBuf::from("/etc/probe")));
    };
    let out = config.service_key.parent().map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    if config.service_key.file_name().and_then(|n| n.to_str()) != Some("service-key") {
        return Err(
            "service_key must be named service-key: setup keeps the key and the certificate beside each other".into()
        );
    }
    Ok((config.host_key.clone(), config.host.clone().unwrap_or_else(|| hostname.to_string()), out))
}

/// `probe setup [--host-key <file>] [--host <name>] [--out <dir>]`. With no arguments it renews, from
/// `/etc/probe.json` or the defaults (the root timer's form).
pub fn setup(args: &[&str]) -> u8 {
    const USAGE: &str = "usage: probe setup [--if-due] [--host-key <file>] [--host <name>] [--out <dir>]   (no arguments: renew now, from /etc/probe.json)";
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
    let config = match Config::load_optional(Path::new(crate::config::DEFAULT_FILE)) {
        Ok(config) => config,
        Err(why) => {
            eprintln!("probe setup: {}", shown(&why));
            return 64;
        }
    };
    let (default_key, default_host, default_out) = match setup_defaults(config.as_ref(), &hostname) {
        Ok(defaults) => defaults,
        Err(why) => {
            eprintln!("probe setup: {}: {}", crate::config::DEFAULT_FILE, shown(&why));
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
                eprintln!("probe setup --if-due: {}", shown(&why));
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
            eprintln!("probe setup: {}", shown(&why));
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"{"person":"jan","confirmed_key":"/k/c.pub","automatic_key":"/k/a.pub","pledge_socket":"/run/p/service.sock"}"#;

    fn with(extra: &str) -> Config {
        Config::parse(&format!("{}, {extra}}}", MINIMAL.trim_end_matches('}'))).unwrap()
    }

    #[test]
    fn with_no_arguments_setup_takes_the_settings_file_or_the_defaults() {
        let (key, host, out) = setup_defaults(None, "h.example").unwrap();
        assert_eq!(
            (key, host.as_str(), out),
            (PathBuf::from("/etc/ssh/ssh_host_ed25519_key"), "h.example", PathBuf::from("/etc/probe"))
        );
        let config = with(r#""host":"a.example","host_key":"/k/host","service_key":"/srv/probe/service-key""#);
        let (key, host, out) = setup_defaults(Some(&config), "h.example").unwrap();
        assert_eq!((key, host.as_str(), out), (PathBuf::from("/k/host"), "a.example", PathBuf::from("/srv/probe")));
        let minimal = Config::parse(MINIMAL).unwrap();
        assert_eq!(setup_defaults(Some(&minimal), "h.example").unwrap().2, PathBuf::from("/etc/probe"));
    }

    #[test]
    fn a_key_that_is_not_named_service_key_is_not_guessed_around() {
        assert!(setup_defaults(Some(&with(r#""service_key":"/etc/probe/other""#)), "h").is_err());
    }
}
