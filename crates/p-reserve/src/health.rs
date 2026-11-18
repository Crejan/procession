//! `preserve health`: the freshness of every pair; the exit code is the worst
//! level (0 ok, 1 warnings, 2 critical). 3: the ledger or the configuration
//! could not be read. 4: a usage error.
//!
//! It reads the ledger file and nothing else: it works without a daemon.

use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use p_reserve_core::Level;
use p_reserve_core::health::{Health, Reason, assess};
use p_reserve_core::textfile::Textfile;
use serde::Serialize;

use crate::config::{Config, DEFAULT_CONFIG};

pub const EXIT_FAILED: u8 = 3;
pub const EXIT_USAGE: u8 = 4;
const SCHEMA_VERSION: u32 = 1;

const USAGE: &str =
    "usage: preserve health [--config FILE] [--ledger FILE] [--format text|json] [--now UNIX_SECONDS]\n";

#[derive(Serialize)]
struct Report<'a> {
    schema_version: u32,
    #[serde(rename = "type")]
    kind: &'static str,
    exit_code: u8,
    #[serde(flatten)]
    health: &'a Health,
}

struct Options {
    config: PathBuf,
    ledger: Option<PathBuf>,
    json: bool,
    now: Option<u64>,
}

fn parse(args: &[&str]) -> Result<Options, String> {
    let mut options = Options { config: PathBuf::from(DEFAULT_CONFIG), ledger: None, json: false, now: None };
    let mut args = args.iter();
    while let Some(&flag) = args.next() {
        let mut value = |what: &str| args.next().copied().ok_or_else(|| format!("{flag} needs {what}"));
        match flag {
            "--config" => options.config = value("a file")?.into(),
            "--ledger" => options.ledger = Some(value("a file")?.into()),
            "--format" => {
                options.json = match value("text or json")? {
                    "json" => true,
                    "text" => false,
                    other => return Err(format!("unknown format {other:?}")),
                }
            }
            "--now" => {
                options.now = Some(
                    value("seconds")?.parse().map_err(|_| "--now takes whole seconds since the epoch".to_owned())?,
                )
            }
            other => return Err(format!("unknown argument {other:?}")),
        }
    }
    Ok(options)
}

/// Run the verb; returns the process exit code.
pub fn run(args: &[&str], out: &mut impl Write, err: &mut impl Write) -> u8 {
    let options = match parse(args) {
        Ok(options) => options,
        Err(message) => {
            let _ = write!(err, "preserve health: {message}\n{USAGE}");
            return EXIT_USAGE;
        }
    };
    match health(&options) {
        Ok(health) => {
            let code = health.exit_code();
            let written = if options.json {
                serde_json::to_writer(
                    &mut *out,
                    &Report { schema_version: SCHEMA_VERSION, kind: "health", exit_code: code, health: &health },
                )
                .map_err(std::io::Error::from)
                .and_then(|()| writeln!(out))
            } else {
                text(&health, out)
            };
            match written {
                Ok(()) => code,
                Err(e) => {
                    let _ = writeln!(err, "preserve health: cannot write the report: {e}");
                    EXIT_FAILED
                }
            }
        }
        Err(message) => {
            let _ = writeln!(err, "preserve health: {message}");
            EXIT_FAILED
        }
    }
}

fn health(options: &Options) -> Result<Health, String> {
    let explicit = options.config.as_path() != std::path::Path::new(DEFAULT_CONFIG);
    let config = match Config::load(&options.config).map_err(|e| e.to_string())? {
        Some(config) => config,
        None if explicit => return Err(format!("{} does not exist", options.config.display())),
        None => Config::default(),
    };
    let path = options.ledger.as_deref().unwrap_or(config.ledger_path());
    let file = Textfile::new(path, config.prefix()).map_err(|e| e.to_string())?;
    let ledger = file.load().map_err(|e| e.to_string())?;
    let now = options.now.map_or_else(SystemTime::now, |secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs));
    let mut declared = config.declared()?;
    if declared.is_empty() {
        let limits = config.default_limits()?;
        declared = ledger.pairs().map(|(pair, _)| (pair.clone(), limits)).collect();
    }
    Ok(assess(&ledger, declared.iter().map(|(pair, limits)| (pair, limits)), now))
}

fn level_word(level: Level) -> &'static str {
    match level {
        Level::Ok => "ok",
        Level::Warning => "warning",
        Level::Critical => "critical",
    }
}

fn reason_words(reason: &Reason) -> String {
    match reason {
        Reason::Overdue => "overdue".to_owned(),
        Reason::Stale => "stale".to_owned(),
        Reason::LastRun(outcome) => format!("last run {}", outcome.name()),
        Reason::Interrupted => "the last run began and never ended".to_owned(),
        Reason::Unreadable(count) => format!("{count} files could not be read"),
        Reason::NeverRun => "no run on record".to_owned(),
    }
}

fn text(health: &Health, out: &mut impl Write) -> std::io::Result<()> {
    writeln!(out, "{}", level_word(health.level))?;
    for pair in &health.pairs {
        let last = pair.last_success.map_or_else(
            || "never".to_owned(),
            |secs| humantime::format_rfc3339_seconds(SystemTime::UNIX_EPOCH + Duration::from_secs(secs)).to_string(),
        );
        let why: Vec<String> = pair.reasons.iter().map(reason_words).collect();
        writeln!(
            out,
            "  {} -> {}: {} (last success {last}){}{}",
            pair.source,
            pair.target,
            level_word(pair.level),
            if why.is_empty() { "" } else { "; " },
            why.join("; ")
        )?;
    }
    Ok(())
}
