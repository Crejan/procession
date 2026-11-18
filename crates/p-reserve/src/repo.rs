//! The verbs that read a repository: `snapshots`, `ls`, `restore`.
//!
//! They open the repository themselves: they work without a daemon. Exit
//! codes: 0 done; 3 failed (the outcome is named on stderr, or in the JSON
//! `error` object); 4 usage error. The password comes from the target's
//! `password_file`, never from an argument or the environment.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use p_reserve_core::Outcome;
use p_reserve_core::engine::{Engine, EngineError, Node, NodeKind, RestoreSummary, Snapshot};
use p_reserve_core::rustic::{Location, RusticEngine};
use serde::Serialize;

use crate::config::{Config, DEFAULT_CONFIG, read_secret};
use crate::health::{EXIT_FAILED, EXIT_USAGE};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Snapshots,
    Ls,
    Restore,
}

impl Verb {
    fn name(self) -> &'static str {
        match self {
            Verb::Snapshots => "snapshots",
            Verb::Ls => "ls",
            Verb::Restore => "restore",
        }
    }

    fn usage(self) -> &'static str {
        match self {
            Verb::Snapshots => "usage: preserve snapshots <target> [--config FILE] [--format text|json]\n",
            Verb::Ls => "usage: preserve ls <target> <snapshot> [path] [--config FILE] [--format text|json]\n",
            Verb::Restore => {
                "usage: preserve restore <target> <snapshot> <path> --to <absolute destination> [--config FILE] [--format text|json]\n"
            }
        }
    }
}

struct Options {
    config: PathBuf,
    json: bool,
    to: Option<PathBuf>,
    positional: Vec<String>,
}

fn parse(verb: Verb, args: &[&str]) -> Result<Options, String> {
    let mut options = Options { config: PathBuf::from(DEFAULT_CONFIG), json: false, to: None, positional: Vec::new() };
    let mut args = args.iter();
    while let Some(&arg) = args.next() {
        let mut value = |what: &str| args.next().copied().ok_or_else(|| format!("{arg} needs {what}"));
        match arg {
            "--config" => options.config = value("a file")?.into(),
            "--format" => {
                options.json = match value("text or json")? {
                    "json" => true,
                    "text" => false,
                    other => return Err(format!("unknown format {other:?}")),
                }
            }
            "--to" if verb == Verb::Restore => options.to = Some(value("a destination")?.into()),
            flag if flag.starts_with("--") => return Err(format!("unknown argument {flag:?}")),
            positional => options.positional.push(positional.to_owned()),
        }
    }
    let (min, max) = match verb {
        Verb::Snapshots => (1, 1),
        Verb::Ls => (2, 3),
        Verb::Restore => (3, 3),
    };
    if !(min..=max).contains(&options.positional.len()) {
        return Err("wrong number of arguments".to_owned());
    }
    if verb == Verb::Restore && options.to.is_none() {
        return Err("restore needs --to".to_owned());
    }
    Ok(options)
}

fn unix(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs())
}

fn rfc3339(time: SystemTime) -> String {
    humantime::format_rfc3339_seconds(SystemTime::UNIX_EPOCH + Duration::from_secs(unix(time))).to_string()
}

#[derive(Serialize)]
struct SnapshotRecord<'a> {
    id: &'a str,
    time: u64,
    host: &'a str,
    paths: &'a [String],
    tags: &'a [String],
}

#[derive(Serialize)]
struct NodeRecord<'a> {
    name: &'a str,
    kind: NodeKind,
    size: u64,
    mtime: Option<u64>,
}

#[derive(Serialize)]
struct Envelope<'a, T: Serialize> {
    schema_version: u32,
    #[serde(rename = "type")]
    kind: &'static str,
    #[serde(flatten)]
    body: T,
    #[serde(skip)]
    _marker: std::marker::PhantomData<&'a ()>,
}

fn emit<T: Serialize>(out: &mut impl Write, kind: &'static str, body: T) -> std::io::Result<()> {
    serde_json::to_writer(
        &mut *out,
        &Envelope { schema_version: SCHEMA_VERSION, kind, body, _marker: std::marker::PhantomData },
    )?;
    writeln!(out)
}

/// Why a verb did not finish: the outcome, in words for a log.
struct Failure {
    outcome: Outcome,
    detail: String,
}

impl From<EngineError> for Failure {
    fn from(e: EngineError) -> Failure {
        Failure { outcome: e.outcome, detail: e.detail }
    }
}

fn plain(detail: impl Into<String>) -> Failure {
    Failure {
        outcome: Outcome::NotRun,
        detail: p_reserve_core::text::for_display(&detail.into(), p_reserve_core::text::MAX_DETAIL),
    }
}

fn open(options: &Options) -> Result<(String, RusticEngine), Failure> {
    let config = Config::load(&options.config)
        .map_err(|e| plain(e.to_string()))?
        .ok_or_else(|| plain(format!("{} does not exist", options.config.display())))?;
    let name = &options.positional[0];
    let target = config.target(name).ok_or_else(|| plain(format!("no target called {name:?} in the configuration")))?;
    let password = read_secret(&target.password_file).map_err(|e| plain(e.to_string()))?;
    let location = Location { repository: target.repository.clone(), options: target.options.clone() };
    Ok((name.clone(), RusticEngine::open(&location, &password)?))
}

/// Run the verb; returns the process exit code.
pub fn run(verb: Verb, args: &[&str], out: &mut impl Write, err: &mut impl Write) -> u8 {
    let options = match parse(verb, args) {
        Ok(options) => options,
        Err(message) => {
            let _ = write!(err, "preserve {}: {message}\n{}", verb.name(), verb.usage());
            return EXIT_USAGE;
        }
    };
    match execute(verb, &options, out) {
        Ok(()) => 0,
        Err(failure) => {
            if options.json {
                #[derive(Serialize)]
                struct Body {
                    outcome: &'static str,
                    /// The engine's own words, for a log; not for display.
                    detail: String,
                }
                let _ = emit(out, "error", Body { outcome: failure.outcome.name(), detail: failure.detail });
            } else {
                let _ = writeln!(err, "preserve {}: {}: {}", verb.name(), failure.outcome.name(), failure.detail);
            }
            EXIT_FAILED
        }
    }
}

fn execute(verb: Verb, options: &Options, out: &mut impl Write) -> Result<(), Failure> {
    let io = |e: std::io::Error| plain(format!("cannot write the result: {e}"));
    let (target, engine) = open(options)?;
    match verb {
        Verb::Snapshots => {
            let snapshots = engine.snapshots()?;
            if options.json {
                #[derive(Serialize)]
                struct Body<'a> {
                    target: &'a str,
                    snapshots: Vec<SnapshotRecord<'a>>,
                }
                let records = snapshots.iter().map(snapshot_record).collect();
                emit(out, "snapshots", Body { target: &target, snapshots: records }).map_err(io)
            } else {
                snapshots
                    .iter()
                    .try_for_each(|s| {
                        writeln!(
                            out,
                            "{}  {}  {}  {}",
                            &s.id[..s.id.len().min(8)],
                            rfc3339(s.time),
                            s.host,
                            s.paths.join(",")
                        )
                    })
                    .map_err(io)
            }
        }
        Verb::Ls => {
            let path = options.positional.get(2).map_or("/", String::as_str);
            let nodes = engine.list(&options.positional[1], path)?;
            if options.json {
                #[derive(Serialize)]
                struct Body<'a> {
                    target: &'a str,
                    snapshot: &'a str,
                    path: &'a str,
                    entries: Vec<NodeRecord<'a>>,
                }
                let entries = nodes.iter().map(node_record).collect();
                emit(out, "ls", Body { target: &target, snapshot: &options.positional[1], path, entries }).map_err(io)
            } else {
                nodes
                    .iter()
                    .try_for_each(|n| {
                        let mark = match n.kind {
                            NodeKind::Dir => "/",
                            NodeKind::Symlink => "@",
                            _ => "",
                        };
                        writeln!(out, "{:>12}  {}{mark}", n.size, n.name)
                    })
                    .map_err(io)
            }
        }
        Verb::Restore => {
            let destination = options.to.as_deref().unwrap_or(Path::new(""));
            let summary: RestoreSummary =
                engine.restore(&options.positional[1], &options.positional[2], destination)?;
            if options.json {
                #[derive(Serialize)]
                struct Body<'a> {
                    target: &'a str,
                    destination: String,
                    #[serde(flatten)]
                    summary: RestoreSummary,
                }
                emit(out, "restore", Body { target: &target, destination: destination.display().to_string(), summary })
                    .map_err(io)
            } else {
                writeln!(out, "restored {} files, {} bytes, to {}", summary.files, summary.bytes, destination.display())
                    .map_err(io)
            }
        }
    }
}

fn snapshot_record(s: &Snapshot) -> SnapshotRecord<'_> {
    SnapshotRecord { id: &s.id, time: unix(s.time), host: &s.host, paths: &s.paths, tags: &s.tags }
}

fn node_record(n: &Node) -> NodeRecord<'_> {
    NodeRecord { name: &n.name, kind: n.kind, size: n.size, mtime: n.mtime.map(unix) }
}
