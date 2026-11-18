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
                    other => return Err(format!("unknown format {}", p_reserve_core::text::shown(other))),
                }
            }
            "--to" if verb == Verb::Restore => options.to = Some(value("a destination")?.into()),
            flag if flag.starts_with("--") => {
                return Err(format!("unknown argument {}", p_reserve_core::text::shown(flag)));
            }
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

/// The most characters of the escaped form shown per field (a path can be 4096 bytes, and an escaped byte is up to six
/// characters). Proposed numbers: a name 1024, a path 8192, a host or a tag 512, an argument echoed 8192.
const NAME_CHARS: usize = 1024;
const PATH_CHARS: usize = 8192;
const HOST_CHARS: usize = 512;
const TAG_CHARS: usize = 512;

/// What is shown of a string from outside: the escape form, cut at a bound, and whether anything was escaped or cut.
struct Shown {
    text: String,
    flagged: bool,
    clipped: bool,
}

impl From<p_reserve_core::text::Clipped> for Shown {
    fn from(c: p_reserve_core::text::Clipped) -> Shown {
        Shown { flagged: c.flagged > 0, clipped: c.clipped, text: c.text }
    }
}

fn show(text: &str, max: usize) -> Shown {
    p_reserve_core::text::escape_clipped(text, max).into()
}

fn show_bytes(bytes: &[u8], max: usize) -> Shown {
    p_reserve_core::text::escape_bytes_clipped(bytes, max).into()
}

impl Shown {
    /// For text output: a cut is marked with an ellipsis.
    fn line(&self) -> String {
        if self.clipped { format!("{}…", self.text) } else { self.text.clone() }
    }
}

/// A snapshot as written to JSON. `escaped` is true if any of host, paths or tags held a character the rule refuses;
/// `clipped` if any was cut at its bound.
#[derive(Serialize)]
struct SnapshotRecord<'a> {
    id: &'a str,
    time: u64,
    host: String,
    paths: Vec<String>,
    tags: Vec<String>,
    escaped: bool,
    clipped: bool,
}

/// A directory entry as written to JSON: `name` is the escape form of the name's bytes, `escaped` says whether anything
/// was escaped and `clipped` whether the name was cut.
#[derive(Serialize)]
struct NodeRecord {
    name: String,
    kind: NodeKind,
    size: u64,
    mtime: Option<u64>,
    escaped: bool,
    clipped: bool,
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
    Failure { outcome: Outcome::NotRun, detail: p_reserve_core::text::for_log(&detail.into()) }
}

/// Whether this build can read a repository at all.
pub const HAS_ENGINE: bool = cfg!(feature = "engine-rustic");

#[cfg(feature = "engine-rustic")]
fn engine(target: &crate::config::TargetConfig, password: &str) -> Result<Box<dyn Engine>, Failure> {
    use p_reserve_core::rustic::{Location, RusticEngine};
    let location = Location { repository: target.repository.clone(), options: target.options.clone() };
    Ok(Box::new(RusticEngine::open(&location, password)?))
}

#[cfg(not(feature = "engine-rustic"))]
fn engine(_target: &crate::config::TargetConfig, _password: &str) -> Result<Box<dyn Engine>, Failure> {
    Err(plain("this build has no repository engine (built without the engine-rustic feature)"))
}

fn open(options: &Options) -> Result<(String, Box<dyn Engine>), Failure> {
    let config = Config::load(&options.config)
        .map_err(|e| plain(e.to_string()))?
        .ok_or_else(|| plain(format!("{} does not exist", options.config.display())))?;
    let name = &options.positional[0];
    let target = config.target(name).ok_or_else(|| plain(format!("no target called {name:?} in the configuration")))?;
    let password = read_secret(&target.password_file).map_err(|e| plain(e.to_string()))?;
    Ok((name.clone(), engine(target, &password)?))
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
                }
                // the engine's own words are not forwarded to a machine reader: the outcome is the code
                let _ = emit(out, "error", Body { outcome: failure.outcome.name() });
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
                        let paths: Vec<String> = s.paths.iter().map(|p| show(p, PATH_CHARS).line()).collect();
                        writeln!(
                            out,
                            "{}  {}  {}  {}",
                            &s.id[..s.id.len().min(8)],
                            rfc3339(s.time),
                            show(&s.host, HOST_CHARS).line(),
                            paths.join(",")
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
                    snapshot: String,
                    path: String,
                    entries: Vec<NodeRecord>,
                }
                let entries = nodes.iter().map(node_record).collect();
                let body = Body {
                    target: &target,
                    snapshot: show(&options.positional[1], 128).line(),
                    path: show(path, PATH_CHARS).line(),
                    entries,
                };
                emit(out, "ls", body).map_err(io)
            } else {
                nodes
                    .iter()
                    .try_for_each(|n| {
                        let mark = match n.kind {
                            NodeKind::Dir => "/",
                            NodeKind::Symlink => "@",
                            _ => "",
                        };
                        writeln!(out, "{:>12}  {}{mark}", n.size, show_bytes(&n.name, NAME_CHARS).line())
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
                emit(out, "restore", Body { target: &target, destination: shown_path(destination), summary })
                    .map_err(io)
            } else {
                writeln!(
                    out,
                    "restored {} files, {} bytes, to {}",
                    summary.files,
                    summary.bytes,
                    shown_path(destination)
                )
                .map_err(io)
            }
        }
    }
}

fn shown_path(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    show_bytes(path.as_os_str().as_bytes(), PATH_CHARS).line()
}

fn snapshot_record(s: &Snapshot) -> SnapshotRecord<'_> {
    let host = show(&s.host, HOST_CHARS);
    let paths: Vec<Shown> = s.paths.iter().map(|p| show(p, PATH_CHARS)).collect();
    let tags: Vec<Shown> = s.tags.iter().map(|t| show(t, TAG_CHARS)).collect();
    let all = || std::iter::once(&host).chain(&paths).chain(&tags);
    let (escaped, clipped) = (all().any(|x| x.flagged), all().any(|x| x.clipped));
    SnapshotRecord {
        id: &s.id,
        time: unix(s.time),
        host: host.text.clone(),
        paths: paths.iter().map(|x| x.text.clone()).collect(),
        tags: tags.iter().map(|x| x.text.clone()).collect(),
        escaped,
        clipped,
    }
}

fn node_record(n: &Node) -> NodeRecord {
    let name = show_bytes(&n.name, NAME_CHARS);
    NodeRecord {
        name: name.text,
        kind: n.kind,
        size: n.size,
        mtime: n.mtime.map(unix),
        escaped: name.flagged,
        clipped: name.clipped,
    }
}
