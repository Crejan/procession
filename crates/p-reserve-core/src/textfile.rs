//! The ledger as a Prometheus textfile: published for the node exporter's
//! textfile collector and read back on the next run.
//!
//! The first three families are fundament's, under a configurable prefix
//! (`fundament_` there, [`DEFAULT_PREFIX`] here):
//! `backup_last_success_timestamp_seconds`, `backup_last_added_bytes` and
//! `backup_first_attempt_timestamp_seconds`, labelled `source` and `target`.
//! Two more carry what `health` needs: `backup_last_unreadable_files` and
//! `backup_last_outcome{outcome="..."}` (value 1). A file that only has the
//! first three still loads, with no last outcome and no unreadable count.
//!
//! Every family is declared (`# HELP`, `# TYPE`) even when it has no sample,
//! so an alert sees an absent series. Timestamps are seconds since the epoch
//! with millisecond precision. The file is written atomically (a temporary
//! file in the same directory, synced, renamed) with an explicit mode, so the
//! umask of the caller changes nothing, and a reader sees the old file or the
//! new one, never half of one.
//!
//! Reading is strict: a malformed line fails the whole file rather than
//! yielding a ledger that forgets pairs (an empty ledger reads as "stale
//! everywhere"). A sample of a name this module does not know is ignored, so
//! a file written by a newer version still loads; every other deviation is an
//! error. A missing file is the first run and gives an empty ledger.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use thiserror::Error;

use crate::ledger::{Cause, Entry, Ledger, Pair};
use crate::outcome::Outcome;

/// The prefix of the metric names unless the caller chooses another.
pub const DEFAULT_PREFIX: &str = "preserve_";

/// The mode the ledger file is written with: readable by the exporter.
pub const FILE_MODE: u32 = 0o644;

/// A ledger file is at most this long.
pub const MAX_BYTES: u64 = 8 * 1024 * 1024;

const LAST_SUCCESS: &str = "backup_last_success_timestamp_seconds";
const ADDED_BYTES: &str = "backup_last_added_bytes";
const FIRST_ATTEMPT: &str = "backup_first_attempt_timestamp_seconds";
const UNREADABLE: &str = "backup_last_unreadable_files";
const LAST_OUTCOME: &str = "backup_last_outcome";
const LAST_ATTEMPT: &str = "backup_last_attempt_timestamp_seconds";

const FAMILIES: [(&str, &str); 6] = [
    (LAST_SUCCESS, "When the last backup of source to target succeeded"),
    (ADDED_BYTES, "Bytes the last successful backup of source to target added"),
    (FIRST_ATTEMPT, "When a source that never succeeded to target was first attempted"),
    (UNREADABLE, "Files the last successful backup of source to target could not read"),
    (
        LAST_OUTCOME,
        "How the last run of source to target ended (value 1, the outcome and an optional cause are labels)",
    ),
    (LAST_ATTEMPT, "When the last run of source to target of any outcome was recorded"),
];

/// Why a ledger file was refused or could not be written.
#[derive(Debug, Error)]
pub enum TextfileError {
    #[error("the metric prefix {0:?} is not a valid metric name part")]
    BadPrefix(String),
    #[error("cannot read {path}: {source}")]
    Read { path: String, source: io::Error },
    #[error("cannot write {path}: {source}")]
    Write { path: String, source: io::Error },
    #[error("{0} is not a regular file")]
    NotARegularFile(String),
    #[error("{0} is larger than the limit")]
    TooLarge(String),
    #[error("{0} is not UTF-8")]
    NotUtf8(String),
    #[error("{path}, line {line}: {problem}")]
    Malformed { path: String, line: usize, problem: String },
}

/// A ledger file and the metric prefix it is written under.
#[derive(Debug, Clone)]
pub struct Textfile {
    path: PathBuf,
    prefix: String,
}

impl Textfile {
    /// The ledger at `path`, metrics named `<prefix>backup_...`.
    pub fn new(path: impl Into<PathBuf>, prefix: &str) -> Result<Textfile, TextfileError> {
        let valid = prefix
            .chars()
            .enumerate()
            .all(|(i, c)| c.is_ascii_alphabetic() || c == '_' || c == ':' || (i > 0 && c.is_ascii_digit()));
        if !valid {
            return Err(TextfileError::BadPrefix(prefix.to_owned()));
        }
        Ok(Textfile { path: path.into(), prefix: prefix.to_owned() })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The ledger as last saved; empty if there is no file (the first run).
    /// A file that cannot be read or understood is an error, not an empty
    /// ledger.
    pub fn load(&self) -> Result<Ledger, TextfileError> {
        let shown = self.path.display().to_string();
        let read_err = |source| TextfileError::Read { path: shown.clone(), source };
        let mut file = match File::open(&self.path) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Ledger::default()),
            Err(e) => return Err(read_err(e)),
        };
        let meta = file.metadata().map_err(read_err)?;
        if !meta.is_file() {
            return Err(TextfileError::NotARegularFile(shown));
        }
        if meta.len() > MAX_BYTES {
            return Err(TextfileError::TooLarge(shown));
        }
        let mut bytes = Vec::new();
        (&mut file).take(MAX_BYTES + 1).read_to_end(&mut bytes).map_err(read_err)?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err(TextfileError::TooLarge(shown));
        }
        let text = String::from_utf8(bytes).map_err(|_| TextfileError::NotUtf8(shown.clone()))?;
        parse(&text, &self.prefix).map_err(|(line, problem)| TextfileError::Malformed { path: shown, line, problem })
    }

    /// Publish `ledger`, replacing the file atomically.
    pub fn save(&self, ledger: &Ledger) -> Result<(), TextfileError> {
        write_atomic(&self.path, render(ledger, &self.prefix).as_bytes(), FILE_MODE)
            .map_err(|source| TextfileError::Write { path: self.path.display().to_string(), source })
    }
}

fn escape_label(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// Seconds since the epoch, to the millisecond, without a trailing zero.
fn seconds(at: SystemTime) -> String {
    let since = at.duration_since(SystemTime::UNIX_EPOCH).unwrap_or(Duration::ZERO);
    match since.subsec_millis() {
        0 => since.as_secs().to_string(),
        ms => format!("{}.{ms:03}", since.as_secs()).trim_end_matches('0').to_owned(),
    }
}

/// The exposition text of `ledger`.
pub fn render(ledger: &Ledger, prefix: &str) -> String {
    let mut out = String::new();
    for (name, help) in FAMILIES {
        let _ = writeln!(out, "# HELP {prefix}{name} {help}\n# TYPE {prefix}{name} gauge");
        for (pair, entry) in ledger.pairs() {
            let labels = format!("source=\"{}\",target=\"{}\"", escape_label(&pair.source), escape_label(&pair.target));
            let sample = match name {
                LAST_SUCCESS => entry.last_success.map(|at| (labels, seconds(at))),
                ADDED_BYTES => entry.last_success.map(|_| (labels, entry.last_added_bytes.to_string())),
                UNREADABLE => entry.last_success.map(|_| (labels, entry.last_unreadable.to_string())),
                FIRST_ATTEMPT => entry.first_attempt.map(|at| (labels, seconds(at))),
                LAST_ATTEMPT => entry.last_attempt.map(|at| (labels, seconds(at))),
                _ => entry.last_outcome.map(|o| {
                    let cause = entry.last_cause.map_or(String::new(), |c| format!(",cause=\"{}\"", c.name()));
                    (format!("{labels},outcome=\"{}\"{cause}", o.name()), "1".to_owned())
                }),
            };
            if let Some((labels, value)) = sample {
                let _ = writeln!(out, "{prefix}{name}{{{labels}}} {value}");
            }
        }
    }
    out
}

/// Read the exposition text written by [`render`] (or by fundament). On
/// failure: the 1-based line and what is wrong with it.
pub fn parse(text: &str, prefix: &str) -> Result<Ledger, (usize, String)> {
    let mut entries: std::collections::BTreeMap<Pair, Entry> = std::collections::BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        let fail = |problem: &str| (number, problem.to_owned());
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, labels, rest) = split_sample(line).map_err(|p| fail(&p))?;
        let Some(family) = name.strip_prefix(prefix) else { continue };
        if !FAMILIES.iter().any(|(known, _)| *known == family) {
            continue;
        }
        let mut source = None;
        let mut target = None;
        let mut outcome = None;
        let mut cause = None;
        for (key, value) in labels {
            let slot = match key.as_str() {
                "source" => &mut source,
                "target" => &mut target,
                "outcome" => &mut outcome,
                "cause" => &mut cause,
                other => return Err(fail(&format!("unknown label {other:?}"))),
            };
            if slot.replace(value).is_some() {
                return Err(fail(&format!("label {key:?} given twice")));
            }
        }
        let (Some(source), Some(target)) = (source, target) else {
            return Err(fail("a sample needs both a source and a target label"));
        };
        if outcome.is_some() != (family == LAST_OUTCOME) || (cause.is_some() && outcome.is_none()) {
            return Err(fail("the outcome and cause labels belong to the last-outcome family, and only to it"));
        }
        let pair = Pair::new(source, target);
        if !seen.insert((family.to_owned(), pair.clone())) {
            return Err(fail("the same sample twice"));
        }
        let value = rest.split_whitespace().next().ok_or_else(|| fail("no value"))?;
        let entry = entries.entry(pair).or_default();
        match family {
            LAST_ATTEMPT => entry.last_attempt = Some(time(value).map_err(|p| fail(&p))?),
            LAST_SUCCESS => entry.last_success = Some(time(value).map_err(|p| fail(&p))?),
            FIRST_ATTEMPT => entry.first_attempt = Some(time(value).map_err(|p| fail(&p))?),
            ADDED_BYTES => entry.last_added_bytes = count(value).map_err(|p| fail(&p))?,
            UNREADABLE => entry.last_unreadable = count(value).map_err(|p| fail(&p))?,
            _ => {
                if value != "1" {
                    return Err(fail("an outcome sample has the value 1"));
                }
                let name = outcome.unwrap_or_default();
                entry.last_outcome =
                    Some(Outcome::from_name(&name).ok_or_else(|| fail(&format!("unknown outcome {name:?}")))?);
                entry.last_cause = match cause {
                    None => None,
                    Some(name) => {
                        Some(Cause::from_name(&name).ok_or_else(|| fail(&format!("unknown cause {name:?}")))?)
                    }
                };
            }
        }
    }
    let mut ledger = Ledger::default();
    for (pair, entry) in entries {
        ledger.insert(pair, entry);
    }
    Ok(ledger)
}

fn count(value: &str) -> Result<u64, String> {
    value.parse().map_err(|_| format!("{value:?} is not a non-negative whole number"))
}

fn time(value: &str) -> Result<SystemTime, String> {
    let bad = || format!("{value:?} is not a time in seconds since the epoch");
    let secs: f64 = value.parse().map_err(|_| bad())?;
    if !secs.is_finite() || secs < 0.0 {
        return Err(bad());
    }
    let millis = (secs * 1000.0).round();
    if millis >= u64::MAX as f64 {
        return Err(bad());
    }
    Ok(SystemTime::UNIX_EPOCH + Duration::from_millis(millis as u64))
}

type Labels = Vec<(String, String)>;

/// `name{k="v",...} rest` or `name rest`.
fn split_sample(line: &str) -> Result<(&str, Labels, &str), String> {
    let end = line.find(['{', ' ', '\t']).ok_or("no value")?;
    let (name, rest) = line.split_at(end);
    if name.is_empty() {
        return Err("no metric name".to_owned());
    }
    let Some(inner) = rest.strip_prefix('{') else { return Ok((name, Vec::new(), rest)) };
    let mut labels = Vec::new();
    let mut chars = inner.char_indices().peekable();
    loop {
        match chars.peek() {
            Some((_, '}')) => {
                let (at, _) = chars.next().unwrap_or((0, '}'));
                return Ok((name, labels, &inner[at + 1..]));
            }
            None => return Err("unterminated label set".to_owned()),
            Some(_) => {}
        }
        let mut key = String::new();
        while let Some(&(_, c)) = chars.peek() {
            if c == '=' {
                break;
            }
            key.push(c);
            chars.next();
        }
        if chars.next().is_none() || key.is_empty() {
            return Err("a label needs a name and =".to_owned());
        }
        if chars.next().map(|(_, c)| c) != Some('"') {
            return Err("a label value is in double quotes".to_owned());
        }
        let mut value = String::new();
        loop {
            match chars.next().map(|(_, c)| c) {
                None => return Err("unterminated label value".to_owned()),
                Some('"') => break,
                Some('\\') => match chars.next().map(|(_, c)| c) {
                    Some('n') => value.push('\n'),
                    Some('"') => value.push('"'),
                    Some('\\') => value.push('\\'),
                    _ => return Err("an escape in a label value is \\\\, \\\" or \\n".to_owned()),
                },
                Some(c) => value.push(c),
            }
        }
        labels.push((key, value));
        if let Some((_, ',')) = chars.peek() {
            chars.next();
        }
    }
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Write `bytes` to `path` so that a reader sees the old file or the new one:
/// a temporary file next to it, with `mode` set explicitly (the umask does
/// not apply), synced, renamed over `path`, and the directory synced.
pub fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let name = path.file_name().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let temp = dir.join(format!(
        ".{}.{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).mode(mode).open(&temp)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&temp, path)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;
    use crate::ledger::Run;

    fn t(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn sample() -> Ledger {
        let mut ledger = Ledger::default();
        ledger.record(Pair::new("home", "offsite"), Run::stored(10, 0), t(1_700_000_000));
        ledger.record(Pair::new("docs \"x\"\\\nnew", "off,site"), Run::stored(7, 3), t(1_700_000_500));
        ledger.record(Pair::new("never", "offsite"), Run::ended(Outcome::Locked), t(1_700_000_900));
        ledger.record(Pair::new("cut", "offsite"), Run::interrupted(), t(1_700_001_000));
        ledger
    }

    #[test]
    fn render_then_parse_gives_the_same_ledger_with_awkward_labels() {
        let ledger = sample();
        let text = render(&ledger, DEFAULT_PREFIX);
        assert_eq!(parse(&text, DEFAULT_PREFIX), Ok(ledger));
    }

    #[test]
    fn every_family_is_declared_even_when_empty_and_the_names_are_fundaments_under_a_prefix() {
        let text = render(&Ledger::default(), "fundament_");
        for (name, _) in FAMILIES {
            assert!(text.contains(&format!("# HELP fundament_{name} ")), "{name}");
            assert!(text.contains(&format!("# TYPE fundament_{name} gauge\n")), "{name}");
        }
        assert_eq!(parse(&text, "fundament_"), Ok(Ledger::default()));
    }

    #[test]
    fn milliseconds_survive_and_whole_seconds_have_no_fraction() {
        let mut ledger = Ledger::default();
        let at = SystemTime::UNIX_EPOCH + Duration::from_millis(1_700_000_000_120);
        ledger.record(Pair::new("a", "b"), Run::stored(1, 0), at);
        let text = render(&ledger, "p_");
        assert!(text.contains("} 1700000000.12\n"), "{text}");
        assert_eq!(parse(&text, "p_").unwrap(), ledger);
        assert!(render(&sample(), "p_").contains("} 1700000000\n"));
    }

    #[test]
    fn a_file_with_only_fundaments_three_families_loads_without_an_outcome() {
        let text = "# HELP fundament_backup_last_success_timestamp_seconds x\n\
                    # TYPE fundament_backup_last_success_timestamp_seconds gauge\n\
                    fundament_backup_last_success_timestamp_seconds{source=\"tank/home\",target=\"box\"} 1700000000\n\
                    fundament_backup_last_added_bytes{source=\"tank/home\",target=\"box\"} 123\n\
                    fundament_backup_first_attempt_timestamp_seconds{source=\"new\",target=\"box\"} 1700000100\n\
                    some_other_metric 4\n";
        let ledger = parse(text, "fundament_").unwrap();
        let home = ledger.entry(&Pair::new("tank/home", "box")).unwrap();
        assert_eq!((home.last_success, home.last_added_bytes, home.last_outcome), (Some(t(1_700_000_000)), 123, None));
        assert_eq!(ledger.entry(&Pair::new("new", "box")).unwrap().first_attempt, Some(t(1_700_000_100)));
    }

    #[test]
    fn a_malformed_file_is_refused_with_its_line_and_never_read_as_empty() {
        let p = "p_";
        let cases = [
            ("p_backup_last_added_bytes{source=\"a\",target=\"b\"} -1\n", 1),
            ("\np_backup_last_added_bytes{source=\"a\",target=\"b\"} x\n", 2),
            ("p_backup_last_success_timestamp_seconds{source=\"a\",target=\"b\"} NaN\n", 1),
            ("p_backup_last_success_timestamp_seconds{source=\"a\",target=\"b\"} -5\n", 1),
            ("p_backup_last_added_bytes{source=\"a\"} 1\n", 1),
            ("p_backup_last_added_bytes{source=\"a\",target=\"b\",x=\"y\"} 1\n", 1),
            (
                "p_backup_last_added_bytes{source=\"a\",target=\"b\"} 1\np_backup_last_added_bytes{source=\"a\",target=\"b\"} 2\n",
                2,
            ),
            ("p_backup_last_added_bytes{source=\"a\",target=\"b\"\n", 1),
            ("p_backup_last_added_bytes{source=\"a\\q\",target=\"b\"} 1\n", 1),
            ("p_backup_last_outcome{source=\"a\",target=\"b\",outcome=\"great\"} 1\n", 1),
            ("p_backup_last_outcome{source=\"a\",target=\"b\"} 1\n", 1),
            ("p_backup_last_added_bytes{source=\"a\",target=\"b\",outcome=\"ok\"} 1\n", 1),
            ("p_backup_last_added_bytes\n", 1),
            ("p_backup_last_outcome{source=\"a\",target=\"b\",outcome=\"failed\",cause=\"cosmic-rays\"} 1\n", 1),
            ("p_backup_last_added_bytes{source=\"a\",target=\"b\",cause=\"interrupted\"} 1\n", 1),
        ];
        for (text, line) in cases {
            assert_eq!(parse(text, p).map_err(|e| e.0), Err(line), "{text:?}");
        }
    }

    #[test]
    fn the_prefix_must_be_a_metric_name_part() {
        assert!(Textfile::new("/x", "preserve_").is_ok());
        for bad in ["9p_", "a b", "a-", "é"] {
            assert!(matches!(Textfile::new("/x", bad), Err(TextfileError::BadPrefix(_))), "{bad}");
        }
    }

    #[test]
    fn save_then_load_round_trips_and_a_missing_file_is_an_empty_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let file = Textfile::new(dir.path().join("ledger.prom"), DEFAULT_PREFIX).unwrap();
        assert_eq!(file.load().unwrap(), Ledger::default());
        file.save(&sample()).unwrap();
        assert_eq!(file.load().unwrap(), sample());
        let mut changed = sample();
        changed.record(Pair::new("home", "offsite"), Run::ended(Outcome::Failed), t(1_700_001_000));
        file.save(&changed).unwrap();
        assert_eq!(file.load().unwrap(), changed);
    }

    #[test]
    fn a_corrupt_ledger_file_is_an_error_not_an_empty_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.prom");
        let file = Textfile::new(&path, DEFAULT_PREFIX).unwrap();
        fs::write(&path, "preserve_backup_last_added_bytes{source=\"a\"} 1\n").unwrap();
        assert!(matches!(file.load(), Err(TextfileError::Malformed { line: 1, .. })));
        fs::write(&path, [0xff, 0xfe]).unwrap();
        assert!(matches!(file.load(), Err(TextfileError::NotUtf8(_))));
        fs::remove_file(&path).unwrap();
        fs::create_dir(&path).unwrap();
        assert!(matches!(file.load(), Err(TextfileError::NotARegularFile(_))));
    }

    #[test]
    fn saving_leaves_no_temporary_file_and_fails_cleanly_in_a_missing_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = Textfile::new(dir.path().join("ledger.prom"), DEFAULT_PREFIX).unwrap();
        file.save(&sample()).unwrap();
        let names: Vec<_> = fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names, vec![std::ffi::OsString::from("ledger.prom")]);
        let missing = Textfile::new(dir.path().join("no/such/ledger.prom"), DEFAULT_PREFIX).unwrap();
        assert!(matches!(missing.save(&sample()), Err(TextfileError::Write { .. })));
    }

    fn mode_under_umask(mask: libc::mode_t) -> u32 {
        let dir = tempfile::tempdir().unwrap(); // made before the mask: 0277 would leave it unwritable
        let file = Textfile::new(dir.path().join("ledger.prom"), DEFAULT_PREFIX).unwrap();
        crate::umask::with(mask, || file.save(&sample())).unwrap();
        fs::metadata(file.path()).unwrap().mode() & 0o7777
    }

    #[test]
    fn the_mode_is_explicit_whatever_the_umask() {
        // no mask that takes the owner's own permissions away (0277 did): the umask is process-wide, and a mask like
        // that, set while another test creates files, makes that test fail with "permission denied"
        for mask in [0o002, 0o022, 0o077, 0o000, 0o007] {
            assert_eq!(mode_under_umask(mask), FILE_MODE, "umask {mask:04o}");
        }
    }

    #[test]
    fn an_existing_file_with_another_mode_comes_out_with_the_explicit_one() {
        let dir = tempfile::tempdir().unwrap();
        let file = Textfile::new(dir.path().join("ledger.prom"), DEFAULT_PREFIX).unwrap();
        fs::write(file.path(), "").unwrap();
        fs::set_permissions(file.path(), fs::Permissions::from_mode(0o666)).unwrap();
        file.save(&sample()).unwrap();
        assert_eq!(fs::metadata(file.path()).unwrap().mode() & 0o7777, FILE_MODE);
    }
}
