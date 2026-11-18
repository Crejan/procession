//! A verb that runs `prover` (`SPEC.md`, "A verb that runs `prover`").
//!
//! The row fixes the whole command: the absolute path, the words that never change, and the map from
//! each agent-facing parameter to the flag it becomes. Nothing from an agent is put in the command but the
//! values of those parameters, as plain words after the flag the row chose, and each was a number in the
//! row's range before it got here (`rate.rs`). The tool runs with a cleared environment and no standard
//! input. The object it prints is read with a limit of its own, checked, and written as the output
//! convention's lines; the tool's own code never becomes the dispatcher's, it travels as `rc` in the
//! trailer. What is not a usable result ends the call as **failed** (exit 70) with a cause that the audit
//! line carries: the output is then a header, one `error` record and a trailer, never half of a result.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::value::RawValue;

use crate::answer::{Answer, Full, header};
use crate::json::Record;
use crate::table::Env;
use crate::{clock, kit};

/// Where `prover` is on a host: beside `probe`, put there by the roll-out.
pub const PROVER_PATH: &str = "/usr/local/bin/prover";

/// The most of the tool's object that is read (more is `object-too-large`).
pub const OBJECT_LIMIT: u64 = 4 << 20;

/// The `schema_version` of the object this reads.
const SCHEMA_VERSION: u64 = 1;

/// Record types that are the dispatcher's: a record of the tool with one of them is a disagreement.
const RESERVED: [&str; 6] = ["header", "unreadable", "restored", "finding", "trailer", "error"];

/// One agent-facing parameter and the flag it becomes.
#[derive(Debug, Clone, Copy)]
pub struct Flag {
    /// `max` for `max=N`.
    pub param: &'static str,
    /// `--max`.
    pub flag: &'static str,
    /// Put after the number (`s` for seconds).
    pub unit: &'static str,
}

/// What a row of the table fixes about the tool it runs.
#[derive(Debug, Clone, Copy)]
pub struct Row {
    pub noun: &'static str,
    pub verb: &'static str,
    /// The `subcommand` the object must carry, and the first word of the command.
    pub subcommand: &'static str,
    /// The words that never change, after the subcommand.
    pub words: &'static [&'static str],
    pub flags: &'static [Flag],
    /// How long the tool may run before it is killed.
    pub timeout: Duration,
}

/// The argument vector after the path, from a row and the (validated) `key=value` parameters.
///
/// # Errors
/// A parameter the row has no flag for: the rating refused those before, so this is a disagreement.
pub fn command(row: &Row, args: &[String]) -> Result<Vec<String>, String> {
    let mut argv = vec![row.subcommand.to_string()];
    argv.extend(row.words.iter().map(|word| (*word).to_string()));
    for arg in args {
        let flag = arg
            .split_once('=')
            .and_then(|(key, value)| row.flags.iter().find(|f| f.param == key).map(|f| (f, value)))
            .filter(|(_, value)| !value.is_empty() && value.bytes().all(|b| b.is_ascii_digit()));
        let Some((flag, value)) = flag else { return Err(format!("no flag for {arg:?}")) };
        argv.push(flag.flag.to_string());
        argv.push(format!("{value}{}", flag.unit));
    }
    Ok(argv)
}

/// Why a run is not a usable result. `code()` is what the audit line says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// The tool could not be run at all (missing, or not safe to run as root).
    Tool(String),
    /// Exit 4: the row and the tool disagree about the arguments.
    Refused,
    /// An exit code the row does not know.
    Failed(i32),
    /// A signal ended it.
    Killed(i32),
    Timeout,
    NotAnObject,
    ObjectTooLarge,
    WrongObject,
    ReservedType,
}

impl Failure {
    /// The exact cause.
    #[must_use]
    pub fn code(&self) -> String {
        match self {
            Failure::Tool(why) => format!("tool-unusable:{why}"),
            Failure::Refused => "tool-refused".into(),
            Failure::Failed(code) => format!("tool-failed:{code}"),
            Failure::Killed(signal) => format!("tool-killed:{signal}"),
            Failure::Timeout => "tool-timeout".into(),
            Failure::NotAnObject => "not-an-object".into(),
            Failure::ObjectTooLarge => "object-too-large".into(),
            Failure::WrongObject => "wrong-object".into(),
            Failure::ReservedType => "reserved-type".into(),
        }
    }

    /// The code of the `error` record: the cause's name without its detail.
    fn record_code(&self) -> &'static str {
        match self {
            Failure::Tool(_) => "tool-unusable",
            Failure::Refused => "tool-refused",
            Failure::Failed(_) => "tool-failed",
            Failure::Killed(_) => "tool-killed",
            Failure::Timeout => "tool-timeout",
            Failure::NotAnObject => "not-an-object",
            Failure::ObjectTooLarge => "object-too-large",
            Failure::WrongObject => "wrong-object",
            Failure::ReservedType => "reserved-type",
        }
    }
}

/// What the tool did.
#[derive(Debug)]
pub struct Ran {
    /// Its exit code.
    pub code: i32,
    pub stdout: Vec<u8>,
}

/// Something that runs the tool: the real one, or one a test puts in its place.
pub trait Tool {
    /// # Errors
    /// Why there is no exit code and output to judge.
    fn run(&self, argv: &[String], timeout: Duration) -> Result<Ran, Failure>;
}

/// The program at an absolute path, with a cleared environment and no standard input.
pub struct Program {
    pub path: PathBuf,
    /// The uid that must own the file and every directory above it, none of which may be writable by group or
    /// others: root (0) for the real one, as root's dispatcher runs it. `None` for a test build's stand-in.
    pub trusted: Option<u32>,
}

/// Why `path` (resolved) is not safe for `trusted` to run: it, or a directory above it down from `from`,
/// is not owned by `trusted` or can be written by group or others. `None` if it is safe.
#[must_use]
pub fn unsafe_chain(path: &Path, trusted: u32, from: &Path) -> Option<String> {
    for step in path.ancestors().take_while(|step| step.starts_with(from)) {
        let Ok(meta) = std::fs::metadata(step) else { return Some(format!("{} cannot be examined", step.display())) };
        if meta.uid() != trusted {
            return Some(format!("{} is not owned by uid {trusted}", step.display()));
        }
        if meta.mode() & 0o022 != 0 {
            return Some(format!("{} can be written by group or others", step.display()));
        }
    }
    None
}

impl Program {
    /// Whether the program can be run: there, an executable file, and (for root's) not for anyone else to change.
    ///
    /// # Errors
    /// [`Failure::Tool`], with why.
    pub fn check(&self) -> Result<(), Failure> {
        let unusable = |why: &str| Failure::Tool(why.to_string());
        let meta = std::fs::metadata(&self.path).map_err(|_| unusable("not found"))?;
        if !meta.is_file() || meta.mode() & 0o111 == 0 {
            return Err(unusable("not an executable file"));
        }
        if let Some(trusted) = self.trusted {
            // Where the name leads, not the name: a link could lead out of the directories that are safe.
            let resolved = std::fs::canonicalize(&self.path).map_err(|_| unusable("not found"))?;
            if let Some(why) = unsafe_chain(&resolved, trusted, Path::new("/")) {
                return Err(Failure::Tool(why));
            }
        }
        Ok(())
    }
}

impl Tool for Program {
    fn run(&self, argv: &[String], timeout: Duration) -> Result<Ran, Failure> {
        self.check()?;
        let mut child = Command::new(&self.path)
            .args(argv)
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Failure::Tool("cannot start".into()))?;
        let Some(mut stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Failure::Tool("no output pipe".into()));
        };
        // Read on its own thread: a tool that holds its pipe open must not hold this up past the limit.
        let (sent, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let read = (&mut stdout).take(OBJECT_LIMIT + 1).read_to_end(&mut bytes);
            let _ = sent.send(read.map(|_| bytes));
        });
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if started.elapsed() >= timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Failure::Timeout);
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(Failure::Tool("cannot wait".into()));
                }
            }
        };
        if let Some(signal) = status.signal() {
            return Err(Failure::Killed(signal));
        }
        let remaining = timeout.saturating_sub(started.elapsed()).max(Duration::from_secs(1));
        let stdout = match received.recv_timeout(remaining) {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(_)) => return Err(Failure::NotAnObject),
            Err(_) => return Err(Failure::Timeout),
        };
        Ok(Ran { code: status.code().unwrap_or(-1), stdout })
    }
}

/// The member of an object as raw text, kept as the tool wrote it.
type Members<'a> = BTreeMap<String, &'a RawValue>;

fn members(text: &str) -> Option<Members<'_>> {
    serde_json::from_str(text).ok()
}

fn list<'a>(members: &Members<'a>, key: &str) -> Option<Vec<&'a RawValue>> {
    serde_json::from_str(members.get(key)?.get()).ok()
}

fn string(raw: &RawValue) -> Option<String> {
    serde_json::from_str(raw.get()).ok()
}

/// `text` without the whitespace between its tokens, strings untouched: one line, the same members in the same order.
#[must_use]
pub fn compact(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let (mut in_string, mut escaped) = (false, false);
    for c in text.chars() {
        if in_string {
            out.push(c);
            match (escaped, c) {
                (true, _) => escaped = false,
                (false, '\\') => escaped = true,
                (false, '"') => in_string = false,
                _ => {}
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if !c.is_whitespace() {
            out.push(c);
        }
    }
    out
}

/// The lines of a usable object, before the trailer.
struct Lines {
    header_extra: Vec<(&'static str, String)>,
    lines: Vec<String>,
    records: u64,
    findings: u64,
    unreadable: u64,
}

fn read_object(row: &Row, bytes: &[u8]) -> Result<Lines, Failure> {
    if bytes.len() as u64 > OBJECT_LIMIT {
        return Err(Failure::ObjectTooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| Failure::NotAnObject)?;
    let object = members(text).ok_or(Failure::NotAnObject)?;
    let number = |key: &str| object.get(key).and_then(|raw| serde_json::from_str::<u64>(raw.get()).ok());
    let word = |key: &str| object.get(key).and_then(|raw| string(raw));
    if number("schema_version") != Some(SCHEMA_VERSION) || word("subcommand").as_deref() != Some(row.subcommand) {
        return Err(Failure::WrongObject);
    }
    let (Some(started_at), Some(mode), Some(cost)) = (word("started_at"), word("mode"), word("cost")) else {
        return Err(Failure::WrongObject);
    };
    let (Some(unreadable), Some(records), Some(restored), Some(findings)) =
        (list(&object, "unreadable"), list(&object, "records"), list(&object, "restored"), list(&object, "findings"))
    else {
        return Err(Failure::WrongObject);
    };
    let mut lines = Vec::new();
    for entry in &unreadable {
        let parts = members(entry.get()).ok_or(Failure::WrongObject)?;
        let (Some(source), Some(reason)) = (parts.get("source"), parts.get("reason")) else {
            return Err(Failure::WrongObject);
        };
        lines.push(format!(
            "{{\"type\":\"unreadable\",\"source\":{},\"reason\":{}}}",
            compact(source.get()),
            compact(reason.get())
        ));
    }
    for record in &records {
        let parts = members(record.get()).ok_or(Failure::WrongObject)?;
        let kind = parts.get("type").and_then(|raw| string(raw)).ok_or(Failure::WrongObject)?;
        if RESERVED.contains(&kind.as_str()) {
            return Err(Failure::ReservedType);
        }
        lines.push(compact(record.get()));
    }
    for entry in &restored {
        lines.push(format!("{{\"type\":\"restored\",\"entry\":{}}}", compact(entry.get())));
    }
    for finding in &findings {
        let parts = members(finding.get()).ok_or(Failure::WrongObject)?;
        let mut line = String::from("{\"type\":\"finding\"");
        for key in ["id", "severity", "subject", "evidence", "recommendation", "changes"] {
            let value = parts.get(key).ok_or(Failure::WrongObject)?;
            line.push_str(&format!(",\"{key}\":{}", compact(value.get())));
        }
        line.push('}');
        lines.push(line);
    }
    Ok(Lines {
        header_extra: vec![
            ("subcommand", row.subcommand.to_string()),
            ("started_at", started_at),
            ("mode", mode),
            ("cost", cost),
        ],
        lines,
        records: records.len() as u64,
        findings: findings.len() as u64,
        unreadable: unreadable.len() as u64,
    })
}

/// What the trailer says of a tool code.
fn result_word(code: i32) -> Option<&'static str> {
    match code {
        0 => Some("info"),
        1 => Some("warnings"),
        2 => Some("critical"),
        3 => Some("failed-diagnostic"),
        _ => None,
    }
}

fn trailer(rc: Option<i32>, result: &str, lines: &Lines, truncated: bool) -> Record {
    Record::new("trailer")
        .opt_int("rc", rc.map(i64::from))
        .str("result", result)
        .num("records", lines.records)
        .num("findings", lines.findings)
        .num("unreadable", lines.unreadable)
        .bool("truncated", truncated)
}

/// Judges what the tool did: the lines of the output and the trailer's code, or why it is not a result.
fn judge(row: &Row, ran: Result<Ran, Failure>) -> Result<(Lines, i32), Failure> {
    let ran = ran?;
    match ran.code {
        0..=2 => read_object(row, &ran.stdout).map(|lines| (lines, ran.code)),
        // The diagnostic itself failed: what the tool gave is kept, and the trailer says that it failed.
        3 => Ok((
            read_object(row, &ran.stdout).unwrap_or(Lines {
                header_extra: Vec::new(),
                lines: Vec::new(),
                records: 0,
                findings: 0,
                unreadable: 0,
            }),
            3,
        )),
        4 => Err(Failure::Refused),
        other => Err(Failure::Failed(other)),
    }
}

/// Runs a row with `tool` and writes the answer. The result is `Ok(0)` for a result, and for a failure
/// the answer (a header, one `error` record, a trailer) has been written and the cause is in `answer`.
///
/// # Errors
/// [`Full`] when the answer is.
pub fn run_with(row: &Row, tool: &dyn Tool, args: &[String], answer: &mut Answer<'_>) -> Result<u8, Full> {
    let head = header(row.noun, row.verb, &kit::hostname(), &clock::now());
    let outcome = match command(row, args) {
        Ok(argv) => judge(row, tool.run(&argv, row.timeout)),
        Err(why) => {
            return fail(answer, head, &Failure::Failed(-1), Some(&why));
        }
    };
    match outcome {
        Ok((lines, code)) => {
            let mut head = head;
            for (key, value) in &lines.header_extra {
                head = head.str(key, value);
            }
            answer.record(&head)?;
            for line in &lines.lines {
                answer.record_line(line)?;
            }
            let result = result_word(code).unwrap_or("failed");
            answer.close(|cut| trailer(Some(code), result, &lines, cut))?;
            Ok(0)
        }
        Err(failure) => fail(answer, head, &failure, None),
    }
}

fn fail(answer: &mut Answer<'_>, head: Record, failure: &Failure, detail: Option<&str>) -> Result<u8, Full> {
    answer.record(&head)?;
    answer.record(&Record::new("error").str("code", failure.record_code()).opt_str("detail", detail))?;
    let empty = Lines { header_extra: Vec::new(), lines: Vec::new(), records: 0, findings: 0, unreadable: 0 };
    answer.close(|cut| trailer(None, "failed", &empty, cut))?;
    answer.fail(&failure.code());
    Ok(0)
}

/// The tool a call uses: the system's at [`PROVER_PATH`], or the one a test build was pointed at.
#[must_use]
pub fn program(env: &Env) -> Program {
    match &env.prover {
        Some(path) => Program { path: path.clone(), trusted: None },
        None => Program { path: Path::new(PROVER_PATH).to_path_buf(), trusted: (env.euid == 0).then_some(0) },
    }
}

/// `rt procs`: the threads that are realtime, and the rest of what `prover procs` says.
pub const PROCS: Row = Row {
    noun: "rt",
    verb: "procs",
    subcommand: "procs",
    words: &["--format", "json"],
    flags: &[Flag { param: "max", flag: "--max", unit: "" }],
    timeout: Duration::from_secs(30),
};

/// `rt irq`: interrupts, their affinity and what moved in a window.
pub const IRQ: Row = Row {
    noun: "rt",
    verb: "irq",
    subcommand: "irq",
    words: &["--format", "json"],
    flags: &[Flag { param: "duration", flag: "--duration", unit: "s" }, Flag { param: "top", flag: "--top", unit: "" }],
    // The longest window an agent can ask for (30 s) and then some.
    timeout: Duration::from_secs(60),
};

/// `rt procs`, as a table row runs it.
///
/// # Errors
/// [`Full`] when the answer is.
pub fn procs(env: &Env, args: &[String], answer: &mut Answer<'_>) -> Result<u8, Full> {
    run_with(&PROCS, &program(env), args, answer)
}

/// `rt irq`, as a table row runs it.
///
/// # Errors
/// [`Full`] when the answer is.
pub fn irq(env: &Env, args: &[String], answer: &mut Answer<'_>) -> Result<u8, Full> {
    run_with(&IRQ, &program(env), args, answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    /// A tool that gives what it was told to.
    struct Fake(Mutex<Option<Result<Ran, Failure>>>, Mutex<Vec<String>>);

    impl Fake {
        fn code(code: i32, stdout: &str) -> Fake {
            Fake(Mutex::new(Some(Ok(Ran { code, stdout: stdout.as_bytes().to_vec() }))), Mutex::default())
        }

        fn failing(failure: Failure) -> Fake {
            Fake(Mutex::new(Some(Err(failure))), Mutex::default())
        }
    }

    impl Tool for Fake {
        fn run(&self, argv: &[String], _: Duration) -> Result<Ran, Failure> {
            *self.1.lock().unwrap() = argv.to_vec();
            self.0.lock().unwrap().take().expect("asked once")
        }
    }

    fn golden(name: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../p-rover/tests/golden").join(format!("{name}.json"));
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    /// What a row writes, the cause it gave, and what it asked the tool.
    fn ran(row: &Row, tool: &Fake, args: &[&str]) -> (Vec<String>, Option<String>) {
        let mut out = Vec::new();
        let mut answer = Answer::new(&mut out, crate::answer::ANSWER_CAP);
        let args: Vec<String> = args.iter().map(ToString::to_string).collect();
        assert_eq!(run_with(row, tool, &args, &mut answer), Ok(0));
        let cause = answer.failure().map(String::from);
        let text = String::from_utf8(out).unwrap();
        (text.lines().map(String::from).collect(), cause)
    }

    fn types(lines: &[String]) -> Vec<String> {
        lines
            .iter()
            .map(|l| {
                let parts = members(l).expect("every line is one object");
                string(parts["type"]).unwrap()
            })
            .collect()
    }

    #[test]
    fn the_command_is_the_fixed_words_and_the_mapped_values_only() {
        let argv = |row: &Row, args: &[&str]| command(row, &args.iter().map(ToString::to_string).collect::<Vec<_>>());
        assert_eq!(argv(&PROCS, &[]).unwrap(), ["procs", "--format", "json"]);
        assert_eq!(argv(&PROCS, &["max=50"]).unwrap(), ["procs", "--format", "json", "--max", "50"]);
        assert_eq!(
            argv(&IRQ, &["duration=2", "top=7"]).unwrap(),
            ["irq", "--format", "json", "--duration", "2s", "--top", "7"]
        );
        // Nothing else gets into the command, whatever reached here.
        for bad in ["max=-1", "max=", "max=5 --arm", "other=1", "max", "duration=1s"] {
            assert!(argv(&IRQ, &[bad]).is_err() && argv(&PROCS, &[bad]).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_result_is_the_convention_s_lines_with_the_tools_records_as_it_wrote_them() {
        for (row, name, code, result) in [(&IRQ, "irq", 1, "warnings"), (&PROCS, "procs", 2, "critical")] {
            let object = golden(name);
            let (lines, cause) = ran(row, &Fake::code(code, &object), &[]);
            assert_eq!(cause, None, "{lines:?}");
            let kinds = types(&lines);
            assert_eq!(kinds[0], "header");
            assert_eq!(kinds.last().unwrap(), "trailer");
            let first: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
            assert_eq!((first["subcommand"].as_str(), first["mode"].as_str()), (Some(name), Some("observe")));
            assert_eq!(first["cost"], "light");
            assert_eq!(first["noun"], "rt");
            // The records are the tool's, byte for byte once the whitespace between tokens is gone.
            let tool_records = list(&members(&object).unwrap(), "records").unwrap();
            let written: Vec<&String> = lines.iter().filter(|l| !l.contains("\"type\":\"finding\"")).collect();
            for record in &tool_records {
                assert!(written.iter().any(|l| **l == compact(record.get())), "{}", record.get());
            }
            // One finding line per finding, in the convention's order of members.
            let findings: Vec<&String> = lines.iter().filter(|l| l.starts_with("{\"type\":\"finding\"")).collect();
            assert_eq!(findings.len(), list(&members(&object).unwrap(), "findings").unwrap().len());
            assert!(
                findings[0].starts_with("{\"type\":\"finding\",\"id\":\"")
                    && findings[0].contains(",\"severity\":")
                    && findings[0].contains(",\"changes\":["),
                "{}",
                findings[0]
            );
            let trailer: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
            assert_eq!((trailer["rc"].as_i64(), trailer["result"].as_str()), (Some(i64::from(code)), Some(result)));
            assert_eq!(trailer["findings"].as_u64(), Some(findings.len() as u64));
            assert_eq!(trailer["truncated"], false);
            assert!(lines.iter().all(|l| !l.contains('\n') && l.starts_with('{') && l.ends_with('}')));
        }
    }

    #[test]
    fn what_the_tool_could_not_read_is_said_in_lines_of_its_own() {
        let object = golden("analyze").replace("\"subcommand\": \"analyze\"", "\"subcommand\": \"irq\"");
        let (lines, cause) = ran(&IRQ, &Fake::code(0, &object), &[]);
        assert!(cause.is_none(), "{lines:?}");
        let unreadable: Vec<&String> = lines.iter().filter(|l| l.starts_with("{\"type\":\"unreadable\"")).collect();
        assert!(!unreadable.is_empty() && unreadable[0].contains("\"source\":\"ethtool lan0\""), "{lines:?}");
        let trailer: serde_json::Value = serde_json::from_str(lines.last().unwrap()).unwrap();
        assert_eq!(trailer["unreadable"].as_u64(), Some(unreadable.len() as u64));
    }

    #[test]
    fn a_diagnostic_that_failed_is_done_and_says_so_in_the_trailer() {
        let (lines, cause) = ran(&IRQ, &Fake::code(3, ""), &[]);
        assert_eq!(cause, None);
        assert_eq!(types(&lines), ["header", "trailer"]);
        let trailer: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
        assert_eq!((trailer["rc"].as_i64(), trailer["result"].as_str()), (Some(3), Some("failed-diagnostic")));
        // What it did write is kept.
        let (lines, _) = ran(&IRQ, &Fake::code(3, &golden("irq")), &[]);
        assert!(lines.len() > 2, "{lines:?}");
    }

    #[test]
    fn every_case_that_is_not_a_result_is_failed_with_its_cause_and_never_half_an_output() {
        let object = golden("irq");
        let with = |from: &str, to: &str| object.replacen(from, to, 1);
        let reserved = with("{\"type\":\"policy\"", "{\"type\":\"trailer\"");
        let huge = format!("{}{}", &object[..object.len() - 2], " ".repeat(OBJECT_LIMIT as usize));
        let cases: Vec<(&str, Fake, &str)> = vec![
            ("exit 4", Fake::code(4, &object), "tool-refused"),
            ("exit 5", Fake::code(5, &object), "tool-failed:5"),
            ("exit 127", Fake::code(127, ""), "tool-failed:127"),
            ("a signal", Fake::failing(Failure::Killed(9)), "tool-killed:9"),
            ("the timeout", Fake::failing(Failure::Timeout), "tool-timeout"),
            ("not runnable", Fake::failing(Failure::Tool("not found".into())), "tool-unusable:not found"),
            ("not json", Fake::code(0, "this is not json"), "not-an-object"),
            ("an array", Fake::code(0, "[1,2]"), "not-an-object"),
            ("empty", Fake::code(1, ""), "not-an-object"),
            ("two objects", Fake::code(0, &format!("{object}{object}")), "not-an-object"),
            (
                "not utf-8",
                Fake(Mutex::new(Some(Ok(Ran { code: 0, stdout: vec![0xff, 0xfe] }))), Mutex::default()),
                "not-an-object",
            ),
            ("over the limit", Fake::code(0, &huge), "object-too-large"),
            (
                "another subcommand",
                Fake::code(0, &with("\"subcommand\": \"irq\"", "\"subcommand\": \"procs\"")),
                "wrong-object",
            ),
            ("another schema", Fake::code(0, &with("\"schema_version\": 1", "\"schema_version\": 2")), "wrong-object"),
            ("no records", Fake::code(0, &with("\"records\"", "\"recordz\"")), "wrong-object"),
            (
                "a finding without its id",
                Fake::code(0, &with("\"id\": \"irqbalance\"", "\"idx\": \"irqbalance\"")),
                "wrong-object",
            ),
            ("a reserved record type", Fake::code(0, &reserved), "reserved-type"),
        ];
        for (what, tool, cause) in cases {
            let (lines, given) = ran(&IRQ, &tool, &[]);
            assert_eq!(given.as_deref(), Some(cause), "{what}");
            // No tool lines: a header, one error record with the code, a trailer that says failed.
            assert_eq!(types(&lines), ["header", "error", "trailer"], "{what}: {lines:?}");
            let error: serde_json::Value = serde_json::from_str(&lines[1]).unwrap();
            assert_eq!(error["code"].as_str(), cause.split(':').next(), "{what}");
            let trailer: serde_json::Value = serde_json::from_str(&lines[2]).unwrap();
            assert_eq!(trailer["result"], "failed", "{what}");
            assert!(trailer["rc"].is_null(), "{what}");
        }
    }

    #[test]
    fn the_object_at_exactly_the_limit_is_read_and_one_byte_more_is_not() {
        let object = golden("irq");
        let pad = |n: usize| format!("{}{}", &object[..object.trim_end().len()], " ".repeat(n));
        let fits = pad(OBJECT_LIMIT as usize - object.trim_end().len());
        assert_eq!(fits.len() as u64, OBJECT_LIMIT);
        assert!(read_object(&IRQ, fits.as_bytes()).is_ok());
        assert!(matches!(
            read_object(&IRQ, pad(OBJECT_LIMIT as usize - object.trim_end().len() + 1).as_bytes()),
            Err(Failure::ObjectTooLarge)
        ));
    }

    #[test]
    fn an_answer_cut_at_the_cap_still_ends_with_the_trailer_and_the_counts_are_the_tools() {
        // About 1.4 MB of records and 300 findings from the tool: more than the cap lets through.
        let object = golden("procs");
        let thread = "{\"type\":\"thread\",\"pid\":1,\"tid\":1,\"comm\":\"cyclic\",\"pad\":\"".to_string()
            + &"x".repeat(80)
            + "\"}";
        let records = vec![thread; 12_000].join(",");
        let finding = "{\"id\":\"f\",\"severity\":\"warn\",\"subject\":{},\"evidence\":[],\"recommendation\":\"r\",\"changes\":[]}";
        let huge = format!(
            "{{\"schema_version\":1,\"subcommand\":\"procs\",\"host\":\"h\",\"started_at\":\"t\",\"mode\":\"observe\",\"cost\":\"light\",\"unreadable\":[],\"records\":[{records}],\"restored\":[],\"findings\":[{}]}}",
            vec![finding; 300].join(",")
        );
        assert!(huge.len() > 1 << 20 && (huge.len() as u64) < OBJECT_LIMIT && !object.is_empty());
        let mut out = Vec::new();
        let mut answer = Answer::new(&mut out, crate::answer::ANSWER_CAP);
        assert_eq!(run_with(&PROCS, &Fake::code(2, &huge), &[], &mut answer), Ok(0));
        assert!(answer.truncated() && answer.failure().is_none());
        let text = String::from_utf8(out).unwrap();
        assert!(text.len() <= crate::answer::ANSWER_CAP, "{}", text.len());
        let lines: Vec<&str> = text.lines().collect();
        let cut: serde_json::Value = serde_json::from_str(lines[lines.len() - 2]).unwrap();
        let trailer: serde_json::Value = serde_json::from_str(lines[lines.len() - 1]).unwrap();
        assert_eq!(cut["type"], "truncated");
        // The trailer: the tool's code and result, and the counts of what the tool reported, not of what was sent.
        assert_eq!(
            (
                trailer["type"].as_str(),
                trailer["rc"].as_i64(),
                trailer["result"].as_str(),
                trailer["truncated"].as_bool()
            ),
            (Some("trailer"), Some(2), Some("critical"), Some(true))
        );
        assert_eq!((trailer["records"].as_u64(), trailer["findings"].as_u64()), (Some(12_000), Some(300)));
        assert!(lines.last().unwrap().len() < crate::answer::CLOSING_MAX);
        // What was written and what was dropped add up to what the tool gave (header, records, findings).
        let sent = lines.len() as u64 - 2;
        assert_eq!(sent + cut["dropped_lines"].as_u64().unwrap(), 1 + 12_000 + 300);
        assert!(
            cut["dropped"]["thread"].as_u64().unwrap() > 0 && cut["dropped"]["finding"].as_u64().unwrap() > 0,
            "{cut}"
        );
    }

    #[test]
    fn compacting_keeps_strings_and_order() {
        assert_eq!(compact("{ \"a b\": [1, 2 ],\n \"c\": \"x \\\" y\" }"), "{\"a b\":[1,2],\"c\":\"x \\\" y\"}");
    }

    // The program itself, as a shell script standing in for `prover`.

    fn script(name: &str, body: &str) -> Program {
        let dir = crate::testdir::new(name);
        let path = dir.join("prover");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        Program { path, trusted: None }
    }

    fn argv() -> Vec<String> {
        vec!["irq".into()]
    }

    #[test]
    fn the_program_runs_with_a_cleared_environment_and_no_input_and_gives_its_code_and_output() {
        let program = script("env", "echo \"[$(env | wc -l)]\"; read line; echo \"got:$line\"; exit 2");
        let ran = program.run(&argv(), Duration::from_secs(20)).unwrap();
        let text = String::from_utf8(ran.stdout).unwrap();
        // `sh` may add PWD and the like itself; what the caller had is not there, and the input is empty.
        assert!(text.contains("got:\n") && !text.contains("HOME") && ran.code == 2, "{text}");
    }

    #[test]
    fn a_signal_a_timeout_and_a_flood_are_told_apart() {
        assert_eq!(
            script("signal", "kill -9 $$").run(&argv(), Duration::from_secs(20)).unwrap_err(),
            Failure::Killed(9)
        );
        let started = Instant::now();
        assert_eq!(script("slow", "sleep 30").run(&argv(), Duration::from_millis(500)).unwrap_err(), Failure::Timeout);
        assert!(started.elapsed() < Duration::from_secs(25), "{:?}", started.elapsed());
        let flood = script("flood", "head -c 6000000 /dev/zero | tr '\\0' x").run(&argv(), Duration::from_secs(20));
        let flood = flood.expect("it exited; the object is judged later");
        assert!(flood.stdout.len() as u64 > OBJECT_LIMIT);
        assert!(matches!(read_object(&IRQ, &flood.stdout), Err(Failure::ObjectTooLarge)));
    }

    #[test]
    fn a_tool_that_is_missing_or_not_executable_or_unsafe_is_not_run() {
        let missing = Program { path: "/no/such/prover".into(), trusted: None };
        assert!(matches!(missing.run(&argv(), Duration::from_secs(1)), Err(Failure::Tool(_))));
        let plain = script("plain", "exit 0");
        std::fs::set_permissions(&plain.path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(plain.run(&argv(), Duration::from_secs(1)), Err(Failure::Tool(_))));
        std::fs::set_permissions(&plain.path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn a_tool_is_run_only_if_it_and_every_directory_above_it_are_the_trusted_uids_and_not_writable_by_others() {
        let dir = crate::testdir::new("chain");
        let (base, sub) = (dir.join("base"), dir.join("base/bin"));
        std::fs::create_dir_all(&sub).unwrap();
        let tool = sub.join("prover");
        std::fs::write(&tool, "#!/bin/sh\nexit 0\n").unwrap();
        let mode =
            |path: &Path, bits: u32| std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap();
        let me = std::fs::metadata(&tool).unwrap().uid();
        for (path, bits) in [(&base, 0o755), (&sub, 0o755), (&tool, 0o755)] {
            mode(path, bits);
        }
        assert_eq!(unsafe_chain(&tool, me, &base), None);
        // Someone else is the trusted one: nothing here is theirs.
        assert!(unsafe_chain(&tool, me + 1, &base).unwrap().contains("not owned"));
        // Writable by group, by others: the file, the directory it is in, the directory above that.
        for (path, bits) in [(&tool, 0o775), (&sub, 0o775), (&base, 0o757)] {
            mode(path, bits);
            let why = unsafe_chain(&tool, me, &base).unwrap_or_else(|| panic!("{} {bits:o}", path.display()));
            assert!(why.contains(&path.display().to_string()) && why.contains("written"), "{why}");
            mode(path, 0o755);
        }
        // The program as a whole, with the check on and the root of the check being this machine's: the
        // chain above the test directory is not under test control, so only the verdict's kind is checked.
        let program = Program { path: tool.clone(), trusted: Some(me + 1) };
        assert!(matches!(program.run(&argv(), Duration::from_secs(1)), Err(Failure::Tool(_))));
        // A link is judged by where it leads.
        let link = dir.join("link-to-prover");
        std::os::unix::fs::symlink(&tool, &link).unwrap();
        let program = Program { path: link, trusted: Some(me + 1) };
        assert!(
            matches!(program.run(&argv(), Duration::from_secs(1)), Err(Failure::Tool(ref why)) if why.contains("not owned"))
        );
    }
}
