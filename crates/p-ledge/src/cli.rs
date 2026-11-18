//! The command line: `pledge serve`, `keys`, `programs`, `history`, and the
//! hidden `key-holder`. Exit codes: 0 done, 2 usage, 3 failed, 4 refused (a
//! rule or the person said no).

use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use serde_json::{Value, json};

use crate::agent::text::escape_unshowable;
use crate::config::Config;
use crate::control::{Client, ClientError};
use crate::dialog::Terminal;
use crate::error::{Error, Result};
use crate::holder::{KeyStore, serve_holder};
use crate::paths::Paths;
use crate::record::read_and_verify;
use crate::serve::{self, Config as ServeConfig};

/// One verb of the command line.
pub struct Verb {
    /// What is typed.
    pub name: &'static str,
    /// One line for the help.
    pub summary: &'static str,
}

/// The verbs, in the help's order. `key-holder` is not listed: `pledge serve`
/// starts it.
pub const VERBS: &[Verb] = &[
    Verb { name: "serve", summary: "run pledge: the SSH agent socket, the dialogs, the record (keys in files)" },
    Verb { name: "keys", summary: "list the keys, make one (shared, bound), retire one" },
    Verb { name: "programs", summary: "list the local programs and admit, block or forget one" },
    Verb {
        name: "agents",
        summary: "start an agent with a delegation (writes its bundle), list the delegations, withdraw one",
    },
    Verb { name: "history", summary: "every signing request, with who asked; --verify checks the chain" },
];

/// What the record's words do and do not say.
pub const HISTORY_LEGEND: &str = "pledge: `approved` means this machine signed, not that the action was done: what ran is in the service's own log, joined to this record by the call's identifier (call=). `received` is a request pledge was holding; `lost` is one it was holding when it went down.";

/// The help text.
#[must_use]
pub fn usage() -> String {
    let mut text = String::from("usage: pledge <verb> [args]\n\nverbs:\n");
    for verb in VERBS {
        text.push_str(&format!("  {:<10} {}\n", verb.name, verb.summary));
    }
    text.push_str(
        "\nserve    [--state-dir D] [--socket-dir D] [--known-hosts FILE]...\n\
         keys     list | create shared|confirmed|automatic|delegation|connection [--type T] | create bound --program P --user U --host-key SHA256:... [--type T] | retire FINGERPRINT\n\
         programs list | admit PROGRAM | block PROGRAM | forget PROGRAM\n\
         agents   start [--groups A,B] [--automatic E,D,S] [--ask E,D,S] [--valid 8h] [--label L] [--service host/name=url]... [--tls-root FILE] [--deadline S] [--output FILE] | list | withdraw ID\n\
         history  [--type T] [--result R] [--format json] [--verify]\n\
         \nhistory: `approved` means this machine signed, not that the action was done; what ran is in the service's own log, joined by the call's identifier\n\
         \nall but serve take [--state-dir D] [--socket-dir D]; types: ed25519 (default), ecdsa-p256\n",
    );
    text
}

/// Removes `--name value` from `args`.
fn take_value(args: &mut Vec<String>, name: &str) -> Option<String> {
    let at = args.iter().position(|a| a == name)?;
    (at + 1 < args.len()).then(|| {
        args.remove(at);
        args.remove(at)
    })
}

/// Removes every `--name value`.
fn take_values(args: &mut Vec<String>, name: &str) -> Vec<String> {
    std::iter::from_fn(|| take_value(args, name)).collect()
}

fn take_switch(args: &mut Vec<String>, name: &str) -> bool {
    args.iter().position(|a| a == name).map(|at| args.remove(at)).is_some()
}

/// Runs the command line.
#[must_use]
pub fn main(mut args: Vec<String>) -> ExitCode {
    if args.is_empty() || matches!(args[0].as_str(), "help" | "--help" | "-h") {
        print!("{}", usage());
        return ExitCode::SUCCESS;
    }
    if matches!(args[0].as_str(), "--version" | "-V") {
        println!("pledge {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    let verb = args.remove(0);
    let result = match verb.as_str() {
        "serve" => serve_verb(args),
        "key-holder" => holder_verb(args),
        "keys" => keys_verb(args),
        "programs" => programs_verb(args),
        "history" => history_verb(args),
        "agents" => agents_verb(args),
        other => {
            eprintln!("pledge: unknown verb '{other}'\n\n{}", usage());
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(code) => ExitCode::from(code),
        Err(Failure::Usage(message)) => {
            eprintln!("pledge {verb}: {message}\n\n{}", usage());
            ExitCode::from(2)
        }
        Err(Failure::Refused(message)) => {
            eprintln!("pledge {verb}: {message}");
            ExitCode::from(4)
        }
        Err(Failure::Failed(message)) => {
            eprintln!("pledge {verb}: {message}");
            ExitCode::from(3)
        }
    }
}

enum Failure {
    Usage(String),
    Refused(String),
    Failed(String),
}

impl From<Error> for Failure {
    fn from(error: Error) -> Self {
        Self::Failed(error.to_string())
    }
}

impl From<ClientError> for Failure {
    fn from(error: ClientError) -> Self {
        match error {
            ClientError::Refused(code) => Self::Refused(code),
            ClientError::Io(e)
                if e.kind() == io::ErrorKind::NotFound || e.kind() == io::ErrorKind::ConnectionRefused =>
            {
                Self::Failed("pledge serve is not running (no answer on its control socket)".into())
            }
            other => Self::Failed(other.to_string()),
        }
    }
}

type Done = std::result::Result<u8, Failure>;

fn paths(args: &mut Vec<String>) -> Result<Paths> {
    let state = take_value(args, "--state-dir").map(PathBuf::from);
    let sockets = take_value(args, "--socket-dir").map(PathBuf::from);
    Paths::resolve(state, sockets)
}

fn no_more(args: &[String]) -> std::result::Result<(), Failure> {
    args.first().map_or(Ok(()), |extra| Err(Failure::Usage(format!("unexpected '{extra}'"))))
}

fn serve_verb(mut args: Vec<String>) -> Done {
    let paths = paths(&mut args)?;
    let mut known_hosts: Vec<PathBuf> =
        take_values(&mut args, "--known-hosts").into_iter().map(PathBuf::from).collect();
    if known_hosts.is_empty() {
        known_hosts = serve::default_known_hosts();
    }
    no_more(&args)?;
    let holder_program = std::env::current_exe().map_err(Error::io("finding the pledge program"))?;
    serve::run(ServeConfig { paths, holder_program, known_hosts, dialogs: Arc::new(Terminal::stdio()) })?;
    Ok(0)
}

fn holder_verb(mut args: Vec<String>) -> Done {
    let dir = take_value(&mut args, "--keys-dir").ok_or_else(|| Failure::Usage("--keys-dir is needed".into()))?;
    no_more(&args)?;
    let store = KeyStore::open(&PathBuf::from(dir))?;
    serve_holder(store, io::stdin().lock(), io::stdout().lock())?;
    Ok(0)
}

fn client(paths: &Paths) -> std::result::Result<Client, Failure> {
    Ok(Client::connect(&paths.control_socket())?)
}

fn keys_verb(mut args: Vec<String>) -> Done {
    let paths = paths(&mut args)?;
    let json_out = take_value(&mut args, "--format").as_deref() == Some("json");
    let key_type = take_value(&mut args, "--type");
    let (program, user, host_key) =
        (take_value(&mut args, "--program"), take_value(&mut args, "--user"), take_value(&mut args, "--host-key"));
    let mut words = args.iter().map(String::as_str);
    match (words.next(), words.next(), words.next()) {
        (Some("list"), None, None) => {
            let data = client(&paths)?.call("keys.list", json!({}))?;
            if json_out {
                println!("{data}");
            } else {
                for key in data["keys"].as_array().into_iter().flatten() {
                    let show = |name: &str| escape_unshowable(key[name].as_str().unwrap_or(""));
                    println!("{:<7} {}  {}", show("purpose"), show("fingerprint"), show("public"));
                }
            }
            Ok(0)
        }
        (
            Some("create"),
            Some(purpose @ ("shared" | "bound" | "confirmed" | "automatic" | "delegation" | "connection")),
            None,
        ) => {
            let mut create = json!({"purpose": purpose});
            for (name, value) in [("key_type", key_type), ("program", program), ("user", user), ("host_key", host_key)]
            {
                if let Some(value) = value {
                    create[name] = Value::String(value);
                }
            }
            let data = client(&paths)?.call("keys.create", create)?;
            println!("{}", data["public"].as_str().map(escape_unshowable).unwrap_or_default());
            Ok(0)
        }
        (Some("retire"), Some(fingerprint), None) => {
            client(&paths)?.call("keys.retire", json!({"fingerprint": fingerprint}))?;
            Ok(0)
        }
        _ => Err(Failure::Usage("keys list | create shared|bound ... | retire FINGERPRINT".into())),
    }
}

fn programs_verb(mut args: Vec<String>) -> Done {
    let paths = paths(&mut args)?;
    let json_out = take_value(&mut args, "--format").as_deref() == Some("json");
    let mut words = args.iter().map(String::as_str);
    match (words.next(), words.next(), words.next()) {
        (Some("list"), None, None) => {
            let data = client(&paths)?.call("programs.list", json!({}))?;
            if json_out {
                println!("{data}");
            } else {
                for entry in data["programs"].as_array().into_iter().flatten() {
                    println!(
                        "{:<8} {}",
                        entry["state"].as_str().unwrap_or("?"),
                        escape_unshowable(entry["program"].as_str().unwrap_or(""))
                    );
                }
            }
            Ok(0)
        }
        (Some("admit"), Some(program), None) => {
            // Admitting generally asks for the program's name to be typed, not for a click.
            // SAFETY: isatty only reads the descriptor's type.
            if unsafe { libc::isatty(0) } != 1 {
                return Err(Failure::Refused(
                    "admitting a program asks for its name to be typed, and there is no terminal".into(),
                ));
            }
            print!("Type the program's name to admit it generally ({}): ", escape_unshowable(program));
            io::stdout().flush().map_err(Error::io("writing"))?;
            let mut typed = String::new();
            io::stdin().lock().read_line(&mut typed).map_err(Error::io("reading"))?;
            if typed.trim_end_matches(['\n', '\r']) != program {
                return Err(Failure::Refused("the name typed is not the program's".into()));
            }
            client(&paths)?.call("programs.admit", json!({"program": program, "scope": "generally"}))?;
            Ok(0)
        }
        (Some(command @ ("block" | "forget")), Some(program), None) => {
            client(&paths)?.call(&format!("programs.{command}"), json!({"program": program}))?;
            Ok(0)
        }
        _ => Err(Failure::Usage("programs list | admit PROGRAM | block PROGRAM | forget PROGRAM".into())),
    }
}

/// The uid of the connecting account of `service.sock`, as the record holds it.
fn peer_uid(entry: &Value) -> Option<String> {
    entry["peer"]["uid"].as_u64().map(|uid| uid.to_string())
}

/// One line of `pledge history` for an entry.
#[must_use]
pub fn history_line(entry: &Value) -> String {
    let text = |name: &str| entry[name].as_str().map(escape_unshowable);
    let mut line =
        format!("{} #{} {}", text("time").unwrap_or_default(), entry["seq"], text("type").unwrap_or_default());
    let mut add = |label: &str, value: Option<String>| {
        if let Some(value) = value {
            line.push_str(&format!(" {label}{value}"));
        }
    };
    match entry["type"].as_str() {
        Some("signing-request") => {
            add("", text("result"));
            add("(", text("reason").map(|r| format!("{r})")));
            add("program=", text("program").or_else(|| text("program_hash")));
            add("", text("use"));
            add("user=", text("user"));
            add("host=", text("host").or_else(|| text("host_fingerprint")));
            add("namespace=", text("namespace"));
            add("key=", text("key_fingerprint"));
        }
        Some("received") => {
            add("", Some("received".to_owned()));
            add("person=", text("person"));
            add("agent=", text("delegation"));
            add("call=", text("call"));
            add("action=", text("action"));
            add("peer-uid=", peer_uid(entry));
        }
        Some("request") => {
            add("", text("result"));
            add("(", text("reason").map(|r| format!("{r})")));
            add("mode=", text("mode"));
            add("peer-uid=", peer_uid(entry));
            add("person=", text("person"));
            add("agent=", text("delegation"));
            add("call=", text("call"));
            add("action=", text("action"));
            add("key=", text("key"));
            add("last-entry-before-start=", text("last_entry_before_start"));
        }
        Some("event") => {
            add("", text("event"));
            for name in ["program", "purpose", "key_fingerprint", "count", "delegation", "by", "broker", "why"] {
                add(&format!("{name}="), text(name));
            }
        }
        _ => {}
    }
    line
}

/// `open,none,none`: exposure, damage, disruption.
fn ceiling_words(text: &str) -> std::result::Result<Value, Failure> {
    let parts: Vec<&str> = text.split(',').collect();
    match parts.as_slice() {
        [exposure, damage, disruption] => Ok(json!({"exposure": exposure, "damage": damage, "disruption": disruption})),
        _ => Err(Failure::Usage("a ceiling is three words: exposure,damage,disruption (open|internal|secret, none|recoverable|lasting, none|brief|outage)".into())),
    }
}

/// `8h`, `30m`, `90s` or a number of seconds.
fn seconds(text: &str) -> std::result::Result<u64, Failure> {
    let (number, unit) = match text.chars().last() {
        Some('h') => (&text[..text.len() - 1], 3600),
        Some('m') => (&text[..text.len() - 1], 60),
        Some('s') => (&text[..text.len() - 1], 1),
        _ => (text, 1),
    };
    number
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(unit))
        .ok_or_else(|| Failure::Usage(format!("'{text}' is not a duration (8h, 30m, 90s or seconds)")))
}

/// The services of the bundle: `--service host/name=url` (repeatable) if given,
/// else the person's own `config.json`.
fn bundle_services(config: &Config, options: &[String]) -> std::result::Result<Vec<Value>, Failure> {
    if options.is_empty() {
        return Ok(config.services.iter().map(|s| json!({"host": s.host, "name": s.name, "url": s.url})).collect());
    }
    options
        .iter()
        .map(|text| {
            let (service, url) =
                text.split_once('=').ok_or_else(|| Failure::Usage(format!("'{text}': --service host/name=url")))?;
            let (host, name) =
                service.split_once('/').ok_or_else(|| Failure::Usage(format!("'{text}': --service host/name=url")))?;
            Ok(json!({"host": host, "name": name, "url": url}))
        })
        .collect()
}

fn agents_verb(mut args: Vec<String>) -> Done {
    let paths = paths(&mut args)?;
    let json_out = take_value(&mut args, "--format").as_deref() == Some("json");
    let (groups, automatic, ask) =
        (take_value(&mut args, "--groups"), take_value(&mut args, "--automatic"), take_value(&mut args, "--ask"));
    let (valid, label, output) =
        (take_value(&mut args, "--valid"), take_value(&mut args, "--label"), take_value(&mut args, "--output"));
    let (tls_root, deadline) = (take_value(&mut args, "--tls-root"), take_value(&mut args, "--deadline"));
    let service_options = take_values(&mut args, "--service");
    let mut words = args.iter().map(String::as_str);
    match (words.next(), words.next(), words.next()) {
        (Some("start"), None, None) => {
            let config = Config::load(&paths.state.join("config.json"))?;
            let services = bundle_services(&config, &service_options)?;
            if services.is_empty() {
                return Err(Failure::Refused("no services: name them in config.json or with --service host/name=url; an agent would have nowhere to send its calls".into()));
            }
            // A bundle holds a private key: it is never written to a terminal.
            // SAFETY: isatty only reads the descriptor's type.
            if output.is_none() && unsafe { libc::isatty(1) } == 1 {
                return Err(Failure::Refused(
                    "the bundle holds a private key: it is not written to a terminal (use --output FILE, or a pipe)"
                        .into(),
                ));
            }
            let mut start = json!({
                "groups": groups.map_or_else(Vec::new, |g| g.split(',').filter(|g| !g.is_empty()).map(str::to_owned).collect()),
                "services": services,
            });
            if let Some(file) = tls_root {
                start["tls_root"] =
                    json!(std::fs::read_to_string(&file).map_err(|e| Failure::Failed(format!("{file}: {e}")))?);
            } else if let Some(root) = &config.tls_root {
                start["tls_root"] = json!(root);
            }
            if let Some(text) = deadline.or_else(|| config.deadline_seconds.map(|d| d.to_string())) {
                start["deadline_seconds"] =
                    json!(text.parse::<u32>().map_err(|_| Failure::Usage("--deadline is a number of seconds".into()))?);
            }
            if let Some(text) = automatic {
                start["automatic_ceiling"] = ceiling_words(&text)?;
            }
            if let Some(text) = ask {
                start["ask_ceiling"] = ceiling_words(&text)?;
            }
            if let Some(text) = valid {
                start["valid_seconds"] = json!(seconds(&text)?);
            }
            if let Some(label) = label {
                start["label"] = json!(label);
            }
            let mut control = client(&paths)?;
            let data = control.call("agents.start", start)?;
            let id = data["delegation"].as_str().unwrap_or_default().to_owned();
            match deliver(&data, output.as_deref()) {
                Ok(()) => {
                    control.call("agents.delivered", json!({"delegation": id}))?;
                    eprintln!("pledge: delegation {id} valid until {}", data["valid_until"].as_str().unwrap_or("?"));
                    Ok(0)
                }
                Err(message) => {
                    let _ = control.call("agents.failed", json!({"delegation": id}));
                    Err(Failure::Failed(format!("{message}; the delegation {id} never existed")))
                }
            }
        }
        (Some("list"), None, None) => {
            let data = client(&paths)?.call("agents.list", json!({}))?;
            if json_out {
                println!("{data}");
            } else {
                for d in data["delegations"].as_array().into_iter().flatten() {
                    let show = |name: &str| escape_unshowable(d[name].as_str().unwrap_or("-"));
                    println!(
                        "{:<9} {}  until {}  groups {}  last asked {}",
                        show("state"),
                        show("delegation"),
                        show("valid_until"),
                        d["groups"],
                        show("last_asked")
                    );
                }
            }
            Ok(0)
        }
        (Some("withdraw"), Some(id), None) => {
            client(&paths)?.call("agents.withdraw", json!({"delegation": id}))?;
            Ok(0)
        }
        _ => Err(Failure::Usage("agents start ... | list | withdraw ID".into())),
    }
}

/// Writes the bundle, once, from one buffer: to a new file only the person can
/// read, or to standard output (never a terminal: checked before). Any error
/// means it did not (all) arrive.
fn deliver(data: &Value, output: Option<&str>) -> std::result::Result<(), String> {
    use base64::Engine as _;
    let mut bundle = base64::engine::general_purpose::STANDARD
        .decode(data["bundle"].as_str().unwrap_or(""))
        .map_err(|_| "the reply has no valid bundle".to_owned())?;
    let result = match output {
        Some(path) => {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path)
                .map_err(|e| format!("{path}: {e}"))?;
            file.write_all(&bundle).and_then(|()| file.sync_all()).map_err(|e| {
                let _ = std::fs::remove_file(path);
                format!("{path}: {e}")
            })
        }
        None => {
            let mut out = io::stdout().lock();
            out.write_all(&bundle).and_then(|()| out.flush()).map_err(|e| format!("writing the bundle: {e}"))
        }
    };
    bundle.fill(0);
    result
}

fn history_verb(mut args: Vec<String>) -> Done {
    let paths = paths(&mut args)?;
    let json_out = take_value(&mut args, "--format").as_deref() == Some("json");
    let (entry_type, result) = (take_value(&mut args, "--type"), take_value(&mut args, "--result"));
    let verify = take_switch(&mut args, "--verify");
    no_more(&args)?;
    let report = read_and_verify(&paths.record())?;
    if let Some(seq) = report.starts_at {
        eprintln!("pledge: earlier entries were removed; the record starts at #{seq}");
    }
    for entry in &report.entries {
        if entry_type.as_deref().is_some_and(|t| entry["type"] != t)
            || result.as_deref().is_some_and(|r| entry["result"] != r)
        {
            continue;
        }
        if json_out {
            println!("{entry}");
        } else {
            println!("{}", history_line(entry));
        }
    }
    if !json_out {
        eprintln!("{HISTORY_LEGEND}");
    }
    for broken in &report.breaks {
        eprintln!("pledge: the record breaks at line {}: {}", broken.line, broken.problem);
    }
    Ok(if verify && !report.breaks.is_empty() { 3 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_history_line_names_who_asked_and_what_without_raw_control_characters() {
        let entry = json!({"time":"2026-11-11T15:04:05Z","seq":7,"type":"signing-request","result":"refused","reason":"blocked",
            "program":"/usr/bin/curl\u{1B}[2J","use":"login","user":"jan","host":"a.example"});
        let line = history_line(&entry);
        assert!(line.contains("refused (blocked)"), "{line}");
        assert!(line.contains("program=/usr/bin/curl\\u{001B}[2J"), "{line}");
        assert!(!line.contains('\u{1B}'));
        assert!(line.contains("user=jan host=a.example"), "{line}");
    }

    #[test]
    fn history_says_what_approved_means_and_shows_received_and_lost() {
        assert!(usage().contains("`approved` means this machine signed, not that the action was done"));
        assert!(HISTORY_LEGEND.contains("call's identifier"));
        let received = history_line(
            &json!({"time":"2026-11-11T15:04:05Z","seq":3,"type":"received","call":"c-1","action":"rt procs"}),
        );
        assert!(received.contains("received") && received.contains("call=c-1"), "{received}");
        let lost = history_line(
            &json!({"time":"2026-11-11T15:04:05Z","seq":9,"type":"request","result":"lost","last_entry_before_start":"2026-11-11T15:00:00Z"}),
        );
        assert!(lost.contains("lost") && lost.contains("last-entry-before-start=2026-11-11T15:00:00Z"), "{lost}");
    }

    #[test]
    fn options_are_taken_out_of_the_arguments() {
        let mut args: Vec<String> = ["list", "--state-dir", "/s", "--x"].map(String::from).to_vec();
        assert_eq!(take_value(&mut args, "--state-dir").as_deref(), Some("/s"));
        assert!(take_switch(&mut args, "--x"));
        assert_eq!(args, ["list"]);
        let mut dangling: Vec<String> = vec!["--state-dir".into()];
        assert_eq!(take_value(&mut dangling, "--state-dir"), None);
    }
}
