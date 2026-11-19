//! The command line of `pact`: `serve`, `stdio`, `call`, `tools`.

use super::Settings;
use super::bundle::Bundle;
use super::catalogue::Catalogue;
use super::guard;
use super::http::HttpTransport;
use super::mcp::{Context, call_once, serve};
use super::rt::{SystemClock, SystemRandomSource, harden};
use super::transport::Transport;
use p_ermit::peer::{self, LOG_INTERVAL, Throttle};
use serde_json::Value;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const USAGE: &str = "usage:
  pact serve --socket PATH [--socket-mode OCTAL] [--client-uid UID]... [--refuse-own-user] [--min-wait SECONDS]
                                                                        (bundle on standard input)
  pact stdio --socket PATH
  pact call [--min-wait SECONDS] TOOL [ARGUMENTS_JSON]                  (bundle on standard input)
  pact tools [--min-wait SECONDS]                                       (bundle on standard input)";

/// How often the tool lists are asked for again (never more often than every 30 seconds).
const REFRESH: Duration = Duration::from_secs(300);

struct Options {
    command: String,
    socket: Option<PathBuf>,
    socket_mode: u32,
    client_uids: Vec<u32>,
    refuse_own_user: bool,
    min_wait: Option<u32>,
    positional: Vec<String>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut it = args.iter();
    let command = it.next().ok_or("no command")?.clone();
    let mut o = Options {
        command,
        socket: None,
        socket_mode: 0o600,
        client_uids: vec![],
        refuse_own_user: false,
        min_wait: None,
        positional: vec![],
    };
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().cloned().ok_or_else(|| format!("{name} needs a value"));
        match a.as_str() {
            "--socket" => o.socket = Some(PathBuf::from(value("--socket")?)),
            "--socket-mode" => {
                o.socket_mode = u32::from_str_radix(&value("--socket-mode")?, 8)
                    .map_err(|_| "--socket-mode is an octal number".to_owned())?
            }
            "--client-uid" => {
                o.client_uids
                    .push(value("--client-uid")?.parse().map_err(|_| "--client-uid is a numeric user id".to_owned())?);
            }
            "--refuse-own-user" => o.refuse_own_user = true,
            "--min-wait" => {
                o.min_wait =
                    Some(value("--min-wait")?.parse().map_err(|_| "--min-wait is a number of seconds".to_owned())?)
            }
            s if s.starts_with("--") => return Err(format!("unknown option {s}")),
            _ => o.positional.push(a.clone()),
        }
    }
    Ok(o)
}

/// One line to standard error, **escaped and bounded**: what reaches a log may hold text from a service or a certificate
/// (a transport's detail, a tool's name), and nothing of it is written raw.
fn log(line: &str) {
    eprintln!("pact: {}", escaped(line));
}

/// `text` as it may be written to standard error: escaped and cut. An error can hold an argument the person or the
/// model gave (a path, an option) or a name from a bundle.
fn escaped(text: &str) -> String {
    p_ermit::text::escape_clipped(text, MAX_LOG_LINE_CHARS).text
}

/// The longest line `pact` logs, in characters of the escaped text.
const MAX_LOG_LINE_CHARS: usize = 2000;

/// Run the command line; the exit status.
#[must_use]
pub fn run(args: Vec<String>) -> i32 {
    let options = match parse(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("pact: {}\n{USAGE}", escaped(&e));
            return 2;
        }
    };
    // A command line that is wrong is a usage error before anything is read or connected: exit 2, as for any other.
    let call = if options.command == "call" {
        match call_arguments(&options) {
            Ok(call) => Some(call),
            Err(e) => {
                eprintln!("pact: {}\n{USAGE}", escaped(&e));
                return 2;
            }
        }
    } else {
        None
    };
    let result = match options.command.as_str() {
        "serve" => cmd_serve(&options),
        "stdio" => cmd_stdio(&options),
        "call" => call.map_or(Ok(()), |(tool, arguments)| cmd_call(&options, &tool, &arguments)),
        "tools" => cmd_tools(&options),
        _ => {
            eprintln!("pact: unknown command\n{USAGE}");
            return 2;
        }
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("pact: {}", escaped(&e));
            1
        }
    }
}

/// Read the bundle from standard input and build everything a session needs.
fn context(options: &Options) -> Result<Arc<Context>, String> {
    harden().iter().for_each(|w| log(w));
    let now = super::rt::Clock::now(&SystemClock);
    let bundle = Bundle::read(guard::bundle_input()?, now).map_err(|e| e.to_string())?;
    let settings = Settings::new(bundle.config.deadline_seconds, options.min_wait);
    #[cfg(not(feature = "pact-tls"))]
    if let Some(s) = bundle.config.services.iter().find(|s| s.url.starts_with("https://")) {
        return Err(format!(
            "{}@{} is an https service, and this pact was built without TLS (feature pact-tls)",
            s.name, s.host
        ));
    }
    let transport: Box<dyn Transport> = Box::new(HttpTransport::new(bundle.config.tls_root.clone()));
    let (catalogue, dropped) =
        Catalogue::build(&bundle.config.services, &settings, &*transport).map_err(|e| e.to_string())?;
    dropped.iter().for_each(|d| log(d));
    log(&format!(
        "agent of {} (delegation {}), {} tools",
        bundle.key.agent().person,
        bundle.key.agent().delegation,
        catalogue.tools.len()
    ));
    Ok(Arc::new(Context::new(
        bundle.config.services,
        catalogue,
        bundle.key,
        settings,
        transport,
        Box::new(SystemClock),
        Box::new(SystemRandomSource::default()),
        Box::new(log),
    )))
}

fn cmd_serve(options: &Options) -> Result<(), String> {
    let path = options.socket.clone().ok_or("serve needs --socket")?;
    let own = p_ermit::peer::own_uid();
    let clients = guard::Clients::new(options.client_uids.clone(), options.refuse_own_user, own)?;
    let ctx = context(options)?;
    // Standard input has been read to its end; nothing else is read after start.
    clients.start_warning(own).iter().for_each(|w| log(w));
    guard::warn_directories(&path, &mut |w| log(w));
    // With the umask 077 the socket never has another mode, not even for the instant before the mode is set.
    let listener = guard::with_private_umask(|| UnixListener::bind(&path))
        .map_err(|e| format!("cannot listen on {}: {e}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(options.socket_mode))
        .map_err(|e| format!("cannot set the socket's mode: {e}"))?;
    log(&format!("listening on {}", path.display()));
    let refresher = Arc::clone(&ctx);
    std::thread::spawn(move || {
        loop {
            std::thread::sleep(REFRESH);
            refresher.refresh();
        }
    });
    let mut throttle = Throttle::new("pact", LOG_INTERVAL);
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        // Read or drop: a client whose credentials cannot be read, or who is not allowed, is closed without a word.
        if peer::accept(&stream, &clients.policy(), "a client was refused", &mut throttle, &mut |l| eprintln!("{l}"))
            .is_none()
        {
            continue;
        }
        let ctx = Arc::clone(&ctx);
        std::thread::spawn(move || {
            let Ok(reader) = stream.try_clone() else { return };
            if let Err(e) = serve(&ctx, reader, stream) {
                log(&format!("a client ended badly: {e}"));
            }
        });
    }
    Ok(())
}

fn cmd_stdio(options: &Options) -> Result<(), String> {
    let path = options.socket.clone().ok_or("stdio needs --socket")?;
    let stream = UnixStream::connect(&path).map_err(|e| format!("cannot connect to {}: {e}", path.display()))?;
    let mut to_socket = stream.try_clone().map_err(|e| e.to_string())?;
    let up = std::thread::spawn(move || {
        let _ = io::copy(&mut io::stdin().lock(), &mut to_socket);
        let _ = to_socket.shutdown(std::net::Shutdown::Write);
    });
    let mut from_socket = stream;
    let mut stdout = io::stdout().lock();
    let mut buf = [0u8; 8192];
    loop {
        match from_socket.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                stdout.write_all(&buf[..n]).and_then(|()| stdout.flush()).map_err(|e| e.to_string())?;
            }
        }
    }
    let _ = up.join();
    Ok(())
}

/// The tool and the arguments of `pact call TOOL [ARGUMENTS_JSON]`: the arguments are one JSON value with **no key twice at any
/// depth** (never read as the first or the last), or the command line is wrong.
fn call_arguments(options: &Options) -> Result<(String, Value), String> {
    let (tool, rest) = options.positional.split_first().ok_or("call needs a tool name")?;
    let arguments: Value = match rest {
        [] => Value::Null,
        [json] => p_ermit::json::parse(json).map_err(|e| format!("the arguments are not JSON: {e}"))?,
        _ => return Err("call takes a tool name and at most one JSON argument".into()),
    };
    Ok((tool.clone(), arguments))
}

fn cmd_call(options: &Options, tool: &str, arguments: &Value) -> Result<(), String> {
    let ctx = context(options)?;
    println!("{}", super::canon::line(&call_once(&ctx, tool, arguments)));
    Ok(())
}

fn cmd_tools(options: &Options) -> Result<(), String> {
    let ctx = context(options)?;
    let tools = ctx.catalogue.read().map_err(|_| "poisoned")?.to_mcp();
    println!("{}", super::canon::line(&tools));
    Ok(())
}
