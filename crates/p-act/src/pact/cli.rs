//! The command line of `pact`: `serve`, `stdio`, `call`, `tools`.

use super::Settings;
use super::bundle::Bundle;
use super::catalogue::Catalogue;
use super::mcp::{Context, call_once, serve};
use super::rt::{SystemClock, SystemRandomSource, harden};
use super::transport::{NoHttp, Transport};
use serde_json::Value;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const USAGE: &str = "usage:
  pact serve --socket PATH [--socket-mode OCTAL] [--min-wait SECONDS]   (bundle on standard input)
  pact stdio --socket PATH
  pact call [--min-wait SECONDS] TOOL [ARGUMENTS_JSON]                  (bundle on standard input)
  pact tools [--min-wait SECONDS]                                       (bundle on standard input)";

/// How often the tool lists are asked for again (never more often than every 30 seconds).
const REFRESH: Duration = Duration::from_secs(300);

struct Options {
    command: String,
    socket: Option<PathBuf>,
    socket_mode: u32,
    min_wait: Option<u32>,
    positional: Vec<String>,
}

fn parse(args: &[String]) -> Result<Options, String> {
    let mut it = args.iter();
    let command = it.next().ok_or("no command")?.clone();
    let mut o = Options { command, socket: None, socket_mode: 0o600, min_wait: None, positional: vec![] };
    while let Some(a) = it.next() {
        let mut value = |name: &str| it.next().cloned().ok_or_else(|| format!("{name} needs a value"));
        match a.as_str() {
            "--socket" => o.socket = Some(PathBuf::from(value("--socket")?)),
            "--socket-mode" => {
                o.socket_mode = u32::from_str_radix(&value("--socket-mode")?, 8)
                    .map_err(|_| "--socket-mode is an octal number".to_owned())?
            }
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

fn log(line: &str) {
    eprintln!("pact: {line}");
}

/// Run the command line; the exit status.
#[must_use]
pub fn run(args: Vec<String>) -> i32 {
    let options = match parse(&args) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("pact: {e}\n{USAGE}");
            return 2;
        }
    };
    let result = match options.command.as_str() {
        "serve" => cmd_serve(&options),
        "stdio" => cmd_stdio(&options),
        "call" => cmd_call(&options),
        "tools" => cmd_tools(&options),
        _ => {
            eprintln!("pact: unknown command\n{USAGE}");
            return 2;
        }
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("pact: {e}");
            1
        }
    }
}

/// Read the bundle from standard input and build everything a session needs.
fn context(options: &Options) -> Result<Arc<Context>, String> {
    harden().iter().for_each(|w| log(w));
    let now = super::rt::Clock::now(&SystemClock);
    let bundle = Bundle::read(io::stdin().lock(), now).map_err(|e| e.to_string())?;
    let settings = Settings::new(bundle.config.deadline_seconds, options.min_wait);
    let transport: Box<dyn Transport> = Box::new(NoHttp);
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
    let ctx = context(options)?;
    // Standard input has been read to its end; nothing else is read after start.
    let listener = UnixListener::bind(&path).map_err(|e| format!("cannot listen on {}: {e}", path.display()))?;
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
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let ctx = Arc::clone(&ctx);
        std::thread::spawn(move || {
            warn_if_same_user(&stream);
            let Ok(reader) = stream.try_clone() else { return };
            if let Err(e) = serve(&ctx, reader, stream) {
                log(&format!("a client ended badly: {e}"));
            }
        });
    }
    Ok(())
}

/// The key stays secret from the model only if they are different users (R2): say so when a client is the same user.
#[cfg(target_os = "linux")]
fn warn_if_same_user(stream: &UnixStream) {
    use std::os::fd::AsRawFd;
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).unwrap_or(0);
    // SAFETY: `cred` and `len` are valid for the call, and `len` is the size of `cred`.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(cred).cast(),
            &mut len,
        )
    };
    // SAFETY: `geteuid` has no arguments and cannot fail.
    if status == 0 && cred.uid == unsafe { libc::geteuid() } {
        log(
            "a client connected as the same user as pact: the agent's key is not kept from it by the sandbox (approvals.md R2)",
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn warn_if_same_user(_: &UnixStream) {}

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

fn cmd_call(options: &Options) -> Result<(), String> {
    let (tool, rest) = options.positional.split_first().ok_or("call needs a tool name")?;
    let arguments: Value = match rest {
        [] => Value::Null,
        [json] => serde_json::from_str(json).map_err(|e| format!("the arguments are not JSON: {e}"))?,
        _ => return Err("call takes a tool name and at most one JSON argument".into()),
    };
    let ctx = context(options)?;
    println!("{}", call_once(&ctx, tool, &arguments));
    Ok(())
}

fn cmd_tools(options: &Options) -> Result<(), String> {
    let ctx = context(options)?;
    let tools = ctx.catalogue.read().map_err(|_| "poisoned")?.to_mcp();
    println!("{tools}");
    Ok(())
}
