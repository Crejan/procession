//! `probe`: a host's diagnostics as a fixed table of rated verbs.
//!
//! `probe <noun> <verb> [args]` runs one verb (the dispatcher, [`dispatch`]);
//! `probe catalog` and `probe <noun>` print the table. `probe serve`, the
//! service an agent talks to, builds its service and stops where the HTTP
//! transport would start. The work is in the library.

use std::ffi::OsString;
use std::io::Write;
use std::process::ExitCode;

use p_robe::audit::{self, Audit};
use p_robe::dispatch::{Caller, Dispatcher, RC_REFUSED};
#[cfg(feature = "test-verbs")]
use p_robe::rate;
use p_robe::{json, rules, serve, table};

const USAGE: &str =
    "usage: sudo -n probe <noun> <verb> [args]   run one verb (arguments are words or key=value, never -flags)
       probe <noun>                        the verbs of one noun
       probe catalog [--format json]       every verb with its rating and whether it can run here
       probe serve [--config <file>]       the service for agents (the HTTP transport is not built yet)
       probe setup --host-key <file>       stage 1: the service's key and certificate
";

/// What the process is, as the dispatcher needs it.
fn caller() -> Caller {
    Caller {
        // SAFETY: `geteuid` has no preconditions and cannot fail.
        euid: unsafe { libc::geteuid() },
        sudo_user: std::env::var("SUDO_USER").ok(),
        from: std::env::var("SSH_CONNECTION").ok().and_then(|text| text.split(' ').next().map(String::from)),
    }
}

/// Where the audit lines and the locks are. A build with `test-verbs` can be
/// pointed at a directory of its own by `PROBE_TEST_SANDBOX`: audit lines go
/// to `<dir>/audit.log`, locks to `<dir>/locks`, and the check that the
/// process is root is waived. No other build has this.
fn wiring(caller: &mut Caller) -> (Box<dyn Audit>, std::path::PathBuf) {
    #[cfg(feature = "test-verbs")]
    if let Some(dir) = std::env::var_os("PROBE_TEST_SANDBOX") {
        let dir = std::path::PathBuf::from(dir);
        let _ = rate::SANDBOX.set(dir.clone());
        caller.euid = 0;
        return (Box::new(audit::FileAudit(dir.join("audit.log"))), dir.join("locks"));
    }
    let _ = caller;
    (Box::new(audit::Syslog::new()), audit::default_lock_dir().to_path_buf())
}

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let text: Vec<&str> = args.iter().map(|arg| arg.to_str().unwrap_or("\u{fffd}")).collect();
    match text.as_slice() {
        [] => {
            eprint!("{USAGE}");
            ExitCode::from(RC_REFUSED)
        }
        ["help" | "--help" | "-h"] => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        ["--version" | "-V"] => {
            println!("probe {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["catalog"] => {
            print!("{}", table::catalog_text(None));
            ExitCode::SUCCESS
        }
        ["catalog", "--format", "json"] => print_records(&table::catalog_records(None)),
        ["serve", rest @ ..] => ExitCode::from(serve::serve(rest)),
        ["setup", rest @ ..] => ExitCode::from(serve::setup(rest)),
        [noun] if rules::is_token(noun) && table::has_noun(noun) => {
            print!("{}", table::catalog_text(Some(noun)));
            ExitCode::SUCCESS
        }
        _ => {
            let mut caller = caller();
            let (sink, lock_dir) = wiring(&mut caller);
            let dispatcher = Dispatcher::new(sink.as_ref(), lock_dir);
            let rc = dispatcher.run(&caller, &args, &mut std::io::stdout().lock(), &mut std::io::stderr().lock());
            ExitCode::from(rc)
        }
    }
}

fn print_records(records: &[json::Record]) -> ExitCode {
    let mut out = std::io::stdout().lock();
    for record in records {
        if writeln!(out, "{}", record.line()).is_err() {
            return ExitCode::from(1);
        }
    }
    ExitCode::SUCCESS
}
