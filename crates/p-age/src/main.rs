//! `page`: the broker of the approval system.
//!
//! The verbs are declared in [`VERBS`]; `serve` runs the broker, `init` makes its register, and `block`,
//! `unblock`, `withdraw` and `status` speak to the running broker (`proposals/admin-socket.md`). The others do
//! nothing yet. What each will do is in `SPEC.md`.

use std::process::ExitCode;

/// One verb of the command line.
struct Verb {
    name: &'static str,
    summary: &'static str,
}

const VERBS: &[Verb] = &[
    Verb {
        name: "serve",
        summary: "run the broker: the connections of pledges and services, the checks, the register",
    },
    Verb { name: "init", summary: "the first start: make the empty register; refused if there is one" },
    Verb { name: "load", summary: "take the site project's data: persons, groups, rules, hosts, keys" },
    Verb { name: "delegations", summary: "list the registered delegations; withdraw one" },
    Verb { name: "block", summary: "block a person (`page block NAME`) or one key (`page block --key SHA256:...`)" },
    Verb {
        name: "unblock",
        summary: "lift a block, as `block` names it; refused while the register cannot be written",
    },
    Verb { name: "withdraw", summary: "withdraw a delegation: `page withdraw SHA256:...`" },
    Verb { name: "status", summary: "is the broker degraded; what the register and the queue hold" },
    Verb { name: "log", summary: "every request that arrived, and what became of it" },
];

fn usage() -> String {
    let mut text = String::from("usage: page <verb> [args]\n\nverbs:\n");
    for verb in VERBS {
        text.push_str(&format!("  {:<12} {}\n", verb.name, verb.summary));
    }
    text
}

/// The path after `--config`, or the default.
fn config_path<'a>(verb: &str, args: &[&'a str]) -> Option<&'a str> {
    match args {
        [] => Some("/etc/page.json"),
        ["--config", file] => Some(file),
        _ => {
            eprintln!("usage: page {verb} [--config FILE]");
            None
        }
    }
}

/// `page block|unblock|withdraw|status [--config FILE] [--key FP] [NAME|FP]`: put one command to the running
/// broker and print what it says. The exit codes are `p_age::admin::EXIT_TABLE`: 0 done, 1 refused, 2 usage,
/// 3 no broker, 4 in force but not stored, 5 degraded (`status` only).
fn admin(verb: &str, args: &[&str]) -> ExitCode {
    use p_age::admin::{Command, EXIT_NO_BROKER, EXIT_TABLE, EXIT_USAGE, Target, ask, render, socket_path};
    let synopsis = format!(
        "usage: page {verb} [--config FILE]{}",
        match verb {
            "block" | "unblock" => " (NAME | --key SHA256:...)",
            "withdraw" => " SHA256:...",
            _ => "",
        }
    );
    // Each verb's help says what the exit codes mean.
    if args.iter().any(|a| matches!(*a, "--help" | "-h")) {
        println!("{synopsis}\n\n{EXIT_TABLE}");
        return ExitCode::SUCCESS;
    }
    let usage = || {
        eprintln!("{synopsis}\n\n{EXIT_TABLE}");
        ExitCode::from(EXIT_USAGE)
    };
    let (mut config, mut key, mut rest) = ("/etc/page.json", None, Vec::new());
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match *arg {
            "--config" => match it.next() {
                Some(file) => config = file,
                None => return usage(),
            },
            "--key" => match it.next() {
                Some(fp) => key = Some(*fp),
                None => return usage(),
            },
            other => rest.push(other),
        }
    }
    let target = |key: Option<&str>, rest: &[&str]| match (key, rest) {
        (Some(fp), []) => fp.parse().ok().map(Target::Key),
        (None, [name]) => Some(Target::Person((*name).to_owned())),
        _ => None,
    };
    let command = match verb {
        "status" if key.is_none() && rest.is_empty() => Some(Command::Status),
        "block" => target(key, &rest).map(Command::Block),
        "unblock" => target(key, &rest).map(Command::Unblock),
        "withdraw" if key.is_none() => match rest.as_slice() {
            [fp] => fp.parse().ok().map(Command::Withdraw),
            _ => None,
        },
        _ => None,
    };
    let Some(command) = command else { return usage() };
    let config = match p_age::config::Config::read(std::path::Path::new(config)) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("page {verb}: {e}");
            return ExitCode::from(EXIT_USAGE);
        }
    };
    match ask(&socket_path(&config.state_dir), &command) {
        Ok(reply) => {
            let (text, code) = render(&command, &reply);
            // What `status` shows is its output whatever the exit code; a refusal, or a change that is not stored,
            // is said on standard error.
            if code == 0 || command == Command::Status {
                println!("{text}")
            } else {
                eprintln!("{text}")
            }
            ExitCode::from(code)
        }
        Err(e) => {
            eprintln!("page {verb}: {e}");
            ExitCode::from(EXIT_NO_BROKER)
        }
    }
}

/// `page init [--config FILE]`: make the empty register for the first start; refused if there is one.
fn init(args: &[&str]) -> ExitCode {
    let Some(path) = config_path("init", args) else { return ExitCode::from(2) };
    let result =
        p_age::config::Config::read(std::path::Path::new(path)).map_err(|e| e.to_string()).and_then(|config| {
            p_age::core::Core::init_state(&config.state_dir.join("register.json")).map_err(|e| e.to_string())
        });
    match result {
        Ok(()) => {
            println!("page init: the register is made");
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("page init: {message}");
            ExitCode::FAILURE
        }
    }
}

/// `page serve [--config FILE]`: run the broker until stopped.
fn serve(args: &[&str]) -> ExitCode {
    let Some(path) = config_path("serve", args) else { return ExitCode::from(2) };
    match run(std::path::Path::new(path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("page serve: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(path: &std::path::Path) -> Result<(), String> {
    use p_age::config::Config;
    use p_age::net::{ConnLimits, listen, sweep_forever};
    use p_age::tls::server_config;

    let config = Config::read(path).map_err(|e| e.to_string())?;
    let read = |p: &std::path::Path| std::fs::read(p).map_err(|e| format!("cannot read {}: {e}", p.display()));
    let tls = server_config(&read(&config.tls_cert)?, &read(&config.tls_key)?).map_err(|e| e.to_string())?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let broker = config.build().map_err(|e| e.to_string())?;
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let limits = ConnLimits::new(config.max_connections, config.max_connections_per_address);
        // The administrator's verbs reach this broker over a socket in the state directory (0600, peer checked).
        let admin_listener = p_age::admin::bind(&config.state_dir).map_err(|e| e.to_string())?;
        tokio::spawn(p_age::admin::serve(admin_listener, broker.clone()));
        let mut listeners = Vec::new();
        for address in &config.listen {
            let listener =
                tokio::net::TcpListener::bind(address).await.map_err(|e| format!("cannot listen on {address}: {e}"))?;
            listeners.push(listener);
        }
        tokio::spawn(sweep_forever(broker.clone()));
        for listener in listeners {
            tokio::spawn(listen(listener, acceptor.clone(), broker.clone(), limits.clone()));
        }
        tokio::signal::ctrl_c().await.map_err(|e| e.to_string())
    })
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    match args.as_slice() {
        [] | ["help"] | ["--help"] | ["-h"] => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        ["--version"] | ["-V"] => {
            println!("page {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["serve", rest @ ..] => serve(rest),
        ["init", rest @ ..] => init(rest),
        [verb @ ("block" | "unblock" | "withdraw" | "status"), rest @ ..] => admin(verb, rest),
        [verb, ..] if VERBS.iter().any(|known| known.name == *verb) => {
            eprintln!("page {verb}: not implemented yet");
            ExitCode::from(2)
        }
        [other, ..] => {
            eprintln!("page: unknown verb '{other}'\n\n{}", usage());
            ExitCode::from(2)
        }
    }
}
