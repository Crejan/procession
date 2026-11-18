//! `page`: the broker of the approval system.
//!
//! The verbs are declared in [`VERBS`]; `serve` runs the broker, the others do
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
    Verb { name: "load", summary: "take the site project's data: persons, groups, rules, hosts, keys" },
    Verb { name: "delegations", summary: "list the registered delegations; withdraw one" },
    Verb { name: "block", summary: "block a person or one of their keys; unblock" },
    Verb { name: "log", summary: "every request that arrived, and what became of it" },
];

fn usage() -> String {
    let mut text = String::from("usage: page <verb> [args]\n\nverbs:\n");
    for verb in VERBS {
        text.push_str(&format!("  {:<12} {}\n", verb.name, verb.summary));
    }
    text
}

/// `page serve [--config FILE]`: run the broker until stopped.
fn serve(args: &[&str]) -> ExitCode {
    let path = match args {
        [] => "/etc/page.json",
        ["--config", file] => file,
        _ => {
            eprintln!("usage: page serve [--config FILE]");
            return ExitCode::from(2);
        }
    };
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
