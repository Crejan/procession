//! `page`: the broker of the approval system.
//!
//! The verbs are declared in [`VERBS`]; none of them does anything yet. What
//! each will do is in `SPEC.md`.

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
