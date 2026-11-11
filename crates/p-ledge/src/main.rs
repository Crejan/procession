//! `pledge`: holds SSH keys and decides who may use them.
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
    Verb { name: "serve", summary: "run pledge: the agent socket, the dialogs, the connection to the broker" },
    Verb { name: "keys", summary: "create the keys, print their public parts for the site project, retire one" },
    Verb { name: "programs", summary: "list the local programs and admit, block or forget one" },
    Verb { name: "agents", summary: "start an agent with a delegation, list the running ones, withdraw one" },
    Verb { name: "history", summary: "every signature, approval and refusal, with who asked" },
];

fn usage() -> String {
    let mut text = String::from("usage: pledge <verb> [args]\n\nverbs:\n");
    for verb in VERBS {
        text.push_str(&format!("  {:<10} {}\n", verb.name, verb.summary));
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
            println!("pledge {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        [verb, ..] if VERBS.iter().any(|known| known.name == *verb) => {
            eprintln!("pledge {verb}: not implemented yet");
            ExitCode::from(2)
        }
        [other, ..] => {
            eprintln!("pledge: unknown verb '{other}'\n\n{}", usage());
            ExitCode::from(2)
        }
    }
}
