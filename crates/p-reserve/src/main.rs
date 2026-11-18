//! `preserve`: the command line of p-reserve.
//!
//! The verbs are declared in [`VERBS`]; `health` is implemented, the rest are
//! not yet. What each will do is in `SPEC.md`.

mod config;
mod health;
mod repo;

use std::process::ExitCode;

/// One verb of the command line.
struct Verb {
    name: &'static str,
    summary: &'static str,
    implemented: bool,
}

const VERBS: &[Verb] = &[
    Verb {
        name: "serve",
        summary: "run the daemon: scheduled backups, the socket the other front ends use",
        implemented: false,
    },
    Verb { name: "run", summary: "back up the declared sources now", implemented: false },
    Verb { name: "status", summary: "what is running, and what ran last", implemented: false },
    Verb {
        name: "health",
        summary: "the freshness of every source; exit code 0 ok, 1 warnings, 2 critical",
        implemented: true,
    },
    Verb { name: "snapshots", summary: "list the snapshots of a target", implemented: repo::HAS_ENGINE },
    Verb { name: "ls", summary: "list a directory of a snapshot", implemented: repo::HAS_ENGINE },
    Verb { name: "restore", summary: "restore a file or a directory of a snapshot", implemented: repo::HAS_ENGINE },
    Verb { name: "prune", summary: "forget by the retention policy, then prune", implemented: false },
    Verb { name: "check", summary: "verify the repository", implemented: false },
    Verb { name: "verify", summary: "restore a sample and compare it with its source", implemented: false },
    Verb { name: "reprovision", summary: "initialise a repository only when it is proven absent", implemented: false },
];

const SCHEMA_VERSION: u32 = 1;

fn usage() -> String {
    let mut text = String::from("usage: preserve <verb> [args]\n       preserve catalog [--format json]\n\nverbs:\n");
    for verb in VERBS {
        text.push_str(&format!("  {:<10} {}\n", verb.name, verb.summary));
    }
    text
}

/// The verb table as one JSON object. Names and summaries are plain ASCII
/// without quotes or backslashes, so they need no escaping.
fn catalog_json() -> String {
    let verbs: Vec<String> = VERBS
        .iter()
        .map(|verb| {
            format!(
                "{{\"name\":\"{}\",\"summary\":\"{}\",\"implemented\":{}}}",
                verb.name, verb.summary, verb.implemented
            )
        })
        .collect();
    format!("{{\"schema_version\":{SCHEMA_VERSION},\"type\":\"catalog\",\"verbs\":[{}]}}", verbs.join(","))
}

fn run_repo(verb: repo::Verb, args: &[&str]) -> ExitCode {
    ExitCode::from(repo::run(verb, args, &mut std::io::stdout().lock(), &mut std::io::stderr().lock()))
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
            println!("preserve {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["catalog"] => {
            print!("{}", usage());
            ExitCode::SUCCESS
        }
        ["catalog", "--format", "json"] => {
            println!("{}", catalog_json());
            ExitCode::SUCCESS
        }
        ["health", rest @ ..] => {
            ExitCode::from(health::run(rest, &mut std::io::stdout().lock(), &mut std::io::stderr().lock()))
        }
        ["snapshots", rest @ ..] => run_repo(repo::Verb::Snapshots, rest),
        ["ls", rest @ ..] => run_repo(repo::Verb::Ls, rest),
        ["restore", rest @ ..] => run_repo(repo::Verb::Restore, rest),
        [verb, ..] if VERBS.iter().any(|known| known.name == *verb) => {
            eprintln!("preserve {verb}: not implemented yet");
            ExitCode::from(health::EXIT_USAGE)
        }
        [other, ..] => {
            eprintln!("preserve: unknown verb '{other}'\n\n{}", usage());
            ExitCode::from(health::EXIT_USAGE)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_names_every_verb_and_carries_the_schema_version() {
        let json = catalog_json();
        assert!(json.starts_with("{\"schema_version\":1,"));
        for verb in VERBS {
            assert!(json.contains(&format!("\"name\":\"{}\"", verb.name)), "{}", verb.name);
        }
    }

    #[test]
    fn verb_text_needs_no_json_escaping() {
        for verb in VERBS {
            for text in [verb.name, verb.summary] {
                assert!(text.is_ascii() && !text.contains(['"', '\\']), "{text}");
            }
        }
    }
}
