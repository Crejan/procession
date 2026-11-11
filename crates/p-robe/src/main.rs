//! `probe`: a host's diagnostics as a fixed table of rated verbs.
//!
//! The table is [`VERBS`]. Nothing runs yet: `probe catalog` prints the
//! table, every verb answers "not implemented". What the dispatcher and the
//! service will do is in `SPEC.md`.

use std::process::ExitCode;

use p_ledge::rating::{Damage, Disruption, Exposure, Rating};

/// One row of the verb table.
struct Verb {
    noun: &'static str,
    verb: &'static str,
    /// The program of this workspace that does the work.
    runs: &'static str,
    /// The worst case over every parameter the verb accepts. A request with
    /// concrete parameters may be rated lower, never higher.
    rating: Rating,
    summary: &'static str,
}

/// A first few rows, to fix the shape. The ratings are proposals.
const VERBS: &[Verb] = &[
    Verb {
        noun: "sys",
        verb: "kit",
        runs: "probe",
        rating: Rating::HARMLESS,
        summary: "what this installation is and whether it can run its verbs",
    },
    Verb {
        noun: "rt",
        verb: "irq",
        runs: "prover irq",
        rating: Rating::HARMLESS,
        summary: "interrupts, their threads and the CPUs they run on",
    },
    Verb {
        noun: "rt",
        verb: "procs",
        runs: "prover procs",
        rating: Rating::new(Exposure::Internal, Damage::None, Disruption::None),
        summary: "realtime processes and threads, with their command lines",
    },
    Verb {
        noun: "rt",
        verb: "jitter",
        runs: "prover probe jitter",
        rating: Rating::new(Exposure::Open, Damage::None, Disruption::Brief),
        summary: "measure wake-up jitter; loads the host and restores what it changed",
    },
    Verb {
        noun: "run",
        verb: "command",
        runs: "the command named",
        rating: Rating::WORST,
        summary: "the fallback: one command, stated in full, run once without a terminal",
    },
];

const SCHEMA_VERSION: u32 = 1;

fn exposure(value: Exposure) -> &'static str {
    match value {
        Exposure::Open => "open",
        Exposure::Internal => "internal",
        Exposure::Secret => "secret",
    }
}

fn damage(value: Damage) -> &'static str {
    match value {
        Damage::None => "none",
        Damage::Recoverable => "recoverable",
        Damage::Lasting => "lasting",
    }
}

fn disruption(value: Disruption) -> &'static str {
    match value {
        Disruption::None => "none",
        Disruption::Brief => "brief",
        Disruption::Outage => "outage",
    }
}

fn catalog_text() -> String {
    let mut text = String::from("noun verb        exposure  damage       disruption  summary\n");
    for row in VERBS {
        text.push_str(&format!(
            "{:<4} {:<11} {:<9} {:<12} {:<11} {}\n",
            row.noun,
            row.verb,
            exposure(row.rating.exposure),
            damage(row.rating.damage),
            disruption(row.rating.disruption),
            row.summary
        ));
    }
    text
}

/// One JSON object per line: a header, then one record per verb. The table's
/// strings are plain ASCII without quotes or backslashes and need no
/// escaping.
fn catalog_json() -> String {
    let mut lines =
        vec![format!("{{\"schema_version\":{SCHEMA_VERSION},\"type\":\"header\",\"subject\":\"catalog\"}}")];
    for row in VERBS {
        lines.push(format!(
            "{{\"type\":\"verb\",\"noun\":\"{}\",\"verb\":\"{}\",\"runs\":\"{}\",\"exposure\":\"{}\",\"damage\":\"{}\",\"disruption\":\"{}\",\"needs_confirmation\":{},\"summary\":\"{}\",\"implemented\":false}}",
            row.noun,
            row.verb,
            row.runs,
            exposure(row.rating.exposure),
            damage(row.rating.damage),
            disruption(row.rating.disruption),
            row.rating.needs_confirmation(),
            row.summary
        ));
    }
    lines.join("\n")
}

fn usage() -> &'static str {
    "usage: probe <noun> <verb> [args]\n       probe catalog [--format json]\n       probe serve\n"
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
            println!("probe {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        ["catalog"] => {
            print!("{}", catalog_text());
            ExitCode::SUCCESS
        }
        ["catalog", "--format", "json"] => {
            println!("{}", catalog_json());
            ExitCode::SUCCESS
        }
        ["serve"] => {
            eprintln!("probe serve: not implemented yet");
            ExitCode::from(2)
        }
        [noun, verb, ..] if VERBS.iter().any(|row| row.noun == *noun && row.verb == *verb) => {
            eprintln!("probe {noun} {verb}: not implemented yet");
            ExitCode::from(2)
        }
        _ => {
            eprintln!("probe: no such verb\n\n{}", usage());
            ExitCode::from(64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fallback_command_is_rated_at_the_top_of_every_scale() {
        let fallback = VERBS.iter().find(|row| row.noun == "run" && row.verb == "command").unwrap();
        assert_eq!(fallback.rating, Rating::WORST);
        assert!(fallback.rating.needs_confirmation());
    }

    #[test]
    fn a_measurement_that_loads_the_host_is_not_harmless() {
        let jitter = VERBS.iter().find(|row| row.noun == "rt" && row.verb == "jitter").unwrap();
        assert!(!jitter.rating.within(Rating::HARMLESS));
    }

    #[test]
    fn no_verb_appears_twice() {
        for (index, row) in VERBS.iter().enumerate() {
            assert!(
                !VERBS[..index].iter().any(|other| other.noun == row.noun && other.verb == row.verb),
                "{} {}",
                row.noun,
                row.verb
            );
        }
    }

    #[test]
    fn the_catalog_has_a_header_and_one_record_per_verb() {
        let json = catalog_json();
        let mut lines = json.lines();
        assert!(lines.next().unwrap().starts_with("{\"schema_version\":1,\"type\":\"header\""));
        assert_eq!(lines.count(), VERBS.len());
    }

    #[test]
    fn table_text_needs_no_json_escaping() {
        for row in VERBS {
            for text in [row.noun, row.verb, row.runs, row.summary] {
                assert!(text.is_ascii() && !text.contains(['"', '\\']), "{text}");
            }
        }
    }
}
