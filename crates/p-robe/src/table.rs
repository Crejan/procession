//! The verb table: the one list of what exists. The catalogue, the
//! dispatcher and (later) the service's tool list and what a site's sudo
//! rule may name are all derived from it.

use std::path::PathBuf;

use p_act::rating::{Damage, Disruption, Exposure, Rating};

use crate::answer::{Answer, Full};
use crate::json::{Record, SCHEMA_VERSION};
use crate::kit;
use crate::prover;
use crate::rate::{Form, Param, ParamType, PathUse};
#[cfg(feature = "test-verbs")]
use crate::testverbs;

/// What a verb knows about the call it runs in.
#[derive(Debug)]
pub struct Env {
    /// The paths the call named, as the dispatcher opened them: the verb reads
    /// these files, never the names again.
    #[allow(dead_code, reason = "read by verbs with a path parameter; only a test verb has one so far")]
    pub paths: Vec<PathUse>,
    /// The login that called through sudo.
    pub identity: String,
    /// The effective uid the dispatcher runs as.
    pub euid: u32,
    /// Where the per-identity locks are.
    pub lock_dir: PathBuf,
    /// Where audit lines go, in words.
    pub audit: String,
    /// Where `prover` is, if a test build was pointed elsewhere (never for root); the system's otherwise.
    pub prover: Option<PathBuf>,
}

/// How a verb runs: writes its answer, returns its exit code.
pub type Run = fn(&Env, &[String], &mut Answer<'_>) -> Result<u8, Full>;

/// Whether a verb can run here.
#[derive(Debug, Clone, Copy)]
pub enum Availability {
    /// It runs in this build.
    Ready(Run),
    /// It needs something this workspace does not have yet.
    NotBuilt(&'static str),
    /// Only the service offers it; the dispatcher refuses it.
    ServiceOnly,
}

/// The arguments a verb accepts, and how they rate.
#[derive(Debug, Clone, Copy)]
pub enum Args {
    /// None: the site's sudo rule pins the verb to exactly its two words.
    None,
    /// Words of the argument class, not looked at: every call is rated at the
    /// row's worst. For rows whose tool is not built yet.
    Some,
    /// Parameters with their rules (`rate.rs`): the rating of a call is the
    /// worst of `floor` and what each parameter contributes.
    Params { floor: Rating, params: &'static [Param] },
}

impl Args {
    /// Whether any argument is accepted.
    #[must_use]
    pub fn takes_any(&self) -> bool {
        !matches!(self, Args::None)
    }
}

/// One row of the table.
#[derive(Debug)]
pub struct Verb {
    pub noun: &'static str,
    pub verb: &'static str,
    /// The program of this workspace that does the work.
    pub runs: &'static str,
    /// The worst case over every parameter the verb accepts. A request with
    /// concrete parameters may be rated lower, never higher.
    pub rating: Rating,
    pub args: Args,
    pub summary: &'static str,
    pub availability: Availability,
    /// The output can carry text that is not the service's (a thread's name, a command line, a file's bytes, a
    /// string from a configuration): marked in the catalogue and in the tool's description. It does not change
    /// the rating.
    pub host_text: bool,
    /// Fields of its records that are content, not names, with the limit of their own in bytes of escaped text
    /// (the usual bound is `text_rule::FIELD_MAX`).
    pub content: &'static [(&'static str, usize)],
}

impl Verb {
    /// `noun verb`, as a person says it.
    #[must_use]
    pub fn label(&self) -> String {
        format!("{} {}", self.noun, self.verb)
    }

    /// `ready`, `unavailable` or `service-only`.
    #[must_use]
    pub fn status(&self) -> &'static str {
        match self.availability {
            Availability::Ready(_) => "ready",
            Availability::NotBuilt(_) => "unavailable",
            Availability::ServiceOnly => "service-only",
        }
    }

    /// Why a verb is not ready, if it is not.
    #[must_use]
    pub fn reason(&self) -> Option<&'static str> {
        match self.availability {
            Availability::Ready(_) => None,
            Availability::NotBuilt(reason) => Some(reason),
            Availability::ServiceOnly => Some("only the service offers it, with the person's approval"),
        }
    }
}

const NEEDS_PROVER: Availability = Availability::NotBuilt("needs prover jitter, which is specified and not built");

/// What `rt procs` accepts: how many thread records at most. Contributes nothing to the rating.
const PROCS_PARAMS: &[Param] = &[Param {
    name: "max",
    form: Form::Key("max"),
    required: false,
    ty: ParamType::Number { min: 1, max: 10_000, steps: &[] },
}];

/// What `rt irq` accepts: the window in seconds and how many unflagged IRQs at most. Nothing contributes to the rating.
const IRQ_PARAMS: &[Param] = &[
    Param {
        name: "duration",
        form: Form::Key("duration"),
        required: false,
        ty: ParamType::Number { min: 1, max: 30, steps: &[] },
    },
    Param {
        name: "top",
        form: Form::Key("top"),
        required: false,
        ty: ParamType::Number { min: 1, max: 1000, steps: &[] },
    },
];

/// The rows. The ratings are proposals (`SPEC.md`).
const CORE: &[Verb] = &[
    Verb {
        noun: "sys",
        verb: "kit",
        runs: "probe",
        rating: Rating::HARMLESS,
        args: Args::None,
        summary: "what this installation is and whether it can run its verbs",
        availability: Availability::Ready(kit::run),
        host_text: true,
        content: &[],
    },
    Verb {
        noun: "rt",
        verb: "irq",
        runs: "prover irq",
        rating: Rating::HARMLESS,
        args: Args::Params { floor: Rating::HARMLESS, params: IRQ_PARAMS },
        summary: "interrupts, their threads and the CPUs they run on",
        availability: Availability::Ready(prover::irq),
        host_text: true,
        content: &[],
    },
    Verb {
        noun: "rt",
        verb: "procs",
        runs: "prover procs",
        rating: Rating::new(Exposure::Internal, Damage::None, Disruption::None),
        args: Args::Params {
            floor: Rating::new(Exposure::Internal, Damage::None, Disruption::None),
            params: PROCS_PARAMS,
        },
        summary: "realtime processes and threads, with their command lines",
        availability: Availability::Ready(prover::procs),
        host_text: true,
        content: &[],
    },
    Verb {
        noun: "rt",
        verb: "jitter",
        runs: "prover probe jitter",
        rating: Rating::new(Exposure::Open, Damage::None, Disruption::Brief),
        args: Args::Some,
        summary: "measure wake-up jitter; loads the host and restores what it changed",
        availability: NEEDS_PROVER,
        host_text: false,
        content: &[],
    },
    Verb {
        noun: "run",
        verb: "command",
        runs: "the command named",
        rating: Rating::WORST,
        args: Args::Some,
        summary: "the fallback: one command, stated in full, run once without a terminal",
        availability: Availability::ServiceOnly,
        host_text: true,
        content: &[],
    },
];

/// Rows that exist only in a build with the `test-verbs` feature.
#[cfg(feature = "test-verbs")]
const BUILD_ONLY: &[Verb] = testverbs::VERBS;
#[cfg(not(feature = "test-verbs"))]
const BUILD_ONLY: &[Verb] = &[];

/// Every row of this build.
pub fn verbs() -> impl Iterator<Item = &'static Verb> {
    CORE.iter().chain(BUILD_ONLY)
}

/// The row for `noun verb`.
#[must_use]
pub fn find(noun: &str, verb: &str) -> Option<&'static Verb> {
    verbs().find(|row| row.noun == noun && row.verb == verb)
}

/// Whether any row has this noun.
#[must_use]
pub fn has_noun(noun: &str) -> bool {
    verbs().any(|row| row.noun == noun)
}

/// `exposure,damage,disruption` in words, as `--within` takes it.
#[must_use]
pub fn format_rating(rating: Rating) -> String {
    format!("{},{},{}", exposure(rating.exposure), damage(rating.damage), disruption(rating.disruption))
}

/// The inverse of [`format_rating`].
#[must_use]
pub fn parse_rating(text: &str) -> Option<Rating> {
    let [e, d, i] = text.split(',').collect::<Vec<_>>()[..] else { return None };
    let exposure = [Exposure::Open, Exposure::Internal, Exposure::Secret].into_iter().find(|v| exposure(*v) == e)?;
    let damage = [Damage::None, Damage::Recoverable, Damage::Lasting].into_iter().find(|v| damage(*v) == d)?;
    let disruption =
        [Disruption::None, Disruption::Brief, Disruption::Outage].into_iter().find(|v| disruption(*v) == i)?;
    Some(Rating::new(exposure, damage, disruption))
}

#[must_use]
pub fn exposure(value: Exposure) -> &'static str {
    match value {
        Exposure::Open => "open",
        Exposure::Internal => "internal",
        Exposure::Secret => "secret",
    }
}

#[must_use]
pub fn damage(value: Damage) -> &'static str {
    match value {
        Damage::None => "none",
        Damage::Recoverable => "recoverable",
        Damage::Lasting => "lasting",
    }
}

#[must_use]
pub fn disruption(value: Disruption) -> &'static str {
    match value {
        Disruption::None => "none",
        Disruption::Brief => "brief",
        Disruption::Outage => "outage",
    }
}

/// The catalogue (or one noun's part of it) as a table for a person.
#[must_use]
pub fn catalog_text(only: Option<&str>) -> String {
    let mut text = String::from("noun verb        exposure  damage       disruption  status        summary\n");
    for row in verbs().filter(|row| only.is_none_or(|noun| row.noun == noun)) {
        text.push_str(&format!(
            "{:<4} {:<11} {:<9} {:<12} {:<11} {:<13} {}{}\n",
            row.noun,
            row.verb,
            exposure(row.rating.exposure),
            damage(row.rating.damage),
            disruption(row.rating.disruption),
            row.status(),
            row.summary,
            if row.host_text { " [output may hold text from the host]" } else { "" }
        ));
    }
    text
}

/// The catalogue as records: a header, then one record per verb.
#[must_use]
pub fn catalog_records(only: Option<&str>) -> Vec<Record> {
    let mut records =
        vec![Record::new("header").num("schema_version", u64::from(SCHEMA_VERSION)).str("subject", "catalog")];
    for row in verbs().filter(|row| only.is_none_or(|noun| row.noun == noun)) {
        if let Args::Params { floor, params } = row.args {
            for param in params {
                records.push(
                    Record::new("param")
                        .str("noun", row.noun)
                        .str("verb", row.verb)
                        .str("name", param.name)
                        .bool("required", param.required)
                        .str("floor", &format_rating(floor))
                        .strs("rules", &param.describe()),
                );
            }
        }
        records.push(
            Record::new("verb")
                .str("noun", row.noun)
                .str("verb", row.verb)
                .str("runs", row.runs)
                .str("exposure", exposure(row.rating.exposure))
                .str("damage", damage(row.rating.damage))
                .str("disruption", disruption(row.rating.disruption))
                .bool("needs_confirmation", row.rating.needs_confirmation())
                .bool("takes_arguments", row.args.takes_any())
                .bool("host_text", row.host_text)
                .str("status", row.status())
                .opt_str("reason", row.reason())
                .str("summary", row.summary),
        );
    }
    records
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(noun: &str, verb: &str) -> &'static Verb {
        find(noun, verb).unwrap()
    }

    #[test]
    fn the_fallback_command_is_rated_at_the_top_of_every_scale_and_is_the_services_alone() {
        let fallback = row("run", "command");
        assert_eq!(fallback.rating, Rating::WORST);
        assert!(fallback.rating.needs_confirmation());
        assert_eq!(fallback.status(), "service-only");
    }

    #[test]
    fn the_rows_whose_output_can_carry_text_from_the_host_are_marked_and_the_mark_is_in_the_catalogue() {
        let marked: Vec<String> = verbs().filter(|row| row.host_text).map(Verb::label).collect();
        let expected = ["sys kit", "rt irq", "rt procs", "run command"];
        for label in expected {
            assert!(marked.contains(&label.to_string()), "{label}: {marked:?}");
        }
        assert!(!marked.contains(&"rt jitter".to_string()), "{marked:?}");
        let records = catalog_records(Some("rt"));
        let members: Vec<(String, bool)> = records
            .iter()
            .map(|r| r.line())
            .filter(|l| l.contains("\"type\":\"verb\""))
            .map(|l| (l.clone(), l.contains("\"host_text\":true")))
            .collect();
        assert_eq!(members.len(), 3);
        assert!(members.iter().all(|(l, _)| l.contains("\"host_text\":")), "{members:?}");
        assert!(members.iter().any(|(l, on)| l.contains("\"verb\":\"irq\"") && *on));
        assert!(members.iter().any(|(l, on)| l.contains("\"verb\":\"jitter\"") && !*on));
        assert!(catalog_text(Some("rt")).contains("[output may hold text from the host]"));
    }

    #[test]
    fn a_measurement_that_loads_the_host_is_not_harmless() {
        assert!(!row("rt", "jitter").rating.within(Rating::HARMLESS));
    }

    #[test]
    fn the_rows_that_run_prover_are_ready_except_the_one_that_needs_a_probe() {
        for verb in ["irq", "procs"] {
            assert_eq!(row("rt", verb).status(), "ready");
        }
        assert_eq!(row("rt", "jitter").status(), "unavailable");
        assert!(row("rt", "jitter").reason().unwrap().contains("prover"));
        assert_eq!(row("sys", "kit").status(), "ready");
    }

    #[test]
    fn a_rating_in_words_round_trips() {
        for exposure in [Exposure::Open, Exposure::Internal, Exposure::Secret] {
            for damage in [Damage::None, Damage::Recoverable, Damage::Lasting] {
                for disruption in [Disruption::None, Disruption::Brief, Disruption::Outage] {
                    let rating = Rating::new(exposure, damage, disruption);
                    assert_eq!(parse_rating(&format_rating(rating)), Some(rating));
                }
            }
        }
        for bad in
            ["", "open", "open,none", "open,none,none,none", "Open,none,none", "open, none,none", "open,none,huge"]
        {
            assert_eq!(parse_rating(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn no_verb_appears_twice() {
        let all: Vec<_> = verbs().collect();
        for (index, row) in all.iter().enumerate() {
            assert!(
                !all[..index].iter().any(|other| other.noun == row.noun && other.verb == row.verb),
                "{}",
                row.label()
            );
        }
    }

    #[test]
    fn every_noun_and_verb_is_a_token() {
        for row in verbs() {
            assert!(crate::rules::is_token(row.noun) && crate::rules::is_token(row.verb), "{}", row.label());
        }
    }

    #[test]
    fn the_catalog_has_a_header_and_one_record_per_verb() {
        let records = catalog_records(None);
        assert!(records[0].line().starts_with("{\"type\":\"header\",\"schema_version\":1"));
        let params: usize =
            verbs().map(|row| if let Args::Params { params, .. } = row.args { params.len() } else { 0 }).sum();
        assert_eq!(records.len(), 1 + verbs().count() + params);
        assert_eq!(
            catalog_records(Some("rt")).len(),
            1 + 3 + 3,
            "three verbs and the three parameters of irq and procs"
        );
        assert_eq!(catalog_text(Some("sys")).lines().count(), 2);
    }

    #[test]
    fn table_text_needs_no_json_escaping_and_no_log_quoting() {
        for row in verbs() {
            for text in [row.noun, row.verb, row.runs, row.summary] {
                assert!(text.is_ascii() && !text.contains(['"', '\\']), "{text}");
            }
        }
    }
}
