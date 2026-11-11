//! Two verbs for trying the service end to end, in a build with the
//! `test-verbs` feature only. Neither does anything to the host.

use p_ledge::rating::{Damage, Disruption, Exposure, Rating};

use crate::answer::{Answer, Full, header};
use crate::json::Record;
use crate::table::{Args, Availability, Env, Verb};
use crate::{clock, kit};

/// `test echo` and `test peak`.
pub const VERBS: &[Verb] = &[
    Verb {
        noun: "test",
        verb: "echo",
        runs: "probe",
        rating: Rating::HARMLESS,
        args: Args::Some,
        summary: "TEST BUILD: answers with its arguments; rated harmless",
        availability: Availability::Ready(echo),
    },
    Verb {
        noun: "test",
        verb: "peak",
        runs: "probe",
        // The top of one scale only: that alone must make the person's
        // confirmed approval key the only one that will do.
        rating: Rating::new(Exposure::Open, Damage::None, Disruption::Outage),
        args: Args::Some,
        summary: "TEST BUILD: answers with its arguments; rated at the top of disruption, does nothing",
        availability: Availability::Ready(echo_of),
    },
];

fn echo(env: &Env, args: &[String], answer: &mut Answer<'_>) -> Result<u8, Full> {
    answer_with("echo", env, args, answer)
}

fn echo_of(env: &Env, args: &[String], answer: &mut Answer<'_>) -> Result<u8, Full> {
    answer_with("peak", env, args, answer)
}

fn answer_with(verb: &str, env: &Env, args: &[String], answer: &mut Answer<'_>) -> Result<u8, Full> {
    answer.record(&header("test", verb, &kit::hostname(), &clock::now()))?;
    answer.record(&Record::new("echo").str("identity", &env.identity).strs("args", args))?;
    Ok(0)
}
