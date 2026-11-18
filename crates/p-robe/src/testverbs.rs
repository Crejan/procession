//! Two verbs for trying the service end to end, in a build with the
//! `test-verbs` feature only. Neither does anything to the host.

use std::io::Read as _;

use p_act::rating::{Damage, Disruption, Exposure, Rating};

use crate::answer::{Answer, Full, header};
use crate::json::Record;
use crate::rate::{Entries, Form, Param, ParamType, PathRule};
use crate::table::{Args, Availability, Env, Verb};
use crate::{clock, kit};

const READ_PARAMS: &[Param] = &[Param {
    name: "path",
    form: Form::Position(0),
    required: true,
    // `<sandbox>/open/` is harmless; anything else this verb reads is secret.
    ty: ParamType::Path(PathRule {
        entries: Entries::Sandbox,
        otherwise: Rating::new(Exposure::Secret, Damage::None, Disruption::None),
    }),
}];

/// `test echo`, `test fail`, `test peak` and `test read`.
pub const VERBS: &[Verb] = &[
    Verb {
        noun: "test",
        verb: "read",
        runs: "probe",
        rating: Rating::new(Exposure::Secret, Damage::None, Disruption::None),
        args: Args::Params { floor: Rating::HARMLESS, params: READ_PARAMS },
        summary: "TEST BUILD: reads the first bytes of one file; rated by where the file is",
        availability: Availability::Ready(read),
    },
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
        verb: "fail",
        runs: "probe",
        rating: Rating::HARMLESS,
        args: Args::Some,
        summary: "TEST BUILD: starts, writes its header and exits with the code of its first argument (2 if none); rated harmless",
        availability: Availability::Ready(fail),
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

/// Does what a verb that was started and gave no usable result does: a code other than 0.
fn fail(_env: &Env, args: &[String], answer: &mut Answer<'_>) -> Result<u8, Full> {
    answer.record(&header("test", "fail", &kit::hostname(), &clock::now()))?;
    Ok(args.first().and_then(|code| code.parse().ok()).unwrap_or(2))
}

/// Reads from the descriptor the dispatcher opened, never from the name.
fn read(env: &Env, _args: &[String], answer: &mut Answer<'_>) -> Result<u8, Full> {
    answer.record(&header("test", "read", &kit::hostname(), &clock::now()))?;
    let Some(used) = env.paths.first() else { return Ok(1) };
    let mut text = String::new();
    let mut failed = None;
    if let Some(mut file) = used.file.as_ref() {
        if !used.is_dir {
            let mut bytes = Vec::new();
            match (&mut file).take(4096).read_to_end(&mut bytes) {
                Ok(_) => text = String::from_utf8_lossy(&bytes).into_owned(),
                Err(error) => failed = Some(error.to_string()),
            }
        }
    } else {
        failed = Some("the file could not be opened".into());
    }
    let resolved = used.resolved.as_ref().map(|path| path.display().to_string());
    answer.record(
        &Record::new("file")
            .opt_str("resolved", resolved.as_deref())
            .bool("is_dir", used.is_dir)
            .str("text", &text)
            .opt_str("error", failed.as_deref()),
    )?;
    Ok(u8::from(failed.is_some()))
}
