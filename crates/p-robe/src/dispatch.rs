//! The dispatcher: `probe <noun> <verb> [args]`.
//!
//! The rules are the ones of `diag-dispatch`. A call is admitted by pure
//! checks ([`admit`]); only then does anything happen: the lock of the
//! identity, a line in the audit, the verb, a line in the audit. No shell is
//! ever between the caller and a verb: a verb is a function of this program
//! (and, later, a program started from an argument vector).
//!
//! Exit codes: 0 ok, 3 unavailable (a verb that cannot run here, or no audit
//! line could be written), 64 refused, 75 busy; a verb's own code otherwise.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;

use crate::answer::{ANSWER_CAP, Answer};
use crate::audit::{self, Audit, CLIP};
use crate::json::Record;
use crate::lock::{self, Fault, Taken};
use crate::rate::{self, Mode};
use crate::rules::{ARG_MAX, IDENTITY_LEN_MAX, check_argument, is_token};
use crate::table::{self, Availability, Env, Verb};
use p_act::rating::Rating;

pub const RC_UNAVAILABLE: u8 = 3;
pub const RC_REFUSED: u8 = 64;
pub const RC_BUSY: u8 = 75;
/// The call's deadline passed before its verb could start (`--until`).
pub const RC_EXPIRED: u8 = 76;
/// How long a call that came through the service (`--call`) waits for the identity's lock.
pub const LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(10);

/// The directory a test build is pointed at by `PROBE_TEST_SANDBOX`, if it may be: **never for a
/// process that is root**, which is what a call through sudo is. So even a sudo rule that kept the
/// variable (`env_keep`, `SETENV`) could not move the audit sink or the lock directory of a dispatcher
/// that runs as root. (Tests of the test build run as an ordinary user.)
#[cfg(feature = "test-verbs")]
#[must_use]
pub fn test_sandbox(variable: Option<OsString>, euid: u32) -> Option<PathBuf> {
    variable.filter(|_| euid != 0).map(PathBuf::from)
}

/// Who calls, as the process found it.
#[derive(Debug, Clone)]
pub struct Caller {
    /// The effective uid. The dispatcher runs as root, by sudo.
    pub euid: u32,
    /// `SUDO_USER`: the login that ran sudo.
    pub sudo_user: Option<String>,
    /// The first word of `SSH_CONNECTION`: where the person came from, if
    /// they came by SSH. Written to the audit line when it is an address.
    pub from: Option<String>,
}

/// A call that passed the pure checks.
#[derive(Debug)]
pub struct Admitted {
    pub identity: String,
    /// The rating the call was approved at (`--within`), if one was given.
    pub within: Option<Rating>,
    /// The call's identifier (`--call`), if the service gave one.
    pub call: Option<String>,
    /// The call's deadline in seconds since the epoch (`--until`): the verb is not started at or after it.
    pub until: Option<i64>,
    pub verb: &'static Verb,
    pub args: Vec<String>,
}

/// A call the rules refuse, and what is known about who made it.
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal {
    pub reason: String,
    pub identity: Option<String>,
}

fn refuse(reason: impl Into<String>, identity: Option<&str>) -> Refusal {
    Refusal { reason: reason.into(), identity: identity.map(String::from) }
}

/// Who the call is by, or why not. Only a person running `sudo -n probe ...`
/// under their own login (or the service's account doing the same) is let in.
fn identify(caller: &Caller) -> Result<String, Refusal> {
    let Some(user) = caller.sudo_user.as_deref() else {
        return Err(refuse("no entrance: not run through sudo", None));
    };
    if caller.euid != 0 {
        return Err(refuse("no entrance: not running as root", None));
    }
    if !is_token(user) || user.len() > IDENTITY_LEN_MAX {
        return Err(refuse("bad identity name", None));
    }
    Ok(user.to_string())
}

/// The pure checks, in the order of `diag-dispatch`.
///
/// # Errors
/// The first rule the call breaks.
pub fn admit(caller: &Caller, argv: &[OsString]) -> Result<Admitted, Refusal> {
    let identity = identify(caller)?;
    let who = Some(identity.as_str());
    let mut words = Vec::with_capacity(argv.len());
    for word in argv {
        match word.to_str() {
            Some(text) => words.push(text.to_string()),
            None => return Err(refuse("argument is not UTF-8", who)),
        }
    }
    // Flags before the noun, each at most once, in any order. `--within
    // <exposure>,<damage>,<disruption>`: the rating the call was approved at; it
    // can only restrict (the call is refused if the dispatcher's own rating is
    // above it). `--call <uuid>`: the identifier of the call the service is
    // running this for, written to every audit line so that an operator can join
    // them to the service's own; it changes nothing else. They are not
    // arguments, which may not start with `-`; they are read here, in this place only.
    let (mut within, mut call, mut until, mut rest) = (None, None, None, words.as_slice());
    loop {
        match rest {
            [flag, value, tail @ ..] if flag == "--within" && within.is_none() => {
                within = Some(
                    table::parse_rating(value)
                        .ok_or_else(|| refuse("bad --within: expected exposure,damage,disruption", who))?,
                );
                rest = tail;
            }
            [flag, value, tail @ ..] if flag == "--call" && call.is_none() => {
                call = Some(
                    p_act::CallId::parse(value)
                        .map_err(|_| refuse("bad --call: expected the call's identifier", who))?
                        .as_str()
                        .to_string(),
                );
                rest = tail;
            }
            [flag, value, tail @ ..] if flag == "--until" && until.is_none() => {
                until = Some(
                    value
                        .parse::<u64>()
                        .ok()
                        .filter(|_| value.len() <= 11 && value.chars().all(|c| c.is_ascii_digit()))
                        .and_then(|secs| i64::try_from(secs).ok())
                        .ok_or_else(|| refuse("bad --until: expected the call's deadline in seconds", who))?,
                );
                rest = tail;
            }
            [flag, ..] if flag == "--within" || flag == "--call" || flag == "--until" => {
                return Err(refuse(format!("bad {flag}: a value is needed, and each once"), who));
            }
            _ => break,
        }
    }
    // The waiting form is reachable only with `--call`: `--until` says how long it may go on, and means
    // nothing without it.
    if until.is_some() && call.is_none() {
        return Err(refuse("--until is only for a call that has --call", who));
    }
    let words = rest.to_vec();
    let [noun, verb, args @ ..] = words.as_slice() else {
        return Err(refuse("a noun and a verb are needed", who));
    };
    if !is_token(noun) {
        return Err(refuse("bad noun", who));
    }
    if !table::has_noun(noun) {
        return Err(refuse(format!("unknown noun {}", audit::quote(&audit::clip(noun, CLIP))), who));
    }
    if !is_token(verb) {
        return Err(refuse("bad verb", who));
    }
    let Some(row) = table::find(noun, verb) else {
        return Err(refuse(format!("unknown verb {noun} {}", audit::quote(&audit::clip(verb, CLIP))), who));
    };
    if args.len() > ARG_MAX {
        return Err(refuse("too many arguments", who));
    }
    for arg in args {
        if let Err(why) = check_argument(arg) {
            return Err(refuse(format!("{why} {}", audit::quote(&audit::clip(arg, CLIP))), who));
        }
    }
    if !row.args.takes_any() && !args.is_empty() {
        return Err(refuse(format!("{} takes no arguments", row.label()), who));
    }
    if matches!(row.availability, Availability::ServiceOnly) {
        return Err(refuse(format!("{} is offered by the service only", row.label()), who));
    }
    Ok(Admitted { identity, within, call, until, verb: row, args: args.to_vec() })
}

/// The identifier of `--call`, if the leading flags hold a well-formed one: read
/// before anything is checked, so that even a refusal can say which call it was.
fn scan_call(argv: &[OsString]) -> Option<String> {
    let mut rest = argv;
    while let [flag, value, tail @ ..] = rest {
        match flag.to_str() {
            Some("--call") => return p_act::CallId::parse(value.to_str()?).ok().map(|id| id.as_str().to_string()),
            Some("--within" | "--until") => rest = tail,
            _ => return None,
        }
    }
    None
}

/// Where a call came from, for the audit lines.
struct Origin<'a> {
    from: &'a str,
    call_id: Option<&'a str>,
}

/// What the dispatcher is wired to.
pub struct Dispatcher<'a> {
    pub audit: &'a dyn Audit,
    /// How long a call with `--call` waits for the identity's lock; a call without it does not wait.
    pub lock_wait: std::time::Duration,
    pub lock_dir: PathBuf,
    pub cap: usize,
}

/// Why a call stopped before or after it ran.
enum Stop {
    Refused(Refusal),
    Busy(String),
    /// The deadline passed before the verb could start.
    Expired(String),
    Unavailable(String),
    /// A line could not be written; the call does not run (or, after the
    /// run, its answer is already out and the exit code says so).
    NoAudit(String),
}

impl<'a> Dispatcher<'a> {
    /// A dispatcher writing audit lines to `audit`, with the usual cap.
    #[must_use]
    pub fn new(audit: &'a dyn Audit, lock_dir: PathBuf) -> Self {
        Self { audit, lock_dir, cap: ANSWER_CAP, lock_wait: LOCK_WAIT }
    }

    fn log(&self, event: &str, fields: &[(&str, &str)]) -> Result<(), Stop> {
        self.audit.write(&audit::line(event, fields)).map_err(Stop::NoAudit)
    }

    /// Runs one call. The answer goes to `out`, a line of words to `err`
    /// when the call does not run. Returns the exit code.
    pub fn run(&self, caller: &Caller, argv: &[OsString], out: &mut dyn Write, err: &mut dyn Write) -> u8 {
        let from =
            caller.from.as_deref().filter(|ip| ip.chars().all(|c| c.is_ascii_hexdigit() || c == '.' || c == ':'));
        let from = from.unwrap_or("-");
        let call_id = scan_call(argv);
        match self.try_run(caller, argv, from, call_id.as_deref(), out) {
            Ok(rc) => rc,
            Err(stop) => self.stopped(stop, caller, argv, &Origin { from, call_id: call_id.as_deref() }, out, err),
        }
    }

    fn stopped(
        &self,
        stop: Stop,
        caller: &Caller,
        argv: &[OsString],
        origin: &Origin<'_>,
        out: &mut dyn Write,
        err: &mut dyn Write,
    ) -> u8 {
        let (from, call_id) = (origin.from, origin.call_id);
        let who = caller.sudo_user.as_deref().map_or_else(|| "-".to_string(), |user| audit::clip(user, CLIP));
        let (code, event, reason, identity) = match stop {
            Stop::NoAudit(why) => {
                let _ = writeln!(err, "probe: unavailable: cannot write the audit line ({})", audit::clip(&why, CLIP));
                return RC_UNAVAILABLE;
            }
            Stop::Refused(refusal) => (RC_REFUSED, "refused", refusal.reason, refusal.identity.unwrap_or(who)),
            Stop::Busy(reason) => (RC_BUSY, "busy", reason, who),
            Stop::Expired(reason) => (RC_EXPIRED, "expired", reason, who),
            Stop::Unavailable(reason) => (RC_UNAVAILABLE, "unavailable", reason, who),
        };
        let cmd = audit::clip(&argv.iter().map(|w| w.to_string_lossy()).collect::<Vec<_>>().join(" "), CLIP);
        let mut fields =
            vec![("reason", reason.as_str()), ("identity", identity.as_str()), ("from", from), ("cmd", cmd.as_str())];
        fields.extend(call_id.map(|id| ("call", id)));
        if let Err(Stop::NoAudit(why)) = self.log(event, &fields) {
            let _ = writeln!(err, "probe: unavailable: cannot write the audit line ({})", audit::clip(&why, CLIP));
            return RC_UNAVAILABLE;
        }
        let message = match code {
            RC_BUSY => format!("busy ({reason}): another call is running"),
            RC_EXPIRED => format!("expired ({reason}): the verb was not started"),
            _ => format!("{event}: {reason}"),
        };
        let _ = writeln!(err, "probe: {message}");
        if code == RC_UNAVAILABLE {
            let _ = writeln!(out, "{}", Record::new("error").str("message", &message).line());
        }
        code
    }

    fn try_run(
        &self,
        caller: &Caller,
        argv: &[OsString],
        from: &str,
        call_id: Option<&str>,
        out: &mut dyn Write,
    ) -> Result<u8, Stop> {
        let call = admit(caller, argv).map_err(Stop::Refused)?;
        let label = call.verb.label();
        let run = match call.verb.availability {
            Availability::Ready(run) => run,
            Availability::NotBuilt(reason) => return Err(Stop::Unavailable(format!("{label}: {reason}"))),
            Availability::ServiceOnly => unreachable!("admit refuses a verb that only the service offers"),
        };
        // The rating is made here, where the files are opened, and the call is
        // refused if it is above the one approved. The files stay open: the
        // verb reads these, not the names again.
        let rated = rate::rate(call.verb, &call.args, Mode::Open)
            .map_err(|why| Stop::Refused(refuse(why.0, Some(&call.identity))))?;
        if let Some(approved) = call.within.filter(|approved| !rated.rating.within(*approved)) {
            let reason = format!(
                "above-approved: rated {} against approved {}",
                table::format_rating(rated.rating),
                table::format_rating(approved)
            );
            return Err(Stop::Refused(refuse(reason, Some(&call.identity))));
        }
        let identity = call.identity.as_str();
        let args = call.args.join(" ");
        let mut fields = vec![
            ("noun", call.verb.noun),
            ("verb", call.verb.verb),
            ("args", args.as_str()),
            ("identity", identity),
            ("from", from),
        ];
        fields.extend(call_id.map(|id| ("call", id)));
        // The waiting form is reachable only with `--call`; `--until` (the call's deadline) bounds it, and
        // the verb is not started at or after it, whatever the wait did: the decision is made here, after
        // the lock is held, by this process's clock.
        let waits = call_id.is_some();
        let now = || p_act::Timestamp::now().map_or(0, p_act::Timestamp::unix);
        if call.until.is_some_and(|until| now() >= until) {
            return Err(Stop::Expired("the deadline had passed before the call reached the dispatcher".into()));
        }
        let wait = match (waits, call.until) {
            (false, _) => std::time::Duration::ZERO,
            (true, None) => self.lock_wait,
            (true, Some(until)) => {
                self.lock_wait.min(std::time::Duration::from_secs(u64::try_from(until - now()).unwrap_or(0)))
            }
        };
        let waiting_since = Instant::now();
        let taken = lock::take_waiting(&self.lock_dir, identity, wait);
        let waited = format!("{:.2}s", waiting_since.elapsed().as_secs_f64());
        if waits {
            fields.push(("waited", waited.as_str()));
        }
        let _lock = match taken {
            Ok(Taken::Held(file)) => Some(file),
            Ok(Taken::NoDirectory) => {
                self.log("nolock", &fields)?;
                None
            }
            Err(Fault::Busy) if call.until.is_some_and(|until| now() >= until) => {
                return Err(Stop::Expired(format!("the deadline passed while waiting for the lock (waited {waited})")));
            }
            Err(Fault::Busy) if waits => return Err(Stop::Busy(format!("identity-busy: waited {waited}"))),
            Err(Fault::Busy) => return Err(Stop::Busy("identity-busy".into())),
            Err(Fault::Refused(reason)) => return Err(Stop::Refused(refuse(reason, Some(identity)))),
        };
        if call.until.is_some_and(|until| now() >= until) {
            return Err(Stop::Expired(format!("the deadline passed before the verb could start (waited {waited})")));
        }
        self.log("start", &fields)?;
        let started = Instant::now();
        let env = Env {
            paths: rated.paths,
            identity: call.identity.clone(),
            euid: caller.euid,
            lock_dir: self.lock_dir.clone(),
            audit: self.audit.describe(),
        };
        let mut answer = Answer::new(out, self.cap);
        let rc = run(&env, &call.args, &mut answer).unwrap_or(0);
        let (rc_text, took, bytes) =
            (rc.to_string(), format!("{:.2}s", started.elapsed().as_secs_f64()), answer.bytes().to_string());
        let mut done = fields.to_vec();
        done.extend([("rc", rc_text.as_str()), ("duration", took.as_str()), ("bytes", bytes.as_str())]);
        if answer.truncated() {
            done.push(("truncated", "true"));
        }
        self.log("done", &done)?;
        Ok(rc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::fake::Memory;

    fn sudo(user: &str) -> Caller {
        Caller { euid: 0, sudo_user: Some(user.into()), from: None }
    }

    fn words(words: &[&str]) -> Vec<OsString> {
        words.iter().map(OsString::from).collect()
    }

    struct Outcome {
        rc: u8,
        out: String,
        err: String,
        lines: Vec<String>,
    }

    fn call_with(sink: &Memory, lock_dir: &std::path::Path, caller: &Caller, argv: &[&str]) -> Outcome {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let rc = Dispatcher::new(sink, lock_dir.to_path_buf()).run(caller, &words(argv), &mut out, &mut err);
        Outcome {
            rc,
            out: String::from_utf8(out).unwrap(),
            err: String::from_utf8(err).unwrap(),
            lines: sink.lines.borrow().clone(),
        }
    }

    /// As `call_with`, with a lock wait of `wait` for a call that has `--call`.
    fn call_waiting(
        sink: &Memory,
        lock_dir: &std::path::Path,
        caller: &Caller,
        argv: &[&str],
        wait: std::time::Duration,
    ) -> Outcome {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut dispatcher = Dispatcher::new(sink, lock_dir.to_path_buf());
        dispatcher.lock_wait = wait;
        let rc = dispatcher.run(caller, &words(argv), &mut out, &mut err);
        Outcome {
            rc,
            out: String::from_utf8(out).unwrap(),
            err: String::from_utf8(err).unwrap(),
            lines: sink.lines.borrow().clone(),
        }
    }

    fn call(caller: &Caller, argv: &[&str]) -> Outcome {
        call_with(&Memory::default(), &crate::testdir::new("locks"), caller, argv)
    }

    fn refused(argv: &[&str]) -> Outcome {
        let outcome = call(&sudo("jan"), argv);
        assert_eq!(outcome.rc, RC_REFUSED, "{argv:?}: {}", outcome.err);
        assert!(outcome.out.is_empty(), "a refused call writes no answer: {argv:?}");
        assert_eq!(outcome.lines.len(), 1, "{argv:?}");
        assert!(outcome.lines[0].starts_with("event=refused "), "{}", outcome.lines[0]);
        outcome
    }

    // -- the entrance --------------------------------------------------

    #[test]
    fn only_a_login_that_came_through_sudo_as_root_is_let_in() {
        let none = Caller { euid: 0, sudo_user: None, from: None };
        assert_eq!(call(&none, &["sys", "kit"]).rc, RC_REFUSED);
        let not_root = Caller { euid: 1000, sudo_user: Some("jan".into()), from: None };
        assert_eq!(call(&not_root, &["sys", "kit"]).rc, RC_REFUSED);
        for bad in ["", "Jan", "1jan", "j an", "jan\nevent=done", &"a".repeat(IDENTITY_LEN_MAX + 1)] {
            assert_eq!(call(&sudo(bad), &["sys", "kit"]).rc, RC_REFUSED, "{bad:?}");
        }
        assert_eq!(call(&sudo("jan"), &["sys", "kit"]).rc, 0);
    }

    #[test]
    fn what_a_caller_calls_himself_cannot_change_the_audit_line() {
        let sink = Memory::default();
        let hostile =
            Caller { euid: 0, sudo_user: Some("x\nevent=done rc=0".into()), from: Some("1.2.3.4\nevent=done".into()) };
        let outcome = call_with(&sink, &crate::testdir::new("locks"), &hostile, &["sys", "kit"]);
        assert_eq!(outcome.rc, RC_REFUSED);
        assert_eq!(outcome.lines.len(), 1);
        assert!(
            !outcome.lines[0].contains('\n') && outcome.lines[0].contains("identity='x\\u{a}event=done rc=0'"),
            "{}",
            outcome.lines[0]
        );
        assert!(outcome.lines[0].contains("from=-"), "a source that is not an address is not copied");
    }

    // -- the words ------------------------------------------------------

    #[test]
    fn a_call_names_a_noun_and_a_verb_of_the_table_and_nothing_else_runs() {
        for argv in [
            &["sys"][..],
            &[],
            &["Sys", "kit"],
            &["-x", "kit"],
            &["nope", "kit"],
            &["sys", "Kit"],
            &["sys", "nope"],
            &["sys", "-h"],
            &["rt", "kit"],
            &["sys kit"],
            &["sys", "kit extra"],
        ] {
            refused(argv);
        }
    }

    #[test]
    fn an_argument_is_checked_against_the_class_the_length_and_the_dash_rule() {
        for bad in ["", "-x", "--help", "a b", "a;b", "`id`", "a'b", &"a".repeat(513)] {
            refused(&["rt", "irq", bad]);
        }
        refused(&["rt", "irq", "ok=1", "bad arg"]);
    }

    #[test]
    fn an_argument_that_is_not_utf8_is_refused() {
        use std::os::unix::ffi::OsStringExt;
        let argv = vec![OsString::from("rt"), OsString::from("irq"), OsString::from_vec(vec![0xff, 0xfe])];
        assert_eq!(admit(&sudo("jan"), &argv).unwrap_err().reason, "argument is not UTF-8");
    }

    #[test]
    fn at_most_64_arguments() {
        let many: Vec<String> = (0..=ARG_MAX).map(|n| format!("k={n}")).collect();
        let mut argv = vec!["rt", "irq"];
        argv.extend(many.iter().map(String::as_str));
        refused(&argv);
        argv.pop();
        assert!(admit(&sudo("jan"), &words(&argv)).is_ok());
    }

    #[test]
    fn a_verb_without_arguments_takes_none() {
        let outcome = refused(&["sys", "kit", "x=1"]);
        assert!(outcome.err.contains("takes no arguments"));
    }

    #[test]
    fn the_refusal_line_holds_what_was_asked_without_letting_it_add_lines_or_fields() {
        let outcome = refused(&["rt", "irq", "a\nevent=done rc=0"]);
        assert!(outcome.lines[0].contains("cmd="), "{}", outcome.lines[0]);
        assert!(!outcome.lines[0].contains('\n'));
        let long = "z".repeat(5000);
        let outcome = refused(&["rt", "irq", &long]);
        assert!(outcome.lines[0].len() < 800, "{}", outcome.lines[0].len());
    }

    #[test]
    fn the_fallback_command_is_refused_with_or_without_arguments() {
        for argv in [&["run", "command"][..], &["run", "command", "path=/bin/true"]] {
            let outcome = refused(argv);
            assert!(outcome.err.contains("offered by the service only"), "{}", outcome.err);
        }
    }

    // -- the audit ------------------------------------------------------

    #[test]
    fn a_line_before_and_a_line_after_each_call_with_who_and_what() {
        let outcome = call(&sudo("jan"), &["sys", "kit"]);
        assert_eq!(outcome.rc, 0);
        assert_eq!(outcome.lines.len(), 2, "{:?}", outcome.lines);
        assert!(
            outcome.lines[0].starts_with("event=start noun=sys verb=kit args='' identity=jan from=-"),
            "{}",
            outcome.lines[0]
        );
        assert!(outcome.lines[1].starts_with("event=done noun=sys verb=kit "), "{}", outcome.lines[1]);
        assert!(
            outcome.lines[1].contains(" rc=0 duration=") && outcome.lines[1].contains(" bytes="),
            "{}",
            outcome.lines[1]
        );
    }

    #[test]
    fn a_call_whose_first_line_cannot_be_written_does_not_run() {
        let sink = Memory { fail_after: Some(0), ..Memory::default() };
        let outcome = call_with(&sink, &crate::testdir::new("locks"), &sudo("jan"), &["sys", "kit"]);
        assert_eq!(outcome.rc, RC_UNAVAILABLE);
        assert!(outcome.out.is_empty(), "nothing ran: {}", outcome.out);
        assert!(outcome.err.contains("cannot write the audit line"));
    }

    #[test]
    fn a_refusal_that_cannot_be_recorded_is_unavailable_not_silent() {
        let sink = Memory { fail_after: Some(0), ..Memory::default() };
        let outcome = call_with(&sink, &crate::testdir::new("locks"), &sudo("jan"), &["sys", "nope"]);
        assert_eq!(outcome.rc, RC_UNAVAILABLE);
    }

    #[test]
    fn the_start_line_comes_before_the_answer() {
        // The sink refuses the second line (the start line, after the nolock
        // line): nothing may have been printed.
        let sink = Memory { fail_after: Some(1), ..Memory::default() };
        let outcome = call_with(&sink, &crate::testdir::new("locks").join("absent"), &sudo("jan"), &["sys", "kit"]);
        assert_eq!(outcome.rc, RC_UNAVAILABLE);
        assert!(outcome.out.is_empty());
    }

    #[test]
    fn a_done_line_that_cannot_be_written_is_reported_by_the_exit_code() {
        let dir = crate::testdir::new("locks");
        let sink = Memory { fail_after: Some(1), ..Memory::default() };
        let outcome = call_with(&sink, &dir, &sudo("jan"), &["sys", "kit"]);
        assert_eq!(outcome.rc, RC_UNAVAILABLE);
        assert!(outcome.out.contains("\"type\":\"summary\""), "the answer was already given");
    }

    // -- the lock ---------------------------------------------------------

    #[test]
    fn one_call_per_identity_at_a_time() {
        let dir = crate::testdir::new("locks");
        let held = lock::take(&dir, "jan").unwrap();
        let sink = Memory::default();
        let outcome = call_with(&sink, &dir, &sudo("jan"), &["sys", "kit"]);
        assert_eq!(outcome.rc, RC_BUSY);
        assert!(outcome.out.is_empty());
        assert!(outcome.lines.len() == 1 && outcome.lines[0].starts_with("event=busy "), "{:?}", outcome.lines);
        assert_eq!(call_with(&Memory::default(), &dir, &sudo("eva"), &["sys", "kit"]).rc, 0);
        drop(held);
        assert_eq!(released(&dir, "jan"), 0, "the lock is free once its holder is done");
    }

    /// The exit code of a call of `who` once its lock is free. A process another test forks while the lock
    /// is held keeps a copy of the descriptor until it has exec'd, so the release can take a moment.
    fn released(dir: &std::path::Path, who: &str) -> u8 {
        let started = Instant::now();
        loop {
            let rc = call_with(&Memory::default(), dir, &sudo(who), &["sys", "kit"]).rc;
            if rc != RC_BUSY || started.elapsed() > std::time::Duration::from_secs(3) {
                return rc;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    #[test]
    fn the_lock_is_released_when_the_call_is_done() {
        let dir = crate::testdir::new("locks");
        for _ in 0..2 {
            assert_eq!(released(&dir, "jan"), 0);
        }
    }

    #[test]
    fn without_a_lock_directory_the_call_runs_and_says_so() {
        let outcome =
            call_with(&Memory::default(), &crate::testdir::new("locks").join("absent"), &sudo("jan"), &["sys", "kit"]);
        assert_eq!(outcome.rc, 0);
        assert!(outcome.lines[0].starts_with("event=nolock "));
    }

    #[test]
    fn a_symlinked_lock_file_is_a_refusal() {
        let dir = crate::testdir::new("locks");
        std::os::unix::fs::symlink(dir.join("x"), dir.join("jan.lock")).unwrap();
        let outcome = call_with(&Memory::default(), &dir, &sudo("jan"), &["sys", "kit"]);
        assert_eq!(outcome.rc, RC_REFUSED);
        assert!(outcome.lines[0].starts_with("event=refused ") && outcome.lines[0].contains("symlink"));
    }

    // -- the verbs ------------------------------------------------------------

    #[test]
    fn a_verb_that_needs_a_tool_not_built_is_unavailable_with_the_reason_and_runs_nothing() {
        for verb in ["irq", "procs", "jitter"] {
            let outcome = call(&sudo("jan"), &["rt", verb]);
            assert_eq!(outcome.rc, RC_UNAVAILABLE, "{verb}");
            assert!(outcome.err.contains("prover"), "{}", outcome.err);
            assert!(outcome.out.contains("\"type\":\"error\""), "{}", outcome.out);
            assert!(outcome.lines.iter().any(|l| l.starts_with("event=unavailable ")), "{:?}", outcome.lines);
            assert!(!outcome.lines.iter().any(|l| l.starts_with("event=start")));
        }
    }

    #[test]
    fn sys_kit_answers_one_json_object_per_line_a_header_first() {
        let outcome = call(&sudo("jan"), &["sys", "kit"]);
        assert_eq!(outcome.rc, 0);
        let lines: Vec<&str> = outcome.out.lines().collect();
        assert!(
            lines[0].starts_with("{\"type\":\"header\",\"schema_version\":1,\"noun\":\"sys\",\"verb\":\"kit\""),
            "{}",
            lines[0]
        );
        assert!(lines.iter().all(|l| l.starts_with('{') && l.ends_with('}')));
        assert!(lines.iter().any(|l| l.contains("\"type\":\"installation\"") && l.contains("\"identity\":\"jan\"")));
        assert!(lines.iter().any(|l| l.contains("\"noun\":\"rt\",\"verb\":\"irq\",\"status\":\"unavailable\"")));
        assert!(lines.last().unwrap().contains("\"type\":\"summary\""));
    }

    #[test]
    fn every_answer_is_capped() {
        let sink = Memory::default();
        let dir = crate::testdir::new("locks");
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut dispatcher = Dispatcher::new(&sink, dir);
        dispatcher.cap = 600;
        let rc = dispatcher.run(&sudo("jan"), &words(&["sys", "kit"]), &mut out, &mut err);
        let text = String::from_utf8(out).unwrap();
        assert_eq!(rc, 0);
        assert!(text.len() <= 600, "{}", text.len());
        assert!(text.lines().last().unwrap().starts_with("{\"type\":\"truncated\""), "{text}");
        assert!(sink.lines.borrow().last().unwrap().contains("truncated=true"));
    }

    // -- waiting for the lock, and the deadline -----------------------------------------------

    fn secs(n: u64) -> std::time::Duration {
        std::time::Duration::from_secs(n)
    }

    fn millis(n: u64) -> std::time::Duration {
        std::time::Duration::from_millis(n)
    }

    fn unix_now() -> i64 {
        p_act::Timestamp::now().unwrap().unix()
    }

    #[test]
    fn a_call_with_call_waits_for_the_lock_and_says_how_long() {
        let dir = crate::testdir::new("locks");
        let held = lock::take(&dir, "jan").unwrap();
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(millis(300));
            drop(held);
        });
        let started = Instant::now();
        let outcome = call_waiting(&Memory::default(), &dir, &sudo("jan"), &["--call", CALL, "sys", "kit"], secs(5));
        releaser.join().unwrap();
        assert_eq!(outcome.rc, 0, "{:?}", outcome.lines);
        assert!(started.elapsed() >= millis(250) && started.elapsed() < secs(4));
        let waited: f64 =
            outcome.lines[0].split(" waited=").nth(1).unwrap().split('s').next().unwrap().parse().unwrap();
        assert!(waited >= 0.25, "{:?}", outcome.lines);
        assert!(outcome.lines.iter().all(|l| l.contains(" waited=")), "{:?}", outcome.lines);
    }

    #[test]
    fn a_call_without_call_does_not_wait() {
        let dir = crate::testdir::new("locks");
        let _held = lock::take(&dir, "jan").unwrap();
        let started = Instant::now();
        // However long the wait is set: the form without --call is the immediate one.
        let outcome = call_waiting(&Memory::default(), &dir, &sudo("jan"), &["sys", "kit"], secs(5));
        assert_eq!(outcome.rc, RC_BUSY);
        assert!(started.elapsed() < millis(500));
        assert!(!outcome.lines[0].contains("waited"), "{:?}", outcome.lines);
    }

    #[test]
    fn still_held_after_the_wait_is_busy_and_the_line_says_it_waited() {
        let dir = crate::testdir::new("locks");
        let _held = lock::take(&dir, "jan").unwrap();
        let started = Instant::now();
        let outcome =
            call_waiting(&Memory::default(), &dir, &sudo("jan"), &["--call", CALL, "sys", "kit"], millis(400));
        assert_eq!(outcome.rc, RC_BUSY);
        assert!(started.elapsed() >= millis(380) && started.elapsed() < secs(3));
        assert!(outcome.out.is_empty() && outcome.lines.len() == 1);
        assert!(
            outcome.lines[0].starts_with("event=busy ") && outcome.lines[0].contains("identity-busy: waited 0.4"),
            "{:?}",
            outcome.lines
        );
        assert!(outcome.lines[0].contains(&format!(" call={CALL}")));
    }

    #[test]
    fn the_verb_is_not_started_at_or_after_the_deadline() {
        let until = |n: i64| n.to_string();
        // Already past, before anything: expired, no lock taken, no verb.
        let past = until(unix_now() - 1);
        let outcome = call(&sudo("jan"), &["--call", CALL, "--until", &past, "sys", "kit"]);
        assert_eq!(outcome.rc, RC_EXPIRED);
        assert!(
            outcome.out.is_empty() && outcome.lines.len() == 1 && outcome.lines[0].starts_with("event=expired "),
            "{:?}",
            outcome.lines
        );
        // The deadline passes while the dispatcher waits for the lock: expired, not busy, and the verb does not start
        // even though the lock is freed a moment later.
        let dir = crate::testdir::new("locks");
        let held = lock::take(&dir, "jan").unwrap();
        let soon = until(unix_now() + 1);
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(millis(1500));
            drop(held);
        });
        let started = Instant::now();
        let outcome = call_waiting(
            &Memory::default(),
            &dir,
            &sudo("jan"),
            &["--call", CALL, "--until", &soon, "sys", "kit"],
            secs(10),
        );
        releaser.join().unwrap();
        assert_eq!(outcome.rc, RC_EXPIRED, "{:?}", outcome.lines);
        assert!(started.elapsed() < secs(3), "the wait was cut at the deadline, not at 10 seconds");
        assert!(outcome.out.is_empty(), "nothing ran");
        assert!(!outcome.lines.iter().any(|l| l.starts_with("event=start")), "{:?}", outcome.lines);
        assert!(outcome.lines[0].contains("the deadline passed while waiting for the lock"), "{:?}", outcome.lines);
        // The lock is taken just before the deadline's second ends: the decision is made after it is held.
        let dir = crate::testdir::new("locks");
        let held = lock::take(&dir, "jan").unwrap();
        let tight = until(unix_now() + 2);
        let releaser = std::thread::spawn(move || {
            std::thread::sleep(millis(2300));
            drop(held);
        });
        let outcome = call_waiting(
            &Memory::default(),
            &dir,
            &sudo("jan"),
            &["--call", CALL, "--until", &tight, "sys", "kit"],
            secs(10),
        );
        releaser.join().unwrap();
        assert_eq!(outcome.rc, RC_EXPIRED, "{:?}", outcome.lines);
        assert!(!outcome.lines.iter().any(|l| l.starts_with("event=start")));
        // A deadline well ahead is no hindrance.
        let far = until(unix_now() + 600);
        let outcome = call(&sudo("jan"), &["--call", CALL, "--until", &far, "sys", "kit"]);
        assert_eq!(outcome.rc, 0, "{:?}", outcome.lines);
    }

    #[test]
    fn until_is_reachable_only_with_call_and_only_as_a_plain_number() {
        let future = (unix_now() + 600).to_string();
        for bad in [
            vec!["--until", future.as_str(), "sys", "kit"],
            vec!["--call", CALL, "--until", "soon", "sys", "kit"],
            vec!["--call", CALL, "--until", "-5", "sys", "kit"],
            vec!["--call", CALL, "--until", "1e9", "sys", "kit"],
            vec!["--call", CALL, "--until", "", "sys", "kit"],
            vec!["--call", CALL, "--until", "123456789012", "sys", "kit"],
            vec!["--call", CALL, "--until", "5", "--until", "6", "sys", "kit"],
            vec!["--call", CALL, "--until"],
            vec!["--call", CALL, "sys", "kit", "--until", "5"],
        ] {
            assert!(admit(&sudo("jan"), &words(&bad)).is_err(), "{bad:?}");
        }
        let call = admit(&sudo("jan"), &words(&["--until", &future, "--call", CALL, "sys", "kit"])).unwrap();
        assert_eq!(call.until, Some(future.parse().unwrap()));
    }

    // -- what may follow the flags, and what the environment may change --------------

    #[test]
    fn nothing_that_starts_with_a_dash_gets_past_the_flags() {
        const FLAGS: [&str; 4] = ["--within", "secret,lasting,outage", "--call", CALL];
        fn with<'a>(rest: &[&'a str]) -> Vec<&'a str> {
            FLAGS.iter().copied().chain(rest.iter().copied()).collect()
        }
        for rest in [
            &["-x", "sys", "kit"][..],
            &["--help"],
            &["--within", "open,none,none", "sys", "kit"],
            &["--call", CALL, "sys", "kit"],
            &["-", "sys", "kit"],
            &["sys", "-x"],
            &["sys", "kit", "--within", "open,none,none"],
            &["rt", "irq", "--call", CALL],
            &["rt", "irq", "-"],
            &["--", "sys", "kit"],
        ] {
            let argv = with(rest);
            assert!(admit(&sudo("jan"), &words(&argv)).is_err(), "{argv:?}");
            assert_eq!(call(&sudo("jan"), &argv).rc, RC_REFUSED, "{argv:?}");
        }
        // What the sudoers `*` could pass after the identifier is still only a verb and its arguments.
        assert!(admit(&sudo("jan"), &words(&with(&["sys", "kit"]))).is_ok());
    }

    #[test]
    fn the_dispatcher_reads_no_environment_variable_but_two_for_the_log_and_one_for_tests() {
        // Every `env::var` of the library's sources, found in the files: a new one has to be argued for here.
        let mut found = Vec::new();
        for entry in std::fs::read_dir(concat!(env!("CARGO_MANIFEST_DIR"), "/src")).unwrap() {
            let path = entry.unwrap().path();
            let file = path.file_name().unwrap().to_string_lossy().into_owned();
            if file.ends_with("_tests.rs") || !file.ends_with(".rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            // Only the code: tests' own uses, and comments, are not the program's.
            let code = text.split("#[cfg(test)]").next().unwrap();
            for line in code.lines().filter(|l| !l.trim_start().starts_with("//")) {
                for pattern in ["env::var(\"", "env::var_os(\"", "env!(\"", "option_env!(\""] {
                    if let Some(at) = line.find(pattern) {
                        let name = line[at + pattern.len()..].split('"').next().unwrap_or("").to_string();
                        found.push(format!("{file}: {pattern}{name}"));
                    }
                }
            }
        }
        found.sort();
        // SUDO_USER and SSH_CONNECTION (main.rs and the log only), PROBE_TEST_SANDBOX (main.rs, test build, never as root),
        // and CARGO_PKG_VERSION / CARGO_MANIFEST_DIR at compile time. Nothing chooses an audit sink or a lock directory.
        for line in &found {
            let ok = ["CARGO_PKG_VERSION", "SUDO_USER", "SSH_CONNECTION", "PROBE_TEST_SANDBOX", "CARGO_MANIFEST_DIR"]
                .iter()
                .any(|name| line.contains(name));
            assert!(ok, "an environment variable the dispatcher did not read before: {line} (all: {found:?})");
        }
    }

    #[cfg(feature = "test-verbs")]
    #[test]
    fn the_test_sandbox_is_never_honoured_for_a_process_that_is_root() {
        let dir = Some(OsString::from("/tmp/x"));
        assert_eq!(test_sandbox(dir.clone(), 0), None, "root: through sudo");
        assert_eq!(test_sandbox(dir.clone(), 1000), Some(PathBuf::from("/tmp/x")));
        assert_eq!(test_sandbox(None, 1000), None);
    }

    // -- --within ---------------------------------------------------------

    #[test]
    fn within_is_read_before_the_noun_and_only_there() {
        let call = admit(&sudo("jan"), &words(&["--within", "internal,none,brief", "sys", "kit"])).unwrap();
        assert_eq!(call.within, table::parse_rating("internal,none,brief"));
        assert_eq!(call.verb.label(), "sys kit");
        assert!(admit(&sudo("jan"), &words(&["sys", "kit"])).unwrap().within.is_none());
        for bad in [
            &["--within"][..],
            &["--within", "sys", "kit"],
            &["--within", "open,none", "sys", "kit"],
            &["--within", "open,none,none"],
            &["sys", "--within", "open,none,none"],
            &["rt", "irq", "--within", "open,none,none"],
        ] {
            assert!(admit(&sudo("jan"), &words(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn within_can_only_restrict_a_call_is_never_let_through_by_it() {
        // A call that rates at or below what is approved runs, with the flag or without it.
        for argv in [
            &["sys", "kit"][..],
            &["--within", "open,none,none", "sys", "kit"],
            &["--within", "secret,lasting,outage", "sys", "kit"],
        ] {
            assert_eq!(call(&sudo("jan"), argv).rc, 0, "{argv:?}");
        }
        // The flag does not make a refused call run.
        assert_eq!(call(&sudo("jan"), &["--within", "secret,lasting,outage", "run", "command"]).rc, RC_REFUSED);
        assert_eq!(call(&sudo("jan"), &["--within", "secret,lasting,outage", "rt", "irq"]).rc, RC_UNAVAILABLE);
    }

    const CALL: &str = "3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11";

    #[test]
    fn call_is_read_with_within_in_either_order_once_each_and_only_before_the_noun() {
        for argv in [
            &["--call", CALL, "sys", "kit"][..],
            &["--call", CALL, "--within", "open,none,none", "sys", "kit"],
            &["--within", "open,none,none", "--call", CALL, "sys", "kit"],
        ] {
            let call = admit(&sudo("jan"), &words(argv)).unwrap();
            assert_eq!(call.call.as_deref(), Some(CALL), "{argv:?}");
            assert_eq!(call.verb.label(), "sys kit");
        }
        for bad in [
            &["--call"][..],
            &["--call", "sys", "kit"],
            &["--call", "not-a-uuid", "sys", "kit"],
            &["--call", CALL, "--call", CALL, "sys", "kit"],
            &["sys", "kit", "--call", CALL],
        ] {
            assert!(admit(&sudo("jan"), &words(bad)).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn every_audit_line_of_a_call_carries_its_identifier_a_refusal_too() {
        let ok = call(&sudo("jan"), &["--call", CALL, "sys", "kit"]);
        assert_eq!(ok.rc, 0);
        assert!(ok.lines.iter().all(|l| l.contains(&format!(" call={CALL}"))), "{:?}", ok.lines);
        assert_eq!(ok.lines.len(), 2);
        // Refused (an unknown verb), unavailable (not built), busy (lock held): the line says which call.
        for argv in [&["--call", CALL, "sys", "nope"][..], &["--call", CALL, "rt", "irq"]] {
            let outcome = call(&sudo("jan"), argv);
            assert!(
                outcome.lines.iter().all(|l| l.contains(&format!(" call={CALL}"))),
                "{argv:?}: {:?}",
                outcome.lines
            );
        }
        let dir = crate::testdir::new("locks");
        let _held = lock::take(&dir, "jan").unwrap();
        let busy = call_waiting(
            &Memory::default(),
            &dir,
            &sudo("jan"),
            &["--call", CALL, "sys", "kit"],
            std::time::Duration::from_millis(100),
        );
        assert_eq!(busy.rc, RC_BUSY);
        assert!(busy.lines[0].contains(&format!(" call={CALL}")), "{:?}", busy.lines);
        // A call without the flag has no such field.
        assert!(!call(&sudo("jan"), &["sys", "kit"]).lines.iter().any(|l| l.contains(" call=")));
    }

    #[cfg(feature = "test-verbs")]
    #[test]
    fn the_test_verbs_exist_in_this_build_with_their_ratings() {
        use p_act::rating::Rating;
        let echo = table::find("test", "echo").unwrap();
        let peak = table::find("test", "peak").unwrap();
        assert_eq!(echo.rating, Rating::HARMLESS);
        assert!(peak.rating.needs_confirmation() && peak.rating.exposure == p_act::rating::Exposure::Open);
        let outcome = call(&sudo("jan"), &["test", "echo", "a=1", "b"]);
        assert_eq!(outcome.rc, 0);
        assert!(outcome.out.contains("\"args\":[\"a=1\",\"b\"]"), "{}", outcome.out);
    }

    #[cfg(not(feature = "test-verbs"))]
    #[test]
    fn without_the_feature_there_are_no_test_verbs() {
        assert!(table::find("test", "echo").is_none());
        refused(&["test", "echo"]);
    }
}
