//! Running the dispatcher for an approved call: `sudo -n probe --within
//! <rating> <noun> <verb> [args]`, with the rating the service signed.
//! `--within` only restricts: the dispatcher rates again where it opens the
//! file and refuses if it is above (`proposals/rating-rule.md`, section 5).

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use p_act::rating::Rating;

use crate::table::format_rating;

/// How long a verb may run before it is killed. The deadline bounds the start of
/// an action, not its run (`doc/approvals.md`, R7), so the service bounds the run
/// itself; a limit per verb in the table is not built.
pub const RUN_LIMIT: std::time::Duration = std::time::Duration::from_secs(600);

/// More than a verb's answer can be (the dispatcher caps it at 1 MiB).
const OUTPUT_LIMIT: u64 = 3 << 20;

/// What the dispatcher did.
#[derive(Debug, PartialEq, Eq)]
pub struct RunOutput {
    /// Its exit code (see `dispatch.rs`); 255 if it ended by a signal.
    pub rc: u8,
    /// It was killed at the run limit.
    pub timed_out: bool,
    /// The signal that ended it, if one did.
    pub signal: Option<i32>,
    /// What it wrote: one JSON object per line.
    pub stdout: String,
}

/// Why a run gave no [`RunOutput`]. The difference is the one an agent hears: `NotStarted` is certain
/// (nothing was started), `Lost` is not (something was, and its result is gone).
#[derive(Debug, PartialEq, Eq)]
pub enum RunError {
    NotStarted(String),
    Lost(String),
}

/// How an approved call is run.
pub trait Runner: Send + Sync {
    /// Runs `action` (`noun verb`) with `params`, refusing above `within`. `call_id` is
    /// the call's identifier, which every audit line of the dispatcher then carries; `until` is its
    /// deadline (seconds since the epoch): the dispatcher waits for its lock no longer than that and does
    /// not start the verb at or after it.
    ///
    /// # Errors
    /// [`RunError::NotStarted`] when it certainly did not start, [`RunError::Lost`] when it may have.
    fn run(
        &self,
        within: Rating,
        call_id: &str,
        until: i64,
        action: &str,
        params: &[String],
    ) -> Result<RunOutput, RunError>;
}

/// The argument vector after `sudo -n --`.
#[must_use]
pub fn argv(
    probe: &std::path::Path,
    within: Rating,
    call_id: &str,
    until: i64,
    action: &str,
    params: &[String],
) -> Vec<String> {
    let mut argv = vec![
        probe.display().to_string(),
        "--within".into(),
        format_rating(within),
        "--call".into(),
        call_id.into(),
        "--until".into(),
        until.to_string(),
    ];
    argv.extend(action.split(' ').map(String::from));
    argv.extend(params.iter().cloned());
    argv
}

/// Through sudo, as the person's own call goes: the service's account has a
/// sudo rule for exactly this program (a site's roll-out writes it).
#[derive(Debug)]
pub struct SudoRunner {
    pub sudo: PathBuf,
    pub probe: PathBuf,
    /// How long a run may take before it is killed ([`RUN_LIMIT`] in service).
    pub limit: std::time::Duration,
}

impl Runner for SudoRunner {
    fn run(
        &self,
        within: Rating,
        call_id: &str,
        until: i64,
        action: &str,
        params: &[String],
    ) -> Result<RunOutput, RunError> {
        let mut child = Command::new(&self.sudo)
            .args(["-n", "--"])
            .args(argv(&self.probe, within, call_id, until, action, params))
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| RunError::NotStarted(format!("cannot start sudo: {e}")))?;
        // A watchdog kills it at the limit; the read then ends with the pipe.
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let timed_out = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watchdog = {
            let (finished, timed_out, pid, limit) = (finished.clone(), timed_out.clone(), child.id(), self.limit);
            std::thread::spawn(move || {
                let started = std::time::Instant::now();
                while !finished.load(std::sync::atomic::Ordering::SeqCst) {
                    if started.elapsed() >= limit {
                        timed_out.store(true, std::sync::atomic::Ordering::SeqCst);
                        // SAFETY: a signal to a child this function started and has not yet waited for.
                        unsafe { libc::kill(i32::try_from(pid).unwrap_or(0), libc::SIGKILL) };
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            })
        };
        // From here on the verb may have run: whatever goes wrong is `Lost`, not `NotStarted`.
        let lost = |what: &str, e: &dyn std::fmt::Display| RunError::Lost(format!("{what}: {e}"));
        let Some(stdout) = child.stdout.take() else {
            let _ = child.kill();
            let _ = child.wait();
            finished.store(true, std::sync::atomic::Ordering::SeqCst);
            let _ = watchdog.join();
            return Err(RunError::Lost("no stdout".into()));
        };
        // The answer is read on its own thread, so that a run cut short at the limit does not wait for a
        // verb that still holds the pipe (sudo can be killed; what it started is not ours to kill).
        let (sent, received) = std::sync::mpsc::channel();
        // One byte more than the limit tells an answer that is too long from one that just fits.
        std::thread::spawn(move || {
            let mut text = String::new();
            let read = stdout.take(OUTPUT_LIMIT + 1).read_to_string(&mut text);
            let _ = sent.send((read, text));
        });
        let status = child.wait();
        finished.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = watchdog.join();
        let timed_out = timed_out.load(std::sync::atomic::Ordering::SeqCst);
        let status = status.map_err(|e| lost("wait", &e))?;
        let (read, text) = if timed_out {
            received.recv_timeout(std::time::Duration::from_secs(1)).unwrap_or((Ok(0), String::new()))
        } else {
            received.recv().map_err(|e| lost("read", &e))?
        };
        if text.len() as u64 > OUTPUT_LIMIT {
            return Err(RunError::Lost("answer over the limit".into()));
        }
        // A read that failed (not UTF-8, say) while the run was not cut short has lost the answer.
        if !timed_out {
            read.map_err(|e| lost("read", &e))?;
        }
        use std::os::unix::process::ExitStatusExt;
        Ok(RunOutput {
            rc: status.code().map_or(255, |code| u8::try_from(code).unwrap_or(255)),
            timed_out,
            signal: status.signal(),
            stdout: text,
        })
    }
}

/// In this process, as a caller that is root: for tests and test builds, where
/// there is no sudo and no root. **The sudo path does not run through this**;
/// what it shares with the real one is the dispatcher, `--within` included.
#[cfg(any(test, feature = "test-verbs"))]
pub struct InProcess {
    pub audit_file: PathBuf,
    pub lock_dir: PathBuf,
    /// The identity the dispatcher sees (`SUDO_USER`): the service's account.
    pub user: String,
    /// Called just before the dispatcher runs: where a test plants a link.
    pub before: Option<Box<dyn Fn() + Send + Sync>>,
}

#[cfg(any(test, feature = "test-verbs"))]
impl Runner for InProcess {
    fn run(
        &self,
        within: Rating,
        call_id: &str,
        until: i64,
        action: &str,
        params: &[String],
    ) -> Result<RunOutput, RunError> {
        use std::ffi::OsString;
        if let Some(before) = &self.before {
            before();
        }
        let mut words: Vec<OsString> = vec![
            "--within".into(),
            format_rating(within).into(),
            "--call".into(),
            call_id.into(),
            "--until".into(),
            until.to_string().into(),
        ];
        words.extend(action.split(' ').map(OsString::from));
        words.extend(params.iter().map(OsString::from));
        let audit = crate::audit::FileAudit(self.audit_file.clone());
        let caller = crate::dispatch::Caller { euid: 0, sudo_user: Some(self.user.clone()), from: None };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let rc =
            crate::dispatch::Dispatcher::new(&audit, self.lock_dir.clone()).run(&caller, &words, &mut out, &mut err);
        Ok(RunOutput { rc, timed_out: false, signal: None, stdout: String::from_utf8_lossy(&out).into_owned() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p_act::rating::{Damage, Disruption, Exposure};

    use std::os::unix::fs::PermissionsExt;

    /// A `sudo` that is the shell script `body` (it is given the whole argument vector, as sudo is).
    fn fake_sudo(name: &str, body: &str) -> SudoRunner {
        let dir = crate::testdir::new(name);
        let path = dir.join("sudo");
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        SudoRunner { sudo: path, probe: "/usr/local/bin/probe".into(), limit: std::time::Duration::from_secs(20) }
    }

    fn run(runner: &SudoRunner) -> Result<RunOutput, RunError> {
        let within = Rating::new(Exposure::Open, Damage::None, Disruption::None);
        runner.run(within, ID, 1_794_409_565, "sys kit", &[])
    }

    #[test]
    fn a_dispatcher_that_answers_and_exits_is_taken_as_it_is() {
        let out = run(&fake_sudo("ok", "echo '{\"type\":\"header\"}'; exit 70")).unwrap();
        assert_eq!((out.rc, out.timed_out, out.signal), (70, false, None));
        assert_eq!(out.stdout, "{\"type\":\"header\"}\n");
    }

    #[test]
    fn a_dispatcher_killed_by_a_signal_says_which() {
        let out = run(&fake_sudo("killed", "echo '{\"type\":\"header\"}'; kill -9 $$")).unwrap();
        assert_eq!((out.signal, out.timed_out), (Some(9), false));
    }

    #[test]
    fn a_run_past_the_limit_is_killed_and_says_so() {
        let started = std::time::Instant::now();
        let mut runner = fake_sudo("slow", "sleep 30");
        runner.limit = std::time::Duration::from_millis(600);
        let out = run(&runner).unwrap();
        assert!(out.timed_out && out.signal == Some(9), "{out:?}");
        assert!(started.elapsed() < std::time::Duration::from_secs(25), "{:?}", started.elapsed());
    }

    #[test]
    fn an_answer_over_the_limit_or_not_text_is_lost_not_unavailable() {
        let big = run(&fake_sudo("big", "head -c 4000000 /dev/zero | tr '\\0' x")).unwrap_err();
        assert!(matches!(big, RunError::Lost(ref why) if why.contains("over the limit")), "{big:?}");
        let binary = run(&fake_sudo("binary", "printf '\\377\\376'")).unwrap_err();
        assert!(matches!(binary, RunError::Lost(_)), "{binary:?}");
    }

    #[test]
    fn a_sudo_that_cannot_be_started_is_the_one_certain_not_started() {
        let mut runner = fake_sudo("absent", "exit 0");
        runner.sudo = runner.sudo.with_file_name("no-such-sudo");
        assert!(matches!(run(&runner), Err(RunError::NotStarted(_))));
    }

    const ID: &str = "3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11";

    #[test]
    fn the_command_is_the_dispatcher_with_the_signed_rating_before_the_words() {
        let within = Rating::new(Exposure::Internal, Damage::None, Disruption::Brief);
        assert_eq!(
            argv(
                std::path::Path::new("/usr/local/bin/probe"),
                within,
                ID,
                1_794_409_565,
                "rt procs",
                &["pid=4711".into()]
            ),
            [
                "/usr/local/bin/probe",
                "--within",
                "internal,none,brief",
                "--call",
                ID,
                "--until",
                "1794409565",
                "rt",
                "procs",
                "pid=4711"
            ]
        );
    }
}
