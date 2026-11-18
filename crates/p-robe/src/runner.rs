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
    /// Its exit code (see `dispatch.rs`).
    pub rc: u8,
    /// It was killed at [`RUN_LIMIT`].
    pub timed_out: bool,
    /// What it wrote: one JSON object per line.
    pub stdout: String,
}

/// How an approved call is run.
pub trait Runner: Send + Sync {
    /// Runs `action` (`noun verb`) with `params`, refusing above `within`. `call_id` is
    /// the call's identifier, which every audit line of the dispatcher then carries; `until` is its
    /// deadline (seconds since the epoch): the dispatcher waits for its lock no longer than that and does
    /// not start the verb at or after it.
    ///
    /// # Errors
    /// Why it could not be started or read, in words.
    fn run(
        &self,
        within: Rating,
        call_id: &str,
        until: i64,
        action: &str,
        params: &[String],
    ) -> Result<RunOutput, String>;
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
}

impl Runner for SudoRunner {
    fn run(
        &self,
        within: Rating,
        call_id: &str,
        until: i64,
        action: &str,
        params: &[String],
    ) -> Result<RunOutput, String> {
        let mut child = Command::new(&self.sudo)
            .args(["-n", "--"])
            .args(argv(&self.probe, within, call_id, until, action, params))
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot start sudo: {e}"))?;
        // A watchdog kills it at the limit; the read then ends with the pipe.
        let finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let timed_out = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let watchdog = {
            let (finished, timed_out, pid) = (finished.clone(), timed_out.clone(), child.id());
            std::thread::spawn(move || {
                let started = std::time::Instant::now();
                while !finished.load(std::sync::atomic::Ordering::SeqCst) {
                    if started.elapsed() >= RUN_LIMIT {
                        timed_out.store(true, std::sync::atomic::Ordering::SeqCst);
                        // SAFETY: a signal to a child this function started and has not yet waited for.
                        unsafe { libc::kill(i32::try_from(pid).unwrap_or(0), libc::SIGKILL) };
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
            })
        };
        let mut text = String::new();
        let read = child.stdout.take().ok_or("no stdout")?.take(OUTPUT_LIMIT).read_to_string(&mut text);
        let status = child.wait();
        finished.store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = watchdog.join();
        read.map_err(|e| e.to_string())?;
        let status = status.map_err(|e| e.to_string())?;
        // sudo's own failure (no rule, no password) is 1: a code a verb could also give;
        // the answer's absence tells them apart for a person reading the log.
        Ok(RunOutput {
            rc: u8::try_from(status.code().unwrap_or(255)).unwrap_or(255),
            timed_out: timed_out.load(std::sync::atomic::Ordering::SeqCst),
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
    ) -> Result<RunOutput, String> {
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
        Ok(RunOutput { rc, timed_out: false, stdout: String::from_utf8_lossy(&out).into_owned() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p_act::rating::{Damage, Disruption, Exposure};

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
