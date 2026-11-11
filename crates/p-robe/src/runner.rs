//! Running the dispatcher for an approved call: `sudo -n probe --within
//! <rating> <noun> <verb> [args]`, with the rating the service signed.
//! `--within` only restricts: the dispatcher rates again where it opens the
//! file and refuses if it is above (`proposals/rating-rule.md`, section 5).

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use p_act::rating::Rating;

use crate::table::format_rating;

/// More than a verb's answer can be (the dispatcher caps it at 1 MiB).
const OUTPUT_LIMIT: u64 = 3 << 20;

/// What the dispatcher did.
#[derive(Debug, PartialEq, Eq)]
pub struct RunOutput {
    /// Its exit code (see `dispatch.rs`).
    pub rc: u8,
    /// What it wrote: one JSON object per line.
    pub stdout: String,
}

/// How an approved call is run.
pub trait Runner: Send + Sync {
    /// Runs `action` (`noun verb`) with `params`, refusing above `within`.
    ///
    /// # Errors
    /// Why it could not be started or read, in words.
    fn run(&self, within: Rating, action: &str, params: &[String]) -> Result<RunOutput, String>;
}

/// The argument vector after `sudo -n --`.
#[must_use]
pub fn argv(probe: &std::path::Path, within: Rating, action: &str, params: &[String]) -> Vec<String> {
    let mut argv = vec![probe.display().to_string(), "--within".into(), format_rating(within)];
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
    fn run(&self, within: Rating, action: &str, params: &[String]) -> Result<RunOutput, String> {
        let mut child = Command::new(&self.sudo)
            .args(["-n", "--"])
            .args(argv(&self.probe, within, action, params))
            .env_clear()
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("cannot start sudo: {e}"))?;
        let mut text = String::new();
        child
            .stdout
            .take()
            .ok_or("no stdout")?
            .take(OUTPUT_LIMIT)
            .read_to_string(&mut text)
            .map_err(|e| e.to_string())?;
        let status = child.wait().map_err(|e| e.to_string())?;
        // sudo's own failure (no rule, no password) is 1: a code a verb could also give;
        // the answer's absence tells them apart for a person reading the log.
        Ok(RunOutput { rc: u8::try_from(status.code().unwrap_or(255)).unwrap_or(255), stdout: text })
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
    fn run(&self, within: Rating, action: &str, params: &[String]) -> Result<RunOutput, String> {
        use std::ffi::OsString;
        if let Some(before) = &self.before {
            before();
        }
        let mut words: Vec<OsString> = vec!["--within".into(), format_rating(within).into()];
        words.extend(action.split(' ').map(OsString::from));
        words.extend(params.iter().map(OsString::from));
        let audit = crate::audit::FileAudit(self.audit_file.clone());
        let caller = crate::dispatch::Caller { euid: 0, sudo_user: Some(self.user.clone()), from: None };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let rc =
            crate::dispatch::Dispatcher::new(&audit, self.lock_dir.clone()).run(&caller, &words, &mut out, &mut err);
        Ok(RunOutput { rc, stdout: String::from_utf8_lossy(&out).into_owned() })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p_act::rating::{Damage, Disruption, Exposure};

    #[test]
    fn the_command_is_the_dispatcher_with_the_signed_rating_before_the_words() {
        let within = Rating::new(Exposure::Internal, Damage::None, Disruption::Brief);
        assert_eq!(
            argv(std::path::Path::new("/usr/local/bin/probe"), within, "rt procs", &["pid=4711".into()]),
            ["/usr/local/bin/probe", "--within", "internal,none,brief", "rt", "procs", "pid=4711"]
        );
    }
}
