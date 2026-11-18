//! Running the few external tools that are the reference implementation
//! (`chronyc`, `journalctl`). A trait, so tests answer from a script.

use std::collections::BTreeMap;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// What a finished command wrote.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Output {
    /// Exit code; `None` when a signal ended it.
    pub code: Option<i32>,
    /// Standard output (capped).
    pub stdout: String,
    /// Standard error (capped).
    pub stderr: String,
}

/// Why a command gave no output.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RunError {
    /// The program is not installed.
    #[error("{0}: not found")]
    NotFound(String),
    /// It did not finish in time and was killed.
    #[error("{0}: no answer within {1:?}")]
    Timeout(String, Duration),
    /// It could not be started.
    #[error("{0}: {1}")]
    Failed(String, String),
}

/// Runs external programs.
pub trait Runner: Send + Sync {
    /// Runs `program` with `args`: by absolute path, no shell, no input, a cleared environment
    /// except `LC_ALL=C`, output capped, killed after `timeout`.
    ///
    /// # Errors
    /// When the program is missing, cannot start, or times out.
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> Result<Output, RunError>;
}

/// At most this much of either stream is kept.
const CAP: u64 = 1 << 20;

/// The real thing.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRunner;

fn drain(mut r: impl Read + Send + 'static) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = (&mut r).take(CAP).read_to_end(&mut buf);
        let _ = std::io::copy(&mut r, &mut std::io::sink());
        p_roc::text::from_bytes(&buf)
    })
}

/// Where a bare program name is looked up: fixed, never `$PATH`.
const TRUSTED_DIRS: [&str; 4] = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"];

/// A program by absolute path: as given, or found in [`TRUSTED_DIRS`].
fn resolve(program: &str) -> Option<std::path::PathBuf> {
    if program.starts_with('/') {
        return Some(program.into());
    }
    TRUSTED_DIRS.iter().map(|d| std::path::Path::new(d).join(program)).find(|p| p.is_file())
}

impl Runner for SystemRunner {
    fn run(&self, program: &str, args: &[&str], timeout: Duration) -> Result<Output, RunError> {
        let path = resolve(program).ok_or_else(|| RunError::NotFound(program.into()))?;
        let mut child = Command::new(path)
            .args(args)
            .env_clear()
            .env("LC_ALL", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => RunError::NotFound(program.into()),
                _ => RunError::Failed(program.into(), e.to_string()),
            })?;
        let out = child.stdout.take().map(drain);
        let err = child.stderr.take().map(drain);
        let start = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(s)) => break s,
                Ok(None) if start.elapsed() >= timeout => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(RunError::Timeout(program.into(), timeout));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(e) => return Err(RunError::Failed(program.into(), e.to_string())),
            }
        };
        let join = |h: Option<std::thread::JoinHandle<String>>| h.and_then(|h| h.join().ok()).unwrap_or_default();
        Ok(Output { code: status.code(), stdout: join(out), stderr: join(err) })
    }
}

/// A script: the answer to each command line (`program arg arg`), else "not found".
#[derive(Default)]
pub struct Scripted(pub BTreeMap<String, Result<Output, RunError>>);

impl Scripted {
    /// Adds a successful answer for `command` (program and arguments joined by spaces).
    #[must_use]
    pub fn answer(mut self, command: &str, stdout: &str) -> Self {
        self.0.insert(command.into(), Ok(Output { code: Some(0), stdout: stdout.into(), stderr: String::new() }));
        self
    }

    /// Adds a failing answer: exit `code` with `stderr`.
    #[must_use]
    pub fn fail(mut self, command: &str, code: i32, stderr: &str) -> Self {
        self.0.insert(command.into(), Ok(Output { code: Some(code), stdout: String::new(), stderr: stderr.into() }));
        self
    }
}

impl Runner for Scripted {
    fn run(&self, program: &str, args: &[&str], _timeout: Duration) -> Result<Output, RunError> {
        let line = std::iter::once(program).chain(args.iter().copied()).collect::<Vec<_>>().join(" ");
        self.0.get(&line).cloned().unwrap_or(Err(RunError::NotFound(program.into())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_runner_captures_reports_and_kills() {
        let r = SystemRunner;
        let o = r.run("/bin/sh", &["-c", "echo out; echo err >&2; exit 3"], Duration::from_secs(5)).unwrap();
        assert_eq!((o.code, o.stdout.as_str(), o.stderr.as_str()), (Some(3), "out\n", "err\n"));
        assert!(matches!(r.run("/nonexistent/prog", &[], Duration::from_secs(1)), Err(RunError::NotFound(_))));
        assert!(matches!(r.run("/bin/sleep", &["5"], Duration::from_millis(100)), Err(RunError::Timeout(..))));
    }
}
