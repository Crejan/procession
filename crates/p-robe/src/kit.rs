//! `sys kit`: what this installation is and whether it can run its verbs.
//!
//! It takes no argument and reads nothing of the host but its own
//! installation: the one verb that has to answer on a broken host.

use crate::answer::{Answer, Full, header};
use crate::json::Record;
use crate::table::{Env, verbs};
use crate::{clock, lock};

/// The host's name, or `unknown`.
#[must_use]
pub fn hostname() -> String {
    let mut buffer = [0u8; 256];
    // SAFETY: the buffer is 256 bytes and its length is passed.
    let done = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if done != 0 {
        return "unknown".into();
    }
    let end = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
    String::from_utf8_lossy(&buffer[..end]).into_owned()
}

/// What is wrong with an installation (`problems`) and what only deserves a
/// note (`warnings`), from what was found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Findings {
    pub problems: Vec<String>,
    pub warnings: Vec<String>,
}

/// Judges the facts. Pure, so each judgement can be tested.
#[must_use]
pub fn judge(lock_problem: Option<&str>, euid: u32, test_verbs: bool) -> Findings {
    let mut found = Findings::default();
    if let Some(problem) = lock_problem {
        found.problems.push(format!("lock directory {problem}"));
    }
    if euid != 0 {
        found.problems.push(format!("not running as root (euid {euid}): verbs that need privilege will fail"));
    }
    if test_verbs {
        found.warnings.push("built with the test-verbs feature: not for a host that is in use".into());
    }
    found
}

/// Runs `sys kit`.
///
/// # Errors
/// [`Full`] if the answer is cut.
pub fn run(env: &Env, _args: &[String], answer: &mut Answer<'_>) -> Result<u8, Full> {
    let test_verbs = cfg!(feature = "test-verbs");
    let lock_problem = lock::directory_problem(&env.lock_dir);
    let executable = std::env::current_exe().ok().map(|path| path.display().to_string());
    answer.record(&header("sys", "kit", &hostname(), &clock::now()))?;
    answer.record(
        &Record::new("installation")
            .str("version", env!("CARGO_PKG_VERSION"))
            .opt_str("executable", executable.as_deref())
            .str("os", std::env::consts::OS)
            .str("arch", std::env::consts::ARCH)
            .bool("test_verbs", test_verbs)
            .str("identity", &env.identity)
            .num("euid", u64::from(env.euid))
            .str("audit", &env.audit)
            .str("lock_dir", &env.lock_dir.display().to_string())
            .opt_str("lock_dir_problem", lock_problem.as_deref()),
    )?;
    let (mut ready, mut unavailable) = (0u64, 0u64);
    for row in verbs() {
        match row.status() {
            "ready" => ready += 1,
            "unavailable" => unavailable += 1,
            _ => {}
        }
        answer.record(
            &Record::new("verb")
                .str("noun", row.noun)
                .str("verb", row.verb)
                .str("status", row.status())
                .opt_str("reason", row.reason()),
        )?;
    }
    let found = judge(lock_problem.as_deref(), env.euid, test_verbs);
    answer.record(
        &Record::new("summary")
            .bool("usable", found.problems.is_empty())
            .num("verbs_ready", ready)
            .num("verbs_unavailable", unavailable)
            .strs("problems", &found.problems)
            .strs("warnings", &found.warnings),
    )?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_installation_has_nothing_to_say() {
        assert_eq!(judge(None, 0, false), Findings::default());
    }

    #[test]
    fn a_lock_directory_that_is_not_safe_or_not_there_is_a_problem() {
        let found = judge(Some("missing: calls run unlocked"), 0, false);
        assert_eq!(found.problems, ["lock directory missing: calls run unlocked"]);
    }

    #[test]
    fn running_unprivileged_is_a_problem_and_a_test_build_a_warning() {
        let found = judge(None, 1000, true);
        assert_eq!(found.problems.len(), 1);
        assert_eq!(found.warnings.len(), 1);
    }
}
