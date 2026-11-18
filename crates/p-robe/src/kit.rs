//! `sys kit`: what this installation is and whether it can run its verbs.
//!
//! It takes no argument and reads nothing of the host but its own
//! installation: the one verb that has to answer on a broken host.

use crate::answer::{Answer, Full, header};
use crate::json::Record;
use crate::table::{Env, verbs};
use crate::{certificate, clock, config, lock};
use p_act::Timestamp;

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

/// What was found of the service's certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Certificate {
    /// There is none: this host has no service installed, or not yet.
    Absent,
    /// Whole days left; negative once it has ended.
    DaysLeft(i64),
    /// It has no end.
    NoEnd,
    /// It is there and cannot be read.
    Unreadable(String),
}

/// Looks at the certificate in `path` at `now`.
#[must_use]
pub fn look_at_certificate(path: &std::path::Path, now: i64) -> Certificate {
    if !path.exists() {
        return Certificate::Absent;
    }
    match certificate::days_left(path, now) {
        Ok(Some(days)) => Certificate::DaysLeft(days),
        Ok(None) => Certificate::NoEnd,
        Err(why) => Certificate::Unreadable(why),
    }
}

/// Judges the facts. Pure, so each judgement can be tested.
#[must_use]
pub fn judge(lock_problem: Option<&str>, euid: u32, test_verbs: bool, certificate: &Certificate) -> Findings {
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
    match certificate {
        Certificate::DaysLeft(days) if *days <= 0 => {
            found.warnings.push("the service's certificate has ended: run `probe setup` as root".into())
        }
        Certificate::DaysLeft(days) if *days < certificate::WARN_BELOW_DAYS => found.warnings.push(format!(
            "the service's certificate has {days} days left (fewer than {}): run `probe setup` as root",
            certificate::WARN_BELOW_DAYS
        )),
        Certificate::Unreadable(why) => found.warnings.push(format!("the service's certificate cannot be read: {why}")),
        _ => {}
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
    let cert_path = config::certificate_path(
        config::Config::load_optional(std::path::Path::new(config::DEFAULT_FILE)).ok().flatten().as_ref(),
    );
    let certificate = look_at_certificate(&cert_path, Timestamp::now().map_or(0, Timestamp::unix));
    let prover = crate::prover::program(env);
    let prover_problem = prover.check().err().map(|failure| failure.code());
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
            .opt_str("lock_dir_problem", lock_problem.as_deref())
            .str("prover", &prover.path.display().to_string())
            .opt_str("prover_problem", prover_problem.as_deref())
            .opt_str(
                "service_certificate",
                (certificate != Certificate::Absent).then(|| cert_path.display().to_string()).as_deref(),
            )
            .opt_int(
                "service_certificate_days_left",
                if let Certificate::DaysLeft(d) = certificate { Some(d) } else { None },
            ),
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
    let mut found = judge(lock_problem.as_deref(), env.euid, test_verbs, &certificate);
    if let Some(problem) = &prover_problem {
        found.warnings.push(format!(
            "prover ({}) cannot be used: rt irq and rt procs fail until it can: {problem}",
            prover.path.display()
        ));
    }
    // The closing record: kept whatever the cap does to the lines before it.
    answer.close(|_cut| {
        Record::new("summary")
            .bool("usable", found.problems.is_empty())
            .num("verbs_ready", ready)
            .num("verbs_unavailable", unavailable)
            .strs("problems", &found.problems)
            .strs("warnings", &found.warnings)
    })?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_clean_installation_has_nothing_to_say() {
        assert_eq!(judge(None, 0, false, &Certificate::Absent), Findings::default());
    }

    #[test]
    fn a_lock_directory_that_is_not_safe_or_not_there_is_a_problem() {
        let found = judge(Some("missing: calls run unlocked"), 0, false, &Certificate::Absent);
        assert_eq!(found.problems, ["lock directory missing: calls run unlocked"]);
    }

    #[test]
    fn running_unprivileged_is_a_problem_and_a_test_build_a_warning() {
        let found = judge(None, 1000, true, &Certificate::Absent);
        assert_eq!(found.problems.len(), 1);
        assert_eq!(found.warnings.len(), 1);
    }

    #[test]
    fn a_certificate_with_fewer_than_five_days_left_is_a_warning_and_never_a_problem() {
        for (days, warned) in [(30, false), (20, false), (5, false), (4, true), (1, true), (0, true), (-3, true)] {
            let found = judge(None, 0, false, &Certificate::DaysLeft(days));
            assert_eq!(found.warnings.len(), usize::from(warned), "{days}: {found:?}");
            assert!(found.problems.is_empty(), "{days}");
        }
        assert!(judge(None, 0, false, &Certificate::DaysLeft(3)).warnings[0].contains("3 days left"));
        assert!(judge(None, 0, false, &Certificate::DaysLeft(0)).warnings[0].contains("has ended"));
        assert!(judge(None, 0, false, &Certificate::Unreadable("x".into())).warnings[0].contains("cannot be read"));
        for quiet in [Certificate::Absent, Certificate::NoEnd] {
            assert_eq!(judge(None, 0, false, &quiet), Findings::default());
        }
    }

    #[test]
    fn the_certificate_file_is_looked_at_for_its_days() {
        let dir = crate::testdir::new("kit-cert");
        assert_eq!(look_at_certificate(&dir.join("absent"), 0), Certificate::Absent);
        std::fs::write(dir.join("junk"), "junk").unwrap();
        assert!(matches!(look_at_certificate(&dir.join("junk"), 0), Certificate::Unreadable(_)));
    }
}
