//! What `pact` needs from the machine: the time, random bytes, and hardening
//! of its own process. Behind traits so that tests control them.

use crate::time::Timestamp;
use ring::rand::{SecureRandom, SystemRandom};

/// The current time.
pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        // A clock before 1970 or after 9999 is not a clock; every call then has a deadline the services refuse.
        Timestamp::now().unwrap_or_else(|| Timestamp::from_unix(0).unwrap_or_else(|| unreachable!("0 is a valid time")))
    }
}

/// Random bytes. Failing to get any is fatal: a call without a fresh identifier is not made.
pub trait Random: Send + Sync {
    fn fill(&self, out: &mut [u8]);
}

/// The operating system's random source, through `ring`.
#[derive(Debug)]
pub struct SystemRandomSource(SystemRandom);

impl Default for SystemRandomSource {
    fn default() -> Self {
        SystemRandomSource(SystemRandom::new())
    }
}

impl Random for SystemRandomSource {
    fn fill(&self, out: &mut [u8]) {
        // `ring` fails only if the system has no random source; nothing safe can be done then.
        assert!(self.0.fill(out).is_ok(), "the system has no random source");
    }
}

/// Make this process hard to read from outside: not dumpable, no core files.
/// Best effort, and returns what it could not do, for the log.
pub fn harden() -> Vec<&'static str> {
    #[allow(unused_mut)]
    let mut failed = Vec::new();
    // SAFETY: `setrlimit` and `prctl` are called with valid, fully initialised arguments and do not touch memory.
    #[cfg(unix)]
    unsafe {
        let none = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::setrlimit(libc::RLIMIT_CORE, &none) != 0 {
            failed.push("could not disable core files");
        }
    }
    #[cfg(target_os = "linux")]
    // SAFETY: as above.
    unsafe {
        if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
            failed.push("could not make the process not dumpable");
        }
    }
    #[cfg(not(target_os = "linux"))]
    failed.push("not dumpable is only set on Linux");
    failed
}

/// A fresh version 4 UUID, lower case with hyphens.
pub fn uuid_v4(random: &dyn Random) -> String {
    let mut b = [0u8; 16];
    random.fill(&mut b);
    b[6] = b[6] & 0x0f | 0x40;
    b[8] = b[8] & 0x3f | 0x80;
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

/// A fresh progress token for a service: 128 random bits as hex.
pub fn token(random: &dyn Random) -> String {
    let mut b = [0u8; 16];
    random.fill(&mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::CallId;

    #[test]
    fn identifiers_are_version_4_uuids_and_differ() {
        let r = SystemRandomSource::default();
        let ids: Vec<String> = (0..50).map(|_| uuid_v4(&r)).collect();
        for id in &ids {
            assert!(CallId::parse(id).is_ok(), "{id}");
        }
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), ids.len());
        assert_eq!(token(&r).len(), 32);
    }

    #[test]
    fn hardening_runs() {
        // Not asserted to succeed everywhere; it must not crash, and says what it could not do.
        let _ = harden();
    }
}
