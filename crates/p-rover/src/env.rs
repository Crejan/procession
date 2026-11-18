//! Everything a subcommand reads from outside itself: the roots of `/proc`,
//! `/sys`, `/dev`, `/etc` and `/boot`, the configuration, the clock.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use p_roc::Root;

use crate::config::Config;
use crate::ethtool::{Ethtool, Unavailable};
use crate::runner::{Runner, SystemRunner};

/// Time, and waiting for it to pass. A fake lets a test change the fixture
/// tree between two samples.
pub trait Clock: Send + Sync {
    /// The wall clock.
    fn now(&self) -> SystemTime;
    /// Waits `d` (a sampling window).
    fn pause(&self, d: Duration);
}

/// The real clock.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }

    fn pause(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

type OnPause = Box<dyn FnMut(Duration) + Send>;

/// A clock fixed at one instant whose `pause` runs a callback instead of waiting.
pub struct FakeClock {
    at: SystemTime,
    on_pause: Mutex<OnPause>,
}

impl FakeClock {
    /// Fixed at `epoch_secs`; `on_pause` is called with every requested pause.
    pub fn new(epoch_secs: u64, on_pause: impl FnMut(Duration) + Send + 'static) -> Self {
        Self { at: UNIX_EPOCH + Duration::from_secs(epoch_secs), on_pause: Mutex::new(Box::new(on_pause)) }
    }
}

impl Clock for FakeClock {
    fn now(&self) -> SystemTime {
        self.at
    }

    fn pause(&self, d: Duration) {
        if let Ok(mut f) = self.on_pause.lock() {
            f(d);
        }
    }
}

/// The environment of one run.
pub struct Env {
    /// `/proc`, `/sys`, `/dev`.
    pub root: Root,
    /// `/etc` (the bootloader configuration).
    pub etc: PathBuf,
    /// `/boot` (`config-<release>`).
    pub boot: PathBuf,
    /// The configuration.
    pub config: Config,
    /// The host's name, for the report header.
    pub host: String,
    /// Time.
    pub clock: Box<dyn Clock>,
    /// Driver settings and counters that only `ethtool` knows.
    pub ethtool: Box<dyn Ethtool>,
    /// External tools (`chronyc`, `journalctl`).
    pub runner: Box<dyn Runner>,
}

impl Env {
    /// The live system.
    #[must_use]
    pub fn system(config: Config) -> Self {
        Self {
            root: Root::system(),
            etc: PathBuf::from("/etc"),
            boot: PathBuf::from("/boot"),
            config,
            host: hostname(),
            clock: Box::new(SystemClock),
            ethtool: Box::new(Unavailable),
            runner: Box::new(SystemRunner),
        }
    }
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: the buffer is valid for its length; gethostname writes at most that many bytes.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc != 0 {
        return "unknown".into();
    }
    let end = buf.iter().position(|b| *b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}
