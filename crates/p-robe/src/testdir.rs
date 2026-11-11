//! A fresh directory under the temporary directory, for the unit tests.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

static NEXT: AtomicU32 = AtomicU32::new(0);

/// A new, empty directory. It is not removed: the temporary directory is
/// the sandbox's, and the names are unique per process.
#[must_use]
pub fn new(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "probe-{name}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).expect("temporary directory");
    dir
}
