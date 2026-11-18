//! Tests that need a given umask. The umask is process-wide, so they take one lock.

use std::sync::Mutex;

static UMASK: Mutex<()> = Mutex::new(());

/// Run `f` with the umask set to `mask`, then restore it.
pub fn with<T>(mask: libc::mode_t, f: impl FnOnce() -> T) -> T {
    let _guard = UMASK.lock().unwrap_or_else(|e| e.into_inner());
    // SAFETY: umask has no failure mode; it is restored below, under the lock.
    let old = unsafe { libc::umask(mask) };
    let result = f();
    // SAFETY: as above.
    unsafe { libc::umask(old) };
    result
}
