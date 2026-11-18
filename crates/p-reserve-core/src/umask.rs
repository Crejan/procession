//! Tests that need a given umask. The umask is process-wide, so they take one lock. Other tests in the process do not
//! take it, so a mask used here must never remove the owner's own permissions (no `0o2xx`, `0o4xx`, `0o1xx` bits):
//! a test that creates files at the same time would fail with "permission denied".

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
