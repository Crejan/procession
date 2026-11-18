//! What `pact serve` checks of its surroundings (`proposals/pact.md`, "What `pact` must be given"): the file the
//! bundle is read from, who may connect, and the directories its socket and its program are in. The decisions are
//! pure functions of owner, mode and user ids so that they are tested without a second user.

use p_ermit::peer::Policy;
use p_ermit::settings::{SettingsError, check_open_secret};
use std::fs::File;
use std::os::fd::AsFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// Standard input, as a file to read the bundle from. **When it is a regular file it is checked through the open
/// descriptor before a byte is read**: owned by the running user, no permission bit for group or others. A pipe, a
/// socket or a terminal has nothing to check and is read as it is.
pub fn bundle_input() -> Result<File, String> {
    let owned = std::io::stdin().as_fd().try_clone_to_owned().map_err(|e| format!("cannot use standard input: {e}"))?;
    let file = File::from(owned);
    match check_open_secret(&file, "standard input", true) {
        Ok(()) | Err(SettingsError::NotARegularFile(_)) => Ok(file),
        Err(e) => Err(refusal(&e)),
    }
}

/// What to change, in words that fit a file that is standard input (the path is not known here).
fn refusal(error: &SettingsError) -> String {
    match error {
        SettingsError::ReadableByOthers { mode, .. } => format!(
            "the bundle on standard input is a file that group or others can access (mode {mode:04o}); the bundle holds the agent's key: run `chmod 600` on the file it is read from, and read it again"
        ),
        SettingsError::WrongOwner { uid, .. } => format!(
            "the bundle on standard input is a file owned by user {uid}, not the user running pact; the bundle holds the agent's key: it must be owned by the user that runs pact"
        ),
        other => format!("cannot check standard input: {other}"),
    }
}

/// Who may connect to the socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clients {
    uids: Vec<u32>,
    refuse_own_user: bool,
}

impl Clients {
    /// `uids` empty means the running user alone (stage 1: the model runs as the same user). `refuse_own_user` (off in
    /// stage 1; a stage-2 sandbox turns it on) says the running user must not be a client: then `uids` must name
    /// somebody else, or nobody could connect.
    pub fn new(uids: Vec<u32>, refuse_own_user: bool, own: u32) -> Result<Clients, String> {
        if refuse_own_user && uids.is_empty() {
            return Err("--refuse-own-user needs at least one --client-uid: nobody else could connect".into());
        }
        if refuse_own_user && uids.contains(&own) {
            return Err(format!("--client-uid {own} is pact's own user, which --refuse-own-user does not admit"));
        }
        Ok(Clients { uids, refuse_own_user })
    }

    /// The policy `p_ermit::peer::accept` checks a connecting peer against.
    #[must_use]
    pub fn policy(&self) -> Policy<'_> {
        if self.uids.is_empty() { Policy::OwnUser } else { Policy::Uids(&self.uids) }
    }

    /// What to say once at start when the running user may connect: the key is then not kept from the client.
    #[must_use]
    pub fn start_warning(&self, own: u32) -> Option<&'static str> {
        (!self.refuse_own_user && self.policy().admits_with(own, own)).then_some(
            "clients may connect as the same user as pact: what pact can read, a client can read (approvals.md R2); stage 1 only",
        )
    }
}

/// A warning for a directory that others could use to replace what is in it, from its owner and mode. A sticky
/// directory (`/tmp`) keeps others from replacing an entry that is not theirs and is not warned about for its mode.
#[must_use]
pub fn directory_warning(what: &str, path: &Path, uid: u32, mode: u32, euid: u32) -> Option<String> {
    let writable = mode & 0o022 != 0 && mode & 0o1000 == 0;
    let owner = uid != 0 && uid != euid;
    let reason = match (writable, owner) {
        (true, _) => format!("can be written by its group or by others (mode {:04o})", mode & 0o7777),
        (false, true) => format!("is owned by user {uid}"),
        (false, false) => return None,
    };
    Some(format!(
        "the directory of {what} ({}) {reason}: somebody who can write there can replace {what}",
        path.display()
    ))
}

/// The warnings for the directory of the socket and the directory of this program, to `say`. Both are warnings:
/// whether it matters depends on the sandbox, which `pact` does not know.
pub fn warn_directories(socket: &Path, say: &mut dyn FnMut(&str)) {
    // SAFETY: `geteuid` has no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let socket_dir = match socket.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => std::path::PathBuf::from("."),
    };
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf));
    for (what, dir) in [("the socket", Some(socket_dir)), ("this program", exe_dir)] {
        let Some(dir) = dir else { continue };
        if let Ok(meta) = std::fs::metadata(&dir)
            && let Some(line) = directory_warning(what, &dir, meta.uid(), meta.permissions().mode(), euid)
        {
            say(&line);
        }
    }
}

/// Runs `f` with the umask `077`, and puts the old one back: what `f` creates has no permission for group or others
/// from its first instant.
pub fn with_private_umask<T>(f: impl FnOnce() -> T) -> T {
    // SAFETY: `umask` only changes this process's file creation mask and cannot fail.
    let old = unsafe { libc::umask(0o077) };
    let out = f();
    // SAFETY: as above.
    unsafe { libc::umask(old) };
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn directories_are_warned_about_by_mode_and_owner() {
        let p = Path::new("/run/pact");
        assert!(directory_warning("the socket", p, 1000, 0o755, 1000).is_none());
        assert!(directory_warning("the socket", p, 0, 0o755, 1000).is_none());
        assert!(directory_warning("the socket", p, 1000, 0o700, 1000).is_none());
        for mode in [0o775, 0o757, 0o777, 0o770 | 0o020, 0o722] {
            let w = directory_warning("the socket", p, 1000, mode, 1000).unwrap();
            assert!(w.contains("/run/pact") && w.contains("written by its group or by others"), "{w}");
        }
        // Sticky and world-writable, like /tmp: others cannot replace what is not theirs.
        assert!(directory_warning("the socket", p, 0, 0o1777, 1000).is_none());
        assert!(directory_warning("the socket", p, 1001, 0o755, 1000).unwrap().contains("owned by user 1001"));
        let w = directory_warning("this program", p, 0, 0o775, 1000).unwrap();
        assert!(w.contains("replace this program"), "{w}");
    }

    #[test]
    fn who_may_connect() {
        let c = Clients::new(vec![], false, 1000).unwrap();
        assert!(c.policy().admits_with(1000, 1000));
        assert!(!c.policy().admits_with(1001, 1000));
        assert!(!c.policy().admits_with(0, 1000));
        assert!(c.start_warning(1000).unwrap().contains("same user"));
        let c = Clients::new(vec![1001, 1002], false, 1000).unwrap();
        assert!(c.policy().admits_with(1002, 1000) && !c.policy().admits_with(1000, 1000));
        assert!(c.start_warning(1000).is_none());
        // Refusing pact's own user: off by default, and meaningless without somebody else.
        let c = Clients::new(vec![1001], true, 1000).unwrap();
        assert!(!c.policy().admits_with(1000, 1000) && c.policy().admits_with(1001, 1000));
        assert!(c.start_warning(1000).is_none());
        assert!(Clients::new(vec![], true, 1000).unwrap_err().contains("--client-uid"));
        assert!(Clients::new(vec![1000, 1001], true, 1000).unwrap_err().contains("own user"));
        // With the setting off the running user may be named, and is admitted.
        assert!(Clients::new(vec![1000], false, 1000).unwrap().start_warning(1000).is_some());
    }

    #[test]
    fn the_refusals_say_what_to_change_and_never_hold_content() {
        let text = refusal(&SettingsError::ReadableByOthers { path: "standard input".into(), mode: 0o644 });
        assert!(text.contains("0644") && text.contains("chmod 600"), "{text}");
        let text = refusal(&SettingsError::WrongOwner { path: "standard input".into(), uid: 7 });
        assert!(text.contains("user 7") && text.contains("owned by the user that runs pact"), "{text}");
    }

    #[test]
    fn the_private_umask_is_in_force_inside_and_restored_after() {
        let dir = tempfile::tempdir().unwrap();
        // SAFETY: reads the mask by setting and restoring it; this test is the only user of the mask that matters.
        let before = unsafe { libc::umask(0o022) };
        let path = dir.path().join("inside");
        with_private_umask(|| std::fs::write(&path, b"x")).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        let after = dir.path().join("after");
        std::fs::write(&after, b"x").unwrap();
        assert_eq!(std::fs::metadata(&after).unwrap().permissions().mode() & 0o777, 0o644);
        // SAFETY: puts back what was there.
        unsafe { libc::umask(before) };
    }
}
