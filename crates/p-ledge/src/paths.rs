//! Where pledge keeps its state and its sockets, and the checks that those
//! places belong to the person alone.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// The places `pledge` uses.
#[derive(Debug, Clone)]
pub struct Paths {
    /// Keys, the record, remembered decisions about programs.
    pub state: PathBuf,
    /// The sockets.
    pub sockets: PathBuf,
}

impl Paths {
    /// The defaults for this user and platform, unless given.
    ///
    /// Linux state: `$XDG_STATE_HOME/pledge`, else `~/.local/state/pledge`;
    /// macOS: `~/Library/Application Support/pledge`. Sockets:
    /// `$XDG_RUNTIME_DIR/pledge`, else `$TMPDIR/pledge`, else
    /// `/tmp/pledge-<uid>`.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] if there is no home directory to put state in.
    pub fn resolve(state: Option<PathBuf>, sockets: Option<PathBuf>) -> Result<Self> {
        let env = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
        let state = match state {
            Some(path) => path,
            None => {
                let home = || env("HOME").ok_or_else(|| Error::Refused("no HOME: give --state-dir".into()));
                if cfg!(target_os = "macos") {
                    home()?.join("Library/Application Support/pledge")
                } else {
                    env("XDG_STATE_HOME").map_or_else(|| home().map(|h| h.join(".local/state")), Ok)?.join("pledge")
                }
            }
        };
        let sockets = sockets.unwrap_or_else(|| {
            // SAFETY: getuid has no preconditions.
            let uid = unsafe { libc::getuid() };
            env("XDG_RUNTIME_DIR")
                .or_else(|| env("TMPDIR"))
                .map_or_else(|| PathBuf::from(format!("/tmp/pledge-{uid}")), |dir| dir.join("pledge"))
        });
        Ok(Self { state, sockets })
    }

    /// The directory holding the key files.
    #[must_use]
    pub fn keys(&self) -> PathBuf {
        self.state.join("keys")
    }
    /// The record.
    #[must_use]
    pub fn record(&self) -> PathBuf {
        self.state.join("record.jsonl")
    }
    /// The remembered decisions about programs.
    #[must_use]
    pub fn programs(&self) -> PathBuf {
        self.state.join("programs.json")
    }
    /// The SSH agent socket.
    #[must_use]
    pub fn agent_socket(&self) -> PathBuf {
        self.sockets.join("agent.sock")
    }
    /// The socket services on this machine submit requests to.
    #[must_use]
    pub fn service_socket(&self) -> PathBuf {
        self.sockets.join("service.sock")
    }
    /// The control socket.
    #[must_use]
    pub fn control_socket(&self) -> PathBuf {
        self.sockets.join("control.sock")
    }
}

/// Creates `dir` (mode 0700) if it does not exist and checks that it is a
/// directory, not a symlink, owned by this user, and closed to everyone else.
///
/// # Errors
///
/// [`Error::Io`] or [`Error::Unsafe`].
pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent).map_err(Error::io(format!("creating {}", parent.display())))?;
    }
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(Error::io(format!("creating {}", dir.display()))(e)),
    }
    check_private(dir, true)
}

/// As [`ensure_private_dir`], and when `grouped` also accepts mode 0710: a
/// group may search the directory (not list it), so that services that run
/// under their own account can reach `service.sock`.
///
/// # Errors
///
/// [`Error::Io`] or [`Error::Unsafe`].
pub fn ensure_socket_dir(dir: &Path, grouped: bool) -> Result<()> {
    if !grouped {
        return ensure_private_dir(dir);
    }
    if let Some(parent) = dir.parent() {
        fs::create_dir_all(parent).map_err(Error::io(format!("creating {}", parent.display())))?;
    }
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(Error::io(format!("creating {}", dir.display()))(e)),
    }
    let meta = fs::symlink_metadata(dir).map_err(Error::io(format!("examining {}", dir.display())))?;
    let unsafe_ = |problem| Error::Unsafe { path: dir.to_owned(), problem };
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(unsafe_("is a symlink or not a directory"));
    }
    // SAFETY: getuid has no preconditions.
    if meta.uid() != unsafe { libc::getuid() } {
        return Err(unsafe_("is not owned by this user"));
    }
    if !matches!(meta.permissions().mode() & 0o777, 0o700 | 0o710) {
        return Err(unsafe_("must be mode 0700 or 0710"));
    }
    Ok(())
}

/// Checks `path` as [`ensure_private_dir`] does (`directory`), or as a
/// private file or socket (not a directory, no access for group or others
/// beyond `allowed_group_bits`).
///
/// # Errors
///
/// [`Error::Io`] or [`Error::Unsafe`].
pub fn check_private(path: &Path, directory: bool) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(Error::io(format!("examining {}", path.display())))?;
    let unsafe_ = |problem| Error::Unsafe { path: path.to_owned(), problem };
    if meta.file_type().is_symlink() {
        return Err(unsafe_("is a symlink"));
    }
    if directory && !meta.is_dir() {
        return Err(unsafe_("is not a directory"));
    }
    // SAFETY: getuid has no preconditions.
    if meta.uid() != unsafe { libc::getuid() } {
        return Err(unsafe_("is not owned by this user"));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(unsafe_("is open to other users: mode must be 0700 or 0600"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;
    use crate::testing::TestDir;

    #[test]
    fn a_private_directory_is_created_and_accepted() {
        let dir = TestDir::new("paths-ok");
        let target = dir.path().join("a/b");
        ensure_private_dir(&target).expect("created");
        assert_eq!(fs::metadata(&target).expect("meta").permissions().mode() & 0o777, 0o700);
        ensure_private_dir(&target).expect("existing is fine");
    }

    #[test]
    fn a_directory_open_to_others_or_a_symlink_is_refused() {
        let dir = TestDir::new("paths-bad");
        let open = dir.path().join("open");
        fs::create_dir(&open).expect("dir");
        fs::set_permissions(&open, fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(matches!(ensure_private_dir(&open), Err(Error::Unsafe { .. })));
        let real = dir.path().join("real");
        ensure_private_dir(&real).expect("real");
        let link = dir.path().join("link");
        symlink(&real, &link).expect("symlink");
        assert!(matches!(ensure_private_dir(&link), Err(Error::Unsafe { problem: "is a symlink", .. })));
    }

    #[test]
    fn explicit_paths_win_and_the_files_are_named() {
        let paths = Paths::resolve(Some("/s".into()), Some("/r".into())).expect("paths");
        assert_eq!(paths.agent_socket(), Path::new("/r/agent.sock"));
        assert_eq!(paths.record(), Path::new("/s/record.jsonl"));
        assert_eq!(paths.keys(), Path::new("/s/keys"));
    }
}
