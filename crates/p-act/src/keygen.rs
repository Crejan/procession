//! The one place that starts `ssh-keygen`. Every signature in the system is verified by that program, so which
//! program it is and what it is given are decided here and nowhere else:
//!
//! - **A fixed path, never `PATH`** ([`KEYGEN_PATH`], `/usr/bin/ssh-keygen`): a service or a helper that runs as root
//!   must not take the program from a directory somebody else can influence. (On a Mac this is Apple's OpenSSH; a
//!   Homebrew `ssh-keygen` earlier in `PATH` is deliberately ignored.)
//! - **Trusted ownership**: the program and every directory above it (after symbolic links are resolved) are owned by
//!   root and not writable by group or others (a sticky directory such as `/tmp` is accepted when what is under it is
//!   not writable by others). Otherwise [`KeygenError::NotTrusted`], saying which and why.
//! - **A cleared environment**: nothing inherited reaches it (`HOME`, a configuration directory, `SSH_AUTH_SOCK`, the
//!   locale). It gets `PATH=/usr/bin:/bin`, `LC_ALL=C`, `LANG=C`, and the two variables that make a passphrase prompt
//!   fail; [`Keygen::command_with_agent`] adds `SSH_AUTH_SOCK` for the socket the caller names, and nothing else.
//! - **A version of at least [`MIN_VERSION`]** (OpenSSH 8.9: `-Y sign`/`-Y verify` with certificates, `cert-authority`
//!   and `namespaces=` in allowed signers, `-O clear`), found by the `ssh -V` next to it, checked once and kept.
//!
//! [`Keygen::system`] is what a program calls; it is checked once. [`Keygen::at`] is for a test or an installation
//! that names its own program, with the same ownership test and a choice of who may own it.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

/// Where `ssh-keygen` is looked for: here and nowhere else.
pub const KEYGEN_PATH: &str = "/usr/bin/ssh-keygen";

/// The oldest OpenSSH accepted, as (major, minor).
pub const MIN_VERSION: (u32, u32) = (8, 9);

/// Why there is no `ssh-keygen` to run. A message for a person to act on; none holds anything but paths and numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeygenError {
    /// There is no such file.
    NotFound(String),
    /// The program or a directory above it may be changed by somebody who should not be able to.
    NotTrusted { path: String, why: String },
    /// The version is older than [`MIN_VERSION`], or `ssh -V` did not say.
    Version { found: String, needed: String },
    /// Reading a file or running a program failed (what, and the kind of error).
    Cannot(String, String),
}

impl std::fmt::Display for KeygenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeygenError::NotFound(path) => {
                write!(f, "{path} does not exist: install the OpenSSH client (ssh-keygen) there")
            }
            KeygenError::NotTrusted { path, why } => write!(f, "{path} is not trusted: {why}"),
            KeygenError::Version { found, needed } => {
                write!(f, "OpenSSH {needed} or later is needed (found: {found})")
            }
            KeygenError::Cannot(what, kind) => write!(f, "cannot use {what}: {kind}"),
        }
    }
}

impl std::error::Error for KeygenError {}

/// Who may own the program and the directories above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owner {
    /// Root only (the system's program).
    Root,
    /// Root, or this user (a test's own directory).
    RootOr(u32),
}

impl Owner {
    fn admits(self, uid: u32) -> bool {
        uid == 0 || self == Owner::RootOr(uid)
    }
}

/// An `ssh-keygen` that passed the ownership test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Keygen {
    program: PathBuf,
    owner: Owner,
}

/// Why an entry on the way to the program is not trusted, from its owner and mode, or `None` if it is.
#[must_use]
pub fn problem(is_dir: bool, uid: u32, mode: u32, owner: Owner) -> Option<String> {
    if !owner.admits(uid) {
        return Some(format!("it is owned by user {uid}, not by root"));
    }
    let sticky = is_dir && mode & 0o1000 != 0;
    if mode & 0o022 != 0 && !sticky {
        return Some(format!("it can be written by its group or by others (mode {:04o})", mode & 0o7777));
    }
    None
}

impl Keygen {
    /// The system's `ssh-keygen`, [`KEYGEN_PATH`]: ownership and version checked **once**, the answer kept for the life
    /// of the process.
    pub fn system() -> Result<&'static Keygen, KeygenError> {
        static SYSTEM: OnceLock<Result<Keygen, KeygenError>> = OnceLock::new();
        SYSTEM
            .get_or_init(|| {
                let keygen = Keygen::at(Path::new(KEYGEN_PATH), Owner::Root)?;
                keygen.check_version()?;
                Ok(keygen)
            })
            .as_ref()
            .map_err(Clone::clone)
    }

    /// `path`, if it and every directory above it pass the ownership test for `owner`. The version is not checked
    /// (there may be no `ssh` beside a test's stand-in): [`Keygen::check_version`] does that.
    pub fn at(path: &Path, owner: Owner) -> Result<Keygen, KeygenError> {
        let shown = path.display().to_string();
        let real = std::fs::canonicalize(path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                KeygenError::NotFound(shown.clone())
            } else {
                KeygenError::Cannot(shown.clone(), e.kind().to_string())
            }
        })?;
        let untrusted = |at: &Path, why: String| KeygenError::NotTrusted {
            path: shown.clone(),
            why: format!("{} {why}", at.display()),
        };
        for dir in real.ancestors().skip(1) {
            let meta = std::fs::metadata(dir)
                .map_err(|e| KeygenError::Cannot(dir.display().to_string(), e.kind().to_string()))?;
            if let Some(why) = problem(true, meta.uid(), meta.permissions().mode(), owner) {
                return Err(untrusted(dir, why));
            }
        }
        let meta = std::fs::metadata(&real).map_err(|e| KeygenError::Cannot(shown.clone(), e.kind().to_string()))?;
        if !meta.is_file() {
            return Err(untrusted(&real, "is not a regular file".to_owned()));
        }
        if let Some(why) = problem(false, meta.uid(), meta.permissions().mode(), owner) {
            return Err(untrusted(&real, why));
        }
        Ok(Keygen { program: real, owner })
    }

    /// The program's path (links resolved).
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// A command for the program with the environment cleared to what it needs. The caller adds arguments and the
    /// standard streams.
    #[must_use]
    pub fn command(&self) -> Command {
        let mut command = Command::new(&self.program);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .env("LANG", "C")
            // A key that wants a passphrase must fail, not ask on a terminal: the "askpass program" is `false`.
            .env("SSH_ASKPASS", "false")
            .env("SSH_ASKPASS_REQUIRE", "force");
        command
    }

    /// As [`Keygen::command`], with `SSH_AUTH_SOCK` set to `socket`: the one variable a caller that deliberately gives
    /// the program an agent (pledge issuing through its private socket) adds.
    #[must_use]
    pub fn command_with_agent(&self, socket: &Path) -> Command {
        let mut command = self.command();
        command.env("SSH_AUTH_SOCK", socket);
        command
    }

    /// The version, from the `ssh -V` in the same directory (which has to pass the ownership test too, with the
    /// same owners), as `(major, minor)`; refused below [`MIN_VERSION`].
    pub fn check_version(&self) -> Result<(u32, u32), KeygenError> {
        let ssh = self.program.with_file_name("ssh");
        let ssh = Keygen::at(&ssh, self.owner).map_err(|e| match e {
            KeygenError::NotFound(p) => KeygenError::Version { found: format!("no {p}"), needed: needed() },
            other => other,
        })?;
        let out = ssh
            .command()
            .arg("-V")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| KeygenError::Cannot(ssh.program.display().to_string(), e.kind().to_string()))?;
        // `ssh -V` writes to standard error: `OpenSSH_9.2p1 Debian-2+deb12u3, OpenSSL 3.0.15 3 Sep 2024`.
        let text = String::from_utf8_lossy(if out.stderr.is_empty() { &out.stdout } else { &out.stderr }).into_owned();
        match parse_version(&text) {
            Some(version) if version >= MIN_VERSION => Ok(version),
            _ => Err(KeygenError::Version {
                found: text.lines().next().unwrap_or("").chars().take(60).collect(),
                needed: needed(),
            }),
        }
    }
}

fn needed() -> String {
    format!("{}.{}", MIN_VERSION.0, MIN_VERSION.1)
}

/// `(major, minor)` of `OpenSSH_<major>.<minor>...` at the start of `text`.
#[must_use]
pub fn parse_version(text: &str) -> Option<(u32, u32)> {
    let rest = text.trim_start().strip_prefix("OpenSSH_")?;
    let (major, rest) = rest.split_once('.')?;
    let minor: String = rest.chars().take_while(char::is_ascii_digit).collect();
    Some((major.parse().ok()?, minor.parse().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A temporary directory with mode 0755 set explicitly: what a directory is created with depends on the umask,
    /// and under 002 it would come out group-writable and be refused, as it should be.
    fn dir_0755() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        dir
    }

    fn own() -> u32 {
        // SAFETY: `geteuid` has no arguments and cannot fail.
        unsafe { libc::geteuid() }
    }

    #[test]
    fn the_rule_for_one_entry() {
        assert_eq!(problem(false, 0, 0o755, Owner::Root), None);
        assert_eq!(problem(true, 0, 0o755, Owner::Root), None);
        assert!(problem(false, 1000, 0o755, Owner::Root).unwrap().contains("user 1000"));
        assert_eq!(problem(false, 1000, 0o755, Owner::RootOr(1000)), None);
        for mode in [0o775, 0o757, 0o777, 0o770 | 0o020, 0o722] {
            assert!(
                problem(false, 0, mode, Owner::Root).unwrap().contains("written by its group or by others"),
                "{mode:o}"
            );
            assert!(problem(true, 0, mode, Owner::Root).is_some());
        }
        // A sticky directory is accepted for its mode (`/tmp`), a sticky file is not special.
        assert_eq!(problem(true, 0, 0o1777, Owner::Root), None);
        assert!(problem(false, 0, 0o1777, Owner::Root).is_some());
        assert!(problem(true, 1000, 0o1777, Owner::Root).is_some(), "the owner is still judged");
    }

    #[test]
    fn the_system_program_is_where_it_is_said_to_be_and_is_trusted_on_this_machine() {
        let keygen = Keygen::system().expect("this machine has a trusted OpenSSH of version 8.9 or later");
        assert!(keygen.program().is_absolute());
        assert!(Keygen::system().unwrap() == keygen, "checked once, the same answer");
    }

    #[test]
    fn versions_are_read_from_ssh_dash_v() {
        assert_eq!(parse_version("OpenSSH_10.2p1, LibreSSL 3.3.6"), Some((10, 2)));
        assert_eq!(parse_version("OpenSSH_9.2p1 Debian-2+deb12u3, OpenSSL 3.0.15"), Some((9, 2)));
        assert_eq!(parse_version("OpenSSH_8.9p1 Ubuntu-3ubuntu0.10, OpenSSL 3.0.2"), Some((8, 9)));
        assert_eq!(parse_version("OpenSSH_8.4p1"), Some((8, 4)));
        assert!(
            Some((8, 4)) < Some(MIN_VERSION) && Some((8, 9)) >= Some(MIN_VERSION) && Some((10, 0)) >= Some(MIN_VERSION)
        );
        for bad in ["", "Dropbear v2022", "OpenSSH_x.1", "OpenSSH_9", "usage: ssh"] {
            assert_eq!(parse_version(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_program_that_is_missing_writable_or_foreign_is_refused_with_the_reason() {
        let dir = dir_0755();
        let tool = dir.path().join("tool");
        std::fs::write(&tool, "#!/bin/sh\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Keygen::at(&tool, Owner::RootOr(own())).is_ok());
        // Owned by the running user, which is not root: refused for the system's rule (unless run as root).
        if own() != 0 {
            let e = Keygen::at(&tool, Owner::Root).unwrap_err();
            assert!(matches!(&e, KeygenError::NotTrusted { why, .. } if why.contains("not by root")), "{e}");
        }
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o775)).unwrap();
        let e = Keygen::at(&tool, Owner::RootOr(own())).unwrap_err().to_string();
        assert!(e.contains("written by its group or by others") && e.contains("0775"), "{e}");
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        // The directory above it matters as much.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let e = Keygen::at(&tool, Owner::RootOr(own())).unwrap_err().to_string();
        assert!(e.contains("written by its group or by others"), "{e}");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        // Missing; and a directory is not a program.
        assert!(matches!(Keygen::at(&dir.path().join("none"), Owner::Root), Err(KeygenError::NotFound(_))));
        assert!(matches!(Keygen::at(dir.path(), Owner::RootOr(own())), Err(KeygenError::NotTrusted { .. })));
        let e = Keygen::at(&dir.path().join("none"), Owner::Root).unwrap_err().to_string();
        assert!(e.contains("install the OpenSSH client"), "{e}");
    }

    #[test]
    fn what_the_program_is_given_is_cleared_and_explicit() {
        let dir = dir_0755();
        let tool = dir.path().join("env");
        std::fs::write(&tool, "#!/bin/sh\nexec /usr/bin/env\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        let keygen = Keygen::at(&tool, Owner::RootOr(own())).unwrap();
        let seen = |mut c: Command| -> Vec<String> {
            let out = c.stdin(Stdio::null()).output().unwrap();
            let mut lines: Vec<String> = String::from_utf8(out.stdout).unwrap().lines().map(str::to_owned).collect();
            lines.retain(|l| !l.starts_with("PWD=") && !l.starts_with("SHLVL=") && !l.starts_with("_="));
            lines.sort();
            lines
        };
        // The parent's environment has these; none of them reaches the program.
        // SAFETY: nothing else in this process reads or writes these variables.
        unsafe {
            std::env::set_var("SSH_AUTH_SOCK", "/leak");
            std::env::set_var("LC_MESSAGES", "de_DE.UTF-8");
            std::env::set_var("PACT_KEYGEN_PARENT_LEAK", "yes");
        }
        let expected = ["LANG=C", "LC_ALL=C", "PATH=/usr/bin:/bin", "SSH_ASKPASS=false", "SSH_ASKPASS_REQUIRE=force"];
        assert_eq!(seen(keygen.command()), expected, "no HOME, no SSH_AUTH_SOCK, no locale, nothing of the parent's");
        // The agent's socket is the one variable that can be added, and only by asking.
        let mut with = expected.map(str::to_owned).to_vec();
        with.push("SSH_AUTH_SOCK=/run/agent.sock".to_owned());
        with.sort();
        assert_eq!(seen(keygen.command_with_agent(Path::new("/run/agent.sock"))), with);
    }
}
