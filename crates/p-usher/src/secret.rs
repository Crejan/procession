//! Reading a secret file (the SMTP password). One function, so that it can
//! be replaced by `p_ermit::settings::read_secret_checked` when that lands;
//! the rule is the same: a regular file, owned by the running user or root,
//! with no permission bit for group or others.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result, bail};

/// A secret file is at most this long.
const MAX_BYTES: u64 = 64 * 1024;

/// Reads `path` after checking the open file; the error says what to run to fix it.
///
/// # Errors
/// When the file is missing, not a regular file, owned by someone else, readable or writable by
/// group or others, too large, or not UTF-8. The text is never in an error.
pub fn read_secret(path: &Path) -> Result<String> {
    let shown = path.display();
    let file = File::open(path).with_context(|| format!("reading {shown}"))?;
    let meta = file.metadata().with_context(|| format!("reading {shown}"))?;
    if !meta.is_file() {
        bail!("{shown} is not a regular file");
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if meta.uid() != 0 && meta.uid() != euid {
        bail!("{shown} is owned by user {}, who is neither root nor the user running this program: as root, run `chown <that user> {shown}`", meta.uid());
    }
    let mode = meta.permissions().mode() & 0o7777;
    if mode & 0o077 != 0 {
        bail!("{shown} has mode {mode:04o}; a secret file must have no permission for group or others: run `chmod 600 {shown}`");
    }
    let mut text = String::new();
    file.take(MAX_BYTES + 1).read_to_string(&mut text).with_context(|| format!("reading {shown} (not UTF-8?)"))?;
    if text.len() as u64 > MAX_BYTES {
        bail!("{shown} is larger than {MAX_BYTES} bytes");
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secret(mode: u32) -> (tempfile::TempDir, std::path::PathBuf) {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("pw");
        std::fs::write(&p, "hunter2\n").unwrap();
        std::fs::set_permissions(&p, PermissionsExt::from_mode(mode)).unwrap();
        (d, p)
    }

    #[test]
    fn a_private_file_is_read() {
        for mode in [0o600, 0o400] {
            let (_d, p) = secret(mode);
            assert_eq!(read_secret(&p).unwrap(), "hunter2\n");
        }
    }

    #[test]
    fn anything_open_to_group_or_others_is_refused_with_the_fix_and_without_the_secret() {
        for mode in [0o640, 0o604, 0o644, 0o660, 0o666, 0o601] {
            let (_d, p) = secret(mode);
            let e = format!("{:#}", read_secret(&p).unwrap_err());
            assert!(e.contains("chmod 600"), "{mode:o}: {e}");
            assert!(!e.contains("hunter2"));
        }
    }

    #[test]
    fn not_a_regular_file_or_missing_is_refused() {
        let d = tempfile::tempdir().unwrap();
        assert!(read_secret(d.path()).is_err());
        assert!(read_secret(&d.path().join("none")).is_err());
    }
}
