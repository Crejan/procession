//! Reading a secret file (the SMTP password), through `p_ermit`: a regular file, owned by the running
//! user or root, with no permission bit for group or others.

use std::path::Path;

use anyhow::{Context, Result};

/// A secret file is at most this long.
const MAX_BYTES: u64 = 4096;

/// Reads `path` after the checks of `p_ermit::settings::read_secret_checked`; the error says what to
/// run to fix it and never holds the content.
///
/// # Errors
/// When the file is refused, cannot be read, or is not UTF-8.
pub fn read_secret(path: &Path) -> Result<String> {
    let bytes = p_ermit::settings::read_secret_checked(path, MAX_BYTES).with_context(|| format!("reading {}", path.display()))?;
    String::from_utf8(bytes).map_err(|e| {
        // Do not leave the bytes in freed memory.
        let mut b = e.into_bytes();
        b.fill(0);
        anyhow::anyhow!("{} is not UTF-8", path.display())
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

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
