//! Who may read and write what the broker keeps: its register and the directory it is in. (The
//! configuration and the site file are read with `p_act::settings`.)

use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use thiserror::Error;

/// Why a file or directory was refused.
#[derive(Debug, Error)]
pub enum PermError {
    #[error("cannot look at {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("{path} can be read or written by someone but its owner (mode {mode:o}); it must be {wanted:o}")]
    NotPrivate { path: String, mode: u32, wanted: u32 },
    #[error("{path} cannot be given to the administrators' group: {why}")]
    Group { path: String, why: String },
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> PermError + '_ {
    move |source| PermError::Io { path: path.display().to_string(), source }
}

/// A file only its owner may read or write (0600).
pub fn check_private_file(path: &Path) -> Result<(), PermError> {
    let mode = std::fs::metadata(path).map_err(io(path))?.mode() & 0o7777;
    if mode & 0o077 != 0 {
        return Err(PermError::NotPrivate { path: path.display().to_string(), mode, wanted: 0o600 });
    }
    Ok(())
}

/// A directory only its owner may enter (0700); made if it is not there.
pub fn ensure_private_dir(path: &Path) -> Result<(), PermError> {
    ensure_dir(path, None)
}

/// As [`ensure_private_dir`]; with `group` the directory may also be exactly 0710 with that group: the group may
/// traverse it (to reach `admin.sock`) and nobody else may do anything.
pub fn ensure_dir(path: &Path, group: Option<u32>) -> Result<(), PermError> {
    if !path.exists() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(path).map_err(io(path))?;
    }
    let meta = std::fs::metadata(path).map_err(io(path))?;
    let mode = meta.mode() & 0o7777;
    let traversable = group.is_some_and(|g| mode == 0o710 && meta.gid() == g);
    if mode & 0o077 != 0 && !traversable {
        return Err(PermError::NotPrivate { path: path.display().to_string(), mode, wanted: 0o700 });
    }
    Ok(())
}

/// Give `path` (a directory) to the group `gid` for traversal: group `gid`, mode 0710, **checked afterwards** with a
/// fresh look at it. Needs the broker's account to be in the group.
pub fn open_dir_to_group(path: &Path, gid: u32) -> Result<(), PermError> {
    give_to_group(path, gid, 0o710, true)
}

/// The state directory as the socket needs it before anything is bound: a real directory (not a link), owned by the
/// broker's user, mode exactly 0700. A 0710 left by a former run (this broker's own) is made 0700 first; anything
/// else that is wrong is refused.
pub fn seal_state_dir(path: &Path) -> Result<(), PermError> {
    let why = |w: String| PermError::Group { path: path.display().to_string(), why: w };
    let look = || std::fs::symlink_metadata(path).map_err(|e| why(format!("cannot look at it: {e}")));
    let meta = look()?;
    if !meta.file_type().is_dir() {
        return Err(why("it is not a directory of its own (a link, or not a directory)".to_owned()));
    }
    if meta.uid() != p_ermit::peer::own_uid() {
        return Err(why(format!("it is owned by user {}, not the broker's", meta.uid())));
    }
    let mode = meta.mode() & 0o7777;
    if mode != 0o700 && mode != 0o710 {
        return Err(why(format!("it is mode {mode:o}; it must be exactly 700")));
    }
    if mode == 0o710 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| why(format!("cannot make it 0700: {e}")))?;
        let mode = look()?.mode() & 0o7777;
        if mode != 0o700 {
            return Err(why(format!("it is mode {mode:o} after making it 0700")));
        }
    }
    Ok(())
}

/// The last look, after the socket and then the directory were given to the group: both are what was set.
pub fn verify_group_access(dir: &Path, socket: &Path, gid: u32) -> Result<(), PermError> {
    let why = |p: &Path, w: String| PermError::Group { path: p.display().to_string(), why: w };
    let d = std::fs::symlink_metadata(dir).map_err(|e| why(dir, e.to_string()))?;
    let s = std::fs::symlink_metadata(socket).map_err(|e| why(socket, e.to_string()))?;
    let own = p_ermit::peer::own_uid();
    if !d.file_type().is_dir() || d.uid() != own || d.gid() != gid || d.mode() & 0o7777 != 0o710 {
        return Err(why(dir, "it is not the broker's directory, group 0710, on the last look".to_owned()));
    }
    if !s.file_type().is_socket() || s.uid() != own || s.gid() != gid || s.mode() & 0o7777 != 0o660 {
        return Err(why(socket, "it is not the broker's socket, group 0660, on the last look".to_owned()));
    }
    Ok(())
}

/// Give `path` (the socket) to the group `gid`: group `gid`, mode 0660, checked afterwards on the file itself (not
/// through a link).
pub fn open_socket_to_group(path: &Path, gid: u32) -> Result<(), PermError> {
    give_to_group(path, gid, 0o660, false)
}

fn give_to_group(path: &Path, gid: u32, mode: u32, dir: bool) -> Result<(), PermError> {
    let why = |w: String| PermError::Group { path: path.display().to_string(), why: w };
    std::os::unix::fs::chown(path, None, Some(gid)).map_err(|e| why(format!("cannot set the group: {e}")))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| why(format!("cannot set the mode: {e}")))?;
    let meta = std::fs::symlink_metadata(path).map_err(|e| why(format!("cannot look at it again: {e}")))?;
    let kind_ok = if dir { meta.file_type().is_dir() } else { meta.file_type().is_socket() };
    if !kind_ok || meta.gid() != gid || meta.mode() & 0o7777 != mode {
        return Err(why(format!(
            "it is group {} mode {:o} after setting {gid} {mode:o}",
            meta.gid(),
            meta.mode() & 0o7777
        )));
    }
    Ok(())
}

/// Replace `path` with `bytes`: a new file (0600) is written and flushed, then renamed over the old one, so a
/// reader sees the old file or the new, never half of one.
pub fn replace_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("tmp");
    let _ = std::fs::remove_file(&tmp);
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)
}
