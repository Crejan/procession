//! The file descriptors of a process that matter to a realtime network
//! program: sockets, and devices such as `/dev/vfio/<group>`, `/dev/uio<n>`.

use std::fs;

use crate::error::Error;
use crate::root::{Root, numeric_entries};

/// What an fd points at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FdKind {
    /// A socket, by inode (look it up with [`crate::net::sockets`]).
    Socket {
        /// The socket inode.
        inode: u64,
    },
    /// `/dev/vfio/<group>`.
    Vfio {
        /// The IOMMU group.
        group: u32,
    },
    /// `/dev/uio<n>`.
    Uio {
        /// The UIO number.
        n: u32,
    },
    /// Another device node under `/dev` (`/dev/EtherCAT0`, ...).
    Device {
        /// The path.
        path: String,
    },
}

/// One fd.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fd {
    /// The number.
    pub fd: i32,
    /// What it is.
    pub kind: FdKind,
}

/// Classifies the target of an fd link; `None` for files, pipes and the like.
#[must_use]
pub fn classify(target: &str) -> Option<FdKind> {
    if let Some(i) = target.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')) {
        return i.parse().ok().map(|inode| FdKind::Socket { inode });
    }
    let dev = target.strip_prefix("/dev/")?;
    if let Some(g) = dev.strip_prefix("vfio/") {
        // /dev/vfio/vfio is the container, not a group.
        return Some(g.parse().map_or_else(|_| FdKind::Device { path: target.into() }, |group| FdKind::Vfio { group }));
    }
    if let Some(n) = dev.strip_prefix("uio").and_then(|n| n.parse().ok()) {
        return Some(FdKind::Uio { n });
    }
    Some(FdKind::Device { path: target.into() })
}

/// The sockets and devices among a process's fds. Reading another user's
/// fds needs `CAP_SYS_PTRACE`.
///
/// # Errors
/// When `/proc/<pid>/fd` cannot be listed (permission, or the process is gone).
pub fn fds(root: &Root, pid: i32) -> Result<Vec<Fd>, Error> {
    let dir = root.proc.join(pid.to_string()).join("fd");
    let mut out = Vec::new();
    for fd in numeric_entries(&dir)? {
        let Ok(target) = fs::read_link(dir.join(fd.to_string())) else { continue };
        if let Some(kind) = classify(&crate::text::from_os(target.as_os_str())) {
            out.push(Fd { fd, kind });
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets() {
        assert_eq!(classify("socket:[4242]"), Some(FdKind::Socket { inode: 4242 }));
        assert_eq!(classify("/dev/vfio/12"), Some(FdKind::Vfio { group: 12 }));
        assert_eq!(classify("/dev/vfio/vfio"), Some(FdKind::Device { path: "/dev/vfio/vfio".into() }));
        assert_eq!(classify("/dev/uio3"), Some(FdKind::Uio { n: 3 }));
        assert_eq!(classify("/dev/EtherCAT0"), Some(FdKind::Device { path: "/dev/EtherCAT0".into() }));
        assert_eq!(classify("pipe:[1]"), None);
        assert_eq!(classify("/home/x/file"), None);
    }
}
