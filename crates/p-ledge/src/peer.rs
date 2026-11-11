//! Who is on the other end of a Unix socket: the user, and the program.
//!
//! In the development form a program is identified by the path of the
//! connecting process (`SPEC.md`, section 8). That is the process at the time
//! of the question: a process that execs another, or a pid that is reused,
//! changes the answer. The form protects nothing and says so.

use std::io;
use std::os::unix::io::AsRawFd;

/// The credentials of the connecting process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    /// The user.
    pub uid: u32,
    /// The process, when the platform says.
    pub pid: Option<i32>,
}

/// The peer of `socket`.
///
/// # Errors
///
/// The operating system's error if the credentials cannot be read.
pub fn peer<S: AsRawFd>(socket: &S) -> io::Result<Peer> {
    let fd = socket.as_raw_fd();
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` and `len` are valid for the call and sized as it expects.
        let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &mut len) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Peer { uid: cred.uid, pid: Some(cred.pid) })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: both out-pointers are valid for the call.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        // SAFETY: `pid` and `len` are valid for the call and sized as it expects.
        let rc = unsafe { libc::getsockopt(fd, libc::SOL_LOCAL, libc::LOCAL_PEERPID, (&raw mut pid).cast(), &mut len) };
        Ok(Peer { uid, pid: (rc == 0).then_some(pid) })
    }
}

/// This process's own user.
#[must_use]
pub fn own_uid() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}

/// The path of the program that process `pid` runs, if it can be read.
#[must_use]
pub fn program_path(pid: i32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.to_string_lossy().into_owned())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut buffer = vec![0_u8; 4096];
        // SAFETY: the buffer is valid for the length given.
        let len = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), 4096) };
        let len = usize::try_from(len).ok().filter(|len| *len > 0)?;
        buffer.truncate(len);
        String::from_utf8(buffer).ok()
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn the_peer_of_a_socket_pair_is_this_process() {
        let (a, _b) = UnixStream::pair().expect("pair");
        let peer = peer(&a).expect("peer");
        assert_eq!(peer.uid, own_uid());
        if let Some(pid) = peer.pid {
            assert_eq!(pid, std::process::id() as i32);
            let path = program_path(pid).expect("path");
            assert_eq!(
                std::fs::canonicalize(path).expect("real"),
                std::fs::canonicalize(std::env::current_exe().expect("exe")).expect("real")
            );
        }
    }
}
