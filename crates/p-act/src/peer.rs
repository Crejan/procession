//! Who is on the other end of an accepted Unix stream socket: the user, the group, the process and the
//! program, read once, one way, for every program that has such a socket (pledge's three, the broker's
//! admin socket, preserve's daemon socket).
//!
//! No dependency on the formats, signatures or `ssh-keygen`: this module needs `libc` and `std`.
//!
//! **Read or drop.** A [`Peer`] exists only if its credentials were read; a socket whose peer cannot be
//! read has no `Peer` and no "anyone" to fall back to. [`admit`] reads and checks in one call and either
//! returns the `Peer` or a [`Refusal`] that says why; [`accept`] does that and reports the refusal through
//! a throttle, so that the one place a connection is dropped is also the one place it is explained.
//!
//! **What the kernel says.** Linux: `SO_PEERCRED` (user, group, process as they were when the socket was
//! connected) and `/proc/<pid>/exe`. macOS: `getpeereid` (user and group, from `LOCAL_PEERCRED`),
//! `LOCAL_PEERPID` and `proc_pidpath`. Another Unix: nothing can be read, which is a refusal, not a
//! default. The program is the process **at the time of the question**: a process that execs another, or a
//! pid that is reused, changes the answer, so it is information for a record, never what a decision rests on.
//!
//! The Linux branches are written after pledge's, which ran on Debian 13; they were not compiled where
//! this module was written (macOS).

use std::fmt;
use std::io;
use std::os::unix::io::AsRawFd;
use std::time::{Duration, Instant};

/// At most one throttled line per ten seconds per socket.
pub const LOG_INTERVAL: Duration = Duration::from_secs(10);

/// This process's own user (the real user id, as pledge uses it).
#[must_use]
pub fn own_uid() -> u32 {
    // SAFETY: `getuid` has no preconditions.
    unsafe { libc::getuid() }
}

/// The path of the program that process `pid` runs, if it can be read.
#[must_use]
pub fn program_path(pid: i32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).ok().map(|p| p.to_string_lossy().into_owned())
    }
    #[cfg(target_os = "macos")]
    {
        let mut buffer = vec![0_u8; 4096];
        // SAFETY: the buffer is valid for the length given.
        let len = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), 4096) };
        let len = usize::try_from(len).ok().filter(|len| *len > 0)?;
        buffer.truncate(len);
        String::from_utf8(buffer).ok()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        None
    }
}

/// The credentials could not be read. Holds the operating system's error.
#[derive(Debug)]
pub struct PeerError {
    source: io::Error,
}

impl PeerError {
    /// The operating system's error.
    #[must_use]
    pub fn source_error(&self) -> &io::Error {
        &self.source
    }
}

impl fmt::Display for PeerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.source.fmt(f)
    }
}

impl std::error::Error for PeerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// The credentials of the connecting process of a Unix socket, as the kernel gave them. It can only be
/// obtained by reading them ([`Peer::read`], [`admit`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    uid: u32,
    gid: u32,
    pid: Option<i32>,
    program: Option<String>,
}

impl Peer {
    /// The credentials of `socket`'s peer and the program it runs.
    pub fn read<S: AsRawFd>(socket: &S) -> Result<Peer, PeerError> {
        let mut peer = Peer::read_credentials(socket)?;
        peer.program = peer.pid.filter(|pid| *pid > 0).and_then(program_path);
        Ok(peer)
    }

    /// The user, group and process only; the program is not looked up (no `/proc` read).
    pub fn read_credentials<S: AsRawFd>(socket: &S) -> Result<Peer, PeerError> {
        credentials(socket.as_raw_fd()).map_err(|source| PeerError { source })
    }

    /// The user.
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The group.
    #[must_use]
    pub fn gid(&self) -> u32 {
        self.gid
    }

    /// The process, when the platform says (0 across pid namespaces).
    #[must_use]
    pub fn pid(&self) -> Option<i32> {
        self.pid
    }

    /// The program's path, when it could be read (Linux `/proc/<pid>/exe`, macOS `proc_pidpath`); `None` from
    /// [`Peer::read_credentials`].
    #[must_use]
    pub fn program(&self) -> Option<&str> {
        self.program.as_deref()
    }

    /// Whether the peer is user `uid`.
    #[must_use]
    pub fn is_user(&self, uid: u32) -> bool {
        self.uid == uid
    }

    /// Whether the peer is one of `uids`.
    #[must_use]
    pub fn is_one_of(&self, uids: &[u32]) -> bool {
        uids.contains(&self.uid)
    }

    /// Whether the peer is the user running this program.
    #[must_use]
    pub fn is_own_user(&self) -> bool {
        self.uid == own_uid()
    }

    /// Whether the peer is the user running this program, or root.
    #[must_use]
    pub fn is_own_user_or_root(&self) -> bool {
        self.uid == 0 || self.is_own_user()
    }
}

#[cfg(target_os = "linux")]
fn credentials(fd: i32) -> io::Result<Peer> {
    // Minimal Linux branch, as pledge's: SO_PEERCRED gives user, group and process.
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for the call and sized as it expects.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &mut len) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Peer { uid: cred.uid, gid: cred.gid, pid: Some(cred.pid), program: None })
}

#[cfg(target_os = "macos")]
fn credentials(fd: i32) -> io::Result<Peer> {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: both out-pointers are valid for the call.
    if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `pid` and `len` are valid for the call and sized as it expects.
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_LOCAL, libc::LOCAL_PEERPID, (&raw mut pid).cast(), &mut len) };
    Ok(Peer { uid, gid, pid: (rc == 0).then_some(pid), program: None })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn credentials(_fd: i32) -> io::Result<Peer> {
    // Nothing is read on another Unix: that is a refusal, never a default.
    Err(io::Error::new(io::ErrorKind::Unsupported, "peer credentials are not read on this system"))
}

/// Who may connect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy<'a> {
    /// Any peer whose credentials were read (for a socket whose file mode decides who connects).
    AnyReadable,
    /// The user running this program.
    OwnUser,
    /// The user running this program, or root.
    OwnUserOrRoot,
    /// One of these users.
    Uids(&'a [u32]),
}

impl Policy<'_> {
    /// Whether a peer of user `uid` is admitted, where `own` is the user running this program.
    #[must_use]
    pub fn admits_with(&self, uid: u32, own: u32) -> bool {
        match self {
            Policy::AnyReadable => true,
            Policy::OwnUser => uid == own,
            Policy::OwnUserOrRoot => uid == own || uid == 0,
            Policy::Uids(uids) => uids.contains(&uid),
        }
    }

    /// Whether a peer of user `uid` is admitted, for the user running this program.
    #[must_use]
    pub fn admits(&self, uid: u32) -> bool {
        self.admits_with(uid, own_uid())
    }

    fn reason(&self) -> &'static str {
        match self {
            Policy::AnyReadable => "",
            Policy::OwnUser => "not this user",
            Policy::OwnUserOrRoot => "neither this user nor root",
            Policy::Uids(_) => "not one of the users allowed",
        }
    }
}

/// Why a connection is dropped.
#[derive(Debug)]
pub enum Refusal {
    /// The credentials could not be read: the connection is dropped, as it would be for any peer.
    Unreadable(PeerError),
    /// The peer is a user the policy does not admit.
    NotAdmitted { uid: u32, why: &'static str },
}

impl Refusal {
    /// The line for a log: `<which>: ...`, as pledge writes it. Never holds anything the peer sent.
    #[must_use]
    pub fn message(&self, which: &str) -> String {
        match self {
            Refusal::Unreadable(e) => {
                format!("{which}: could not read the peer's credentials ({e}): the connection was dropped")
            }
            Refusal::NotAdmitted { uid, why } => format!("{which}: a connection from user {uid} ({why}) was dropped"),
        }
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message("peer"))
    }
}

impl std::error::Error for Refusal {}

/// Read the peer of `socket` and check it against `policy`. **Read or drop**: the only way to a [`Peer`] is
/// credentials that were read and a user the policy admits.
pub fn admit<S: AsRawFd>(socket: &S, policy: &Policy<'_>) -> Result<Peer, Refusal> {
    let peer = Peer::read(socket).map_err(Refusal::Unreadable)?;
    if policy.admits(peer.uid()) {
        Ok(peer)
    } else {
        Err(Refusal::NotAdmitted { uid: peer.uid(), why: policy.reason() })
    }
}

/// At most one line per interval for the connections that are dropped, with the count of those not printed,
/// so that something connecting in a loop cannot fill a log. One per socket. It builds lines and never writes
/// them: the caller gives the sink (stderr, a log), and nothing here goes into a record.
#[derive(Debug)]
pub struct Throttle {
    label: String,
    interval: Duration,
    last: Option<Instant>,
    held_back: u64,
}

impl Throttle {
    /// A throttle that lets one line through per `interval`; lines start with `<label>: ` (the program's name).
    #[must_use]
    pub fn new(label: &str, interval: Duration) -> Throttle {
        Throttle { label: label.to_owned(), interval, last: None, held_back: 0 }
    }

    /// The line to print for `message` at `now`, or `None` if it is held back (and counted). The next one
    /// to get through says how many were not printed.
    pub fn line(&mut self, now: Instant, message: &str) -> Option<String> {
        if self.last.is_some_and(|last| now.saturating_duration_since(last) < self.interval) {
            self.held_back += 1;
            return None;
        }
        let held = std::mem::take(&mut self.held_back);
        self.last = Some(now);
        Some(if held == 0 {
            format!("{}: {message}", self.label)
        } else {
            format!(
                "{}: {message} ({held} more like it in the last {}s were not printed)",
                self.label,
                self.interval.as_secs()
            )
        })
    }

    /// [`Throttle::line`] at the current time, to the caller's `sink`.
    pub fn report(&mut self, message: &str, sink: &mut dyn FnMut(&str)) {
        if let Some(line) = self.line(Instant::now(), message) {
            sink(&line);
        }
    }
}

/// [`admit`], and a refusal goes to `throttle` and then `sink` as one (throttled) line headed `which`:
/// the peer if it may connect, else `None`. Nothing is told to the peer.
pub fn accept<S: AsRawFd>(
    socket: &S,
    policy: &Policy<'_>,
    which: &str,
    throttle: &mut Throttle,
    sink: &mut dyn FnMut(&str),
) -> Option<Peer> {
    match admit(socket, policy) {
        Ok(peer) => Some(peer),
        Err(refusal) => {
            throttle.report(&refusal.message(which), sink);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    struct Fd(i32);
    impl AsRawFd for Fd {
        fn as_raw_fd(&self) -> i32 {
            self.0
        }
    }

    fn ten() -> Throttle {
        Throttle::new("prog", Duration::from_secs(10))
    }

    #[test]
    fn the_peer_of_a_socket_pair_is_this_process() {
        let (a, _b) = UnixStream::pair().unwrap();
        let peer = Peer::read(&a).unwrap();
        assert_eq!(peer.uid(), own_uid());
        assert!(
            peer.is_user(own_uid())
                && peer.is_own_user()
                && peer.is_own_user_or_root()
                && peer.is_one_of(&[1, own_uid()])
        );
        assert!(!peer.is_one_of(&[]) && !peer.is_user(own_uid().wrapping_add(1)));
        // SAFETY: `getgid` has no preconditions.
        assert_eq!(peer.gid(), unsafe { libc::getgid() });
        if let Some(pid) = peer.pid() {
            assert_eq!(pid, i32::try_from(std::process::id()).unwrap());
            let program = peer.program().expect("the program of this process");
            assert_eq!(
                std::fs::canonicalize(program).unwrap(),
                std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
            );
        }
        // Without the program lookup.
        let bare = Peer::read_credentials(&a).unwrap();
        assert_eq!((bare.uid(), bare.gid(), bare.pid()), (peer.uid(), peer.gid(), peer.pid()));
        assert_eq!(bare.program(), None);
        // Both ends of the pair are this process.
        assert_eq!(Peer::read(&_b).unwrap().uid(), own_uid());
    }

    #[test]
    fn the_program_of_a_pid_and_of_none() {
        assert!(program_path(i32::try_from(std::process::id()).unwrap()).is_some());
        assert_eq!(program_path(i32::MAX), None);
        assert_eq!(program_path(-1), None);
    }

    #[test]
    fn what_is_not_a_socket_has_no_peer_and_is_never_anyone() {
        // A pipe, a regular file, /dev/null, a closed descriptor: the read fails, and nothing stands in for a peer.
        let (reader, _writer) = std::io::pipe().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        for (label, result) in
            [("pipe", Peer::read(&reader)), ("file", Peer::read(&file)), ("closed fd", Peer::read(&Fd(-1)))]
        {
            let e = result.expect_err(label);
            assert!(
                e.source_error().raw_os_error().is_some() || e.source_error().kind() == io::ErrorKind::Unsupported,
                "{label}: {e}"
            );
        }
        assert!(Peer::read_credentials(&file).is_err());
        // `admit` refuses them for every policy, `AnyReadable` included.
        for policy in [Policy::AnyReadable, Policy::OwnUser, Policy::OwnUserOrRoot, Policy::Uids(&[own_uid()])] {
            assert!(matches!(admit(&file, &policy), Err(Refusal::Unreadable(_))), "{policy:?}");
            assert!(matches!(admit(&Fd(-1), &policy), Err(Refusal::Unreadable(_))), "{policy:?}");
        }
    }

    #[test]
    fn the_policies() {
        // Pure: users 0 (root), 1000 (this program's) and 1001.
        let own = 1000;
        for (policy, root, mine, other) in [
            (Policy::AnyReadable, true, true, true),
            (Policy::OwnUser, false, true, false),
            (Policy::OwnUserOrRoot, true, true, false),
            (Policy::Uids(&[1001]), false, false, true),
            (Policy::Uids(&[0, 1000]), true, true, false),
            (Policy::Uids(&[]), false, false, false),
        ] {
            assert_eq!(
                [policy.admits_with(0, own), policy.admits_with(1000, own), policy.admits_with(1001, own)],
                [root, mine, other],
                "{policy:?}"
            );
        }
        // For this process.
        assert!(
            Policy::OwnUser.admits(own_uid())
                && Policy::OwnUserOrRoot.admits(own_uid())
                && Policy::OwnUserOrRoot.admits(0)
        );
    }

    #[test]
    fn admit_returns_the_peer_or_says_why_not() {
        let (a, _b) = UnixStream::pair().unwrap();
        assert_eq!(admit(&a, &Policy::OwnUser).unwrap().uid(), own_uid());
        assert!(admit(&a, &Policy::AnyReadable).is_ok());
        assert!(admit(&a, &Policy::OwnUserOrRoot).is_ok());
        let other = own_uid().wrapping_add(1);
        match admit(&a, &Policy::Uids(&[other])) {
            Err(Refusal::NotAdmitted { uid, why }) => {
                assert_eq!((uid, why), (own_uid(), "not one of the users allowed"))
            }
            r => panic!("{r:?}"),
        }
        // Pledge's texts, word for word.
        let refusal = Refusal::NotAdmitted { uid: 1234, why: Policy::OwnUser.reason() };
        assert_eq!(
            refusal.message("control socket"),
            "control socket: a connection from user 1234 (not this user) was dropped"
        );
        assert_eq!(
            Refusal::NotAdmitted { uid: 7, why: Policy::OwnUserOrRoot.reason() }.message("admin socket"),
            "admin socket: a connection from user 7 (neither this user nor root) was dropped"
        );
        let file = std::fs::File::open("/dev/null").unwrap();
        let unreadable = admit(&file, &Policy::OwnUser).unwrap_err().message("SSH agent socket");
        assert!(
            unreadable.starts_with("SSH agent socket: could not read the peer's credentials (")
                && unreadable.ends_with("): the connection was dropped"),
            "{unreadable}"
        );
    }

    #[test]
    fn the_throttle_lets_one_line_through_per_interval_and_counts_the_rest() {
        let mut t = ten();
        let start = Instant::now();
        let at = |s: u64| start + Duration::from_secs(s);
        assert_eq!(t.line(at(0), "a connection was dropped").as_deref(), Some("prog: a connection was dropped"));
        for s in [1, 2, 9] {
            assert_eq!(t.line(at(s), "x"), None, "{s}");
        }
        // The first one after the interval carries the count of the three held back, and starts a new interval.
        assert_eq!(
            t.line(at(10), "again").as_deref(),
            Some("prog: again (3 more like it in the last 10s were not printed)")
        );
        assert_eq!(t.line(at(19), "x"), None);
        assert_eq!(
            t.line(at(20), "later").as_deref(),
            Some("prog: later (1 more like it in the last 10s were not printed)")
        );
        // Quiet for a long time: no count.
        assert_eq!(t.line(at(500), "quiet").as_deref(), Some("prog: quiet"));
        // The interval is per throttle: another socket's throttle is not held back by this one.
        assert_eq!(ten().line(at(501), "other socket").as_deref(), Some("prog: other socket"));
        // A clock that steps back is not a panic and holds back like a short interval.
        assert_eq!(t.line(start, "back"), None);
    }

    #[test]
    fn accept_drops_and_reports_through_the_callers_sink() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let mut throttle = ten();
        let mut lines: Vec<String> = Vec::new();
        for _ in 0..5 {
            assert_eq!(
                accept(&file, &Policy::OwnUser, "service socket", &mut throttle, &mut |l| lines.push(l.to_owned())),
                None
            );
        }
        assert_eq!(lines.len(), 1, "one line for five drops");
        assert!(lines[0].starts_with("prog: service socket: could not read the peer's credentials ("), "{}", lines[0]);
        let (a, _b) = UnixStream::pair().unwrap();
        let peer =
            accept(&a, &Policy::OwnUser, "control socket", &mut throttle, &mut |l| lines.push(l.to_owned())).unwrap();
        assert_eq!(peer.uid(), own_uid());
        assert_eq!(lines.len(), 1, "an admitted peer says nothing");
        let other = own_uid().wrapping_add(1);
        assert!(
            accept(&a, &Policy::Uids(&[other]), "control socket", &mut throttle, &mut |l| lines.push(l.to_owned()))
                .is_none()
        );
        assert_eq!(lines.len(), 1, "held back: the interval has not passed");
    }

    #[test]
    fn the_refusal_is_an_error_and_holds_no_peer_data() {
        let e: Box<dyn std::error::Error> = Box::new(Refusal::NotAdmitted { uid: 5, why: "not this user" });
        assert_eq!(e.to_string(), "peer: a connection from user 5 (not this user) was dropped");
        let file = std::fs::File::open("/dev/null").unwrap();
        let unreadable = Peer::read(&file).unwrap_err();
        assert!(std::error::Error::source(&unreadable).is_some());
    }
}
