//! The service's end of `service.sock`: submit one request, wait for its
//! answer. One request per connection, as the connections document asks of a
//! service. The messages are `p_act::exchange`'s; this is only the transport.
//!
//! Stage 1: `ClearancePolicy::Refused` in both directions. A stage-2 service
//! has the other policy, set at its start and never read from what arrives.

use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use p_act::Timestamp;
use p_act::exchange::{Answer, Cancel, ClearancePolicy, LineReader, Message, Outcome, Submit, write_message};

/// Stage 1: pledge never sends a clearance.
pub const POLICY: ClearancePolicy = ClearancePolicy::Refused;
/// A line that is not complete within this after its first byte ends the connection.
const LINE_TIMEOUT: Duration = Duration::from_secs(10);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the wait looks at the cancel flag and the clock.
const TICK: Duration = Duration::from_millis(100);

/// How a wait ended.
#[derive(Debug)]
pub enum Waited {
    /// An answer to this request that is one (an unknown `result` is not).
    Answer(Outcome),
    /// The call's deadline passed by our own clock with no answer.
    Deadline,
    /// The agent went away: `cancel` was sent and the connection closed.
    Cancelled,
    /// Pledge could not be reached, or the connection broke or broke the rules.
    Broken(String),
}

/// Pledge's socket and who must own it.
#[derive(Debug, Clone)]
pub struct PledgeLink {
    pub socket: PathBuf,
    /// The uid of the person: the directory, the socket and the peer must be theirs.
    pub uid: u32,
}

impl PledgeLink {
    /// The door seen from this side (`service-sock.md`, section 3): neither
    /// the directory nor the socket is a symlink, both belong to the person,
    /// and the socket is a socket.
    fn check_door(&self) -> Result<(), String> {
        let dir = self.socket.parent().ok_or("socket without a directory")?;
        for (path, want_socket) in [(dir, false), (self.socket.as_path(), true)] {
            let meta = path.symlink_metadata().map_err(|e| format!("{}: {e}", path.display()))?;
            if meta.file_type().is_symlink() {
                return Err(format!("{} is a symlink", path.display()));
            }
            if meta.uid() != self.uid {
                return Err(format!("{} is not the person's (uid {})", path.display(), meta.uid()));
            }
            if want_socket != meta.file_type().is_socket() || (!want_socket && !meta.is_dir()) {
                return Err(format!("{} is not what it should be", path.display()));
            }
        }
        Ok(())
    }

    /// Connects and checks the peer's uid; the door check comes first.
    ///
    /// # Errors
    /// Why pledge cannot be used, in words.
    pub fn connect(&self) -> Result<UnixStream, String> {
        self.check_door()?;
        let stream = UnixStream::connect(&self.socket).map_err(|e| format!("cannot connect: {e}"))?;
        let peer = peer_uid(&stream).ok_or("cannot tell who is on the socket")?;
        if peer != self.uid {
            return Err(format!("the peer is uid {peer}, not the person's"));
        }
        stream.set_write_timeout(Some(WRITE_TIMEOUT)).map_err(|e| e.to_string())?;
        stream.set_read_timeout(Some(LINE_TIMEOUT)).map_err(|e| e.to_string())?;
        Ok(stream)
    }

    /// Submits `submit` and waits until it is answered, the call's `deadline`
    /// passes, or `cancel` is set. A connection that ends or breaks the rules
    /// is [`Waited::Broken`]; the request is **not** submitted again.
    pub fn submit_and_wait(
        &self,
        submit: &Submit,
        deadline: Timestamp,
        cancel: &AtomicBool,
        note: &dyn Fn(&str),
    ) -> Waited {
        let mut stream = match self.connect() {
            Ok(stream) => stream,
            Err(why) => return Waited::Broken(why),
        };
        let hash = submit.hash();
        if let Err(e) = write_message(&mut stream, &Message::Submit(submit.clone()), POLICY) {
            return Waited::Broken(format!("cannot submit: {e}"));
        }
        let mut reader = LineReader::new(&stream);
        loop {
            // At the deadline the call is over: nothing is waited for after it. Whether pledge then
            // records `expired` or `cancelled` for a submitter that goes away is pledge's to settle
            // (`record.md` section 9: at or after the deadline, or within 2 seconds before it, `expired`).
            if now_unix() >= deadline.unix() {
                return Waited::Deadline;
            }
            if cancel.load(Ordering::SeqCst) {
                let _ = write_message(&mut &stream, &Message::Cancel(Cancel { request: hash }), POLICY);
                return Waited::Cancelled;
            }
            if !readable(&stream, TICK) {
                continue;
            }
            match reader.read_message(POLICY) {
                Ok(Some(Message::Answer(Answer { request, outcome }))) if request == hash => match outcome {
                    Outcome::Unknown => note("an answer with a result this program does not know is no answer"),
                    outcome => return Waited::Answer(outcome),
                },
                Ok(Some(Message::Answer(_) | Message::Cancel(_))) => note("a message for a request not held: ignored"),
                Ok(Some(Message::Submit(_))) => return Waited::Broken("pledge sent a submit".into()),
                Ok(Some(Message::Error(e))) => return Waited::Broken(format!("pledge sent error {}", e.error.wire())),
                Ok(None) => return Waited::Broken("pledge closed the connection".into()),
                Err(e) => return Waited::Broken(format!("bad line from pledge: {e}")),
            }
        }
    }
}

fn now_unix() -> i64 {
    Timestamp::now().map_or(0, Timestamp::unix)
}

/// Whether there is something to read within `wait` (or the peer has closed).
fn readable(stream: &UnixStream, wait: Duration) -> bool {
    let mut fd = libc::pollfd { fd: stream.as_raw_fd(), events: libc::POLLIN, revents: 0 };
    let millis = i32::try_from(wait.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: one valid pollfd, count 1.
    let ready = unsafe { libc::poll(&raw mut fd, 1, millis) };
    ready > 0
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = u32::try_from(std::mem::size_of::<libc::ucred>()).ok()?;
    // SAFETY: SO_PEERCRED writes a `ucred` of `len` bytes into `cred`.
    let done = unsafe {
        libc::getsockopt(stream.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, (&raw mut cred).cast(), &raw mut len)
    };
    (done == 0).then_some(cred.uid)
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let (mut uid, mut gid) = (0, 0);
    // SAFETY: `getpeereid` writes two integers.
    (unsafe { libc::getpeereid(stream.as_raw_fd(), &raw mut uid, &raw mut gid) } == 0).then_some(uid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn peer_uid(_: &UnixStream) -> Option<u32> {
    None
}

/// Whether anything listens on `socket`: a connect and an immediate close.
#[must_use]
pub fn reachable(link: &PledgeLink) -> bool {
    link.connect().is_ok()
}
