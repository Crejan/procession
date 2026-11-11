//! One connection on `service.sock`: pledge's transport for the shared
//! exchange (`proposals/service-sock.md`).
//!
//! Reads `submit`, `cancel` (and ignores anything else a service sends),
//! hands each `submit` to [`approvals::submit`] on a thread of its own, since a
//! request may wait for the person until its deadline, and writes the
//! `answer`s. Up to [`MAX_OPEN`] requests may be open on a connection. The end
//! of the connection cancels what is still open. A request that does not parse
//! is answered `refused`/`malformed` and the connection stays.

use std::collections::HashSet;
use std::io::{self, Read};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use p_act::DocumentHash;
use p_act::exchange::{
    Answer, ClearancePolicy, ErrorCode, ErrorMessage, ExchangeError, LineReader, Message, write_message,
};

use crate::approvals::{self, Responder};
use crate::shared::Shared;

/// Requests open on one connection (the transport's parameter).
pub const MAX_OPEN: usize = 16;
/// How long a line may take from its first byte.
pub const LINE_TIMEOUT: Duration = Duration::from_secs(10);

/// Applies [`LINE_TIMEOUT`] to a socket: from the first byte of a line that
/// has not ended, a read may wait only for what is left of the ten seconds.
/// Between lines it waits as long as it takes.
pub struct TimedRead {
    stream: UnixStream,
    partial_since: Option<Instant>,
    timeout: Duration,
}

impl TimedRead {
    /// Reads from `stream`.
    #[must_use]
    pub fn new(stream: UnixStream) -> Self {
        Self { stream, partial_since: None, timeout: LINE_TIMEOUT }
    }
}

impl Read for TimedRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = match self.partial_since {
            None => None,
            Some(since) => match self.timeout.checked_sub(since.elapsed()).filter(|left| !left.is_zero()) {
                Some(left) => Some(left),
                None => return Err(io::ErrorKind::TimedOut.into()),
            },
        };
        // macOS refuses to set a timeout on a socket whose peer has gone; the read then ends at once.
        let _ = self.stream.set_read_timeout(left);
        let n = self
            .stream
            .read(buf)
            .map_err(|e| if e.kind() == io::ErrorKind::WouldBlock { io::ErrorKind::TimedOut.into() } else { e })?;
        match buf[..n].iter().rposition(|b| *b == b'\n') {
            Some(last) if last + 1 == n => self.partial_since = None,
            Some(_) => self.partial_since = Some(Instant::now()),
            None if n > 0 => {
                self.partial_since.get_or_insert_with(Instant::now);
            }
            None => {}
        }
        Ok(n)
    }
}

fn send_error(writer: &Mutex<UnixStream>, error: ErrorCode) {
    if let Ok(mut stream) = writer.lock() {
        let _ = write_message(&mut *stream, &Message::Error(ErrorMessage { error }), ClearancePolicy::Refused);
    }
}

/// Serves one connection until it ends.
pub fn serve(shared: &Arc<Shared>, stream: UnixStream, peer: Option<(u32, Option<i32>)>) {
    let Ok(write_half) = stream.try_clone() else { return };
    let writer = Arc::new(Mutex::new(write_half));
    let send_writer = Arc::clone(&writer);
    let send: approvals::Send = Arc::new(move |answer: &Answer| {
        if let Ok(mut stream) = send_writer.lock() {
            let _ = write_message(&mut *stream, &Message::Answer(answer.clone()), ClearancePolicy::Refused);
        }
    });
    let id = shared.approvals.responder_id();
    let responder = Responder { id, send, peer };
    let open: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
    let mut hashes: Vec<DocumentHash> = Vec::new();
    let mut lines = LineReader::new(TimedRead::new(stream));
    loop {
        match lines.read_message(ClearancePolicy::Refused) {
            Ok(None) => break,
            Ok(Some(Message::Submit(submitted))) => {
                let hash = submitted.hash();
                let key = hash.to_string();
                {
                    let Ok(mut open) = open.lock() else { break };
                    if !open.contains(&key) && open.len() >= MAX_OPEN {
                        send_error(&writer, ErrorCode::TooManyOpen);
                        break;
                    }
                    open.insert(key.clone());
                }
                hashes.push(hash);
                let (shared, responder, open) = (Arc::clone(shared), responder.clone(), Arc::clone(&open));
                thread::spawn(move || {
                    approvals::submit(&shared, &submitted, responder);
                    if let Ok(mut open) = open.lock() {
                        open.remove(&key);
                    }
                });
            }
            Ok(Some(Message::Cancel(cancel))) => shared.approvals.cancel(&cancel.request, id),
            Ok(Some(Message::Answer(answer))) => {
                eprintln!("pledge: an answer from a service for {}: ignored", answer.request)
            }
            Ok(Some(Message::Error(_))) => break,
            Err(ExchangeError::BadRequest { hash, .. }) => approvals::refuse_malformed(shared, hash, &responder),
            Err(error) => {
                if let Some(code) = error.code() {
                    send_error(&writer, code);
                }
                break;
            }
        }
    }
    shared.approvals.cancel_all(&hashes, id);
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn a_partial_line_is_timed_and_the_time_between_lines_is_not() {
        let (mut a, b) = UnixStream::pair().expect("pair");
        let mut reader = TimedRead::new(b);
        reader.timeout = Duration::from_millis(150);
        a.write_all(b"begun").expect("write");
        let mut buf = [0_u8; 16];
        assert_eq!(reader.read(&mut buf).expect("first bytes"), 5);
        assert_eq!(reader.read(&mut buf).expect_err("timed out").kind(), io::ErrorKind::TimedOut);

        let (mut c, d) = UnixStream::pair().expect("pair");
        let mut reader = TimedRead::new(d);
        reader.timeout = Duration::from_millis(100);
        let late = thread::spawn(move || {
            thread::sleep(Duration::from_millis(300));
            c.write_all(b"line\n").expect("write");
        });
        assert_eq!(reader.read(&mut buf).expect("waits for the first byte"), 5);
        late.join().expect("thread");
    }
}
