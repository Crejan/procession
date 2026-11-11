//! The SSH agent protocol's messages (draft-miller-ssh-agent): framing, the
//! requests this SSH agent understands and the replies it gives.
//!
//! ```text
//! message := uint32 length || byte type || payload[length - 1]
//! ```
//!
//! Understood: `SSH_AGENTC_REQUEST_IDENTITIES` (11), `SSH_AGENTC_SIGN_REQUEST`
//! (13) and the `session-bind@openssh.com` extension (27). Everything else is
//! answered with `SSH_AGENT_FAILURE` (5). A request is parsed strictly:
//! trailing bytes make it malformed, as they do in OpenSSH's own SSH agent.

use std::fmt;
use std::io::{self, Read};

use super::wire::{Reader, put_string, put_u32};

/// `SSH_AGENT_FAILURE`
pub const FAILURE: u8 = 5;
/// `SSH_AGENT_SUCCESS`
pub const SUCCESS: u8 = 6;
/// `SSH_AGENTC_REQUEST_IDENTITIES`
pub const REQUEST_IDENTITIES: u8 = 11;
/// `SSH_AGENT_IDENTITIES_ANSWER`
pub const IDENTITIES_ANSWER: u8 = 12;
/// `SSH_AGENTC_SIGN_REQUEST`
pub const SIGN_REQUEST: u8 = 13;
/// `SSH_AGENT_SIGN_RESPONSE`
pub const SIGN_RESPONSE: u8 = 14;
/// `SSH_AGENTC_EXTENSION`
pub const EXTENSION: u8 = 27;

/// The largest message read: OpenSSH's own limit (256 KiB). A longer length
/// is refused before anything is allocated for it.
pub const MAX_MESSAGE_LEN: usize = 256 * 1024;

/// One request, borrowed from the message it was parsed out of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request<'a> {
    /// List the keys on offer.
    RequestIdentities,
    /// Sign `data` with the key whose blob is `key_blob`.
    Sign {
        /// The key, by its public key blob (the raw key or its certificate).
        key_blob: &'a [u8],
        /// What to sign, unread: [`SignContent::parse`] reads it.
        ///
        /// [`SignContent::parse`]: super::sign_content::SignContent::parse
        data: &'a [u8],
        /// The signature flags (the hash for RSA); 0 for other key types.
        flags: u32,
    },
    /// An extension request: its name and the rest of the payload.
    Extension {
        /// The extension's name.
        name: &'a str,
        /// What follows the name.
        body: &'a [u8],
    },
    /// A message type this SSH agent does not understand.
    Unsupported(u8),
}

/// A message of a type this SSH agent understands whose payload does not
/// parse. Answered like [`Request::Unsupported`]: with `SSH_AGENT_FAILURE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed {
    /// The message's type byte, `None` if the message was empty.
    pub message_type: Option<u8>,
}

impl fmt::Display for Malformed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.message_type {
            Some(kind) => write!(f, "malformed SSH agent message of type {kind}"),
            None => f.write_str("empty SSH agent message"),
        }
    }
}

impl std::error::Error for Malformed {}

impl<'a> Request<'a> {
    /// Parses one message (type byte and payload, without the length).
    ///
    /// # Errors
    ///
    /// [`Malformed`] if the message is empty or its payload does not parse
    /// exactly.
    pub fn parse(message: &'a [u8]) -> Result<Self, Malformed> {
        let Some((&kind, payload)) = message.split_first() else { return Err(Malformed { message_type: None }) };
        let malformed = Malformed { message_type: Some(kind) };
        let mut reader = Reader::new(payload);
        let request = match kind {
            REQUEST_IDENTITIES => Self::RequestIdentities,
            SIGN_REQUEST => {
                let (Some(key_blob), Some(data), Some(flags)) = (reader.string(), reader.string(), reader.u32()) else {
                    return Err(malformed);
                };
                Self::Sign { key_blob, data, flags }
            }
            EXTENSION => {
                let name = reader.utf8().ok_or(malformed)?;
                let body = reader.rest();
                return Ok(Self::Extension { name, body });
            }
            other => return Ok(Self::Unsupported(other)),
        };
        if reader.remaining() == 0 { Ok(request) } else { Err(malformed) }
    }
}

/// Why a message could not be read from a connection.
#[derive(Debug)]
pub enum FrameError {
    /// The length is 0: not even a type byte.
    Empty,
    /// The length is more than [`MAX_MESSAGE_LEN`].
    TooLong(u32),
    /// The connection failed, or ended in the middle of a message.
    Io(io::Error),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("SSH agent message of length 0"),
            Self::TooLong(len) => write!(f, "SSH agent message of {len} bytes is longer than {MAX_MESSAGE_LEN}"),
            Self::Io(error) => write!(f, "reading an SSH agent message: {error}"),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for FrameError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Reads one message (type byte and payload) from `reader`. `Ok(None)` when
/// the connection ended cleanly, between messages.
///
/// # Errors
///
/// [`FrameError`] for a length of 0 or above [`MAX_MESSAGE_LEN`], and for
/// I/O errors, including a connection that ends inside a message.
pub fn read_message<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0_u8; 4];
    let mut filled = 0;
    while filled < header.len() {
        match reader.read(&mut header[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Ok(count) => filled += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    let length = u32::from_be_bytes(header);
    match usize::try_from(length) {
        Ok(0) => return Err(FrameError::Empty),
        Ok(length) if length <= MAX_MESSAGE_LEN => {}
        _ => return Err(FrameError::TooLong(length)),
    }
    let mut message = vec![0; length as usize];
    reader.read_exact(&mut message)?;
    Ok(Some(message))
}

/// A framed message: length, type, payload.
///
/// # Panics
///
/// If the payload is 4 GiB or longer, which no SSH agent message is.
#[must_use]
pub fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    put_u32(&mut out, u32::try_from(payload.len() + 1).expect("a reply is shorter than 4 GiB"));
    out.push(kind);
    out.extend_from_slice(payload);
    out
}

/// `SSH_AGENT_FAILURE`, framed.
#[must_use]
pub fn failure_reply() -> Vec<u8> {
    frame(FAILURE, &[])
}

/// `SSH_AGENT_SUCCESS`, framed.
#[must_use]
pub fn success_reply() -> Vec<u8> {
    frame(SUCCESS, &[])
}

/// One key on offer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity<'a> {
    /// The public key blob.
    pub blob: &'a [u8],
    /// The comment shown by `ssh-add -l`.
    pub comment: &'a str,
}

/// `SSH_AGENT_IDENTITIES_ANSWER`, framed.
///
/// # Panics
///
/// With 2^32 keys or more, or a key blob or comment of 4 GiB.
#[must_use]
pub fn identities_reply(identities: &[Identity<'_>]) -> Vec<u8> {
    let mut payload = Vec::new();
    put_u32(&mut payload, u32::try_from(identities.len()).expect("fewer than 2^32 keys"));
    for identity in identities {
        put_string(&mut payload, identity.blob);
        put_string(&mut payload, identity.comment.as_bytes());
    }
    frame(IDENTITIES_ANSWER, &payload)
}

/// `SSH_AGENT_SIGN_RESPONSE` carrying `signature` (the signature blob: type
/// and signature as `string`s), framed.
#[must_use]
pub fn sign_reply(signature: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    put_string(&mut payload, signature);
    frame(SIGN_RESPONSE, &payload)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::agent::testing::SESSION_ID;
    use crate::agent::wire::{put_u32, strings};

    fn sign_message(key: &[u8], data: &[u8], flags: u32, trailing: &[u8]) -> Vec<u8> {
        let mut message = vec![SIGN_REQUEST];
        message.extend(strings(&[key, data]));
        put_u32(&mut message, flags);
        message.extend_from_slice(trailing);
        message
    }

    #[test]
    fn the_three_requests_parse() {
        assert_eq!(Request::parse(&[REQUEST_IDENTITIES]), Ok(Request::RequestIdentities));
        let message = sign_message(b"key", b"data", 2, b"");
        assert_eq!(Request::parse(&message), Ok(Request::Sign { key_blob: b"key", data: b"data", flags: 2 }));
        let mut extension = vec![EXTENSION];
        extension.extend(strings(&[b"session-bind@openssh.com"]));
        extension.extend_from_slice(&SESSION_ID);
        assert_eq!(
            Request::parse(&extension),
            Ok(Request::Extension { name: "session-bind@openssh.com", body: &SESSION_ID })
        );
    }

    // ported: testR11_7_unknownOpcode_returnsFailure
    #[test]
    fn an_unknown_type_is_unsupported_not_an_error() {
        assert_eq!(Request::parse(&[0xFE]), Ok(Request::Unsupported(0xFE)));
        // Messages this SSH agent never serves, whatever their payload:
        for kind in [1, 17, 18, 19, 20, 22, 23, 25, 26] {
            assert_eq!(Request::parse(&[kind, 1, 2, 3]), Ok(Request::Unsupported(kind)));
        }
    }

    #[test]
    fn a_payload_that_does_not_parse_exactly_is_malformed() {
        assert_eq!(Request::parse(&[]), Err(Malformed { message_type: None }));
        let bad = Malformed { message_type: Some(SIGN_REQUEST) };
        assert_eq!(Request::parse(&[SIGN_REQUEST]), Err(bad));
        let full = sign_message(b"key", b"data", 0, b"");
        assert_eq!(Request::parse(&full[..full.len() - 1]), Err(bad));
        assert_eq!(Request::parse(&sign_message(b"key", b"data", 0, &[0])), Err(bad));
        assert_eq!(Request::parse(&[REQUEST_IDENTITIES, 0]), Err(Malformed { message_type: Some(REQUEST_IDENTITIES) }));
        assert_eq!(
            Request::parse(&[EXTENSION, 0, 0, 0, 2, 0xFF, 0xFE]),
            Err(Malformed { message_type: Some(EXTENSION) })
        );
    }

    #[test]
    fn replies_are_framed() {
        assert_eq!(failure_reply(), [0, 0, 0, 1, FAILURE]);
        assert_eq!(success_reply(), [0, 0, 0, 1, SUCCESS]);
        assert_eq!(sign_reply(b"sig"), [0, 0, 0, 8, SIGN_RESPONSE, 0, 0, 0, 3, b's', b'i', b'g']);
        let reply =
            identities_reply(&[Identity { blob: b"k1", comment: "one" }, Identity { blob: b"k2", comment: "" }]);
        let mut reader = Reader::new(&reply);
        assert_eq!(reader.u32(), Some(u32::try_from(reply.len()).expect("short") - 4));
        assert_eq!(reader.u8(), Some(IDENTITIES_ANSWER));
        assert_eq!(reader.u32(), Some(2));
        assert_eq!((reader.string(), reader.string()), (Some(&b"k1"[..]), Some(&b"one"[..])));
        assert_eq!((reader.string(), reader.string()), (Some(&b"k2"[..]), Some(&b""[..])));
        assert_eq!(reader.remaining(), 0);
        assert_eq!(identities_reply(&[]), [0, 0, 0, 5, IDENTITIES_ANSWER, 0, 0, 0, 0]);
    }

    #[test]
    fn messages_are_read_from_a_stream_one_by_one() {
        let mut stream = frame(REQUEST_IDENTITIES, &[]);
        stream.extend(frame(SIGN_REQUEST, b"xyz"));
        let mut reader = Cursor::new(stream);
        assert_eq!(read_message(&mut reader).unwrap(), Some(vec![REQUEST_IDENTITIES]));
        assert_eq!(read_message(&mut reader).unwrap(), Some(vec![SIGN_REQUEST, b'x', b'y', b'z']));
        assert_eq!(read_message(&mut reader).unwrap(), None);
    }

    #[test]
    fn a_stream_with_a_bad_length_or_cut_short_is_an_error() {
        let empty = read_message(&mut Cursor::new(vec![0, 0, 0, 0]));
        assert!(matches!(empty, Err(FrameError::Empty)));
        let too_long =
            read_message(&mut Cursor::new((u32::try_from(MAX_MESSAGE_LEN).expect("small") + 1).to_be_bytes().to_vec()));
        assert!(matches!(too_long, Err(FrameError::TooLong(_))));
        let huge = read_message(&mut Cursor::new(vec![0xFF; 4]));
        assert!(matches!(huge, Err(FrameError::TooLong(u32::MAX))));
        let cut_header = read_message(&mut Cursor::new(vec![0, 0]));
        assert!(matches!(cut_header, Err(FrameError::Io(_))));
        let cut_body = read_message(&mut Cursor::new(vec![0, 0, 0, 9, 1, 2]));
        assert!(matches!(cut_body, Err(FrameError::Io(_))));
        let largest = frame(SIGN_REQUEST, &vec![0; MAX_MESSAGE_LEN - 1]);
        assert_eq!(read_message(&mut Cursor::new(largest)).unwrap().map(|m| m.len()), Some(MAX_MESSAGE_LEN));
    }
}
