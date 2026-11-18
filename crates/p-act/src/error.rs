use thiserror::Error;

/// A string from outside, as it may appear in a message: escaped (`p_ermit::text::escape`) and cut to `max` characters. An
/// error's `Display` never prints a value from a document, only names, and those through this.
pub(crate) fn shown(s: &str, max: usize) -> String {
    p_ermit::text::escape_clipped(s, max).text
}

/// Why a document was refused. Each cause has its own variant; nothing is
/// cleaned up or ignored.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseError {
    #[error("document is {len} bytes, the limit is {limit}")]
    TooLarge { len: usize, limit: usize },
    #[error("document is not UTF-8")]
    NotUtf8,
    #[error("document starts with a byte order mark")]
    ByteOrderMark,
    #[error("document contains a line break")]
    LineBreak,
    #[error("document is not one JSON object: {}", shown(.0, 128))]
    NotJson(String),
    #[error("member `{}` appears twice", shown(.0, 64))]
    DuplicateMember(String),
    #[error("unknown member `{}`", shown(.0, 64))]
    UnknownMember(String),
    #[error("member `{0}` is missing")]
    MissingMember(&'static str),
    #[error("member `{}` is not {expected}", shown(member, 64))]
    WrongType { member: String, expected: &'static str },
    #[error("version {} is not known", shown(.0, 16))]
    UnsupportedVersion(String),
    #[error("type is `{}`, expected `{expected}`", shown(found, 32))]
    WrongDocumentType { expected: &'static str, found: String },
    #[error("member `{}` contains a control character", shown(.0, 64))]
    ControlCharacter(String),
    #[error("member `{}` contains a bidirectional mark", shown(.0, 64))]
    BidiMark(String),
    #[error("an id is not a version 4 UUID in lower case with hyphens")]
    MalformedUuid(String),
    #[error("a time is not a UTC time to the second, like 2026-11-11T15:04:05Z")]
    MalformedTime(String),
    #[error("a host is not a valid host name")]
    MalformedHost(String),
    #[error("a service name is not a valid one ([a-z][a-z0-9-]*)")]
    MalformedServiceName(String),
    #[error("an action is not lower-case words separated by single spaces")]
    MalformedAction(String),
    #[error("more than {limit} parameters")]
    TooManyParams { limit: usize },
    #[error("parameter {index} is longer than {limit} bytes")]
    ParamTooLong { index: usize, limit: usize },
    #[error("claim is longer than {limit} characters")]
    ClaimTooLong { limit: usize },
    #[error("`{0}` is not standard padded base64")]
    MalformedBase64(&'static str),
    #[error("rating member `{member}` has a value that is not one of its values")]
    MalformedRating { member: &'static str, value: String },
    #[error("a hash is not like sha256:<64 lower-case hex digits>")]
    MalformedHash(String),
    #[error("member `{member}` is not {expected} bytes of base64")]
    BadLength { member: &'static str, expected: usize },
    #[error("a fingerprint is not like SHA256:<43 base64 characters>")]
    MalformedFingerprint(String),
    #[error("member `{0}` is not a certificate line")]
    MalformedCertificateLine(&'static str),
    #[error("`{0}` is a set and has an entry twice")]
    DuplicateEntry(&'static str),
    #[error("an entry of `{0}` is not a usable name")]
    MalformedName(&'static str),
    #[error("signature is not an armoured SSH signature")]
    MalformedSignature,
    #[error("the call inside the request is refused: {0}")]
    InnerCall(Box<ParseError>),
}
