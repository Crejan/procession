use thiserror::Error;

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
    #[error("document is not one JSON object: {0}")]
    NotJson(String),
    #[error("member `{0}` appears twice")]
    DuplicateMember(String),
    #[error("unknown member `{0}`")]
    UnknownMember(String),
    #[error("member `{0}` is missing")]
    MissingMember(&'static str),
    #[error("member `{member}` is not {expected}")]
    WrongType { member: String, expected: &'static str },
    #[error("version {0} is not known")]
    UnsupportedVersion(String),
    #[error("type is `{found}`, expected `{expected}`")]
    WrongDocumentType { expected: &'static str, found: String },
    #[error("member `{0}` contains a control character")]
    ControlCharacter(String),
    #[error("member `{0}` contains a bidirectional mark")]
    BidiMark(String),
    #[error("`{0}` is not a version 4 UUID in lower case with hyphens")]
    MalformedUuid(String),
    #[error("`{0}` is not a UTC time to the second, like 2026-11-11T15:04:05Z")]
    MalformedTime(String),
    #[error("`{0}` is not a valid host name")]
    MalformedHost(String),
    #[error("`{0}` is not a valid service name ([a-z][a-z0-9-]*)")]
    MalformedServiceName(String),
    #[error("`{0}` is not an action: lower-case words separated by single spaces")]
    MalformedAction(String),
    #[error("more than {limit} parameters")]
    TooManyParams { limit: usize },
    #[error("parameter {index} is longer than {limit} bytes")]
    ParamTooLong { index: usize, limit: usize },
    #[error("claim is longer than {limit} characters")]
    ClaimTooLong { limit: usize },
    #[error("`{0}` is not standard padded base64")]
    MalformedBase64(&'static str),
    #[error("`{value}` is not a value of rating member `{member}`")]
    MalformedRating { member: &'static str, value: String },
    #[error("`{0}` is not a hash, like sha256:<64 lower-case hex digits>")]
    MalformedHash(String),
    #[error("signature is not an armoured SSH signature")]
    MalformedSignature,
    #[error("the call inside the request is refused: {0}")]
    InnerCall(Box<ParseError>),
}
