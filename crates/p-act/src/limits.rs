//! The numbers several programs must agree on, in one place. Each is the
//! documents' (`approvals.md` section 7, `approval-formats.md` section 2,
//! `approval-connections.md` section 3.1); the programs use these and not a copy.

/// A call is at most this many bytes.
pub const MAX_CALL_BYTES: usize = crate::call::MAX_BYTES;
/// A request is at most this many bytes.
pub const MAX_REQUEST_BYTES: usize = crate::request::MAX_BYTES;
/// A clearance is at most this many bytes.
pub const MAX_CLEARANCE_BYTES: usize = crate::clearance::MAX_BYTES;
/// A line of the exchange is at most this many bytes, `\n` not counted.
pub const MAX_EXCHANGE_LINE_BYTES: usize = crate::exchange::MAX_LINE;
/// At most this many parameters in a call.
pub const MAX_PARAMS: usize = crate::call::MAX_PARAMS;
/// Each parameter is at most this many bytes.
pub const MAX_PARAM_BYTES: usize = crate::call::MAX_PARAM_BYTES;
/// All parameters of a call together can be shown up to this many characters (not bytes): `Call::showable`.
pub const MAX_PARAMS_SHOWN_CHARS: usize = crate::call::MAX_PARAMS_SHOWN_CHARS;
/// A claim is at most this many characters.
pub const MAX_CLAIM_CHARS: usize = crate::call::MAX_CLAIM_CHARS;

/// The furthest ahead a call's deadline may be when a program first sees it: 10 minutes (R7). It is also
/// the longest `deadline_seconds` of an agent's bundle.
pub const MAX_DEADLINE_AHEAD_SECONDS: i64 = 600;
/// The tolerated difference between two clocks: 60 seconds. It is applied only where a bound is set on
/// how far ahead a deadline may be, and never extends a deadline (`approval-connections.md` 3.6).
pub const CLOCK_TOLERANCE_SECONDS: i64 = 60;
/// A service accepts a clearance for this long after its `at`.
pub const CLEARANCE_VALID_SECONDS: i64 = 60;
/// A delegation is valid for this long by default: 8 hours.
pub const DEFAULT_DELEGATION_SECONDS: i64 = 8 * 3600;
/// A delegation is valid for at most this long: 24 hours.
pub const MAX_DELEGATION_SECONDS: i64 = 24 * 3600;
/// An agent's bundle is at most this many bytes, counted over the whole of what is read from standard input.
pub const MAX_BUNDLE_BYTES: usize = 64 * 1024;
