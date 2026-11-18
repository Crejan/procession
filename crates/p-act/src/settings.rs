//! Reading a program's settings file, the one way for `pledge`, `probe`, `page` and `pact`'s siblings:
//! **one JSON object**, **no unknown member**, and **a file that nobody but its owner (and root) can
//! write**.
//!
//! - *One object*: the file is one JSON object and nothing else: no array, no second value, no trailing
//!   text, no byte order mark. A member that appears twice at the top is refused (`serde` alone would keep
//!   the last).
//! - *No unknown member*: this function cannot know the members, so the caller's type must say so:
//!   `#[serde(deny_unknown_fields)]` on it and on every struct inside it (a type that does not would
//!   let an unknown member through, and nothing here can tell). The error then is
//!   [`SettingsError::Invalid`], with `serde`'s text, which names the member and holds no value.
//! - *Who can write it*: the file is opened first and the checks are on the open file (no gap between the
//!   check and the read). It must be a regular file, owned by root or by the user running the program, with
//!   no group or other write permission. A file somebody else can replace or edit is a way to change what a
//!   program that runs with more rights does. (The directory it is in matters as much; this function does
//!   not look at it. Access control lists are not looked at either.)

use crate::error::ParseError;
use crate::object::Object;
use serde::de::DeserializeOwned;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use thiserror::Error;

/// A settings file is at most this long unless the caller says otherwise.
pub const DEFAULT_MAX_BYTES: u64 = 1024 * 1024;

/// Why a settings file was refused. Never holds the file's content.
#[derive(Debug, Error)]
pub enum SettingsError {
    /// There is no such file (or a directory on the way is missing): for the caller to decide what that means
    /// (an empty configuration, "none", or an error), without looking at an I/O error's kind.
    #[error("{0} does not exist")]
    NotFound(String),
    #[error("cannot read {path}: {source}")]
    Io { path: String, source: std::io::Error },
    #[error("{0} is not a regular file")]
    NotARegularFile(String),
    #[error("{path} can be written by someone other than its owner (mode {mode:04o}); a settings file must not be writable by its group or by others: run `chmod 600 {}`", shell_quote(.path))]
    WritableByOthers { path: String, mode: u32 },
    #[error("{path} is owned by user {uid}, who is neither root nor the user running this program; a settings file must be owned by root or by the user that runs the program: as root, run `chown <that user> {}`", shell_quote(.path))]
    WrongOwner { path: String, uid: u32 },
    #[error("{0} is larger than the limit")]
    TooLarge(String),
    #[error("not one JSON object: {0}")]
    NotAnObject(ParseError),
    #[error("the file has a byte order mark")]
    ByteOrderMark,
    #[error("the file is not UTF-8")]
    NotUtf8,
    #[error("{0}")]
    Invalid(String),
}

/// `path` as one word for a shell, for the remedy in a message: left alone if it has only safe characters, else in
/// single quotes. It is the caller's own argument, never a value from the file.
fn shell_quote(path: &str) -> String {
    if !path.is_empty()
        && path.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(b, b'/' | b'.' | b'_' | b'-' | b'+' | b',' | b':' | b'@' | b'%' | b'=')
        })
    {
        path.to_owned()
    } else {
        format!("'{}'", path.replace('\'', "'\\''"))
    }
}

/// Whether a file with this owner and mode may be trusted by a program running as `euid`: owned by root
/// or by `euid`, and not writable by its group or by others.
pub fn check_owner_and_mode(path: &str, uid: u32, mode: u32, euid: u32) -> Result<(), SettingsError> {
    if mode & 0o022 != 0 {
        return Err(SettingsError::WritableByOthers { path: path.to_owned(), mode: mode & 0o7777 });
    }
    if uid != 0 && uid != euid {
        return Err(SettingsError::WrongOwner { path: path.to_owned(), uid });
    }
    Ok(())
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` has no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

/// Read the settings file at `path` into `T`, with the rules above and at most `max_bytes`.
pub fn read_limited<T: DeserializeOwned>(path: &Path, max_bytes: u64) -> Result<T, SettingsError> {
    let shown = path.display().to_string();
    let io = |source| SettingsError::Io { path: shown.clone(), source };
    let file = File::open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound { SettingsError::NotFound(shown.clone()) } else { io(e) }
    })?;
    let meta = file.metadata().map_err(io)?;
    if !meta.is_file() {
        return Err(SettingsError::NotARegularFile(shown));
    }
    check_owner_and_mode(&shown, meta.uid(), meta.permissions().mode(), effective_uid())?;
    let mut bytes = Vec::new();
    file.take(max_bytes + 1).read_to_end(&mut bytes).map_err(io)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(SettingsError::TooLarge(shown));
    }
    parse(&bytes)
}

/// As [`read`], but a file that does not exist is `Ok(None)`. Every other problem, a file that is there and
/// refused included, is an error: only absence is not.
pub fn read_optional<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, SettingsError> {
    match read(path) {
        Ok(v) => Ok(Some(v)),
        Err(SettingsError::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// [`read_limited`] with [`DEFAULT_MAX_BYTES`].
pub fn read<T: DeserializeOwned>(path: &Path) -> Result<T, SettingsError> {
    read_limited(path, DEFAULT_MAX_BYTES)
}

/// The same reading of a document that is already in memory (for tests, and for a file read some other way).
pub fn parse<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, SettingsError> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(SettingsError::ByteOrderMark);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| SettingsError::NotUtf8)?;
    // One object, nothing after it, no member twice at the top.
    Object::parse(text, "").map_err(SettingsError::NotAnObject)?;
    serde_json::from_str(text).map_err(|e| SettingsError::Invalid(describe(&e)))
}

/// What is wrong, without any value from the file: `serde` writes the offending value into some messages
/// (`invalid type: string "..."`), and a settings file may hold a secret. Names of members are kept (they are
/// the caller's own, or what tells a person which one to remove); values are not.
fn describe(e: &serde_json::Error) -> String {
    let message = e.to_string();
    let first = message.split(" at line ").next().unwrap_or("");
    let names_only = ["unknown field `", "missing field `", "duplicate field `"].iter().any(|p| first.starts_with(p));
    if names_only {
        format!("{first} at line {} column {}", e.line(), e.column())
    } else {
        format!("a value of the wrong kind or out of range at line {} column {}", e.line(), e.column())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::io::Write;

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Strict {
        listen: String,
        #[serde(default)]
        limit: u32,
        #[serde(default)]
        inner: Option<Inner>,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(deny_unknown_fields)]
    struct Inner {
        a: u8,
    }

    fn write(dir: &Path, name: &str, text: &[u8], mode: u32) -> std::path::PathBuf {
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        File::create(&path).unwrap().write_all(text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    #[test]
    fn a_good_file_is_read() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o600, 0o644, 0o640, 0o400, 0o444] {
            let p = write(dir.path(), "s.json", br#"{"listen":"127.0.0.1:1","limit":5,"inner":{"a":1}}"#, mode);
            assert_eq!(
                read::<Strict>(&p).unwrap(),
                Strict { listen: "127.0.0.1:1".into(), limit: 5, inner: Some(Inner { a: 1 }) },
                "{mode:o}"
            );
        }
        // Whitespace and a trailing newline are fine.
        let p = write(dir.path(), "n.json", b"{\n  \"listen\": \"x\"\n}\n", 0o600);
        assert_eq!(read::<Strict>(&p).unwrap().listen, "x");
    }

    #[test]
    fn a_file_others_can_write_is_refused_before_it_is_read() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o660, 0o620, 0o666, 0o602, 0o662, 0o777, 0o664, 0o646] {
            let p = write(dir.path(), "w.json", br#"{"listen":"x"}"#, mode);
            match read::<Strict>(&p) {
                Err(SettingsError::WritableByOthers { mode: m, .. }) => assert_eq!(m, mode, "{mode:o}"),
                other => panic!("{mode:o}: {other:?}"),
            }
        }
        // The check does not look at the content: a file that is not even JSON gets the permission error first.
        let p = write(dir.path(), "junk", b"not json", 0o666);
        assert!(matches!(read::<Strict>(&p), Err(SettingsError::WritableByOthers { .. })));
    }

    #[test]
    fn the_owner_rule() {
        // root's files, and the running user's, are fine; anyone else's is not.
        assert!(check_owner_and_mode("f", 0, 0o644, 1000).is_ok());
        assert!(check_owner_and_mode("f", 1000, 0o600, 1000).is_ok());
        assert!(check_owner_and_mode("f", 0, 0o600, 0).is_ok());
        assert!(matches!(
            check_owner_and_mode("f", 1001, 0o600, 1000),
            Err(SettingsError::WrongOwner { uid: 1001, .. })
        ));
        assert!(
            matches!(check_owner_and_mode("f", 1000, 0o600, 0), Err(SettingsError::WrongOwner { uid: 1000, .. })),
            "a root process does not trust a file of an ordinary user"
        );
        // The mode is checked first, and the set-id and sticky bits are not write bits.
        assert!(matches!(check_owner_and_mode("f", 1001, 0o666, 1000), Err(SettingsError::WritableByOthers { .. })));
        assert!(check_owner_and_mode("f", 0, 0o4755, 1000).is_ok());
        assert!(check_owner_and_mode("f", 0, 0o1644, 1000).is_ok());
    }

    #[test]
    fn a_root_owned_file_of_the_system_passes_the_owner_check() {
        // /etc/hosts is owned by root and not writable by others on macOS and Linux: it gets as far as the content.
        let r = read::<Strict>(Path::new("/etc/hosts"));
        assert!(matches!(r, Err(SettingsError::NotAnObject(_))), "{r:?}");
    }

    #[test]
    fn what_is_not_a_regular_file_or_not_there_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(read::<Strict>(dir.path()), Err(SettingsError::NotARegularFile(_))));
        assert!(matches!(read::<Strict>(&dir.path().join("nothing")), Err(SettingsError::NotFound(_))));
        assert!(matches!(read::<Strict>(Path::new("/dev/null")), Err(SettingsError::NotARegularFile(_))));
    }

    #[test]
    fn one_object_and_nothing_else() {
        for (text, label) in [
            (&b"[]"[..], "array"),
            (b"null", "null"),
            (b"1", "number"),
            (b"\"x\"", "string"),
            (b"", "empty"),
            (b"{", "truncated"),
            (br#"{"listen":"x"} {"listen":"y"}"#, "two objects"),
            (br#"{"listen":"x"} junk"#, "trailing text"),
            (br#"{"listen":"x","listen":"y"}"#, "a member twice"),
        ] {
            let r = parse::<Strict>(text);
            assert!(matches!(r, Err(SettingsError::NotAnObject(_))), "{label}: {r:?}");
        }
        assert!(matches!(
            parse::<Strict>(&[&[0xEF, 0xBB, 0xBF][..], br#"{"listen":"x"}"#].concat()),
            Err(SettingsError::ByteOrderMark)
        ));
        assert!(matches!(parse::<Strict>(&[0xff, 0xfe]), Err(SettingsError::NotUtf8)));
    }

    #[test]
    fn the_callers_type_refuses_unknown_members_and_wrong_types() {
        for text in [
            r#"{"listen":"x","extra":1}"#,
            r#"{"listen":"x","inner":{"a":1,"b":2}}"#,
            r#"{"limit":1}"#,
            r#"{"listen":5}"#,
            r#"{"listen":"x","limit":-1}"#,
            r#"{"listen":"x","limit":"1"}"#,
        ] {
            assert!(matches!(parse::<Strict>(text.as_bytes()), Err(SettingsError::Invalid(_))), "{text}");
        }
    }

    #[test]
    fn the_size_limit_is_counted_over_what_is_read() {
        let dir = tempfile::tempdir().unwrap();
        let body = format!(r#"{{"listen":"{}"}}"#, "a".repeat(100));
        let p = write(dir.path(), "big.json", body.as_bytes(), 0o600);
        assert!(read_limited::<Strict>(&p, body.len() as u64).is_ok());
        assert!(matches!(read_limited::<Strict>(&p, body.len() as u64 - 1), Err(SettingsError::TooLarge(_))));
        let junk = write(dir.path(), "junk.json", &vec![b' '; 3000], 0o600);
        assert!(matches!(read_limited::<Strict>(&junk, 1000), Err(SettingsError::TooLarge(_))));
    }

    #[test]
    fn errors_do_not_hold_the_content() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "s.json", br#"{"listen":"hunter2-secret","extra":"hunter2-secret"}"#, 0o600);
        let shown = format!("{}", read::<Strict>(&p).unwrap_err());
        assert!(!shown.contains("hunter2"), "{shown}");
        let wrong = parse::<Strict>(br#"{"listen":"x","limit":"hunter2-secret"}"#).unwrap_err().to_string();
        assert!(!wrong.contains("hunter2") && wrong.contains("line 1"), "{wrong}");
        let unknown = parse::<Strict>(br#"{"listen":"x","extra_member":"hunter2-secret"}"#).unwrap_err().to_string();
        assert!(unknown.contains("extra_member") && !unknown.contains("hunter2"), "{unknown}");
        let dup = parse::<Strict>(br#"{"listen":"hunter2-secret","listen":"x"}"#).unwrap_err().to_string();
        assert!(!dup.contains("hunter2"), "{dup}");
    }

    #[test]
    fn a_missing_file_is_told_apart_and_only_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nothing.json");
        assert!(matches!(read::<Strict>(&missing), Err(SettingsError::NotFound(p)) if p.ends_with("nothing.json")));
        assert!(
            matches!(read::<Strict>(&dir.path().join("no-dir").join("s.json")), Err(SettingsError::NotFound(_))),
            "a missing directory on the way"
        );
        assert!(matches!(read_limited::<Strict>(&missing, 10), Err(SettingsError::NotFound(_))));
        assert!(matches!(read_optional::<Strict>(&missing), Ok(None)));
        // A file that is there is read, or refused, and is never "missing".
        let good = write(dir.path(), "good.json", br#"{"listen":"x"}"#, 0o600);
        assert_eq!(read_optional::<Strict>(&good).unwrap().unwrap().listen, "x");
        let bad_mode = write(dir.path(), "open.json", br#"{"listen":"x"}"#, 0o666);
        assert!(matches!(read_optional::<Strict>(&bad_mode), Err(SettingsError::WritableByOthers { .. })));
        let bad_content = write(dir.path(), "bad.json", b"[]", 0o600);
        assert!(matches!(read_optional::<Strict>(&bad_content), Err(SettingsError::NotAnObject(_))));
        let wrong_type = write(dir.path(), "wrong.json", br#"{"listen":5}"#, 0o600);
        assert!(matches!(read_optional::<Strict>(&wrong_type), Err(SettingsError::Invalid(_))));
        assert!(matches!(read_optional::<Strict>(dir.path()), Err(SettingsError::NotARegularFile(_))));
        // Not being allowed to look is not absence either: a directory without search permission.
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        write(&locked, "s.json", br#"{"listen":"x"}"#, 0o600);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let r = read_optional::<Strict>(&locked.join("s.json"));
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        // (As root the directory is searchable anyway.)
        assert!(matches!(r, Err(SettingsError::Io { .. })) || effective_uid() == 0, "{r:?}");
    }

    #[test]
    fn the_refusals_say_what_to_do() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "s.json", br#"{"listen":"hunter2-secret"}"#, 0o664);
        let text = read::<Strict>(&p).unwrap_err().to_string();
        let path = p.display().to_string();
        assert!(text.contains("can be written by someone other than its owner"), "{text}");
        assert!(text.contains("must not be writable by its group or by others"), "{text}");
        assert!(text.contains(&format!("run `chmod 600 {path}`")), "{text}");
        assert!(text.contains("0664") && !text.contains("hunter2"), "{text}");
        // The owner's case, with the words of before kept in it.
        let text = check_owner_and_mode("/etc/prog/s.json", 1001, 0o600, 1000).unwrap_err().to_string();
        assert!(
            text.contains("is owned by user 1001, who is neither root nor the user running this program"),
            "{text}"
        );
        assert!(
            text.contains("must be owned by root or by the user that runs the program")
                && text.contains("chown <that user> /etc/prog/s.json"),
            "{text}"
        );
        // The path is one word for a shell, whatever it holds.
        let text = check_owner_and_mode("/tmp/it's here/s.json", 0, 0o666, 1000).unwrap_err().to_string();
        assert!(text.contains(r#"chmod 600 '/tmp/it'\''s here/s.json'"#), "{text}");
        assert_eq!(shell_quote("/etc/a-b_c.d/s.json"), "/etc/a-b_c.d/s.json");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("$(x)"), "'$(x)'");
    }
}
