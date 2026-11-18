//! Reading a program's settings file, one way for every program that has one: **a file that nobody but its owner
//! (and root) can write**, of **one object** with **no unknown key** and **no key twice**, within a size limit, and
//! errors that never hold a value from the file.
//!
//! Two classes of file, one strictness:
//!
//! - **JSON**, for programs that speak the approval system's formats, is read by `p-act` (`p_act::settings::read`,
//!   `read_optional`, `parse`), on top of [`read_checked`]: one JSON object and nothing else, no member twice at the top.
//! - **TOML** (`read_toml`, `read_toml_optional`, `parse_toml`; feature `toml`, off by default, which brings `toml` 0.9
//!   and `serde`) for the tools a person configures by hand.
//!
//! What every reader does, in [`read_checked`]:
//!
//! - *Who can write it*: the file is opened first and the checks are on the open file (no gap between the check and
//!   the read). It must be a regular file, owned by root or by the user running the program, with no group or other
//!   write permission. A file somebody else can replace or edit is a way to change what a program that runs with
//!   more rights does. (The directory it is in matters as much; this does not look at it. Access control lists are
//!   not looked at either.)
//! - *No unknown key*: the readers cannot know the keys, so the caller's type must say so:
//!   `#[serde(deny_unknown_fields)]` on it and on every struct inside it (a type that does not would let an unknown
//!   key through, and nothing here can tell). The error then is [`SettingsError::Invalid`], which names the key.
//! - *Values stay out of errors*: `serde` and the parsers write the offending value into some messages
//!   (`invalid type: string "..."`), and a settings file may hold a secret. Errors say what kind of thing is wrong and
//!   where (line and column), and keep the names of keys (the caller's own, or what tells a person which one to remove).

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

/// A settings file is at most this long unless the caller says otherwise.
pub const DEFAULT_MAX_BYTES: u64 = 1024 * 1024;

/// Why a settings file was refused. Never holds the file's content.
#[derive(Debug)]
pub enum SettingsError {
    /// There is no such file (or a directory on the way is missing): for the caller to decide what that means
    /// (an empty configuration, "none", or an error), without looking at an I/O error's kind.
    NotFound(String),
    Io {
        path: String,
        source: std::io::Error,
    },
    NotARegularFile(String),
    WritableByOthers {
        path: String,
        mode: u32,
    },
    WrongOwner {
        path: String,
        uid: u32,
    },
    TooLarge(String),
    /// The JSON file is not one object (what is wrong, without a value).
    NotAnObject(String),
    ByteOrderMark,
    NotUtf8,
    /// A key or value the caller's type does not accept, or syntax that is wrong (what and where, without a value).
    Invalid(String),
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SettingsError::NotFound(path) => write!(f, "{path} does not exist"),
            SettingsError::Io { path, source } => write!(f, "cannot read {path}: {source}"),
            SettingsError::NotARegularFile(path) => write!(f, "{path} is not a regular file"),
            SettingsError::WritableByOthers { path, mode } => write!(
                f,
                "{path} can be written by someone other than its owner (mode {mode:04o}); a settings file must not be writable by its group or by others: run `chmod 600 {}`",
                shell_quote(path)
            ),
            SettingsError::WrongOwner { path, uid } => write!(
                f,
                "{path} is owned by user {uid}, who is neither root nor the user running this program; a settings file must be owned by root or by the user that runs the program: as root, run `chown <that user> {}`",
                shell_quote(path)
            ),
            SettingsError::TooLarge(path) => write!(f, "{path} is larger than the limit"),
            SettingsError::NotAnObject(why) => write!(f, "not one JSON object: {why}"),
            SettingsError::ByteOrderMark => f.write_str("the file has a byte order mark"),
            SettingsError::NotUtf8 => f.write_str("the file is not UTF-8"),
            SettingsError::Invalid(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for SettingsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SettingsError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
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

/// Open `path`, check the open file (a regular file, owned by root or the running user, no group or other write
/// bit) and read at most `max_bytes` of it; more is [`SettingsError::TooLarge`]. A file that does not exist is
/// [`SettingsError::NotFound`]. The content is read only after the checks, and is not looked at here.
pub fn read_checked(path: &Path, max_bytes: u64) -> Result<Vec<u8>, SettingsError> {
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
    Ok(bytes)
}

/// The text of a settings file: no byte order mark, UTF-8.
#[cfg(feature = "toml")]
fn text_of(bytes: &[u8]) -> Result<&str, SettingsError> {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(SettingsError::ByteOrderMark);
    }
    std::str::from_utf8(bytes).map_err(|_| SettingsError::NotUtf8)
}

/// `line L column C` of byte offset `at` in `text` (1-based, columns in characters).
#[cfg(feature = "toml")]
fn position(text: &str, at: usize) -> (usize, usize) {
    let at = at.min(text.len());
    let before = &text[..at];
    let line = before.matches('\n').count() + 1;
    let column = before.rsplit('\n').next().map_or(0, |l| l.chars().count()) + 1;
    (line, column)
}

// --- TOML ------------------------------------------------------------------------------------

/// Read the TOML settings file at `path` into `T`: the same checks on the file as for JSON, then `toml` 0.9 with the
/// caller's type (which refuses unknown keys with `#[serde(deny_unknown_fields)]`; `toml` itself refuses a key given
/// twice and text after the document).
#[cfg(feature = "toml")]
pub fn read_toml_limited<T: serde::de::DeserializeOwned>(path: &Path, max_bytes: u64) -> Result<T, SettingsError> {
    parse_toml(&read_checked(path, max_bytes)?)
}

/// [`read_toml_limited`] with [`DEFAULT_MAX_BYTES`].
#[cfg(feature = "toml")]
pub fn read_toml<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, SettingsError> {
    read_toml_limited(path, DEFAULT_MAX_BYTES)
}

/// As [`read_toml`], but a file that does not exist is `Ok(None)`; every other problem is an error.
#[cfg(feature = "toml")]
pub fn read_toml_optional<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Option<T>, SettingsError> {
    match read_toml(path) {
        Ok(v) => Ok(Some(v)),
        Err(SettingsError::NotFound(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

/// The same reading of a TOML document that is already in memory.
#[cfg(feature = "toml")]
pub fn parse_toml<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, SettingsError> {
    let text = text_of(bytes)?;
    toml::from_str(text).map_err(|e| SettingsError::Invalid(describe_toml(&e, text)))
}

/// What is wrong with a TOML document, without any value from it. `toml`'s own `Display` shows the offending line of
/// the file, so it is never used; its message is kept only where it names keys and not values.
#[cfg(feature = "toml")]
fn describe_toml(e: &toml::de::Error, text: &str) -> String {
    let (line, column) = e.span().map_or((0, 0), |span| position(text, span.start));
    let at = if line == 0 { String::new() } else { format!(" at line {line} column {column}") };
    let message = e.message();
    let names_only = ["unknown field `", "missing field `", "duplicate key `", "duplicate field `", "duplicate key"]
        .iter()
        .any(|p| message.starts_with(p));
    if names_only {
        let first = message.lines().next().unwrap_or("");
        format!("{first}{at}")
    } else {
        format!("a value of the wrong kind or out of range, or syntax that is wrong{at}")
    }
}

#[cfg(all(test, feature = "toml"))]
mod toml_tests {
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
    fn what_toml_does_with_the_cases_that_matter() {
        // Found, not assumed: each of these is refused by `toml` 0.9 itself or by the caller's type.
        for (label, text) in [
            ("a key twice", "listen = \"x\"\nlisten = \"y\"\n"),
            ("a key twice, once dotted", "inner.a = 1\n[inner]\na = 2\n"),
            ("a table twice", "listen = \"x\"\n[inner]\na = 1\n[inner]\na = 2\n"),
            ("trailing garbage", "listen = \"x\"\nthis is not toml\n"),
            ("trailing garbage on the line", "listen = \"x\" oops\n"),
            ("a second document", "listen = \"x\"\n---\nlisten = \"y\"\n"),
            ("an unknown key", "listen = \"x\"\nextra = 1\n"),
            ("an unknown key in a table", "listen = \"x\"\n[inner]\na = 1\nb = 2\n"),
            ("a missing key", "limit = 1\n"),
            ("a wrong type", "listen = 5\n"),
            ("out of range", "listen = \"x\"\nlimit = -1\n"),
            ("an unterminated string", "listen = \"x\n"),
        ] {
            let r = parse_toml::<Strict>(text.as_bytes());
            assert!(matches!(r, Err(SettingsError::Invalid(_))), "{label}: {r:?}");
        }
        // And what it accepts.
        assert_eq!(
            parse_toml::<Strict>(b"listen = \"x\"\nlimit = 5\n[inner]\na = 1\n").unwrap(),
            Strict { listen: "x".into(), limit: 5, inner: Some(Inner { a: 1 }) }
        );
        assert_eq!(parse_toml::<Strict>(b"# a comment\nlisten = 'single'  # another\n").unwrap().listen, "single");
        assert!(parse_toml::<Strict>(b"listen = \"x\"").is_ok(), "no final newline");
    }

    #[test]
    fn a_good_file_is_read_and_the_file_checks_are_the_same_as_for_json() {
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o600, 0o644, 0o640, 0o400] {
            let p = write(dir.path(), "s.toml", b"listen = \"127.0.0.1:1\"\nlimit = 5\n", mode);
            assert_eq!(read_toml::<Strict>(&p).unwrap().limit, 5, "{mode:o}");
        }
        for mode in [0o660, 0o620, 0o666, 0o602, 0o664, 0o646] {
            let p = write(dir.path(), "w.toml", b"listen = \"x\"\n", mode);
            match read_toml::<Strict>(&p) {
                Err(SettingsError::WritableByOthers { mode: m, .. }) => assert_eq!(m, mode),
                other => panic!("{mode:o}: {other:?}"),
            }
        }
        // The check comes before the content is looked at.
        let junk = write(dir.path(), "junk.toml", b"not toml at all", 0o666);
        assert!(matches!(read_toml::<Strict>(&junk), Err(SettingsError::WritableByOthers { .. })));
        assert!(matches!(read_toml::<Strict>(dir.path()), Err(SettingsError::NotARegularFile(_))));
        assert!(matches!(read_toml::<Strict>(Path::new("/dev/null")), Err(SettingsError::NotARegularFile(_))));
        // A root-owned file of the system passes the owner check and fails on content.
        assert!(matches!(read_toml::<Strict>(Path::new("/etc/hosts")), Err(SettingsError::Invalid(_))));
        // The remedy is in the text.
        let text =
            read_toml::<Strict>(&write(dir.path(), "m.toml", b"listen = \"x\"\n", 0o664)).unwrap_err().to_string();
        assert!(
            text.contains("run `chmod 600 ") && text.contains("must not be writable by its group or by others"),
            "{text}"
        );
    }

    #[test]
    fn absence_is_told_apart_and_only_absence() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nothing.toml");
        assert!(matches!(read_toml::<Strict>(&missing), Err(SettingsError::NotFound(_))));
        assert!(matches!(read_toml_optional::<Strict>(&missing), Ok(None)));
        let good = write(dir.path(), "good.toml", b"listen = \"x\"\n", 0o600);
        assert_eq!(read_toml_optional::<Strict>(&good).unwrap().unwrap().listen, "x");
        let bad = write(dir.path(), "bad.toml", b"listen = 5\n", 0o600);
        assert!(matches!(read_toml_optional::<Strict>(&bad), Err(SettingsError::Invalid(_))));
        let open = write(dir.path(), "open.toml", b"listen = \"x\"\n", 0o666);
        assert!(matches!(read_toml_optional::<Strict>(&open), Err(SettingsError::WritableByOthers { .. })));
    }

    #[test]
    fn the_size_limit_bom_and_encoding() {
        let dir = tempfile::tempdir().unwrap();
        let body = format!("listen = \"{}\"\n", "a".repeat(100));
        let p = write(dir.path(), "big.toml", body.as_bytes(), 0o600);
        assert!(read_toml_limited::<Strict>(&p, body.len() as u64).is_ok());
        assert!(matches!(read_toml_limited::<Strict>(&p, body.len() as u64 - 1), Err(SettingsError::TooLarge(_))));
        assert!(matches!(
            parse_toml::<Strict>(&[&[0xEF, 0xBB, 0xBF][..], b"listen = \"x\"\n"].concat()),
            Err(SettingsError::ByteOrderMark)
        ));
        assert!(matches!(parse_toml::<Strict>(&[0xff, 0xfe]), Err(SettingsError::NotUtf8)));
    }

    #[test]
    fn errors_keep_the_names_of_keys_and_never_a_value() {
        let secret = "hunter2-secret";
        let cases = [
            format!("listen = \"x\"\nlimit = \"{secret}\"\n"),
            format!("listen = \"x\"\nextra_key = \"{secret}\"\n"),
            format!("listen = \"x\"\nlisten = \"{secret}\"\n"),
            format!("listen = \"x\"\n[inner]\na = \"{secret}\"\n"),
            format!("listen = \"{secret}\nlimit = 1\n"),
            format!("listen = \"x\" {secret}\n"),
            format!("{secret}\n"),
            format!("[inner]\nb = \"{secret}\"\n"),
        ];
        for text in &cases {
            let shown = parse_toml::<Strict>(text.as_bytes()).unwrap_err().to_string();
            assert!(!shown.contains("hunter2"), "{text:?} -> {shown}");
            assert!(!shown.contains('\n'), "one line: {shown}");
        }
        // The names are kept, with where.
        let unknown = parse_toml::<Strict>(format!("listen = \"x\"\nextra_key = \"{secret}\"\n").as_bytes())
            .unwrap_err()
            .to_string();
        assert!(unknown.contains("extra_key") && unknown.contains("line 2"), "{unknown}");
        let missing = parse_toml::<Strict>(b"limit = 1\n").unwrap_err().to_string();
        assert!(missing.contains("listen"), "{missing}");
        let twice = parse_toml::<Strict>(format!("listen = \"x\"\nlisten = \"{secret}\"\n").as_bytes())
            .unwrap_err()
            .to_string();
        assert!(twice.contains("line 2"), "{twice}");
        let wrong =
            parse_toml::<Strict>(format!("listen = \"x\"\nlimit = \"{secret}\"\n").as_bytes()).unwrap_err().to_string();
        assert!(wrong.contains("line 2") && wrong.contains("wrong kind"), "{wrong}");
        // From a file, too: the error is the same and the path is the caller's own.
        let dir = tempfile::tempdir().unwrap();
        let p = write(dir.path(), "s.toml", format!("listen = \"x\"\nlimit = \"{secret}\"\n").as_bytes(), 0o600);
        assert!(!read_toml::<Strict>(&p).unwrap_err().to_string().contains("hunter2"));
    }
}

#[cfg(test)]
mod core_tests {
    use super::*;
    use std::io::Write;

    fn write(dir: &Path, name: &str, text: &[u8], mode: u32) -> std::path::PathBuf {
        let path = dir.join(name);
        let _ = std::fs::remove_file(&path);
        File::create(&path).unwrap().write_all(text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    // The tests of the checks, on bytes: no parsing. Each of the programs' readers sits on `read_checked`.

    #[test]
    fn a_good_file_is_read_as_bytes() {
        let guard = tempfile::tempdir().unwrap();
        let dir = guard.path().to_path_buf();
        for mode in [0o600, 0o644, 0o640, 0o400, 0o444] {
            let p = write(&dir, "s", b"content", mode);
            assert_eq!(read_checked(&p, DEFAULT_MAX_BYTES).unwrap(), b"content", "{mode:o}");
        }
        assert_eq!(read_checked(&write(&dir, "empty", b"", 0o600), 10).unwrap(), b"");
    }

    #[test]
    fn a_file_others_can_write_is_refused_before_it_is_read() {
        let guard = tempfile::tempdir().unwrap();
        let dir = guard.path().to_path_buf();
        for mode in [0o660, 0o620, 0o666, 0o602, 0o662, 0o777, 0o664, 0o646] {
            let p = write(&dir, "w", b"content", mode);
            match read_checked(&p, 100) {
                Err(SettingsError::WritableByOthers { mode: m, .. }) => assert_eq!(m, mode, "{mode:o}"),
                other => panic!("{mode:o}: {other:?}"),
            }
        }
    }

    #[test]
    fn the_owner_rule() {
        assert!(check_owner_and_mode("f", 0, 0o644, 1000).is_ok());
        assert!(check_owner_and_mode("f", 1000, 0o600, 1000).is_ok());
        assert!(check_owner_and_mode("f", 0, 0o600, 0).is_ok());
        assert!(matches!(
            check_owner_and_mode("f", 1001, 0o600, 1000),
            Err(SettingsError::WrongOwner { uid: 1001, .. })
        ));
        assert!(matches!(check_owner_and_mode("f", 1000, 0o600, 0), Err(SettingsError::WrongOwner { uid: 1000, .. })));
        assert!(matches!(check_owner_and_mode("f", 1001, 0o666, 1000), Err(SettingsError::WritableByOthers { .. })));
        assert!(check_owner_and_mode("f", 0, 0o4755, 1000).is_ok());
        assert!(check_owner_and_mode("f", 0, 0o1644, 1000).is_ok());
    }

    #[test]
    fn what_is_not_a_regular_file_or_not_there_is_refused_and_absence_is_told_apart() {
        let guard = tempfile::tempdir().unwrap();
        let dir = guard.path().to_path_buf();
        assert!(matches!(read_checked(&dir, 10), Err(SettingsError::NotARegularFile(_))));
        assert!(matches!(read_checked(Path::new("/dev/null"), 10), Err(SettingsError::NotARegularFile(_))));
        assert!(
            matches!(read_checked(&dir.join("nothing"), 10), Err(SettingsError::NotFound(p)) if p.ends_with("nothing"))
        );
        assert!(matches!(read_checked(&dir.join("no-dir").join("x"), 10), Err(SettingsError::NotFound(_))));
        // A root-owned system file passes the owner check.
        assert!(read_checked(Path::new("/etc/hosts"), DEFAULT_MAX_BYTES).is_ok());
    }

    #[test]
    fn the_size_limit_is_counted_over_what_is_read() {
        let guard = tempfile::tempdir().unwrap();
        let dir = guard.path().to_path_buf();
        let body = vec![b'a'; 100];
        let p = write(&dir, "big", &body, 0o600);
        assert_eq!(read_checked(&p, 100).unwrap().len(), 100);
        assert!(matches!(read_checked(&p, 99), Err(SettingsError::TooLarge(_))));
        assert!(matches!(
            read_checked(&write(&dir, "junk", &[b' '; 3000], 0o600), 1000),
            Err(SettingsError::TooLarge(_))
        ));
    }

    #[test]
    fn the_refusals_say_what_to_do() {
        let guard = tempfile::tempdir().unwrap();
        let dir = guard.path().to_path_buf();
        let p = write(&dir, "s", b"hunter2-secret", 0o664);
        let text = read_checked(&p, 100).unwrap_err().to_string();
        let path = p.display().to_string();
        assert!(text.contains("can be written by someone other than its owner"), "{text}");
        assert!(text.contains("must not be writable by its group or by others"), "{text}");
        assert!(text.contains(&format!("run `chmod 600 {path}`")), "{text}");
        assert!(text.contains("0664") && !text.contains("hunter2"), "{text}");
        let text = check_owner_and_mode("/etc/prog/s", 1001, 0o600, 1000).unwrap_err().to_string();
        assert!(
            text.contains("is owned by user 1001, who is neither root nor the user running this program"),
            "{text}"
        );
        assert!(
            text.contains("must be owned by root or by the user that runs the program")
                && text.contains("chown <that user> /etc/prog/s"),
            "{text}"
        );
        let text = check_owner_and_mode("/tmp/it's here/s", 0, 0o666, 1000).unwrap_err().to_string();
        assert!(text.contains(r#"chmod 600 '/tmp/it'\''s here/s'"#), "{text}");
        assert_eq!(shell_quote("/etc/a-b_c.d/s"), "/etc/a-b_c.d/s");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("$(x)"), "'$(x)'");
    }

    #[test]
    fn errors_are_errors_with_a_source_where_there_is_one() {
        let e: Box<dyn std::error::Error> = Box::new(SettingsError::TooLarge("f".into()));
        assert_eq!(e.to_string(), "f is larger than the limit");
        let io = SettingsError::Io { path: "f".into(), source: std::io::Error::other("boom") };
        assert!(std::error::Error::source(&io).is_some());
        assert!(std::error::Error::source(&SettingsError::NotFound("f".into())).is_none());
    }
}
