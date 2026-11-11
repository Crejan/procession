//! The rules a call must pass before anything else happens. They are the
//! ones `diag-tools` keeps (`dispatch.py`), and they are pure: no I/O, so
//! each can be tested alone.

/// How many arguments a call may carry.
pub const ARG_MAX: usize = p_act::limits::MAX_PARAMS;
/// How long one argument may be, in bytes.
pub const ARG_LEN_MAX: usize = p_act::limits::MAX_PARAM_BYTES;
/// How long an identity (the login that called through sudo) may be. A login
/// is at most 32 on Linux; `diag-tools` had no limit, and the name becomes a
/// file name.
pub const IDENTITY_LEN_MAX: usize = 32;

/// `[a-z][a-z0-9-]*`: what a noun, a verb and an identity look like.
#[must_use]
pub fn is_token(word: &str) -> bool {
    let mut chars = word.chars();
    matches!(chars.next(), Some('a'..='z')) && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-'))
}

/// What an argument may be made of. No space, quote, backtick, semicolon,
/// ampersand or control character; the rest of ASCII punctuation that a
/// `key=value` or a pattern needs is in. There is no shell to read them, the
/// class only keeps a later reader (a log, a dialog) honest.
fn is_argument_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "]_.,:/=+@%^$*?!~|(){}<>[\\-".contains(c)
}

/// The argument class as a regular expression for a tool's schema, **derived
/// from [`is_argument_char`]** so that the two cannot differ.
#[must_use]
pub fn argument_pattern() -> String {
    let mut class = String::new();
    for c in '!'..='~' {
        if is_argument_char(c) {
            if matches!(c, '\\' | ']' | '[' | '^' | '-') {
                class.push('\\');
            }
            class.push(c);
        }
    }
    format!("^[{class}]+$")
}

/// Why an argument is refused, or `Ok`.
///
/// # Errors
/// A short reason when the argument is empty, too long, starts with `-`
/// (options are `key=value`) or holds a character outside the class.
pub fn check_argument(arg: &str) -> Result<(), &'static str> {
    if arg.is_empty() {
        Err("empty argument")
    } else if arg.len() > ARG_LEN_MAX {
        Err("argument too long")
    } else if !arg.chars().all(is_argument_char) {
        Err("bad argument")
    } else if arg.starts_with('-') {
        Err("argument starts with -; options are key=value")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens() {
        for good in ["sys", "kit", "a", "nfs-client", "a1-2"] {
            assert!(is_token(good), "{good}");
        }
        for bad in ["", "Sys", "1a", "-a", "a_b", "a b", "a/b", "a\n", "ä", "a."] {
            assert!(!is_token(bad), "{bad:?}");
        }
    }

    #[test]
    fn arguments_that_a_key_value_or_a_pattern_needs() {
        for good in
            ["pid=4711", "unit=ssh.service", "grep=a|b", "p=(x){2}", "t=[0-9]+", "a\\sb", "@host", "50%", "x=1,2:3/4"]
        {
            assert_eq!(check_argument(good), Ok(()), "{good}");
        }
    }

    #[test]
    fn arguments_a_shell_or_a_log_line_would_mistake() {
        for bad in ["a b", "a;b", "a&b", "`x`", "a'b", "a\"b", "a\nb", "a\tb", "a\0b", "é", "a\u{202e}b", "#x", "a#"] {
            assert_eq!(check_argument(bad), Err("bad argument"), "{bad:?}");
        }
        assert_eq!(check_argument(""), Err("empty argument"));
    }

    #[test]
    fn no_argument_starts_with_a_dash() {
        for bad in ["-x", "--help", "-", "-5"] {
            assert!(check_argument(bad).is_err(), "{bad}");
        }
        assert_eq!(check_argument("key=-5"), Ok(()));
    }

    #[test]
    fn the_schema_pattern_is_the_class_and_nothing_else() {
        let pattern = argument_pattern();
        let class = pattern.strip_prefix("^[").and_then(|p| p.strip_suffix("]+$")).unwrap();
        let mut members = Vec::new();
        let mut chars = class.chars();
        while let Some(c) = chars.next() {
            members.push(if c == '\\' { chars.next().unwrap() } else { c });
        }
        for c in (0u8..=127).map(char::from) {
            assert_eq!(members.contains(&c), is_argument_char(c) && c != ' ' && !c.is_control(), "{c:?}");
        }
    }

    #[test]
    fn an_argument_is_at_most_512_bytes() {
        assert_eq!(check_argument(&"a".repeat(ARG_LEN_MAX)), Ok(()));
        assert_eq!(check_argument(&"a".repeat(ARG_LEN_MAX + 1)), Err("argument too long"));
    }
}
