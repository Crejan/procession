//! JSON that is signed, checked or decided on is read **strictly**: an object with a repeated key is refused, at every
//! depth, and neither the first nor the last is taken. `serde_json` alone keeps the last (and `RawValue`, a derived
//! struct's fields and `HashMap`s each do their own thing), so a second reader of the same bytes, in another language,
//! could see a different member than this one: the rule is reader strictness, one reader for everyone.
//!
//! - [`parse`] gives a [`serde_json::Value`] that has no repeated key anywhere;
//! - [`check`] only checks (use it before a typed `serde` read, so that maps and flattened members are covered too);
//! - [`from_str`] and [`from_slice`] are `check` and then the typed read.
//!
//! Errors say where (the path of the member: `a.b[2].c`), never what (no value from the document is repeated), and a
//! name in a path is escaped and bounded like every text from outside.

use serde::de::{DeserializeOwned, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::cell::RefCell;
use std::fmt;

/// The longest path an error carries, in characters (names inside are escaped and cut first).
pub const MAX_PATH_CHARS: usize = 200;
const MAX_NAME_CHARS: usize = 64;

/// Why a document was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JsonError {
    /// An object has a key twice. `path` is where: the keys and indexes down to the object, then the repeated key
    /// (`services[0].host`); empty is not possible (the repeated key is always the last part).
    DuplicateKey { path: String },
    /// Not JSON, or not the shape asked for: what and where, without a value (the position, not the text).
    Invalid { line: usize, column: usize },
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            JsonError::DuplicateKey { path } => write!(f, "the key `{path}` appears twice in an object"),
            JsonError::Invalid { line, column } => {
                write!(f, "not valid JSON, or not of the form expected, at line {line} column {column}")
            }
        }
    }
}

impl std::error::Error for JsonError {}

/// Where the walk is, for a path in an error.
#[derive(Default)]
struct Walk {
    path: RefCell<Vec<String>>,
    found: RefCell<Option<String>>,
}

impl Walk {
    fn here(&self, last: &str) -> String {
        let mut out = String::new();
        for part in self.path.borrow().iter() {
            if !part.starts_with('[') && !out.is_empty() {
                out.push('.');
            }
            out.push_str(part);
        }
        if !out.is_empty() {
            out.push('.');
        }
        out.push_str(&crate::text::escape_clipped(last, MAX_NAME_CHARS).text);
        crate::text::escape_clipped(&out, MAX_PATH_CHARS).text
    }
}

struct ValueSeed<'w>(&'w Walk);

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(ValueVisitor(self.0))
    }
}

struct ValueVisitor<'w>(&'w Walk);

impl<'de> Visitor<'de> for ValueVisitor<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Value, E> {
        Ok(v.into())
    }

    fn visit_u64<E>(self, v: u64) -> Result<Value, E> {
        Ok(v.into())
    }

    fn visit_f64<E>(self, v: f64) -> Result<Value, E> {
        Ok(serde_json::Number::from_f64(v).map_or(Value::Null, Value::Number))
    }

    fn visit_str<E>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_owned()))
    }

    fn visit_string<E>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_none<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        loop {
            self.0.path.borrow_mut().push(format!("[{}]", items.len()));
            let next = seq.next_element_seed(ValueSeed(self.0));
            self.0.path.borrow_mut().pop();
            match next? {
                Some(item) => items.push(item),
                None => return Ok(Value::Array(items)),
            }
        }
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut members = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if members.contains_key(&key) {
                *self.0.found.borrow_mut() = Some(self.0.here(&key));
                return Err(serde::de::Error::custom("duplicate key"));
            }
            self.0.path.borrow_mut().push(key.clone());
            let value = map.next_value_seed(ValueSeed(self.0));
            self.0.path.borrow_mut().pop();
            members.insert(key, value?);
        }
        Ok(Value::Object(members))
    }
}

fn invalid(e: &serde_json::Error) -> JsonError {
    JsonError::Invalid { line: e.line(), column: e.column() }
}

fn walked(text: &str) -> Result<Value, JsonError> {
    let walk = Walk::default();
    let mut de = serde_json::Deserializer::from_str(text);
    let result = ValueSeed(&walk).deserialize(&mut de).and_then(|v| de.end().map(|()| v));
    match result {
        Ok(value) => Ok(value),
        Err(error) => match walk.found.into_inner() {
            Some(path) => Err(JsonError::DuplicateKey { path }),
            None => Err(invalid(&error)),
        },
    }
}

/// `text` as a [`Value`], refusing a repeated key at any depth (and text after the value).
pub fn parse(text: &str) -> Result<Value, JsonError> {
    walked(text)
}

/// [`parse`] for bytes (which must be UTF-8).
pub fn parse_slice(bytes: &[u8]) -> Result<Value, JsonError> {
    walked(std::str::from_utf8(bytes).map_err(|_| JsonError::Invalid { line: 0, column: 0 })?)
}

/// Whether `text` is JSON with no repeated key anywhere; nothing is kept.
pub fn check(text: &str) -> Result<(), JsonError> {
    walked(text).map(drop)
}

/// `text` as a `T`, after [`check`]: so a repeated key is refused even where `T` would not notice it (a map, a flattened
/// member, a `Value`).
pub fn from_str<T: DeserializeOwned>(text: &str) -> Result<T, JsonError> {
    check(text)?;
    T::deserialize(&mut serde_json::Deserializer::from_str(text)).map_err(|e| invalid(&e))
}

/// [`from_str`] for bytes.
pub fn from_slice<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, JsonError> {
    from_str(std::str::from_utf8(bytes).map_err(|_| JsonError::Invalid { line: 0, column: 0 })?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::HashMap;

    #[test]
    fn a_repeated_key_is_refused_at_every_depth_and_the_error_says_where() {
        for (text, path) in [
            (r#"{"a":1,"a":2}"#, "a"),
            (r#"{"a":{"b":1,"b":2}}"#, "a.b"),
            (r#"{"a":[{"x":1},{"y":1,"y":2}]}"#, "a[1].y"),
            (r#"{"a":[[{"k":1,"k":1}]]}"#, "a[0][0].k"),
            (r#"{"a":{"b":{"c":{"d":1,"d":1}}}}"#, "a.b.c.d"),
            (r#"[{"a":1,"a":2}]"#, "[0].a"),
            (r#"{"a":1,"b":2,"a":3}"#, "a"),
            // Equal values or different, equal keys once escapes are read.
            (r#"{"a":1,"a":1}"#, "a"),
            (r#"{"":1,"":2}"#, ""),
        ] {
            assert_eq!(parse(text), Err(JsonError::DuplicateKey { path: path.into() }), "{text}");
            assert_eq!(check(text), parse(text).map(drop), "{text}");
            assert_eq!(from_str::<Value>(text), Err(JsonError::DuplicateKey { path: path.into() }), "{text}");
        }
    }

    #[test]
    fn without_a_repeated_key_it_is_serde_jsons_value() {
        for text in [
            "null",
            "true",
            "1",
            "-0.5",
            "1e3",
            r#""x""#,
            "[]",
            "{}",
            r#"{"a":[1,2,{"b":null}],"c":{"d":"e"}}"#,
            r#"{"a":1,"b":{"a":2},"c":[{"a":3}]}"#,
        ] {
            assert_eq!(parse(text).unwrap(), serde_json::from_str::<Value>(text).unwrap(), "{text}");
        }
        // The same key in different objects, or at different depths, is fine.
        assert!(check(r#"{"a":{"a":{"a":1}},"b":[{"a":1},{"a":2}]}"#).is_ok());
    }

    #[test]
    fn what_is_not_json_is_invalid_with_a_position_and_never_a_value() {
        for text in [
            "",
            "{",
            r#"{"a":}"#,
            r#"{"a":1} SECRET"#,
            r#"{"a":1}{"a":2}"#,
            "nul",
            r#"{"a" 1}"#,
            "[1,]",
            "{\"a\":SECRET}",
        ] {
            let e = parse(text).unwrap_err();
            assert!(matches!(e, JsonError::Invalid { .. }), "{text}: {e:?}");
            assert!(!e.to_string().contains("SECRET"));
        }
        assert!(matches!(parse_slice(&[0xff]), Err(JsonError::Invalid { .. })));
        assert_eq!(parse_slice(b"{\"a\":1}").unwrap(), serde_json::json!({"a": 1}));
    }

    #[test]
    fn the_typed_read_covers_maps_and_flattened_members_that_serde_alone_does_not() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct Inner {
            a: u8,
        }
        #[derive(Debug, Deserialize, PartialEq)]
        struct Outer {
            map: HashMap<String, u8>,
            inner: Inner,
        }
        let text = r#"{"map":{"k":1,"k":2},"inner":{"a":1}}"#;
        // `serde_json` alone: a map keeps the last, silently.
        assert_eq!(serde_json::from_str::<Outer>(text).unwrap().map["k"], 2);
        assert_eq!(from_str::<Outer>(text), Err(JsonError::DuplicateKey { path: "map.k".into() }));
        assert_eq!(
            from_str::<Outer>(r#"{"map":{},"inner":{"a":1,"a":2}}"#),
            Err(JsonError::DuplicateKey { path: "inner.a".into() })
        );
        assert_eq!(from_str::<Outer>(r#"{"map":{"k":1},"inner":{"a":1}}"#).unwrap().inner, Inner { a: 1 });
        // A shape error is Invalid, not a duplicate.
        assert!(matches!(from_str::<Outer>(r#"{"map":{},"inner":{"a":"x"}}"#), Err(JsonError::Invalid { .. })));
        assert!(from_slice::<Outer>(br#"{"map":{},"inner":{"a":1}}"#).is_ok());
    }

    #[test]
    fn names_in_a_path_are_escaped_and_bounded_and_no_value_is_echoed() {
        let text = "{\"k\\u0085\\u202e\":1,\"k\\u0085\\u202e\":\"SECRET\"}".to_owned();
        let e = parse(&text).unwrap_err();
        let shown = e.to_string();
        assert!(crate::text::check(&shown).is_ok(), "{shown}");
        assert!(shown.contains("\\u{85}") && !shown.contains("SECRET"), "{shown}");
        let long = "n".repeat(500);
        let e = parse(&format!("{{\"{long}\":1,\"{long}\":1}}")).unwrap_err();
        let JsonError::DuplicateKey { path } = e else { panic!() };
        assert!(path.chars().count() <= MAX_PATH_CHARS);
        // Deep documents are bounded by `serde_json`'s own recursion limit, as an error.
        let deep = format!("{}1{}", "[".repeat(300), "]".repeat(300));
        assert!(matches!(parse(&deep), Err(JsonError::Invalid { .. })));
    }
}
