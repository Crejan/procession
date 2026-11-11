//! The strict reading of one JSON object, shared by the three documents.
//!
//! `serde_json` alone would keep the last of two equal members and say little
//! about why a document is refused, so the members are collected first, with
//! duplicates, and each is taken by name. What is left over is unknown.

use crate::error::ParseError;
use crate::text;
use serde::Deserialize;
use serde::de::{DeserializeOwned, Deserializer, MapAccess, Visitor};
use serde_json::value::RawValue;
use std::fmt;

struct Members(Vec<(String, Box<RawValue>)>);

impl<'de> Deserialize<'de> for Members {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Members;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("an object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Members, A::Error> {
                let mut members = Vec::new();
                while let Some(entry) = map.next_entry()? {
                    members.push(entry);
                }
                Ok(Members(members))
            }
        }
        d.deserialize_map(V)
    }
}

pub(crate) struct Object {
    /// `service.` for a nested object, empty at the top; prefixes member names in errors.
    prefix: &'static str,
    members: Vec<(String, Box<RawValue>)>,
}

impl Object {
    pub(crate) fn parse(raw: &str, prefix: &'static str) -> Result<Object, ParseError> {
        let Members(members) = serde_json::from_str(raw).map_err(|e| ParseError::NotJson(e.to_string()))?;
        for (i, (name, _)) in members.iter().enumerate() {
            if members[..i].iter().any(|(earlier, _)| earlier == name) {
                return Err(ParseError::DuplicateMember(format!("{prefix}{name}")));
            }
        }
        Ok(Object { prefix, members })
    }

    fn remove(&mut self, name: &str) -> Option<Box<RawValue>> {
        let i = self.members.iter().position(|(n, _)| n == name)?;
        Some(self.members.swap_remove(i).1)
    }

    fn typed<T: DeserializeOwned>(&self, name: &str, raw: &RawValue, expected: &'static str) -> Result<T, ParseError> {
        serde_json::from_str(raw.get())
            .map_err(|_| ParseError::WrongType { member: format!("{}{name}", self.prefix), expected })
    }

    pub(crate) fn take_raw(&mut self, name: &'static str) -> Result<Box<RawValue>, ParseError> {
        self.remove(name).ok_or(ParseError::MissingMember(name))
    }

    pub(crate) fn take_object(&mut self, name: &'static str, prefix: &'static str) -> Result<Object, ParseError> {
        let raw = self.take_raw(name)?;
        Object::parse(raw.get(), prefix).map_err(|e| match e {
            ParseError::NotJson(_) => {
                ParseError::WrongType { member: format!("{}{name}", self.prefix), expected: "an object" }
            }
            other => other,
        })
    }

    /// A string without control characters or bidirectional marks.
    pub(crate) fn take_string(&mut self, name: &'static str) -> Result<String, ParseError> {
        self.take_text(name, false)
    }

    /// As [`Object::take_string`], but `\n` is allowed: for an armoured signature.
    pub(crate) fn take_armour(&mut self, name: &'static str) -> Result<String, ParseError> {
        self.take_text(name, true)
    }

    fn take_text(&mut self, name: &'static str, allow_newline: bool) -> Result<String, ParseError> {
        let raw = self.take_raw(name)?;
        let s: String = self.typed(name, &raw, "a string")?;
        text::check(&format!("{}{name}", self.prefix), &s, allow_newline)?;
        Ok(s)
    }

    pub(crate) fn take_strings(&mut self, name: &'static str) -> Result<Vec<String>, ParseError> {
        let raw = self.take_raw(name)?;
        let all: Vec<String> = self.typed(name, &raw, "an array of strings")?;
        for s in &all {
            text::check(&format!("{}{name}", self.prefix), s, false)?;
        }
        Ok(all)
    }

    pub(crate) fn take_optional_string(&mut self, name: &'static str) -> Result<Option<String>, ParseError> {
        if self.members.iter().any(|(n, _)| n == name) { self.take_string(name).map(Some) } else { Ok(None) }
    }

    /// `v` must be 1 and `type` must be `expected`, before anything else is looked at.
    pub(crate) fn take_header(&mut self, expected: &'static str) -> Result<(), ParseError> {
        let raw = self.take_raw("v")?;
        let v: serde_json::Number = self.typed("v", &raw, "a number")?;
        if v.as_u64() != Some(1) {
            return Err(ParseError::UnsupportedVersion(v.to_string()));
        }
        let found = self.take_string("type")?;
        if found != expected {
            return Err(ParseError::WrongDocumentType { expected, found });
        }
        Ok(())
    }

    /// Whatever has not been taken is unknown.
    pub(crate) fn finish(self) -> Result<(), ParseError> {
        match self.members.into_iter().next() {
            Some((name, _)) => Err(ParseError::UnknownMember(format!("{}{name}", self.prefix))),
            None => Ok(()),
        }
    }
}

/// What every document's parser checks before it looks inside: size, encoding, one line.
pub(crate) fn check_bytes(bytes: &[u8], limit: usize) -> Result<&str, ParseError> {
    if bytes.len() > limit {
        return Err(ParseError::TooLarge { len: bytes.len(), limit });
    }
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return Err(ParseError::ByteOrderMark);
    }
    if bytes.iter().any(|&b| b == b'\n' || b == b'\r') {
        return Err(ParseError::LineBreak);
    }
    std::str::from_utf8(bytes).map_err(|_| ParseError::NotUtf8)
}
