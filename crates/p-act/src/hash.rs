use crate::error::ParseError;
use ring::digest::{SHA256, digest};
use std::fmt;
use std::str::FromStr;

/// What every signed document has: the bytes it was parsed from or written to.
pub trait Document {
    /// Exactly the bytes that are signed and verified.
    fn as_bytes(&self) -> &[u8];

    /// `sha256:<hex>` of [`Document::as_bytes`].
    fn hash(&self) -> DocumentHash {
        DocumentHash::of(self.as_bytes())
    }
}

/// SHA-256 over a document's bytes, written `sha256:<64 lower-case hex digits>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DocumentHash([u8; 32]);

impl DocumentHash {
    #[must_use]
    pub fn of(bytes: &[u8]) -> DocumentHash {
        let mut out = [0u8; 32];
        out.copy_from_slice(digest(&SHA256, bytes).as_ref());
        DocumentHash(out)
    }
}

impl fmt::Display for DocumentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("sha256:")?;
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl FromStr for DocumentHash {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, ParseError> {
        let bad = || ParseError::MalformedHash(s.to_owned());
        let hex = s.strip_prefix("sha256:").ok_or_else(bad)?;
        if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(bad());
        }
        let nibble = |b: u8| if b.is_ascii_digit() { b - b'0' } else { b - b'a' + 10 };
        let mut out = [0u8; 32];
        for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks(2)) {
            *byte = nibble(pair[0]) << 4 | nibble(pair[1]);
        }
        Ok(DocumentHash(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector_and_round_trip() {
        let h = DocumentHash::of(b"abc");
        assert_eq!(h.to_string(), "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(h.to_string().parse::<DocumentHash>(), Ok(h));
    }

    #[test]
    fn refuses_malformed() {
        let good = DocumentHash::of(b"").to_string();
        for bad in [
            good.to_uppercase(),
            good.replace("sha256:", "sha512:"),
            good[..good.len() - 1].to_owned(),
            format!("{good}0"),
            good.replace("sha256:", ""),
            format!("{} ", good),
            String::new(),
        ] {
            assert!(bad.parse::<DocumentHash>().is_err(), "{bad:?}");
        }
    }
}
