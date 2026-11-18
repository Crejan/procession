//! Host strings as Rust strings without losing a byte. The kernel gives
//! bytes (`comm`, command lines, link targets, file names); a byte that is not
//! UTF-8 must reach the output escaped, not replaced. These functions map
//! each invalid byte to a private-use character, [`BYTE_BASE`] plus the byte;
//! the output stage (`prover`'s sanitizer) writes it as `\x{ff}`. A genuine
//! character in that range (U+10F700 to U+10F7FF, plane 16 private use) is
//! indistinguishable from an invalid byte; none is known to occur.

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// The private-use code point that stands for the invalid byte 0x00.
pub const BYTE_BASE: u32 = 0x10_F700;

/// The byte a stand-in character stands for.
#[must_use]
pub fn stands_for_byte(c: char) -> Option<u8> {
    let v = u32::from(c);
    (BYTE_BASE..BYTE_BASE + 256).contains(&v).then(|| (v - BYTE_BASE) as u8)
}

/// Bytes to a string; each byte that is not part of valid UTF-8 becomes its stand-in.
#[must_use]
pub fn from_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        out.extend(chunk.invalid().iter().filter_map(|b| char::from_u32(BYTE_BASE + u32::from(*b))));
    }
    out
}

/// The bytes a string from [`from_bytes`] stands for: stand-ins turn back into their bytes.
#[must_use]
pub fn to_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    for c in s.chars() {
        match stands_for_byte(c) {
            Some(b) => out.push(b),
            None => out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
        }
    }
    out
}

/// An OS string (file name, link target) to a string, losslessly in the sense of [`from_bytes`].
#[must_use]
pub fn from_os(s: &OsStr) -> String {
    from_bytes(s.as_bytes())
}

/// The name of a directory entry, in the sense of [`from_bytes`].
#[must_use]
pub fn entry_name(e: &std::fs::DirEntry) -> String {
    from_os(&e.file_name())
}

/// `std::fs::read_to_string` that does not fail on bytes that are not UTF-8.
///
/// # Errors
/// The I/O error of the read.
pub fn read_to_string(path: impl AsRef<Path>) -> io::Result<String> {
    std::fs::read(path).map(|b| from_bytes(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_bytes_get_stand_ins_and_valid_text_is_untouched() {
        assert_eq!(from_bytes("héllo".as_bytes()), "héllo");
        let s = from_bytes(b"a\xffb\xc3");
        assert_eq!(s.chars().map(stands_for_byte).collect::<Vec<_>>(), [None, Some(0xff), None, Some(0xc3)]);
        assert_eq!(stands_for_byte('x'), None);
        assert_eq!(to_bytes(&from_bytes(b"a\xffb\xc3\xa9\xc3")), b"a\xffb\xc3\xa9\xc3");
    }
}
