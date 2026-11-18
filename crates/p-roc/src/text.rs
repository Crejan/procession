//! Host strings as Rust strings without losing or confusing a byte. The kernel gives
//! bytes (`comm`, command lines, link targets, file names); a string must be able to
//! stand for any of them, and two different byte strings must never become the same
//! string. UTF-8 text is itself. A byte that is not UTF-8 is `ESC` followed by the
//! private-use character `BYTE_BASE + byte`; a genuine `ESC` character is written
//! `ESC ESC`. That mapping is injective, so [`to_bytes`] gives back exactly the bytes
//! the host had, and the output stage escapes *those bytes* with
//! `p_ermit::text::escape_bytes`. (A genuine private-use character in
//! `BYTE_BASE..BYTE_BASE+256` stays itself: only after `ESC` does it mean a byte.)

use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// The private-use code point that, after [`ESC`], stands for the invalid byte 0x00.
pub const BYTE_BASE: u32 = 0x10_F700;

/// The character that introduces a stand-in for an invalid byte, and is doubled when it is
/// genuine (U+10FFFF, a noncharacter).
pub const ESC: char = '\u{10FFFF}';

/// The byte a stand-in character stands for (after [`ESC`]).
#[must_use]
pub fn stands_for_byte(c: char) -> Option<u8> {
    let v = u32::from(c);
    (BYTE_BASE..BYTE_BASE + 256).contains(&v).then(|| (v - BYTE_BASE) as u8)
}

/// Bytes to a string, injectively; see the module text.
#[must_use]
pub fn from_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            out.push(c);
            if c == ESC {
                out.push(ESC);
            }
        }
        for b in chunk.invalid() {
            out.push(ESC);
            out.extend(char::from_u32(BYTE_BASE + u32::from(*b)));
        }
    }
    out
}

/// The bytes a string from [`from_bytes`] stands for.
#[must_use]
pub fn to_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == ESC {
            match chars.peek().copied() {
                Some(ESC) => {
                    chars.next();
                }
                Some(n) if stands_for_byte(n).is_some() => {
                    out.extend(stands_for_byte(n));
                    chars.next();
                    continue;
                }
                _ => {}
            }
        }
        out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
    }
    out
}

/// An OS string (file name, link target) to a string, as [`from_bytes`] does.
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
    fn the_mapping_is_injective_and_reversible() {
        let genuine_stand_in = "\u{10F7FF}".as_bytes(); // what the byte 0xff would be, as a real character
        let samples: [&[u8]; 8] = [
            b"a",
            b"\xff",
            genuine_stand_in,
            "\u{10FFFF}".as_bytes(),
            b"\xf4\x8f\x9f",
            b"\xf4\x8f\x9f\xff",
            b"x\xffy\xc3",
            b"",
        ];
        let strings: Vec<String> = samples.iter().map(|b| from_bytes(b)).collect();
        for (i, a) in strings.iter().enumerate() {
            assert_eq!(to_bytes(a), samples[i], "round trip {i}");
            for (j, b) in strings.iter().enumerate().filter(|(j, _)| *j != i) {
                assert_ne!(a, b, "{i} and {j} became the same string");
            }
        }
        assert_eq!(from_bytes("héllo".as_bytes()), "héllo");
    }
}
