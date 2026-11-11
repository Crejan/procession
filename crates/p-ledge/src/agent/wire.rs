//! SSH wire-format primitives (RFC 4251, section 5): big-endian integers,
//! `string` (a 4-byte length and that many bytes) and `mpint`.

/// Reads fields from a byte slice. Every read either succeeds or returns
/// `None` and leaves the reader where it was; nothing panics on short or
/// hostile input.
#[derive(Debug, Clone)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    /// A reader at the start of `data`.
    #[must_use]
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// How many bytes were read so far.
    #[must_use]
    pub fn offset(&self) -> usize {
        self.pos
    }

    /// How many bytes are left.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    /// The bytes not read yet.
    #[must_use]
    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    fn take(&mut self, count: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(count).filter(|end| *end <= self.data.len())?;
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Some(bytes)
    }

    /// One byte.
    pub fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|bytes| bytes[0])
    }

    /// A big-endian `uint32`.
    pub fn u32(&mut self) -> Option<u32> {
        self.take(4).and_then(|bytes| bytes.try_into().ok()).map(u32::from_be_bytes)
    }

    /// A big-endian `uint64`.
    pub fn u64(&mut self) -> Option<u64> {
        self.take(8).and_then(|bytes| bytes.try_into().ok()).map(u64::from_be_bytes)
    }

    /// A `string`: the bytes after a 4-byte length. `None` if the length runs
    /// past the end; the reader does not move then.
    pub fn string(&mut self) -> Option<&'a [u8]> {
        let start = self.pos;
        let bytes = self.u32().and_then(|len| usize::try_from(len).ok()).and_then(|len| self.take(len));
        if bytes.is_none() {
            self.pos = start;
        }
        bytes
    }

    /// A `string` that is valid UTF-8.
    pub fn utf8(&mut self) -> Option<&'a str> {
        let start = self.pos;
        let text = self.string().and_then(|bytes| std::str::from_utf8(bytes).ok());
        if text.is_none() {
            self.pos = start;
        }
        text
    }
}

/// Appends a big-endian `uint32`.
pub fn put_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Appends a big-endian `uint64`.
pub fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

/// Appends a `string`.
///
/// # Panics
///
/// If `bytes` is longer than `u32::MAX`, which no SSH message can be.
pub fn put_string(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(out, u32::try_from(bytes.len()).expect("an SSH string is shorter than 4 GiB"));
    out.extend_from_slice(bytes);
}

/// Appends an `mpint` for the unsigned big-endian number `bytes`: leading
/// zeros dropped, one zero added if the top bit is set.
///
/// # Panics
///
/// If `bytes` is longer than `u32::MAX`.
pub fn put_mpint(out: &mut Vec<u8>, bytes: &[u8]) {
    let start = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len());
    let number = &bytes[start..];
    if number.first().is_some_and(|byte| byte & 0x80 != 0) {
        put_u32(out, u32::try_from(number.len() + 1).expect("an mpint is shorter than 4 GiB"));
        out.push(0);
        out.extend_from_slice(number);
    } else {
        put_string(out, number);
    }
}

/// `string(a) || string(b) || ...` as one buffer.
#[must_use]
pub fn strings(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for part in parts {
        put_string(&mut out, part);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_and_strings_round_trip() {
        let mut buf = Vec::new();
        buf.push(7);
        put_u32(&mut buf, 0xDEAD_BEEF);
        put_u64(&mut buf, 0x0102_0304_0506_0708);
        put_string(&mut buf, b"abc");
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.u8(), Some(7));
        assert_eq!(reader.u32(), Some(0xDEAD_BEEF));
        assert_eq!(reader.u64(), Some(0x0102_0304_0506_0708));
        assert_eq!(reader.string(), Some(&b"abc"[..]));
        assert_eq!(reader.remaining(), 0);
        assert_eq!(reader.u8(), None);
    }

    #[test]
    fn a_string_that_runs_past_the_end_reads_nothing_and_does_not_move() {
        let mut buf = Vec::new();
        put_u32(&mut buf, 5);
        buf.extend_from_slice(b"abcd");
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.string(), None);
        assert_eq!(reader.offset(), 0);
        assert_eq!(reader.u32(), Some(5));
    }

    #[test]
    fn a_length_of_four_gigabytes_is_refused_not_allocated() {
        let mut reader = Reader::new(&[0xFF, 0xFF, 0xFF, 0xFF, 1, 2, 3]);
        assert_eq!(reader.string(), None);
    }

    #[test]
    fn utf8_refuses_invalid_text_and_does_not_move() {
        let buf = strings(&[&[0xFF, 0xFE]]);
        let mut reader = Reader::new(&buf);
        assert_eq!(reader.utf8(), None);
        assert_eq!(reader.offset(), 0);
    }

    #[test]
    fn mpint_is_canonical() {
        let mut out = Vec::new();
        put_mpint(&mut out, &[0, 0, 0x80, 1]);
        assert_eq!(out, [0, 0, 0, 3, 0, 0x80, 1]);
        out.clear();
        put_mpint(&mut out, &[0, 0, 0x7F]);
        assert_eq!(out, [0, 0, 0, 1, 0x7F]);
        out.clear();
        put_mpint(&mut out, &[0, 0]);
        assert_eq!(out, [0, 0, 0, 0]);
    }
}
