//! How long the service's certificate has left: read from the certificate line
//! itself (`<type> <base64> [comment]`), so that `sys kit` needs no program on a
//! host that is not well.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// A warning when fewer days than this are left (`doc/approvals.md`, section 7).
pub const WARN_BELOW_DAYS: i64 = 5;

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        if self.0.len() < n {
            return Err("the certificate is cut short".into());
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| "short")?))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().map_err(|_| "short")?))
    }

    fn string(&mut self) -> Result<&'a [u8], String> {
        let n = self.u32()? as usize;
        self.take(n)
    }
}

/// What a certificate line says that matters here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// When it ends, in seconds since the epoch (`u64::MAX`: never).
    pub valid_before: u64,
    /// The bytes of the key it certifies (an Ed25519 public key; the point of an ECDSA key).
    pub subject: Vec<u8>,
}

/// Reads a certificate line. Ed25519 and ECDSA P-256 certificates only (the key types of the system).
///
/// # Errors
/// Why the line is not a certificate this reads.
pub fn facts(line: &str) -> Result<Facts, String> {
    let mut words = line.split_whitespace();
    let (kind, blob) = (words.next().ok_or("empty")?, words.next().ok_or("no key data")?);
    let blob = STANDARD.decode(blob).map_err(|_| "the key data is not base64")?;
    let mut reader = Reader(&blob);
    let inner = String::from_utf8_lossy(reader.string()?).into_owned();
    if inner != kind {
        return Err("the line's type is not the blob's".into());
    }
    reader.string()?; // nonce
    let subject = match kind {
        "ssh-ed25519-cert-v01@openssh.com" => reader.string()?.to_vec(),
        "ecdsa-sha2-nistp256-cert-v01@openssh.com" => {
            reader.string()?; // the curve
            reader.string()?.to_vec()
        }
        other => return Err(format!("`{other}` is not a certificate type this reads")),
    };
    reader.u64()?; // serial
    reader.u32()?; // user or host
    reader.string()?; // key id
    reader.string()?; // principals
    reader.u64()?; // valid after
    Ok(Facts { valid_before: reader.u64()?, subject })
}

/// When the certificate in `line` ends, in seconds since the epoch.
///
/// # Errors
/// Why the line is not a certificate this reads.
pub fn valid_before(line: &str) -> Result<u64, String> {
    facts(line).map(|f| f.valid_before)
}

/// The key bytes of a public key line (`ssh-ed25519 <base64> [comment]`), the same bytes a certificate
/// for that key carries as its subject. Ed25519 only: the service's key is one.
///
/// # Errors
/// Why the line is not an Ed25519 public key.
pub fn ed25519_public(line: &str) -> Result<Vec<u8>, String> {
    let mut words = line.split_whitespace();
    let (kind, blob) = (words.next().ok_or("empty")?, words.next().ok_or("no key data")?);
    if kind != "ssh-ed25519" {
        return Err(format!("`{kind}` is not an Ed25519 public key"));
    }
    let blob = STANDARD.decode(blob).map_err(|_| "the key data is not base64")?;
    let mut reader = Reader(&blob);
    if reader.string()? != b"ssh-ed25519" {
        return Err("the line's type is not the blob's".into());
    }
    Ok(reader.string()?.to_vec())
}

/// The whole days left of the certificate in the file at `path` at `now` (seconds since the
/// epoch): negative once it has ended. `None` if it has no end.
///
/// # Errors
/// Why the file cannot be read or is not a certificate this reads.
pub fn days_left(path: &std::path::Path, now: i64) -> Result<Option<i64>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let end = valid_before(text.trim())?;
    if end == u64::MAX {
        return Ok(None);
    }
    let end = i64::try_from(end).map_err(|_| "the end is out of range")?;
    Ok(Some((end - now).div_euclid(86_400)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    fn keygen(args: &[&str]) {
        let out = Command::new("ssh-keygen").args(args).stdin(Stdio::null()).output().expect("ssh-keygen");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }

    fn certificate(dir: &std::path::Path, kind: &[&str], validity: &str) -> std::path::PathBuf {
        let (ca, key) = (dir.join("ca"), dir.join("key"));
        for file in [&ca, &key] {
            let mut args = vec!["-q", "-N", "", "-C", ""];
            args.extend(kind);
            args.extend(["-f", file.to_str().unwrap()]);
            keygen(&args);
        }
        keygen(&[
            "-q",
            "-s",
            ca.to_str().unwrap(),
            "-I",
            "x",
            "-n",
            "x",
            "-V",
            validity,
            "-O",
            "clear",
            dir.join("key.pub").to_str().unwrap(),
        ]);
        dir.join("key-cert.pub")
    }

    fn now() -> i64 {
        p_act::Timestamp::now().unwrap().unix()
    }

    #[test]
    fn the_days_left_are_read_from_the_certificate_for_both_key_types() {
        for kind in [&["-t", "ed25519"][..], &["-t", "ecdsa", "-b", "256"]] {
            for (validity, lo, hi) in
                [("+30d", 29, 30), ("+3d", 2, 3), ("+10h", 0, 0), ("20200101Z:20200102Z", -9999, -1)]
            {
                let dir = crate::testdir::new("cert");
                let path = certificate(&dir, kind, validity);
                let days = days_left(&path, now()).unwrap().unwrap();
                assert!((lo..=hi).contains(&days), "{kind:?} {validity}: {days}");
            }
        }
    }

    #[test]
    fn what_is_not_a_certificate_this_reads_is_said_so() {
        let dir = crate::testdir::new("cert");
        assert!(valid_before("").is_err());
        assert!(valid_before("ssh-ed25519 AAAA").is_err());
        assert!(valid_before("ssh-ed25519-cert-v01@openssh.com !!!").is_err());
        let plain = dir.join("plain");
        keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", plain.to_str().unwrap()]);
        let line = std::fs::read_to_string(dir.join("plain.pub")).unwrap();
        assert!(valid_before(&line).is_err(), "a key that is not a certificate");
        assert!(days_left(&dir.join("absent"), 0).is_err());
    }
}
