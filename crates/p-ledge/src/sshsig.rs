//! SSHSIG (`PROTOCOL.sshsig`): the data a key signs, and the armoured file
//! that carries the signature. pledge builds an approval itself, so that the
//! key holder only signs bytes and never has to know what they mean.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::digest;

use crate::agent::wire::{put_string, put_u32};

const MAGIC: &[u8] = b"SSHSIG";
const HASH_ALGORITHM: &str = "sha512";

/// The bytes a key signs for `message` in `namespace`: `"SSHSIG"`, the
/// namespace, an empty reserved string, `sha512`, and the digest of the
/// message.
#[must_use]
pub fn signed_data(namespace: &str, message: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    put_string(&mut out, namespace.as_bytes());
    put_string(&mut out, b"");
    put_string(&mut out, HASH_ALGORITHM.as_bytes());
    put_string(&mut out, digest::digest(&digest::SHA512, message).as_ref());
    out
}

/// The armoured signature file, as `ssh-keygen -Y sign` writes it: the
/// public key (or certificate) blob of the signer, the namespace and the
/// signature blob (`string` type, `string` signature).
#[must_use]
pub fn armour(public_blob: &[u8], namespace: &str, signature_blob: &[u8]) -> String {
    let mut blob = MAGIC.to_vec();
    put_u32(&mut blob, 1);
    put_string(&mut blob, public_blob);
    put_string(&mut blob, namespace.as_bytes());
    put_string(&mut blob, b"");
    put_string(&mut blob, HASH_ALGORITHM.as_bytes());
    put_string(&mut blob, signature_blob);
    wrap("SSH SIGNATURE", &blob)
}

/// `-----BEGIN <label>-----`, the base64 of `bytes` in lines of 70, the end line.
pub(crate) fn wrap(label: &str, bytes: &[u8]) -> String {
    let body = STANDARD.encode(bytes);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in body.as_bytes().chunks(70) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signed_data_is_the_documented_layout() {
        let data = signed_data("ns", b"msg");
        assert!(data.starts_with(b"SSHSIG\0\0\0\x02ns\0\0\0\0\0\0\0\x06sha512\0\0\0\x40"));
        assert_eq!(data.len(), 6 + 4 + 2 + 4 + 4 + 6 + 4 + 64);
    }

    #[test]
    fn armour_wraps_at_seventy_and_ends_with_a_newline() {
        let text = armour(&[1; 200], "ns", &[2; 100]);
        assert!(text.starts_with("-----BEGIN SSH SIGNATURE-----\n") && text.ends_with("-----END SSH SIGNATURE-----\n"));
        assert!(text.lines().all(|l| l.len() <= 70 || l.starts_with("-----")));
    }
}
