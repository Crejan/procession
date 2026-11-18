//! pledge's key holder behind `p_act::sshsig`'s seam: the holder signs bytes and knows nothing of what they
//! mean; the SSHSIG's data and file are assembled by `p-act`, for approvals, the connection document and
//! the probe a certificate is checked with.

use p_act::sign::{Namespace, SignError};
use p_act::sshsig::{HolderSigner, KeyHolder, RawSignature, SshsigSigner};

use crate::agent::wire::Reader;
use crate::shared::Shared;

/// A key of the holder, signing under `signing` (its plain public blob) and standing in the signature as
/// `shown` (the same blob, or the certificate the site CA made for it).
struct HolderKey<'a> {
    shared: &'a Shared,
    signing: &'a [u8],
    shown: &'a [u8],
}

impl KeyHolder for HolderKey<'_> {
    fn key_blob(&self) -> Vec<u8> {
        self.shown.to_vec()
    }

    fn sign_raw(&self, data: &[u8]) -> Result<RawSignature, SignError> {
        let holder_error = |why: &str| SignError::Holder(why.to_owned());
        let blob = self
            .shared
            .holder
            .lock()
            .map_err(|_| holder_error("the key holder is not there"))?
            .sign(self.signing, data)
            .map_err(|_| holder_error("the key holder could not sign"))?;
        raw_from_blob(&blob).ok_or_else(|| holder_error("the key holder's signature does not read"))
    }
}

/// The holder answers with an SSH signature blob (what the SSH agent protocol needs too): `string(type)` and
/// `string(signature)`, an Ed25519 signature's 64 bytes or an ECDSA `string(mpint r) string(mpint s)`.
fn raw_from_blob(blob: &[u8]) -> Option<RawSignature> {
    let mut reader = Reader::new(blob);
    let kind = reader.string()?;
    let body = reader.string()?;
    match kind {
        b"ssh-ed25519" => Some(RawSignature::Ed25519(body.try_into().ok()?)),
        b"ecdsa-sha2-nistp256" => {
            let mut parts = Reader::new(body);
            let mut fixed = [0_u8; 64];
            for half in fixed.chunks_mut(32) {
                let mpint = parts.string()?;
                let number = mpint.strip_prefix(&[0]).unwrap_or(mpint);
                half[32usize.checked_sub(number.len())?..].copy_from_slice(number);
            }
            Some(RawSignature::EcdsaP256Fixed(fixed))
        }
        _ => None,
    }
}

/// The armoured SSHSIG of `message` in `namespace`, made by the holder's key `signing` and carrying `shown`.
/// `None` if the holder cannot sign or the result is not a well-formed signature.
pub fn sign(shared: &Shared, signing: &[u8], shown: &[u8], namespace: Namespace, message: &[u8]) -> Option<String> {
    HolderSigner(HolderKey { shared, signing, shown }).sign(namespace, message).ok()
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use p_act::sign::Namespace;

    use super::sign;
    use crate::agent::wire::{put_string, put_u32};
    use crate::approvals_tests::Lab;

    /// pledge's own writer before the seam (its `sshsig.rs`), kept here as the reference the seam must equal.
    fn the_old_writer(public_blob: &[u8], namespace: &str, message: &[u8], signature_blob: &[u8]) -> String {
        let mut data = b"SSHSIG".to_vec();
        put_string(&mut data, namespace.as_bytes());
        put_string(&mut data, b"");
        put_string(&mut data, b"sha512");
        put_string(&mut data, ring::digest::digest(&ring::digest::SHA512, message).as_ref());
        let _ = data;
        let mut blob = b"SSHSIG".to_vec();
        put_u32(&mut blob, 1);
        put_string(&mut blob, public_blob);
        put_string(&mut blob, namespace.as_bytes());
        put_string(&mut blob, b"");
        put_string(&mut blob, b"sha512");
        put_string(&mut blob, signature_blob);
        let body = STANDARD.encode(&blob);
        let mut out = String::from("-----BEGIN SSH SIGNATURE-----\n");
        for line in body.as_bytes().chunks(70) {
            out.push_str(&String::from_utf8_lossy(line));
            out.push('\n');
        }
        out.push_str("-----END SSH SIGNATURE-----\n");
        out
    }

    #[test]
    fn for_an_ed25519_key_the_approval_is_byte_for_byte_what_pledge_wrote_before_the_seam() {
        let lab = Lab::new();
        let shared = &lab.rig.shared;
        let key = shared.key_with_purpose("confirmed").expect("key");
        let request = b"a request's bytes";
        let mut data = b"SSHSIG".to_vec();
        put_string(&mut data, b"approval-v1@procession");
        put_string(&mut data, b"");
        put_string(&mut data, b"sha512");
        put_string(&mut data, ring::digest::digest(&ring::digest::SHA512, request).as_ref());
        let blob = shared.holder.lock().expect("holder").sign(&key.blob, &data).expect("signs");
        let before = the_old_writer(&key.blob, "approval-v1@procession", request, &blob);
        let after = sign(shared, &key.blob, &key.blob, Namespace::Approval, request).expect("signs");
        assert_eq!(after, before, "Ed25519 signatures are deterministic: the same bytes");
    }
}
