//! The form of an SSHSIG, written in one place (`PROTOCOL.sshsig`), independent of who signs.
//!
//! A signature is made in three steps, and only the middle one needs the key:
//!
//! 1. [`signing_input`]: the bytes the key signs for a message in a [`Namespace`] (the hash is fixed to
//!    `sha512`);
//! 2. the signer signs those bytes and hands back a [`RawSignature`]: Ed25519's 64 bytes, or ECDSA P-256 as
//!    `r || s` (64 bytes, fixed width) or as DER, which is converted in [`ssh_signature_blob`] and nowhere else;
//! 3. [`armour_signature`]: the file `ssh-keygen -Y sign` writes, from the key's blob (its certificate's, if it is
//!    certified), the namespace and the signature blob.
//!
//! [`SshsigSigner`] is what the signing functions of [`crate::sign`] take. `ssh-keygen` on a key file
//! ([`crate::sign::Signer`]) and a key holder that signs bytes ([`HolderSigner`] over a [`KeyHolder`]) are both
//! one. The namespace is the enum, so a namespace that is not the system's cannot be written; what
//! comes out is always checked to be a signature that [`crate::sign::looks_armoured`] accepts and whose algorithm is the key's.
//! Everything the seam writes is verified by `ssh-keygen -Y verify`, as every signature in the system is.

use crate::sign::{Namespace, SignError, key_type, put_string};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::digest::{SHA512, digest};

const MAGIC: &[u8] = b"SSHSIG";
/// The hash of the message in the signed data: `sha512`, which is what `ssh-keygen` uses.
pub const HASH_ALGORITHM: &str = "sha512";
/// `ssh-keygen` wraps the armour at this many columns.
const COLUMNS: usize = 70;

const ED25519: &str = "ssh-ed25519";
const ECDSA_P256: &str = "ecdsa-sha2-nistp256";
const CERT_SUFFIX: &str = "-cert-v01@openssh.com";

/// The bytes a key signs for `message` in `namespace`: `"SSHSIG"`, the namespace, an empty reserved string,
/// `sha512` and the digest of the message, each a string.
#[must_use]
pub fn signing_input(namespace: Namespace, message: &[u8]) -> Vec<u8> {
    signing_input_in(namespace.as_str(), message)
}

/// [`signing_input`] for any namespace text: the one place the signed data is built.
pub(crate) fn signing_input_in(namespace: &str, message: &[u8]) -> Vec<u8> {
    let mut out = MAGIC.to_vec();
    put_string(&mut out, namespace.as_bytes());
    put_string(&mut out, b"");
    put_string(&mut out, HASH_ALGORITHM.as_bytes());
    put_string(&mut out, digest(&SHA512, message).as_ref());
    out
}

/// What a signer hands back for [`signing_input`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawSignature {
    /// Ed25519: the 64 bytes `R || S`.
    Ed25519([u8; 64]),
    /// ECDSA P-256 as `r || s`, each 32 bytes big-endian (what `ring` and most libraries write).
    EcdsaP256Fixed([u8; 64]),
    /// ECDSA P-256 as ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }` (what a Secure Enclave or `openssl` write).
    /// Strict DER: a non-minimal encoding is refused.
    EcdsaP256Der(Vec<u8>),
}

fn bad(why: &'static str) -> SignError {
    SignError::RawSignature(why)
}

/// `r` or `s` of a DER integer as 32 bytes big-endian.
fn der_scalar(bytes: &[u8]) -> Result<[u8; 32], SignError> {
    let Some((&first, rest)) = bytes.split_first() else { return Err(bad("an empty DER integer")) };
    if first & 0x80 != 0 {
        return Err(bad("a negative DER integer"));
    }
    // Minimal DER: a leading zero only where the next byte has its top bit set.
    let number = if first == 0 && !rest.is_empty() {
        if rest[0] & 0x80 == 0 {
            return Err(bad("a DER integer with an unneeded leading zero"));
        }
        rest
    } else {
        bytes
    };
    if number.len() > 32 {
        return Err(bad("a DER integer longer than 32 bytes"));
    }
    let mut out = [0u8; 32];
    out[32 - number.len()..].copy_from_slice(number);
    Ok(out)
}

/// Parse `SEQUENCE { INTEGER r, INTEGER s }` strictly into `r || s`.
fn der_to_fixed(der: &[u8]) -> Result<[u8; 64], SignError> {
    // P-256 signatures are at most 72 bytes: every length here fits one byte.
    let (&seq, rest) = der.split_first().ok_or_else(|| bad("an empty DER signature"))?;
    if seq != 0x30 {
        return Err(bad("a DER signature that is not a sequence"));
    }
    let (&len, body) = rest.split_first().ok_or_else(|| bad("a truncated DER signature"))?;
    if len & 0x80 != 0 || usize::from(len) != body.len() {
        return Err(bad("a DER signature whose length is wrong"));
    }
    let integer = |input: &[u8]| -> Result<([u8; 32], usize), SignError> {
        let [tag, len, ..] = input else { return Err(bad("a truncated DER integer")) };
        let len = usize::from(*len);
        if *tag != 0x02 || len & 0x80 != 0 || len == 0 || input.len() < 2 + len {
            return Err(bad("a DER integer that is malformed"));
        }
        Ok((der_scalar(&input[2..2 + len])?, 2 + len))
    };
    let (r, used) = integer(body)?;
    let (s, used_s) = integer(&body[used..])?;
    if used + used_s != body.len() {
        return Err(bad("a DER signature with bytes after s"));
    }
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&r);
    out[32..].copy_from_slice(&s);
    Ok(out)
}

/// An SSH `mpint` of a 32-byte big-endian scalar, as a string: leading zero bytes stripped, and one zero byte
/// put back if the first byte left has its top bit set (so that the number is not negative). This is where
/// hand-written encoders go wrong, and it is written once.
fn put_mpint(out: &mut Vec<u8>, scalar: &[u8; 32]) {
    let start = scalar.iter().position(|b| *b != 0).unwrap_or(32);
    let number = &scalar[start..];
    if number.first().is_some_and(|b| b & 0x80 != 0) {
        let mut padded = vec![0];
        padded.extend_from_slice(number);
        put_string(out, &padded);
    } else {
        put_string(out, number);
    }
}

/// The signature blob of an SSH signature: `string(algorithm) || string(signature)`; for Ed25519 the 64 bytes,
/// for ECDSA P-256 `string(mpint r) || string(mpint s)`. A zero `r` or `s` is refused: it is not a signature.
pub fn ssh_signature_blob(raw: &RawSignature) -> Result<Vec<u8>, SignError> {
    let mut out = Vec::new();
    match raw {
        RawSignature::Ed25519(sig) => {
            put_string(&mut out, ED25519.as_bytes());
            put_string(&mut out, sig);
        }
        RawSignature::EcdsaP256Fixed(_) | RawSignature::EcdsaP256Der(_) => {
            let fixed = match raw {
                RawSignature::EcdsaP256Fixed(f) => *f,
                RawSignature::EcdsaP256Der(der) => der_to_fixed(der)?,
                RawSignature::Ed25519(_) => unreachable!("matched above"),
            };
            let (r, s) = fixed.split_at(32);
            if r.iter().all(|b| *b == 0) || s.iter().all(|b| *b == 0) {
                return Err(bad("an ECDSA signature with a zero r or s"));
            }
            let (r, s): (&[u8; 32], &[u8; 32]) =
                (r.try_into().map_err(|_| bad("r"))?, s.try_into().map_err(|_| bad("s"))?);
            let mut body = Vec::new();
            put_mpint(&mut body, r);
            put_mpint(&mut body, s);
            put_string(&mut out, ECDSA_P256.as_bytes());
            put_string(&mut out, &body);
        }
    }
    Ok(out)
}

/// The algorithm a key blob (a key's or a certificate's) is for, if it is one `p-act` signs with.
fn algorithm_of(key_blob: &[u8]) -> Result<&'static str, SignError> {
    let kind = key_type(key_blob).ok_or(SignError::MalformedSignature)?;
    match kind.strip_suffix(CERT_SUFFIX).unwrap_or(&kind) {
        ED25519 => Ok(ED25519),
        ECDSA_P256 => Ok(ECDSA_P256),
        _ => Err(SignError::UnsupportedKeyType(kind)),
    }
}

/// Check that `signature_blob` is a well-formed signature blob of `algorithm`.
fn check_signature_blob(algorithm: &str, signature_blob: &[u8]) -> Result<(), SignError> {
    let mut r = crate::sign::Reader(signature_blob);
    let kind = r.string().ok_or_else(|| bad("a signature blob without a type"))?;
    if kind != algorithm.as_bytes() {
        return Err(bad("a signature of another algorithm than the key's"));
    }
    let body = r.string().ok_or_else(|| bad("a signature blob without a signature"))?;
    if !r.0.is_empty() {
        return Err(bad("a signature blob with bytes after the signature"));
    }
    match algorithm {
        ED25519 if body.len() == 64 => Ok(()),
        ED25519 => Err(bad("an Ed25519 signature that is not 64 bytes")),
        _ => {
            let mut parts = crate::sign::Reader(body);
            for _ in 0..2 {
                let mpint = parts.string().ok_or_else(|| bad("an ECDSA signature without r and s"))?;
                let minimal = match mpint {
                    [] => false,
                    [0, next, ..] => next & 0x80 != 0 && mpint.len() <= 33,
                    [first, ..] => first & 0x80 == 0 && mpint.len() <= 32,
                };
                if !minimal {
                    return Err(bad("an ECDSA r or s that is not a minimal positive mpint"));
                }
            }
            if parts.0.is_empty() { Ok(()) } else { Err(bad("an ECDSA signature with bytes after s")) }
        }
    }
}

/// The armoured signature file, as `ssh-keygen -Y sign` writes it, from the signer's key blob (its certificate's
/// if it is certified: then the certificate stands in the signature, as `p-act` reads it), the namespace and the
/// signature blob ([`ssh_signature_blob`]). Refused if the key is not Ed25519 or ECDSA P-256 (as a key or a
/// certificate), if the signature blob is not well formed or is of another algorithm than the key's.
/// [`crate::sign::looks_armoured`] accepts what it returns.
pub fn armour_signature(
    namespace: Namespace,
    key_or_cert_blob: &[u8],
    signature_blob: &[u8],
) -> Result<String, SignError> {
    check_signature_blob(algorithm_of(key_or_cert_blob)?, signature_blob)?;
    Ok(armour_in(namespace.as_str(), key_or_cert_blob, signature_blob))
}

/// [`armour_signature`] without the checks and for any namespace text: the one place the file is built.
pub(crate) fn armour_in(namespace: &str, key_blob: &[u8], signature_blob: &[u8]) -> String {
    let mut blob = MAGIC.to_vec();
    blob.extend_from_slice(&1u32.to_be_bytes());
    put_string(&mut blob, key_blob);
    put_string(&mut blob, namespace.as_bytes());
    put_string(&mut blob, b"");
    put_string(&mut blob, HASH_ALGORITHM.as_bytes());
    put_string(&mut blob, signature_blob);
    let b64 = STANDARD.encode(blob);
    let mut out = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for chunk in b64.as_bytes().chunks(COLUMNS) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str("-----END SSH SIGNATURE-----\n");
    out
}

/// Anything that can make the armoured SSHSIG of a message in a namespace: what `sign_call`, `sign_approval`,
/// `ConnectionDocument::sign` and the other signing functions take.
pub trait SshsigSigner {
    fn sign(&self, namespace: Namespace, message: &[u8]) -> Result<String, SignError>;
}

impl<T: SshsigSigner + ?Sized> SshsigSigner for &T {
    fn sign(&self, namespace: Namespace, message: &[u8]) -> Result<String, SignError> {
        (**self).sign(namespace, message)
    }
}

/// A key that signs bytes and knows nothing of what they mean: pledge's key holder.
pub trait KeyHolder {
    /// The wire form of the public key, or of the certificate if the key is certified. This is what stands in
    /// the signature, and it is the key the signature verifies under.
    fn key_blob(&self) -> Vec<u8>;

    /// Sign `data` (a [`signing_input`]) with that key. Failures are [`SignError::Holder`].
    fn sign_raw(&self, data: &[u8]) -> Result<RawSignature, SignError>;
}

/// A [`SshsigSigner`] made of a [`KeyHolder`]: the seam assembles the signed data and the file around it.
#[derive(Debug, Clone)]
pub struct HolderSigner<H>(pub H);

impl<H: KeyHolder> SshsigSigner for HolderSigner<H> {
    fn sign(&self, namespace: Namespace, message: &[u8]) -> Result<String, SignError> {
        let blob = self.0.key_blob();
        // The algorithm is the key's: a holder that answers with another one is refused, never written.
        let raw = self.0.sign_raw(&signing_input(namespace, message))?;
        armour_signature(namespace, &blob, &ssh_signature_blob(&raw)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::{PublicKey, Signer, verify_broker, verify_connection};
    use ring::rand::SystemRandom;
    use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    fn keygen(args: &[&str]) {
        let out =
            Command::new("ssh-keygen").args(args).stdin(Stdio::null()).output().expect("these tests need ssh-keygen");
        assert!(out.status.success(), "ssh-keygen {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    fn strings(parts: &[&[u8]]) -> Vec<u8> {
        let mut out = Vec::new();
        parts.iter().for_each(|p| put_string(&mut out, p));
        out
    }

    fn ed25519_blob(public: &[u8]) -> Vec<u8> {
        strings(&[b"ssh-ed25519", public])
    }

    fn p256_blob(point: &[u8]) -> Vec<u8> {
        strings(&[b"ecdsa-sha2-nistp256", b"nistp256", point])
    }

    fn line_of(blob: &[u8]) -> String {
        let kind = String::from_utf8(crate::sign::Reader(blob).string().unwrap().to_vec()).unwrap();
        format!("{kind} {}", STANDARD.encode(blob))
    }

    /// The seed and public key out of an unencrypted OpenSSH Ed25519 private key file.
    fn read_seed(text: &str) -> ([u8; 32], [u8; 32]) {
        let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
        let blob = STANDARD.decode(body).unwrap();
        let first = blob.windows(11).position(|w| w == b"ssh-ed25519").unwrap();
        let second = blob[first + 11..].windows(11).position(|w| w == b"ssh-ed25519").unwrap() + first + 11;
        let mut p = second + 11 + 4;
        let public: [u8; 32] = blob[p..p + 32].try_into().unwrap();
        p += 32 + 4;
        (blob[p..p + 32].try_into().unwrap(), public)
    }

    enum Pair {
        Ed25519(Ed25519KeyPair),
        P256(EcdsaKeyPair),
    }

    /// A key holder in the sense of pledge's: signs bytes, knows nothing of what they mean.
    struct Holder {
        pair: Pair,
        blob: Vec<u8>,
        /// For P-256: hand the signature in as DER instead of `r || s`.
        der: bool,
    }

    /// `r || s` as ASN.1 DER, the way a Secure Enclave returns it.
    fn to_der(fixed: &[u8]) -> Vec<u8> {
        let integer = |scalar: &[u8]| {
            let start = scalar.iter().position(|b| *b != 0).unwrap_or(scalar.len() - 1);
            let mut n = scalar[start..].to_vec();
            if n[0] & 0x80 != 0 {
                n.insert(0, 0);
            }
            let mut out = vec![0x02, u8::try_from(n.len()).unwrap()];
            out.extend(n);
            out
        };
        let mut body = integer(&fixed[..32]);
        body.extend(integer(&fixed[32..]));
        let mut out = vec![0x30, u8::try_from(body.len()).unwrap()];
        out.extend(body);
        out
    }

    impl KeyHolder for Holder {
        fn key_blob(&self) -> Vec<u8> {
            self.blob.clone()
        }

        fn sign_raw(&self, data: &[u8]) -> Result<RawSignature, SignError> {
            Ok(match &self.pair {
                Pair::Ed25519(p) => RawSignature::Ed25519(p.sign(data).as_ref().try_into().unwrap()),
                Pair::P256(p) => {
                    let sig =
                        p.sign(&SystemRandom::new(), data).map_err(|_| SignError::Holder("signing failed".into()))?;
                    if self.der {
                        RawSignature::EcdsaP256Der(to_der(sig.as_ref()))
                    } else {
                        RawSignature::EcdsaP256Fixed(sig.as_ref().try_into().unwrap())
                    }
                }
            })
        }
    }

    struct Env {
        dir: tempfile::TempDir,
        count: std::cell::Cell<usize>,
    }

    impl Env {
        fn new() -> Env {
            Env { dir: tempfile::tempdir().unwrap(), count: std::cell::Cell::new(0) }
        }

        /// A file name no earlier call used.
        fn unique(&self, name: &str) -> String {
            self.count.set(self.count.get() + 1);
            format!("{name}-{}", self.count.get())
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }

        /// A CA key (the "delegation" or site CA): Ed25519 or P-256, as a file; its public key.
        fn ca(&self, name: &str, p256: bool) -> (PathBuf, PublicKey) {
            let path = self.path(name);
            let kind = if p256 { vec!["-t", "ecdsa", "-b", "256"] } else { vec!["-t", "ed25519"] };
            let mut args = vec!["-q", "-N", "", "-C", "", "-f", path.to_str().unwrap()];
            args.extend(kind);
            keygen(&args);
            let public = PublicKey::read(&PathBuf::from(format!("{}.pub", path.display()))).unwrap();
            (path, public)
        }

        /// Certify the public key line `line` for `principal`; the certificate's blob.
        fn certify(&self, ca: &Path, name: &str, line: &str, principal: &str) -> Vec<u8> {
            let pub_file = self.path(&format!("{name}.pub"));
            std::fs::write(&pub_file, format!("{line}\n")).unwrap();
            keygen(&[
                "-q",
                "-s",
                ca.to_str().unwrap(),
                "-I",
                name,
                "-n",
                principal,
                "-V",
                "20200101Z:20990101Z",
                "-O",
                "clear",
                pub_file.to_str().unwrap(),
            ]);
            let cert = std::fs::read_to_string(self.path(&format!("{name}-cert.pub"))).unwrap();
            STANDARD.decode(cert.split_whitespace().nth(1).unwrap()).unwrap()
        }

        /// An Ed25519 holder; its private key file is `ssh-keygen`'s, so that its output can be compared with `ssh-keygen -Y sign`.
        fn ed25519(&self, name: &str, ca: Option<(&Path, &str)>) -> (Holder, PathBuf, String) {
            let name = &self.unique(name);
            let key = self.path(name);
            keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", key.to_str().unwrap()]);
            let (seed, public) = read_seed(&std::fs::read_to_string(&key).unwrap());
            let pair = Ed25519KeyPair::from_seed_and_public_key(&seed, &public).unwrap();
            let plain = ed25519_blob(&public);
            let blob = match ca {
                None => plain.clone(),
                Some((ca, principal)) => self.certify(ca, name, &line_of(&plain), principal),
            };
            // The file `ssh-keygen -Y sign` is given: the certificate beside the key (it was written there by `certify`).
            let file = if ca.is_some() { PathBuf::from(format!("{}-cert.pub", key.display())) } else { key.clone() };
            (Holder { pair: Pair::Ed25519(pair), blob, der: false }, file, line_of(&plain))
        }

        fn p256(&self, name: &str, ca: Option<(&Path, &str)>, der: bool) -> (Holder, String) {
            let name = &self.unique(name);
            let rng = SystemRandom::new();
            let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
            let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap();
            let plain = p256_blob(pair.public_key().as_ref());
            let blob = match ca {
                None => plain.clone(),
                Some((ca, principal)) => self.certify(ca, name, &line_of(&plain), principal),
            };
            (Holder { pair: Pair::P256(pair), blob, der }, line_of(&plain))
        }
    }

    /// `ssh-keygen -Y verify` of `sig` over `data`, with `allowed` as the allowed-signers file.
    fn ssh_verify(env: &Env, allowed: &str, principal: &str, namespace: &str, sig: &str, data: &[u8]) -> bool {
        let (allowed_file, sig_file) = (env.path("allowed-v"), env.path("sig-v"));
        std::fs::write(&allowed_file, allowed).unwrap();
        std::fs::write(&sig_file, sig).unwrap();
        let mut child = Command::new("ssh-keygen")
            .args(["-Y", "verify", "-f"])
            .arg(&allowed_file)
            .args(["-I", principal, "-n", namespace, "-s"])
            .arg(&sig_file)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // A child that exits first (it failed) makes this write fail with `Broken pipe`: the status is the answer.
        let _ = child.stdin.take().unwrap().write_all(data);
        child.wait().unwrap().success()
    }

    fn messages() -> Vec<Vec<u8>> {
        let mut all: Vec<Vec<u8>> = vec![vec![], b"a".to_vec(), b"{\"v\":1}".to_vec()];
        for n in [55, 64, 111, 112, 128, 1000, 16 * 1024, 70_000] {
            all.push((0..n).map(|i| u8::try_from(i * 7 % 251).unwrap()).collect());
        }
        all
    }

    // --- the form ------------------------------------------------------------------------------

    #[test]
    fn the_signing_input_is_the_documented_layout() {
        let data = signing_input(Namespace::Call, b"msg");
        let expected_start = [
            &b"SSHSIG"[..],
            &[0, 0, 0, 18],
            b"call-v1@procession",
            &[0, 0, 0, 0],
            &[0, 0, 0, 6],
            b"sha512",
            &[0, 0, 0, 64],
        ]
        .concat();
        assert!(data.starts_with(&expected_start));
        assert_eq!(data.len(), 6 + 4 + 18 + 4 + 4 + 6 + 4 + 64);
        assert_eq!(&data[data.len() - 64..], digest(&SHA512, b"msg").as_ref());
        // Each namespace gives its own, and the message is hashed: changing one byte changes the tail.
        assert_ne!(signing_input(Namespace::Call, b"msg"), signing_input(Namespace::Request, b"msg"));
        assert_ne!(signing_input(Namespace::Call, b"msg"), signing_input(Namespace::Call, b"msh"));
        for ns in Namespace::ALL {
            assert!(signing_input(ns, b"").windows(ns.as_str().len()).any(|w| w == ns.as_str().as_bytes()));
        }
    }

    // --- the mpint, where hand-written encoders fail ------------------------------------------------

    /// What an SSH ECDSA signature blob holds, decoded back to `r || s`, with the rules of the format checked.
    fn decode_ecdsa(blob: &[u8]) -> [u8; 64] {
        let mut r = crate::sign::Reader(blob);
        assert_eq!(r.string().unwrap(), b"ecdsa-sha2-nistp256");
        let mut body = crate::sign::Reader(r.string().unwrap());
        assert!(r.0.is_empty());
        let mut out = [0u8; 64];
        for (i, half) in out.chunks_mut(32).enumerate() {
            let mpint = body.string().unwrap();
            // Positive and minimal: no leading zero unless the next byte has its top bit set.
            assert!(!mpint.is_empty() && mpint[0] & 0x80 == 0, "r/s {i} is negative or empty: {mpint:02x?}");
            if mpint[0] == 0 {
                assert!(mpint.len() > 1 && mpint[1] & 0x80 != 0, "r/s {i} has an unneeded zero: {mpint:02x?}");
            }
            let number = if mpint[0] == 0 { &mpint[1..] } else { mpint };
            assert!(number.len() <= 32);
            half[32 - number.len()..].copy_from_slice(number);
        }
        assert!(body.0.is_empty());
        out
    }

    fn fixed(r: &[u8], s: &[u8]) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[32 - r.len()..32].copy_from_slice(r);
        out[64 - s.len()..].copy_from_slice(s);
        out
    }

    fn mpints(raw: &RawSignature) -> (Vec<u8>, Vec<u8>) {
        let blob = ssh_signature_blob(raw).unwrap();
        let mut r = crate::sign::Reader(&blob);
        r.string().unwrap();
        let mut body = crate::sign::Reader(r.string().unwrap());
        (body.string().unwrap().to_vec(), body.string().unwrap().to_vec())
    }

    #[test]
    fn the_mpint_of_r_and_s_in_every_case_that_goes_wrong() {
        let ones = |n: usize, first: u8| {
            let mut v = vec![1u8; n];
            v[0] = first;
            v
        };
        // r with its top bit set gets a zero byte in front; so does s; both at once.
        let (r, s) = mpints(&RawSignature::EcdsaP256Fixed(fixed(&ones(32, 0x80), &ones(32, 0x7f))));
        assert_eq!((r.len(), &r[..2], s.len()), (33, &[0x00, 0x80][..], 32));
        let (r, s) = mpints(&RawSignature::EcdsaP256Fixed(fixed(&ones(32, 0x7f), &ones(32, 0xff))));
        assert_eq!((r.len(), s.len(), &s[..2]), (32, 33, &[0x00, 0xff][..]));
        let (r, s) = mpints(&RawSignature::EcdsaP256Fixed(fixed(&ones(32, 0x80), &ones(32, 0x80))));
        assert_eq!((r.len(), s.len()), (33, 33));
        // A leading zero byte is stripped (31 bytes left, top bit clear)...
        let mut with_zero = ones(32, 0);
        with_zero[1] = 0x7f;
        let (r, _) = mpints(&RawSignature::EcdsaP256Fixed(fixed(&with_zero, &ones(32, 0x01))));
        assert_eq!((r.len(), r[0]), (31, 0x7f));
        // ...and one in front of a byte with its top bit set is stripped and put back once: 32 bytes `00 80 ..`.
        let mut zero_then_high = ones(32, 0);
        zero_then_high[1] = 0x80;
        let (r, _) = mpints(&RawSignature::EcdsaP256Fixed(fixed(&zero_then_high, &ones(32, 0x01))));
        assert_eq!((r.len(), &r[..2]), (32, &[0x00, 0x80][..]));
        // Several leading zero bytes, and a tiny number.
        let mut small = vec![0u8; 32];
        small[31] = 5;
        let (r, s) = mpints(&RawSignature::EcdsaP256Fixed(fixed(&small, &small)));
        assert_eq!((r, s), (vec![5], vec![5]));
        small[31] = 0x80;
        assert_eq!(mpints(&RawSignature::EcdsaP256Fixed(fixed(&small, &small))).0, vec![0, 0x80]);
        // Zero is not a signature.
        let zero = [0u8; 32];
        for raw in [fixed(&zero, &ones(32, 1)), fixed(&ones(32, 1), &zero), [0u8; 64]] {
            assert!(matches!(ssh_signature_blob(&RawSignature::EcdsaP256Fixed(raw)), Err(SignError::RawSignature(_))));
        }
    }

    #[test]
    fn the_mpint_round_trips_for_many_values_including_the_edges() {
        // Every first-byte class in r and s, with and without leading zeros, and a spread of pseudo-random values.
        let mut values: Vec<[u8; 32]> = vec![];
        for first in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
            for second in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
                for third in [0x00u8, 0x80] {
                    let mut v = [0x11u8; 32];
                    (v[0], v[1], v[2]) = (first, second, third);
                    values.push(v);
                }
            }
        }
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..500 {
            let mut v = [0u8; 32];
            for b in &mut v {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                *b = u8::try_from(x & 0xff).unwrap();
            }
            values.push(v);
        }
        for r in &values {
            for s in [&values[0], &values[7], &values[values.len() - 1], r] {
                let raw = fixed(r, s);
                let blob = ssh_signature_blob(&RawSignature::EcdsaP256Fixed(raw));
                if r.iter().all(|b| *b == 0) || s.iter().all(|b| *b == 0) {
                    assert!(blob.is_err());
                    continue;
                }
                assert_eq!(decode_ecdsa(&blob.unwrap()), raw);
                // And the DER form of the same signature gives the same blob.
                assert_eq!(
                    ssh_signature_blob(&RawSignature::EcdsaP256Der(to_der(&raw))).unwrap(),
                    ssh_signature_blob(&RawSignature::EcdsaP256Fixed(raw)).unwrap()
                );
            }
        }
    }

    #[test]
    fn der_is_converted_once_and_strictly() {
        let ok = |der: &[u8]| ssh_signature_blob(&RawSignature::EcdsaP256Der(der.to_vec()));
        // r = 1, s = 2; r with a needed zero byte; the longest, 72 bytes.
        assert_eq!(decode_ecdsa(&ok(&[0x30, 6, 2, 1, 1, 2, 1, 2]).unwrap())[31], 1);
        let high = [vec![0x30, 8, 2, 2, 0x00, 0x80, 2, 2, 0x00, 0x81]].concat();
        let blob = ok(&high).unwrap();
        let decoded = decode_ecdsa(&blob);
        assert_eq!((decoded[31], decoded[63]), (0x80, 0x81));
        let mut longest = vec![0x30, 70, 2, 33, 0];
        longest.extend([0x80; 32]);
        longest.extend([2, 33, 0]);
        longest.extend([0xfe; 32]);
        assert_eq!(longest.len(), 72);
        assert_eq!(decode_ecdsa(&ok(&longest).unwrap())[..32], [0x80; 32]);
        // Everything that is not strict DER of two positive integers of at most 32 bytes.
        let bad: &[&[u8]] = &[
            &[],
            &[0x30],
            &[0x31, 6, 2, 1, 1, 2, 1, 2],
            &[0x30, 7, 2, 1, 1, 2, 1, 2],
            &[0x30, 5, 2, 1, 1, 2, 1, 2],
            &[0x30, 6, 2, 1, 1, 2, 1, 2, 0],
            &[0x30, 6, 3, 1, 1, 2, 1, 2],
            &[0x30, 6, 2, 1, 1, 3, 1, 2],
            &[0x30, 6, 2, 0, 2, 1, 1, 2],
            &[0x30, 4, 2, 1, 1],
            &[0x30, 6, 2, 1, 0xff, 2, 1, 2],
            &[0x30, 7, 2, 2, 0x00, 0x01, 2, 1, 2],
            &[0x30, 0x81, 6, 2, 1, 1, 2, 1, 2],
            &[0x30, 6, 2, 1, 0, 2, 1, 2],
            &[0x30, 4, 2, 9, 1, 1, 1],
        ];
        for der in bad {
            assert!(matches!(ok(der), Err(SignError::RawSignature(_))), "{der:02x?}");
        }
        // An integer of 33 bytes without a leading zero, and one of 34.
        let mut too_long = vec![0x30, 39, 2, 33];
        too_long.extend([0x01; 33]);
        too_long.extend([2, 1, 1]);
        assert!(matches!(ok(&too_long), Err(SignError::RawSignature(_))));
    }

    #[test]
    fn what_is_armoured_is_checked_against_the_key() {
        let ed = ed25519_blob(&[3; 32]);
        let p256 = p256_blob(&[4; 65]);
        let ed_sig = ssh_signature_blob(&RawSignature::Ed25519([9; 64])).unwrap();
        let ec_sig = ssh_signature_blob(&RawSignature::EcdsaP256Fixed([7; 64])).unwrap();
        assert!(armour_signature(Namespace::Call, &ed, &ed_sig).is_ok());
        assert!(armour_signature(Namespace::Call, &p256, &ec_sig).is_ok());
        // The algorithm is the key's.
        assert!(matches!(armour_signature(Namespace::Call, &ed, &ec_sig), Err(SignError::RawSignature(_))));
        assert!(matches!(armour_signature(Namespace::Call, &p256, &ed_sig), Err(SignError::RawSignature(_))));
        // Another key type, an unreadable blob, a malformed signature blob.
        let rsa = strings(&[b"ssh-rsa", &[1], &[2]]);
        assert!(
            matches!(armour_signature(Namespace::Call, &rsa, &ed_sig), Err(SignError::UnsupportedKeyType(t)) if t == "ssh-rsa")
        );
        assert!(armour_signature(Namespace::Call, &[1, 2], &ed_sig).is_err());
        assert!(armour_signature(Namespace::Call, &ed, &strings(&[b"ssh-ed25519", &[1; 63]])).is_err());
        assert!(armour_signature(Namespace::Call, &ed, &[ed_sig.clone(), vec![0]].concat()).is_err());
        assert!(
            armour_signature(Namespace::Call, &p256, &strings(&[b"ecdsa-sha2-nistp256", &strings(&[&[0x80], &[1]])]))
                .is_err(),
            "a negative mpint"
        );
        assert!(
            armour_signature(Namespace::Call, &p256, &strings(&[b"ecdsa-sha2-nistp256", &strings(&[&[0, 1], &[1]])]))
                .is_err(),
            "an unneeded zero"
        );
        assert!(
            armour_signature(Namespace::Call, &p256, &strings(&[b"ecdsa-sha2-nistp256", &strings(&[&[1], &[]])]))
                .is_err(),
            "an empty s"
        );
        // What is written looks armoured, wraps at 70 and ends with a newline.
        let sig = armour_signature(Namespace::Approval, &ed, &ed_sig).unwrap();
        assert!(crate::sign::looks_armoured(&sig) && sig.ends_with("-----END SSH SIGNATURE-----\n"));
        assert!(sig.lines().skip(1).filter(|l| !l.starts_with("-----")).all(|l| l.len() <= 70));
    }

    // --- against `ssh-keygen` ---------------------------------------------------------------------

    #[test]
    fn ed25519_is_byte_for_byte_what_ssh_keygen_writes_plain_and_certified_under_either_ca() {
        let env = Env::new();
        let (ed_ca, _) = env.ca("ca-ed", false);
        let (p256_ca, _) = env.ca("ca-p256", true);
        for (label, ca) in
            [("plain", None), ("under an Ed25519 CA", Some(&ed_ca)), ("under a P-256 CA", Some(&p256_ca))]
        {
            let (holder, file, _) =
                env.ed25519(&format!("k-{}", label.replace(' ', "-")), ca.map(|c| (c.as_path(), "alice")));
            let signer = HolderSigner(holder);
            for ns in Namespace::ALL {
                for message in messages() {
                    let ours = signer.sign(ns, &message).unwrap();
                    let theirs = Signer::plain(&file).sign(ns, &message).unwrap();
                    assert_eq!(ours, theirs, "{label} {ns:?} {} bytes", message.len());
                }
            }
        }
    }

    #[test]
    fn ssh_keygen_verifies_what_the_seam_writes_for_every_key_and_certificate_combination() {
        let env = Env::new();
        let (ed_ca, ed_ca_pub) = env.ca("ca-ed", false);
        let (p256_ca, p256_ca_pub) = env.ca("ca-p256", true);
        let message = b"the message".to_vec();
        for ns in Namespace::ALL {
            let name = ns.as_str();
            // Plain keys, Ed25519 and P-256 (raw `r || s` and DER).
            let (ed, _, ed_line) = env.ed25519("plain-ed", None);
            let (p, p_line) = env.p256("plain-p", None, false);
            let (pd, pd_line) = env.p256("plain-pd", None, true);
            for (label, holder, line) in [("ed25519", ed, ed_line), ("p256", p, p_line), ("p256 der", pd, pd_line)] {
                let sig = HolderSigner(holder).sign(ns, &message).unwrap();
                assert!(
                    ssh_verify(&env, &format!("jan namespaces=\"{name}\" {line}\n"), "jan", name, &sig, &message),
                    "{label} {ns:?}"
                );
                assert!(
                    !ssh_verify(&env, &format!("jan namespaces=\"{name}\" {line}\n"), "jan", name, &sig, b"changed"),
                    "{label} {ns:?}"
                );
                let other = Namespace::ALL.iter().find(|n| **n != ns).unwrap().as_str();
                assert!(
                    !ssh_verify(&env, &format!("jan namespaces=\"{other}\" {line}\n"), "jan", other, &sig, &message),
                    "{label}: another namespace"
                );
            }
            // Certified keys, every combination: the certificate is the key blob in the signature, `ssh-keygen` checks it.
            for (ca_label, ca, ca_pub) in [("ed25519 ca", &ed_ca, &ed_ca_pub), ("p256 ca", &p256_ca, &p256_ca_pub)] {
                let allowed = format!("* cert-authority,namespaces=\"{name}\" {ca_pub}\n");
                let (ed, _, _) = env.ed25519(&format!("cert-ed-{ca_label:.2}"), Some((ca, "alice")));
                let (p, _) = env.p256(&format!("cert-p-{ca_label:.2}"), Some((ca, "alice")), false);
                let (pd, _) = env.p256(&format!("cert-pd-{ca_label:.2}"), Some((ca, "alice")), true);
                for (label, holder) in [("ed25519", ed), ("p256", p), ("p256 der", pd)] {
                    let sig = HolderSigner(holder).sign(ns, &message).unwrap();
                    assert!(
                        ssh_verify(&env, &allowed, "alice", name, &sig, &message),
                        "{label} certified by {ca_label} {ns:?}"
                    );
                    assert!(
                        !ssh_verify(&env, &allowed, "bob", name, &sig, &message),
                        "{label} certified by {ca_label}: another principal"
                    );
                    assert!(
                        !ssh_verify(&env, &allowed, "alice", name, &sig, b"changed"),
                        "{label} certified by {ca_label}"
                    );
                }
            }
        }
    }

    #[test]
    fn the_signing_functions_of_the_crate_take_any_signer() {
        // The stage-2 combination: an Ed25519 agent key certified by a P-256 delegation key, signing a call; a
        // P-256 plain key signing a sign-in; a P-256 broker key certified by an Ed25519 CA signing a standing.
        let env = Env::new();
        let (p256_ca, p256_ca_pub) = env.ca("ca-p256", true);
        let (ed_ca, ed_ca_pub) = env.ca("ca-ed", false);
        let (agent, _, _) = env.ed25519("agent", Some((&p256_ca, "alice")));
        let call = crate::call::Call::compose(&crate::call::CallContent {
            id: crate::call::CallId::parse("3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11").unwrap(),
            deadline: "2026-11-11T15:06:05Z".parse().unwrap(),
            service: crate::call::ServiceId { host: "a.example".into(), name: "probe".into() },
            action: "rt procs".into(),
            params: vec!["pid=4711".into()],
            claim: None,
        })
        .unwrap();
        let signer: &dyn SshsigSigner = &HolderSigner(agent);
        let sig = crate::sign::sign_call(signer, &call).unwrap();
        assert_eq!(crate::sign::verify_call(&call, &sig, &p256_ca_pub).unwrap(), "alice");
        assert_eq!(crate::sign::verify_call_agent(&call, &sig, &p256_ca_pub).unwrap().person, "alice");

        let (conn, conn_line) = env.p256("conn", None, true);
        let doc = crate::broker::ConnectionDocument::compose("jan", &[1; 32], &[2; 32]).unwrap();
        let sig = doc.sign(&HolderSigner(conn)).unwrap();
        doc.verify(&PublicKey::parse(&conn_line).unwrap(), &sig).unwrap();
        verify_connection("jan", &PublicKey::parse(&conn_line).unwrap(), &sig, crate::hash::Document::as_bytes(&doc))
            .unwrap();

        let (broker, _) = env.p256("broker", Some((&ed_ca, "broker")), false);
        let standing = crate::broker::Standing::compose(&crate::broker::StandingContent {
            to: "jan".into(),
            nonce: [1; 32],
            n: 0,
            blocked: false,
            blocked_keys: vec![],
            withdrawn: vec![],
            certificates: vec![],
            groups: vec![],
        })
        .unwrap();
        let sig = standing.sign(&HolderSigner(broker)).unwrap();
        verify_broker(&ed_ca_pub, &sig, crate::hash::Document::as_bytes(&standing)).unwrap();
        crate::broker::Standing::parse_verified(crate::hash::Document::as_bytes(&standing).to_vec(), &sig, &ed_ca_pub)
            .unwrap();
    }

    #[test]
    fn p256_signatures_with_the_top_bit_set_in_r_and_in_s_verify() {
        // Not left to chance in one run: sign until a signature with the top bit set in r, one with it set in s, and one
        // with neither have each been seen, and verify each of them with `ssh-keygen`.
        let env = Env::new();
        let (holder, line) = env.p256("edge", None, false);
        let (mut r_high, mut s_high, mut neither) = (false, false, false);
        let mut count = 0;
        while !(r_high && s_high && neither) && count < 400 {
            count += 1;
            let message = format!("message {count}").into_bytes();
            let raw = holder.sign_raw(&signing_input(Namespace::Approval, &message)).unwrap();
            let RawSignature::EcdsaP256Fixed(fixed) = &raw else { panic!() };
            let (r_top, s_top) = (fixed[0] & 0x80 != 0, fixed[32] & 0x80 != 0);
            let first_time = (r_top && !r_high) || (s_top && !s_high) || (!r_top && !s_top && !neither);
            (r_high, s_high, neither) = (r_high || r_top, s_high || s_top, neither || (!r_top && !s_top));
            if first_time {
                let sig =
                    armour_signature(Namespace::Approval, &holder.blob, &ssh_signature_blob(&raw).unwrap()).unwrap();
                assert!(
                    ssh_verify(
                        &env,
                        &format!("jan namespaces=\"approval-v1@procession\" {line}\n"),
                        "jan",
                        "approval-v1@procession",
                        &sig,
                        &message
                    ),
                    "r_top {r_top} s_top {s_top}"
                );
            }
        }
        assert!(r_high && s_high && neither, "not all seen in {count} signatures");
        // And a run of plain signatures, as a sanity check of the whole path.
        for i in 0..40 {
            let message = format!("run {i}").into_bytes();
            let sig = HolderSigner(Holder {
                pair: Pair::P256(
                    EcdsaKeyPair::from_pkcs8(
                        &ECDSA_P256_SHA256_FIXED_SIGNING,
                        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                            .unwrap()
                            .as_ref(),
                        &SystemRandom::new(),
                    )
                    .unwrap(),
                ),
                blob: holder.blob.clone(),
                der: i % 2 == 0,
            })
            .sign(Namespace::Call, &message);
            // A different key under the first key's blob is refused by `ssh-keygen`, never accepted.
            let sig = sig.unwrap();
            assert!(!ssh_verify(
                &env,
                &format!("jan namespaces=\"call-v1@procession\" {line}\n"),
                "jan",
                "call-v1@procession",
                &sig,
                &message
            ));
        }
    }

    #[test]
    fn a_holder_that_fails_or_answers_for_another_algorithm_writes_nothing() {
        let env = Env::new();
        let (mut ed, _, _) = env.ed25519("k", None);
        let (p, _) = env.p256("p", None, false);
        // The key blob is Ed25519's; the holder signs with a P-256 key: refused, not armoured.
        let wrong = Holder { pair: p.pair, blob: ed.blob.clone(), der: false };
        assert!(matches!(HolderSigner(wrong).sign(Namespace::Call, b"x"), Err(SignError::RawSignature(_))));
        // The key blob is not a key.
        ed.blob = vec![1, 2, 3];
        assert!(HolderSigner(ed).sign(Namespace::Call, b"x").is_err());
        struct Failing;
        impl KeyHolder for Failing {
            fn key_blob(&self) -> Vec<u8> {
                ed25519_blob(&[0; 32])
            }
            fn sign_raw(&self, _: &[u8]) -> Result<RawSignature, SignError> {
                Err(SignError::Holder("the key is locked".into()))
            }
        }
        assert!(
            matches!(HolderSigner(Failing).sign(Namespace::Call, b"x"), Err(SignError::Holder(m)) if m == "the key is locked")
        );
    }
}
