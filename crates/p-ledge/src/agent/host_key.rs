//! An SSH server's host key, parsed from its wire blob, able to verify the
//! signature the server made over the key-exchange hash. Used for
//! `session-bind@openssh.com`: the client passes that signature on so the SSH
//! agent can check which host the connection really reached.
//!
//! Supported: `ssh-ed25519`, `ecdsa-sha2-nistp256` and `-nistp384`, and
//! `ssh-rsa` keys of 2048 to 8192 bits with `rsa-sha2-256` or `rsa-sha2-512`
//! signatures, each also as an OpenSSH host certificate (the signature is
//! made with the certified key). Anything else does not parse, and a binding
//! with it stays unverifiable. In particular:
//!
//! - `ecdsa-sha2-nistp521` is not supported (Atticus supports it): the
//!   verification library offers no P-521. A host with only a P-521 key
//!   cannot be verified, so logins to it are refused while a host binding is
//!   required.
//! - RSA above 8192 bits is not supported (Atticus: up to 16384), for the
//!   same reason. `ssh-rsa` with SHA-1 signatures is refused, as in Atticus.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ring::digest;
use ring::signature::{self, UnparsedPublicKey};

use super::wire::{Reader, put_string, strings};

/// Shortest RSA modulus accepted, in bits.
pub const MIN_RSA_BITS: usize = 2048;
/// Longest RSA modulus accepted, in bits (the most the verifier checks).
pub const MAX_RSA_BITS: usize = 8192;

const CERT_SUFFIX: &str = "-cert-v01@openssh.com";

/// The elliptic curves supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    /// NIST P-256, with SHA-256.
    P256,
    /// NIST P-384, with SHA-384.
    P384,
}

impl Curve {
    fn name(self) -> &'static str {
        match self {
            Self::P256 => "nistp256",
            Self::P384 => "nistp384",
        }
    }

    fn scalar_len(self) -> usize {
        match self {
            Self::P256 => 32,
            Self::P384 => 48,
        }
    }

    fn algorithm(self) -> &'static signature::EcdsaVerificationAlgorithm {
        match self {
            Self::P256 => &signature::ECDSA_P256_SHA256_FIXED,
            Self::P384 => &signature::ECDSA_P384_SHA384_FIXED,
        }
    }
}

/// The public key itself, without any certificate around it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Material {
    /// 32 bytes.
    Ed25519(Vec<u8>),
    /// `q` is the uncompressed point.
    Ecdsa { curve: Curve, q: Vec<u8> },
    /// Both as big-endian bytes, `n` without leading zeros.
    Rsa { e: Vec<u8>, n: Vec<u8> },
}

/// The fields of an OpenSSH certificate that decide which host names it
/// vouches for (`PROTOCOL.certkeys`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// 1 for a user certificate, 2 for a host certificate.
    pub cert_type: u32,
    /// The names the certificate is for.
    pub principals: Vec<String>,
    /// First second it is valid (Unix time).
    pub valid_after: u64,
    /// First second it is no longer valid (Unix time).
    pub valid_before: u64,
    /// Wire blob of the CA's key.
    pub ca_key: Vec<u8>,
}

impl Certificate {
    const HOST_TYPE: u32 = 2;

    /// Whether this is a host certificate and `now` (Unix time, seconds) is
    /// inside its validity.
    #[must_use]
    pub fn is_valid_host_certificate(&self, now: u64) -> bool {
        self.cert_type == Self::HOST_TYPE && self.valid_after <= now && now < self.valid_before
    }
}

/// A parsed host key, plain or certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKey {
    /// The wire blob as the server sent it (the certificate, for a
    /// certificate host key).
    pub blob: Vec<u8>,
    /// The key type string, e.g. `ssh-ed25519-cert-v01@openssh.com`.
    pub key_type: String,
    /// The key that signs for the host.
    pub material: Material,
    /// Present for an OpenSSH certificate.
    pub certificate: Option<Certificate>,
}

impl HostKey {
    /// Parses a wire blob. `None` for any key type or shape not supported,
    /// for trailing bytes, and for a certificate whose CA signature does not
    /// verify: principals from an unsigned certificate would name any host
    /// the forger likes.
    #[must_use]
    pub fn parse(blob: &[u8]) -> Option<Self> {
        let mut reader = Reader::new(blob);
        let key_type = reader.utf8()?;
        let (base_type, is_certificate) = match key_type.strip_suffix(CERT_SUFFIX) {
            Some(base) => (base, true),
            None => (key_type, false),
        };
        if is_certificate {
            reader.string()?; // nonce
        }
        let material = match base_type {
            "ssh-ed25519" => {
                let public = reader.string()?;
                (public.len() == 32).then(|| Material::Ed25519(public.to_vec()))?
            }
            "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" => {
                let curve = if base_type.ends_with("256") { Curve::P256 } else { Curve::P384 };
                (reader.utf8()? == curve.name()).then_some(())?;
                Material::Ecdsa { curve, q: reader.string()?.to_vec() }
            }
            "ssh-rsa" => {
                let e = reader.string()?;
                let n = strip_leading_zeros(reader.string()?);
                (MIN_RSA_BITS..=MAX_RSA_BITS).contains(&bit_length(n)).then_some(())?;
                Material::Rsa { e: strip_leading_zeros(e).to_vec(), n: n.to_vec() }
            }
            _ => return None,
        };
        let certificate = if is_certificate { Some(parse_certificate_tail(&mut reader, blob)?) } else { None };
        (reader.remaining() == 0).then_some(())?;
        Some(Self { blob: blob.to_vec(), key_type: key_type.to_owned(), material, certificate })
    }

    /// Whether this is a certificate.
    #[must_use]
    pub fn is_certificate(&self) -> bool {
        self.certificate.is_some()
    }

    /// The certified key alone, as `known_hosts` lists a plain host key. For
    /// a plain key this is the blob itself.
    #[must_use]
    pub fn plain_blob(&self) -> Vec<u8> {
        if !self.is_certificate() {
            return self.blob.clone();
        }
        match &self.material {
            Material::Ed25519(public) => strings(&[b"ssh-ed25519", public]),
            Material::Ecdsa { curve, q } => {
                strings(&[format!("ecdsa-sha2-{}", curve.name()).as_bytes(), curve.name().as_bytes(), q])
            }
            Material::Rsa { e, n } => {
                let mut out = Vec::new();
                put_string(&mut out, b"ssh-rsa");
                super::wire::put_mpint(&mut out, e);
                super::wire::put_mpint(&mut out, n);
                out
            }
        }
    }

    /// `SHA256:<base64 without padding>`, as `ssh-keygen -l` prints it: over
    /// the plain key, also for a certificate.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let hash = digest::digest(&digest::SHA256, &self.plain_blob());
        let mut text = String::from("SHA256:");
        text.push_str(&STANDARD_NO_PAD.encode(hash.as_ref()));
        text
    }

    /// Whether `signature_blob` (`string` type, `string` signature) is this
    /// key's valid signature over `data`.
    #[must_use]
    pub fn verify(&self, signature_blob: &[u8], data: &[u8]) -> bool {
        let mut reader = Reader::new(signature_blob);
        let (Some(sig_type), Some(sig)) = (reader.utf8(), reader.string()) else { return false };
        if reader.remaining() != 0 {
            return false;
        }
        match &self.material {
            Material::Ed25519(public) => {
                sig_type == "ssh-ed25519"
                    && UnparsedPublicKey::new(&signature::ED25519, public).verify(data, sig).is_ok()
            }
            Material::Ecdsa { curve, q } => {
                if sig_type != format!("ecdsa-sha2-{}", curve.name()) {
                    return false;
                }
                let Some(fixed) = ecdsa_fixed(sig, curve.scalar_len()) else { return false };
                UnparsedPublicKey::new(curve.algorithm(), q).verify(data, &fixed).is_ok()
            }
            Material::Rsa { e, n } => {
                // `ssh-rsa` as a signature type means SHA-1: refused.
                let params: &signature::RsaParameters = match sig_type {
                    "rsa-sha2-256" => &signature::RSA_PKCS1_2048_8192_SHA256,
                    "rsa-sha2-512" => &signature::RSA_PKCS1_2048_8192_SHA512,
                    _ => return false,
                };
                signature::RsaPublicKeyComponents { n: n.as_slice(), e: e.as_slice() }.verify(params, data, sig).is_ok()
            }
        }
    }
}

/// The fields after the key material, through the CA's signature. `blob` is
/// the whole certificate; the CA signed everything before its own signature.
fn parse_certificate_tail(reader: &mut Reader<'_>, blob: &[u8]) -> Option<Certificate> {
    reader.u64()?; // serial
    let cert_type = reader.u32()?;
    reader.string()?; // key id
    let packed = reader.string()?;
    let valid_after = reader.u64()?;
    let valid_before = reader.u64()?;
    reader.string()?; // critical options
    reader.string()?; // extensions
    reader.string()?; // reserved
    let ca_key = reader.string()?;
    let signed_part = &blob[..reader.offset()];
    let ca_signature = reader.string()?;
    let ca = HostKey::parse(ca_key).filter(|ca| !ca.is_certificate())?;
    if !ca.verify(ca_signature, signed_part) {
        return None;
    }
    let mut principals = Vec::new();
    let mut names = Reader::new(packed);
    while names.remaining() > 0 {
        principals.push(names.utf8()?.to_owned());
    }
    Some(Certificate { cert_type, principals, valid_after, valid_before, ca_key: ca_key.to_vec() })
}

fn strip_leading_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len());
    &bytes[start..]
}

fn bit_length(number: &[u8]) -> usize {
    match number.first() {
        None => 0,
        Some(first) => (number.len() - 1) * 8 + (8 - first.leading_zeros() as usize),
    }
}

/// An ECDSA signature body (`mpint` r, `mpint` s, nothing after) as one
/// fixed-width r‖s, or `None` if either is negative or wider than the curve.
fn ecdsa_fixed(body: &[u8], width: usize) -> Option<Vec<u8>> {
    let mut reader = Reader::new(body);
    let (r, s) = (reader.string()?, reader.string()?);
    if reader.remaining() != 0 {
        return None;
    }
    let mut out = vec![0; 2 * width];
    for (index, scalar) in [r, s].into_iter().enumerate() {
        if scalar.first().is_some_and(|byte| byte & 0x80 != 0) {
            return None;
        }
        let scalar = strip_leading_zeros(scalar);
        let slot = &mut out[index * width..(index + 1) * width];
        let start = width.checked_sub(scalar.len())?;
        slot[start..].copy_from_slice(scalar);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;

    use super::*;
    use crate::agent::testing::{SESSION_ID, certificate, ecdsa_key, ed25519_key, fresh_ed25519_key, rsa_key};
    use crate::agent::wire::put_mpint;

    /// The blob of the key in a `.pub` file of `testdata`.
    fn blob_of(line: &str) -> Vec<u8> {
        STANDARD.decode(line.split_whitespace().nth(1).expect("key field")).expect("base64")
    }

    const NOW: u64 = 1_800_000_000; // 2027-01-15

    // ported: testHostKey_verifiesEveryKeyType (P-521 differs: see the module docs)
    #[test]
    fn every_supported_key_type_verifies_a_signature_over_the_session_id() {
        let ca = ed25519_key(7);
        let ed = ed25519_key(3);
        let p256 = ecdsa_key(false);
        let hosts = [
            ("ssh-ed25519", ed25519_key(2)),
            ("ecdsa nistp256", ecdsa_key(false)),
            ("ecdsa nistp384", ecdsa_key(true)),
            ("rsa-sha2-256", rsa_key("rsa-sha2-256")),
            ("rsa-sha2-512", rsa_key("rsa-sha2-512")),
            ("ed25519 host certificate", certificate(&ed, &ca, &["host.example.org"], 2, u64::MAX, None)),
            ("ecdsa host certificate", certificate(&p256, &ca, &["host.example.org"], 2, u64::MAX, None)),
        ];
        for (name, host) in hosts {
            let key = HostKey::parse(&host.blob).unwrap_or_else(|| panic!("{name} parses"));
            assert!(key.verify(&host.sign(&SESSION_ID), &SESSION_ID), "{name}");
        }
    }

    #[test]
    fn a_p521_key_does_not_parse_so_a_binding_with_it_is_unverifiable() {
        let blob = blob_of(include_str!("../../testdata/host_p521.pub"));
        assert_eq!(HostKey::parse(&blob), None);
    }

    // ported: testHostKey_fingerprint, against what ssh-keygen -l printed
    #[test]
    fn the_fingerprint_is_what_ssh_keygen_prints_and_a_certificate_has_that_of_its_key() {
        let plain = HostKey::parse(&blob_of(include_str!("../../testdata/host_ed.pub"))).expect("plain");
        assert_eq!(plain.fingerprint(), "SHA256:1T2d+o1uviO6G2bFXBL66gkeZjLHNtJDENGwH+Q0A+w");
        let cert = HostKey::parse(&blob_of(include_str!("../../testdata/host_ed-cert.pub"))).expect("certificate");
        assert_eq!(cert.fingerprint(), plain.fingerprint());
        assert_eq!(cert.plain_blob(), plain.blob);
        let p256 =
            HostKey::parse(&blob_of(include_str!("../../testdata/host_p256-cert.pub"))).expect("p256 certificate");
        assert_eq!(p256.fingerprint(), "SHA256:03BKZqwHOAF5ufeYfLIh1BVFHt18w+OQXlGlik1kMz8");
        let plain_p256 = HostKey::parse(&blob_of(include_str!("../../testdata/host_p256.pub"))).expect("p256");
        assert_eq!(p256.plain_blob(), plain_p256.blob);
    }

    // new: certificates made by OpenSSH itself
    #[test]
    fn certificates_made_by_ssh_keygen_parse_with_their_principals_and_validity() {
        let cert =
            HostKey::parse(&blob_of(include_str!("../../testdata/host_ed-cert.pub"))).expect("ed25519, ed25519 CA");
        let certificate = cert.certificate.expect("is a certificate");
        assert_eq!(certificate.principals, ["host.example.org", "backup.example.org"]);
        assert_eq!(certificate.cert_type, 2);
        assert!(certificate.is_valid_host_certificate(NOW));
        assert!(!certificate.is_valid_host_certificate(1_500_000_000)); // 2017: before 2020-01-01
        assert!(!certificate.is_valid_host_certificate(4_102_444_800)); // 2100-01-01
        assert_eq!(certificate.ca_key, blob_of(include_str!("../../testdata/ca_ed.pub")));
        // The CA here is RSA and signs with rsa-sha2-512.
        let cert = HostKey::parse(&blob_of(include_str!("../../testdata/host_p256-cert.pub"))).expect("p256, RSA CA");
        assert_eq!(cert.certificate.expect("certificate").ca_key, blob_of(include_str!("../../testdata/ca_rsa.pub")));
    }

    #[test]
    fn a_user_certificate_parses_but_is_not_a_host_certificate() {
        let cert =
            HostKey::parse(&blob_of(include_str!("../../testdata/host_rsa-cert.pub"))).expect("user certificate");
        let certificate = cert.certificate.expect("certificate");
        assert_eq!(certificate.cert_type, 1);
        assert!(!certificate.is_valid_host_certificate(NOW));
    }

    #[test]
    fn a_tampered_certificate_does_not_parse() {
        let mut blob = blob_of(include_str!("../../testdata/host_ed-cert.pub"));
        let position = blob.windows(16).position(|w| w == b"host.example.org").expect("principal");
        blob[position] = b'H';
        assert_eq!(HostKey::parse(&blob), None);
    }

    // ported: testHostCertificate_forgedCASignatureRejected
    #[test]
    fn a_certificate_whose_ca_signature_does_not_verify_does_not_parse() {
        let ca = ed25519_key(8);
        let host = ed25519_key(9);
        let good = certificate(&host, &ca, &["prod.example.org"], 2, u64::MAX, None);
        assert!(HostKey::parse(&good.blob).is_some());
        let zeros = strings(&[b"ssh-ed25519", &[0; 64]]);
        let forged = certificate(&host, &ca, &["github.com"], 2, u64::MAX, Some(zeros));
        assert_eq!(HostKey::parse(&forged.blob), None);
        let other = certificate(&host, &ca, &["github.com"], 2, u64::MAX, Some(fresh_ed25519_key().sign(b"x")));
        assert_eq!(HostKey::parse(&other.blob), None);
        // A certificate as the CA of a certificate is not accepted.
        let inner = certificate(&ca, &ed25519_key(10), &["ca"], 2, u64::MAX, None);
        let nested = certificate(&host, &inner, &["prod.example.org"], 2, u64::MAX, None);
        assert_eq!(HostKey::parse(&nested.blob), None);
        // A certificate cut short does not read past its end.
        assert_eq!(HostKey::parse(&good.blob[..good.blob.len() - 1]), None);
    }

    // ported: testHostKey_rejectsWrongSignatures
    #[test]
    fn wrong_signatures_fail() {
        let host = ed25519_key(11);
        let key = HostKey::parse(&host.blob).expect("parses");
        assert!(!key.verify(&host.sign(&[1]), &SESSION_ID), "signature over other data");
        assert!(!key.verify(&ed25519_key(12).sign(&SESSION_ID), &SESSION_ID), "another host's signature");
        let mut trailing = host.sign(&SESSION_ID);
        trailing.push(0);
        assert!(!key.verify(&trailing, &SESSION_ID), "trailing bytes");
        let p256 = ecdsa_key(false);
        let p256_key = HostKey::parse(&p256.blob).expect("parses");
        assert!(!p256_key.verify(&ecdsa_key(true).sign(&SESSION_ID), &SESSION_ID), "another curve");
        assert!(!p256_key.verify(&host.sign(&SESSION_ID), &SESSION_ID), "another algorithm");
        assert!(!key.verify(&[], &SESSION_ID));
        assert!(!key.verify(&[0, 0, 0, 200], &SESSION_ID));
    }

    #[test]
    fn rsa_with_sha1_is_refused_whatever_the_bytes() {
        let sha1 = rsa_key("ssh-rsa");
        let key = HostKey::parse(&sha1.blob).expect("the key parses");
        assert!(!key.verify(&sha1.sign(&SESSION_ID), &SESSION_ID));
        let good = rsa_key("rsa-sha2-256");
        assert!(key.verify(&good.sign(&SESSION_ID), &SESSION_ID));
        assert!(!key.verify(&good.sign(&[1]), &SESSION_ID));
    }

    #[test]
    fn an_ecdsa_signature_with_a_negative_or_too_wide_scalar_fails() {
        let host = ecdsa_key(false);
        let key = HostKey::parse(&host.blob).expect("parses");
        let negative = {
            let mut body = Vec::new();
            put_string(&mut body, &[0x80; 32]); // not an mpint: high bit without a leading zero
            put_mpint(&mut body, &[1; 32]);
            strings(&[b"ecdsa-sha2-nistp256", &body])
        };
        assert!(!key.verify(&negative, &SESSION_ID));
        let wide = {
            let mut body = Vec::new();
            put_mpint(&mut body, &[1; 33]);
            put_mpint(&mut body, &[1; 32]);
            strings(&[b"ecdsa-sha2-nistp256", &body])
        };
        assert!(!key.verify(&wide, &SESSION_ID));
    }

    // ported: the key-shape cases of testHostKey_rejectsWrongSignatures
    #[test]
    fn keys_of_a_shape_not_accepted_do_not_parse() {
        let host = ed25519_key(13);
        let mut trailing = host.blob.clone();
        trailing.push(0);
        assert_eq!(HostKey::parse(&trailing), None, "trailing bytes");
        assert_eq!(HostKey::parse(&strings(&[b"sk-ssh-ed25519@openssh.com", &[1; 32]])), None, "unknown type");
        assert_eq!(HostKey::parse(&strings(&[b"ssh-dss", &[1; 128]])), None, "DSA");
        assert_eq!(HostKey::parse(&strings(&[b"ssh-ed25519", &[1; 31]])), None, "short ed25519");
        assert_eq!(HostKey::parse(&[]), None);
        // The modulus decides: 1024 bits does not parse, 2048 does, 8192 does, 8193 does not.
        let rsa = |bits: usize| {
            let mut n = vec![0xFF; bits / 8];
            n[0] = 0x80;
            let mut blob = Vec::new();
            put_string(&mut blob, b"ssh-rsa");
            put_mpint(&mut blob, &[1, 0, 1]);
            put_mpint(&mut blob, &n);
            blob
        };
        assert_eq!(HostKey::parse(&rsa(1024)), None);
        assert!(HostKey::parse(&rsa(2048)).is_some());
        assert!(HostKey::parse(&rsa(8192)).is_some());
        assert_eq!(HostKey::parse(&rsa(8200)), None);
        // An ECDSA key whose curve name does not match its type.
        let blob = strings(&[b"ecdsa-sha2-nistp256", b"nistp384", &[4; 65]]);
        assert_eq!(HostKey::parse(&blob), None);
        // A truncated key does not read past its end.
        assert_eq!(HostKey::parse(&host.blob[..host.blob.len() - 1]), None);
    }
}
