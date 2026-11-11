//! Fixtures for the tests of this module: host keys that sign, host
//! certificates, and builders for the data a client sends.

use std::rc::Rc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, Ed25519KeyPair, KeyPair, RsaKeyPair};

use super::wire::{put_mpint, put_string, put_u32, put_u64, strings};

pub const SESSION_ID: [u8; 32] = [0x5E; 32];
pub const HOSTBOUND: &str = "publickey-hostbound-v00@openssh.com";

type Signer = Rc<dyn Fn(&[u8]) -> Vec<u8>>;

/// A key that can sign, with the wire blob of its public part.
pub struct TestKey {
    pub blob: Vec<u8>,
    signer: Signer,
}

impl TestKey {
    /// The signature blob (`string` type, `string` signature) over `data`.
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        (self.signer)(data)
    }
}

pub fn ed25519_key(seed: u8) -> TestKey {
    let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).expect("seed");
    let blob = strings(&[b"ssh-ed25519", pair.public_key().as_ref()]);
    TestKey { blob, signer: Rc::new(move |data| strings(&[b"ssh-ed25519", pair.sign(data).as_ref()])) }
}

/// A fresh ed25519 key with a seed no other call used.
pub fn fresh_ed25519_key() -> TestKey {
    use std::sync::atomic::{AtomicU8, Ordering};
    static NEXT: AtomicU8 = AtomicU8::new(1);
    ed25519_key(NEXT.fetch_add(1, Ordering::Relaxed))
}

pub fn ecdsa_key(p384: bool) -> TestKey {
    let (alg, curve, size) = if p384 {
        (&signature::ECDSA_P384_SHA384_FIXED_SIGNING, "nistp384", 48)
    } else {
        (&signature::ECDSA_P256_SHA256_FIXED_SIGNING, "nistp256", 32)
    };
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(alg, &rng).expect("generate");
    let pair = EcdsaKeyPair::from_pkcs8(alg, pkcs8.as_ref(), &rng).expect("load");
    let key_type = format!("ecdsa-sha2-{curve}");
    let blob = strings(&[key_type.as_bytes(), curve.as_bytes(), pair.public_key().as_ref()]);
    TestKey {
        blob,
        signer: Rc::new(move |data| {
            let raw = pair.sign(&rng, data).expect("sign");
            let (r, s) = raw.as_ref().split_at(size);
            let mut body = Vec::new();
            put_mpint(&mut body, r);
            put_mpint(&mut body, s);
            strings(&[key_type.as_bytes(), &body])
        }),
    }
}

/// The 2048-bit RSA key in `testdata/host_rsa.pem`. `sig_type` is the
/// signature algorithm the key claims: `rsa-sha2-256`, `rsa-sha2-512`, or
/// `ssh-rsa` (the bytes are SHA-256's, so only the claim is wrong).
pub fn rsa_key(sig_type: &'static str) -> TestKey {
    let pem = include_str!("../../testdata/host_rsa.pem");
    let body: String = pem.lines().filter(|line| !line.starts_with("-----")).collect();
    let der = STANDARD.decode(body).expect("base64");
    let pair = RsaKeyPair::from_pkcs8(&der).expect("rsa key");
    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-rsa");
    let components = signature::RsaPublicKeyComponents::<Vec<u8>>::from(pair.public());
    put_mpint(&mut blob, &components.e);
    put_mpint(&mut blob, &components.n);
    let rng = SystemRandom::new();
    TestKey {
        blob,
        signer: Rc::new(move |data| {
            let padding: &dyn signature::RsaEncoding =
                if sig_type == "rsa-sha2-512" { &signature::RSA_PKCS1_SHA512 } else { &signature::RSA_PKCS1_SHA256 };
            let mut sig = vec![0; pair.public().modulus_len()];
            pair.sign(padding, &rng, data, &mut sig).expect("sign");
            strings(&[sig_type.as_bytes(), &sig])
        }),
    }
}

/// An OpenSSH certificate around `key`'s public part, signed by `ca` (or
/// carrying `forged` instead of the CA's signature). Signatures are the
/// certified key's own.
pub fn certificate(
    key: &TestKey,
    ca: &TestKey,
    principals: &[&str],
    cert_type: u32,
    valid_before: u64,
    forged: Option<Vec<u8>>,
) -> TestKey {
    let mut reader = super::wire::Reader::new(&key.blob);
    let key_type = reader.utf8().expect("type").to_owned();
    let rest = reader.rest().to_vec();
    let mut blob = Vec::new();
    put_string(&mut blob, format!("{key_type}-cert-v01@openssh.com").as_bytes());
    put_string(&mut blob, &[0x4E; 32]);
    blob.extend_from_slice(&rest);
    put_u64(&mut blob, 1);
    put_u32(&mut blob, cert_type);
    put_string(&mut blob, b"host-id");
    let packed: Vec<u8> = principals.iter().flat_map(|p| strings(&[p.as_bytes()])).collect();
    put_string(&mut blob, &packed);
    put_u64(&mut blob, 0);
    put_u64(&mut blob, valid_before);
    for _ in 0..3 {
        put_string(&mut blob, b"");
    }
    put_string(&mut blob, &ca.blob);
    let signature = forged.unwrap_or_else(|| ca.sign(&blob));
    put_string(&mut blob, &signature);
    TestKey { blob, signer: Rc::clone(&key.signer) }
}

/// What a client signs for a login.
pub struct UserauthData {
    pub session_id: Vec<u8>,
    pub message: u8,
    pub user: Vec<u8>,
    pub service: &'static str,
    pub method: &'static str,
    pub flag: u8,
    pub algorithm: &'static str,
    pub key: Vec<u8>,
    pub host_key: Option<Vec<u8>>,
    pub trailing: Vec<u8>,
}

impl UserauthData {
    pub fn new(key: &[u8]) -> Self {
        Self {
            session_id: SESSION_ID.to_vec(),
            message: 50,
            user: b"jan".to_vec(),
            service: "ssh-connection",
            method: "publickey",
            flag: 1,
            algorithm: "ssh-ed25519",
            key: key.to_vec(),
            host_key: None,
            trailing: Vec::new(),
        }
    }

    pub fn hostbound(key: &[u8], host_key: &[u8]) -> Self {
        Self { method: HOSTBOUND, host_key: Some(host_key.to_vec()), ..Self::new(key) }
    }

    pub fn build(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(&mut out, &self.session_id);
        out.push(self.message);
        put_string(&mut out, &self.user);
        put_string(&mut out, self.service.as_bytes());
        put_string(&mut out, self.method.as_bytes());
        out.push(self.flag);
        put_string(&mut out, self.algorithm.as_bytes());
        put_string(&mut out, &self.key);
        if let Some(host_key) = &self.host_key {
            put_string(&mut out, host_key);
        }
        out.extend_from_slice(&self.trailing);
        out
    }
}

/// What a client signs for SSHSIG.
pub fn sshsig_data(namespace: &[u8], algorithm: &str, hash: &[u8], reserved: &[u8], trailing: &[u8]) -> Vec<u8> {
    let mut out = b"SSHSIG".to_vec();
    put_string(&mut out, namespace);
    put_string(&mut out, reserved);
    put_string(&mut out, algorithm.as_bytes());
    put_string(&mut out, hash);
    out.extend_from_slice(trailing);
    out
}

pub fn sshsig(namespace: &str) -> Vec<u8> {
    sshsig_data(namespace.as_bytes(), "sha512", &[0x5A; 64], b"", b"")
}

/// The body of a `session-bind@openssh.com` extension for `host`.
pub fn bind_body(
    host: &TestKey,
    session_id: &[u8],
    forwarding: u8,
    signature: Option<Vec<u8>>,
    trailing: &[u8],
) -> Vec<u8> {
    let mut out = Vec::new();
    put_string(&mut out, &host.blob);
    put_string(&mut out, session_id);
    put_string(&mut out, &signature.unwrap_or_else(|| host.sign(session_id)));
    out.push(forwarding);
    out.extend_from_slice(trailing);
    out
}

/// A `known_hosts` line for `key`.
pub fn known_hosts_line(patterns: &str, key: &[u8], marker: &str) -> String {
    let key_type = super::wire::Reader::new(key).utf8().expect("type").to_owned();
    let prefix = if marker.is_empty() { String::new() } else { format!("{marker} ") };
    format!("{prefix}{patterns} {key_type} {}", STANDARD.encode(key))
}
