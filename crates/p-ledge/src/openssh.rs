//! What `pledge agents start` hands to an agent: its Ed25519 key as an
//! unmodified OpenSSH private key block, and its certificate, issued by the
//! person's delegation key (`doc/approval-formats.md`, section 3.1).
//!
//! Both are written here, not by `ssh-keygen`: the delegation key lives in the
//! key holder (in hardware, later), so there is no file for `ssh-keygen -s` to
//! sign with. The holder signs the certificate's bytes; it parses nothing. The
//! results are checked against `ssh-keygen` in the tests, and every
//! certificate is checked by the same code that checks calls before it is
//! handed out.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::agent::wire::{put_string, put_u32, put_u64, strings};
use crate::error::{Error, Result};
use crate::sshsig::wrap;

const CERT_TYPE: &str = "ssh-ed25519-cert-v01@openssh.com";
/// The extension that carries a delegation's groups.
pub const GROUPS_EXTENSION: &str = "groups@procession";

/// Bytes that are secret: never printed, zeroed when dropped.
pub struct Secret(Vec<u8>);

impl Secret {
    /// The bytes. Whoever calls this is responsible for them.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

/// An agent's key pair, made in memory from the system's random source.
pub struct AgentKey {
    seed: Secret,
    public: [u8; 32],
}

impl AgentKey {
    /// A new key.
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if the random source fails.
    pub fn generate() -> Result<Self> {
        let mut seed = vec![0_u8; 32];
        SystemRandom::new().fill(&mut seed).map_err(|_| Error::Holder("the system's random source failed".into()))?;
        let seed = Secret(seed);
        let pair = Ed25519KeyPair::from_seed_unchecked(seed.expose())
            .map_err(|_| Error::Holder("a seed did not make a key".into()))?;
        let public = pair.public_key().as_ref().try_into().map_err(|_| Error::Holder("bad public key".into()))?;
        Ok(Self { seed, public })
    }

    /// The public key's wire blob.
    #[must_use]
    pub fn public_blob(&self) -> Vec<u8> {
        strings(&[b"ssh-ed25519", &self.public])
    }

    /// The public key as a line, `ssh-ed25519 AAAA...`.
    #[must_use]
    pub fn public_line(&self) -> String {
        format!("ssh-ed25519 {}", STANDARD.encode(self.public_blob()))
    }

    /// The signature blob (`string` type, `string` signature) over `data`.
    ///
    /// # Errors
    ///
    /// [`Error::Holder`] if the seed does not load.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let pair = Ed25519KeyPair::from_seed_unchecked(self.seed.expose()).map_err(|_| Error::Holder("seed".into()))?;
        Ok(strings(&[b"ssh-ed25519", pair.sign(data).as_ref()]))
    }

    /// The OpenSSH private key block (`openssh-key-v1`, no passphrase), exactly
    /// as `ssh-keygen` writes it.
    #[must_use]
    pub fn private_block(&self, comment: &str) -> Secret {
        let mut check = [0_u8; 4];
        // A check value that is not secret; it only has to be the same twice.
        let _ = SystemRandom::new().fill(&mut check);
        let mut private = Vec::new();
        private.extend_from_slice(&check);
        private.extend_from_slice(&check);
        put_string(&mut private, b"ssh-ed25519");
        put_string(&mut private, &self.public);
        let mut both = self.seed.expose().to_vec();
        both.extend_from_slice(&self.public);
        put_string(&mut private, &both);
        put_string(&mut private, comment.as_bytes());
        let mut pad = 1_u8;
        while private.len() % 8 != 0 {
            private.push(pad);
            pad += 1;
        }
        let mut blob = b"openssh-key-v1\0".to_vec();
        put_string(&mut blob, b"none");
        put_string(&mut blob, b"none");
        put_string(&mut blob, b"");
        put_u32(&mut blob, 1);
        put_string(&mut blob, &self.public_blob());
        put_string(&mut blob, &private);
        both.fill(0);
        private.fill(0);
        Secret(wrap("OPENSSH PRIVATE KEY", &blob).into_bytes())
    }
}

/// What an agent's certificate says.
pub struct CertificateParts<'a> {
    /// The person: its only principal.
    pub person: &'a str,
    /// The delegation's groups, sorted, without duplicates; may be empty.
    pub groups: &'a [String],
    /// A free label for dialogs and the record.
    pub label: &'a str,
    /// First second it is valid (Unix time).
    pub valid_after: u64,
    /// First second it is no longer valid (Unix time).
    pub valid_before: u64,
    /// The certificate's serial.
    pub serial: u64,
}

/// The part of the certificate that the delegation key signs: everything up to
/// and including the issuing key.
///
/// # Errors
///
/// [`Error::Holder`] if the random source fails.
pub fn certificate_to_sign(
    agent_public: &[u8; 32],
    parts: &CertificateParts<'_>,
    issuer_blob: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce = [0_u8; 32];
    SystemRandom::new().fill(&mut nonce).map_err(|_| Error::Holder("the system's random source failed".into()))?;
    let mut out = Vec::new();
    put_string(&mut out, CERT_TYPE.as_bytes());
    put_string(&mut out, &nonce);
    put_string(&mut out, agent_public);
    put_u64(&mut out, parts.serial);
    put_u32(&mut out, 1); // a user certificate
    put_string(&mut out, parts.label.as_bytes());
    put_string(&mut out, &strings(&[parts.person.as_bytes()]));
    put_u64(&mut out, parts.valid_after);
    put_u64(&mut out, parts.valid_before);
    put_string(&mut out, b""); // critical options: none
    let mut extensions = Vec::new();
    if !parts.groups.is_empty() {
        put_string(&mut extensions, GROUPS_EXTENSION.as_bytes());
        put_string(&mut extensions, &strings(&[parts.groups.join(",").as_bytes()]));
    }
    put_string(&mut out, &extensions);
    put_string(&mut out, b""); // reserved
    put_string(&mut out, issuer_blob);
    Ok(out)
}

/// The finished certificate blob: the signed part and the signature blob.
#[must_use]
pub fn certificate_blob(signed_part: &[u8], signature_blob: &[u8]) -> Vec<u8> {
    let mut out = signed_part.to_vec();
    put_string(&mut out, signature_blob);
    out
}

/// The certificate as a `-cert.pub` line.
#[must_use]
pub fn certificate_line(blob: &[u8]) -> String {
    format!("{CERT_TYPE} {}", STANDARD.encode(blob))
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;
    use crate::testing::TestDir;

    #[test]
    fn a_secret_never_prints() {
        assert_eq!(format!("{:?}", Secret(b"hunter2".to_vec())), "Secret(..)");
    }

    #[test]
    fn ssh_keygen_reads_the_private_key_block_and_finds_the_public_key() {
        let dir = TestDir::new("openssh-key");
        let key = AgentKey::generate().expect("key");
        let file = dir.path().join("agent");
        std::fs::write(&file, key.private_block("pledge test").expose()).expect("write");
        std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o600)).expect("chmod");
        let output = Command::new("ssh-keygen").args(["-y", "-P", "", "-f"]).arg(&file).output().expect("run");
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        let printed = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        assert_eq!(printed.split(' ').take(2).collect::<Vec<_>>().join(" "), key.public_line());
        let block = String::from_utf8(key.private_block("x").expose().to_vec()).expect("text");
        assert!(
            block.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n")
                && block.ends_with("-----END OPENSSH PRIVATE KEY-----\n")
        );
    }

    #[test]
    fn the_key_signs_what_ring_verifies() {
        use ring::signature::{ED25519, UnparsedPublicKey};
        let key = AgentKey::generate().expect("key");
        let signature = key.sign(b"data").expect("sign");
        let mut reader = crate::agent::wire::Reader::new(&signature);
        assert_eq!(reader.utf8(), Some("ssh-ed25519"));
        UnparsedPublicKey::new(&ED25519, key.public).verify(b"data", reader.string().expect("sig")).expect("verifies");
    }
}
