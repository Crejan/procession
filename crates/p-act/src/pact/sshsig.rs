//! The in-process SSHSIG writer, for one namespace: `call-v1@procession`, by
//! an Ed25519 key, certified or not.
//!
//! This is a second writer of the format that `ssh-keygen -Y sign` writes, and
//! it exists only here (decision of the designer, `proposals/pact.md` (a)):
//! everything else in `p-act` signs through `ssh-keygen`. Its specification is
//! the test: for the same key, certificate and message the output must be, byte
//! for byte, what `ssh-keygen -Y sign` writes (Ed25519 is deterministic), and
//! `ssh-keygen -Y verify` must accept it.

use crate::call::Call;
use crate::hash::Document;
use crate::sign::{Namespace, put_string};
use crate::sshsig::{RawSignature, armour_in, signing_input_in, ssh_signature_blob};
use ring::signature::{Ed25519KeyPair, KeyPair};

/// An Ed25519 key, and its certificate if it has one, that signs calls.
pub struct CallSigner {
    pair: Ed25519KeyPair,
    /// The wire form of what stands in the signature as the public key: the certificate, else the key.
    public_key_blob: Vec<u8>,
}

impl std::fmt::Debug for CallSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CallSigner(..)")
    }
}

/// The wire form of an Ed25519 public key.
pub(crate) fn ed25519_blob(public: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    put_string(&mut blob, b"ssh-ed25519");
    put_string(&mut blob, public);
    blob
}

impl CallSigner {
    /// `certificate_blob` is the wire form of the certificate (the base64 field of a `-cert.pub` line, decoded).
    #[must_use]
    pub fn new(pair: Ed25519KeyPair, certificate_blob: Option<Vec<u8>>) -> CallSigner {
        let public_key_blob = certificate_blob.unwrap_or_else(|| ed25519_blob(pair.public_key().as_ref()));
        CallSigner { pair, public_key_blob }
    }

    /// The armoured signature over a call's bytes, namespace `call-v1@procession`. It takes a
    /// [`Call`] and not bytes: there is no way to ask this for anything else.
    #[must_use]
    pub fn sign_call(&self, call: &Call) -> String {
        self.write(Namespace::Call.as_str(), call.as_bytes())
    }

    fn write(&self, namespace: &str, message: &[u8]) -> String {
        // The form is written once, in `crate::sshsig`; this only signs the bytes it asks for.
        let signature = self.pair.sign(&signing_input_in(namespace, message));
        let mut raw = [0u8; 64];
        raw.copy_from_slice(signature.as_ref());
        // An Ed25519 signature blob is well formed by construction.
        let signature_blob = ssh_signature_blob(&RawSignature::Ed25519(raw)).unwrap_or_default();
        armour_in(namespace, &self.public_key_blob, &signature_blob)
    }

    /// For the tests of the writer's specification only: any namespace.
    #[cfg(test)]
    pub(crate) fn write_in(&self, namespace: &str, message: &[u8]) -> String {
        self.write(namespace, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pact::fixture::Fixture;
    use crate::sign::{PublicKey, Signer, signature_certificate, signature_fingerprint, verify_call};
    use std::io::Write;
    use std::process::{Command, Stdio};

    fn keygen_sign(file: &std::path::Path, namespace: &str, message: &[u8]) -> String {
        let mut child = Command::new("ssh-keygen")
            .args(["-Y", "sign", "-n", namespace, "-f"])
            .arg(file)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(message).unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    }

    fn verify(
        allowed: &str,
        principal: &str,
        namespace: &str,
        sig: &str,
        message: &[u8],
        dir: &std::path::Path,
    ) -> bool {
        let (allowed_file, sig_file) = (dir.join("allowed-x"), dir.join("sig-x"));
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
        child.stdin.take().unwrap().write_all(message).unwrap();
        child.wait().unwrap().success()
    }

    /// Messages of different lengths, around the places where framing and wrapping change, and large ones.
    fn messages() -> Vec<Vec<u8>> {
        let mut all: Vec<Vec<u8>> = vec![vec![], b"a".to_vec(), b"{\"v\":1}".to_vec()];
        for n in [55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 255, 256, 1000, 4096, 16 * 1024, 70_000, 200_000] {
            all.push((0..n).map(|i| u8::try_from(i * 7 % 251).unwrap()).collect());
        }
        all
    }

    const NAMESPACES: [&str; 7] = [
        "call-v1@procession",
        "request-v1@procession",
        "approval-v1@procession",
        "clearance-v1@procession",
        "file",
        "git",
        "a-very-long-namespace-name-that-goes-on-and-on-and-on@example.org",
    ];

    #[test]
    fn the_output_is_what_ssh_keygen_writes_with_a_certificate() {
        let f = Fixture::new("alice", &[]);
        let signer = f.signer();
        let cert_file = f.agent_cert_file();
        for namespace in NAMESPACES {
            for message in messages() {
                let ours = signer.write_in(namespace, &message);
                let theirs = keygen_sign(&cert_file, namespace, &message);
                assert_eq!(ours, theirs, "{namespace}, {} bytes", message.len());
            }
        }
    }

    #[test]
    fn the_output_is_what_ssh_keygen_writes_without_a_certificate() {
        let f = Fixture::new("alice", &[]);
        let signer = f.plain_signer();
        for namespace in NAMESPACES {
            for message in messages() {
                assert_eq!(
                    signer.write_in(namespace, &message),
                    keygen_sign(&f.agent, namespace, &message),
                    "{namespace}, {} bytes",
                    message.len()
                );
            }
        }
    }

    #[test]
    fn ssh_keygen_verifies_what_it_writes_for_calls() {
        let f = Fixture::new("alice", &[]);
        let signer = f.signer();
        let delegation = PublicKey::read(&f.delegation_pub()).unwrap();
        for (i, params) in [vec![], vec!["pid=4711".to_owned()], vec!["x".repeat(512); 30]].into_iter().enumerate() {
            let call = f.call("probe", "a.example", params, i);
            let sig = signer.sign_call(&call);
            assert_eq!(verify_call(&call, &sig, &delegation).unwrap(), "alice");
            // ...and the library's own signer writes the same bytes.
            let theirs = crate::sign::sign_call(&Signer::certified(&f.agent).unwrap(), &call).unwrap();
            assert_eq!(sig, theirs);
            assert_eq!(signature_certificate(&sig).unwrap().principals, ["alice"]);
        }
    }

    #[test]
    fn ssh_keygen_refuses_what_is_not_for_the_namespace_or_the_bytes() {
        let f = Fixture::new("alice", &[]);
        let signer = f.signer();
        let call = f.call("probe", "a.example", vec![], 0);
        let sig = signer.sign_call(&call);
        let allowed = format!(
            "alice cert-authority,namespaces=\"call-v1@procession\" {}\n",
            PublicKey::read(&f.delegation_pub()).unwrap()
        );
        let ok = |sig: &str, ns: &str, msg: &[u8]| verify(&allowed, "alice", ns, sig, msg, f.dir.path());
        assert!(ok(&sig, "call-v1@procession", call.as_bytes()));
        assert!(!ok(&sig, "request-v1@procession", call.as_bytes()), "wrong namespace");
        assert!(!ok(&sig, "call-v1@procession", b"changed"), "changed bytes");
        let other = signer.write_in("request-v1@procession", call.as_bytes());
        assert!(!ok(&other, "call-v1@procession", call.as_bytes()), "signed in another namespace");
        // An expired certificate is the library's to see; the writer only carries it.
        let expired = Fixture::new_with_validity("alice", &[], "20200101Z:20200102Z");
        let sig = expired.signer().sign_call(&call);
        let allowed = format!(
            "alice cert-authority,namespaces=\"call-v1@procession\" {}\n",
            PublicKey::read(&expired.delegation_pub()).unwrap()
        );
        assert!(!verify(&allowed, "alice", "call-v1@procession", &sig, call.as_bytes(), expired.dir.path()));
    }

    #[test]
    fn the_key_behind_the_signature_is_the_agents() {
        let f = Fixture::new("alice", &["extension:groups@procession=a,b"]);
        let call = f.call("probe", "a.example", vec![], 0);
        let sig = f.signer().sign_call(&call);
        let agent_pub = PublicKey::read(&f.agent_pub()).unwrap();
        assert_eq!(signature_fingerprint(&sig).unwrap(), agent_pub.fingerprint());
        let plain = f.plain_signer().sign_call(&call);
        assert_eq!(signature_fingerprint(&plain).unwrap(), agent_pub.fingerprint());
    }

    #[test]
    fn the_armour_wraps_at_seventy_columns_and_ends_with_a_newline() {
        let f = Fixture::new("alice", &[]);
        let sig = f.signer().write_in("call-v1@procession", &[1; 5000]);
        let lines: Vec<&str> = sig.lines().collect();
        assert_eq!(lines.first(), Some(&"-----BEGIN SSH SIGNATURE-----"));
        assert_eq!(lines.last(), Some(&"-----END SSH SIGNATURE-----"));
        assert!(lines[1..lines.len() - 2].iter().all(|l| l.len() == 70));
        assert!(sig.ends_with('\n'));
    }
}
