//! Real keys for the tests of `pact`, made with `ssh-keygen` in a temporary directory.

use super::sshsig::CallSigner;
use crate::call::{Call, CallContent, CallId, ServiceId};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::signature::Ed25519KeyPair;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;

pub(crate) struct Fixture {
    pub dir: TempDir,
    pub delegation: PathBuf,
    pub agent: PathBuf,
}

fn keygen(args: &[&str]) {
    let out = Command::new("ssh-keygen").args(args).stdin(Stdio::null()).output().expect("these tests need ssh-keygen");
    assert!(out.status.success(), "ssh-keygen {args:?}: {}", String::from_utf8_lossy(&out.stderr));
}

impl Fixture {
    /// An Ed25519 delegation key and an agent key certified by it for `person`, issued as pledge does (`-O clear`).
    pub fn new(person: &str, options: &[&str]) -> Fixture {
        Fixture::new_with_validity(person, options, "20200101Z:20990101Z")
    }

    pub fn new_with_validity(person: &str, options: &[&str], validity: &str) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let (delegation, agent) = (dir.path().join("delegation"), dir.path().join("agent"));
        for key in [&delegation, &agent] {
            keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", key.to_str().unwrap()]);
        }
        let mut args =
            vec!["-q", "-s", delegation.to_str().unwrap(), "-I", "agent", "-n", person, "-V", validity, "-O", "clear"];
        for o in options {
            args.extend(["-O", o]);
        }
        let pub_file = format!("{}.pub", agent.display());
        args.push(&pub_file);
        keygen(&args);
        Fixture { dir, delegation, agent }
    }

    pub fn agent_cert_file(&self) -> PathBuf {
        PathBuf::from(format!("{}-cert.pub", self.agent.display()))
    }

    pub fn agent_pub(&self) -> PathBuf {
        PathBuf::from(format!("{}.pub", self.agent.display()))
    }

    pub fn delegation_pub(&self) -> PathBuf {
        PathBuf::from(format!("{}.pub", self.delegation.display()))
    }

    pub fn key_file_text(&self) -> String {
        std::fs::read_to_string(&self.agent).unwrap()
    }

    pub fn cert_line(&self) -> String {
        std::fs::read_to_string(self.agent_cert_file()).unwrap().trim_end().to_owned()
    }

    /// The bundle's bytes: the configuration line, the key block, the certificate line.
    pub fn bundle(&self, config: &str) -> Vec<u8> {
        format!("{config}\n{}{}\n", self.key_file_text(), self.cert_line()).into_bytes()
    }

    pub fn default_config(url: &str) -> String {
        format!(r#"{{"v":1,"services":[{{"host":"a.example","name":"probe","url":"{url}"}}],"deadline_seconds":120}}"#)
    }

    fn pair(&self) -> Ed25519KeyPair {
        let (seed, public) = read_seed(&self.key_file_text());
        Ed25519KeyPair::from_seed_and_public_key(&seed, &public).unwrap()
    }

    pub fn signer(&self) -> CallSigner {
        let cert = self.cert_line();
        let blob = STANDARD.decode(cert.split_whitespace().nth(1).unwrap()).unwrap();
        CallSigner::new(self.pair(), Some(blob))
    }

    pub fn plain_signer(&self) -> CallSigner {
        CallSigner::new(self.pair(), None)
    }

    pub fn call(&self, name: &str, host: &str, params: Vec<String>, n: usize) -> Call {
        Call::compose(&CallContent {
            id: CallId::parse(&format!("3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f{n:04x}")).unwrap(),
            deadline: "2026-11-11T15:06:05Z".parse().unwrap(),
            service: ServiceId { host: host.into(), name: name.into() },
            action: "rt procs".into(),
            params,
            claim: None,
        })
        .unwrap()
    }
}

/// The seed and public key out of an unencrypted OpenSSH Ed25519 private key file. Test-only and trusting:
/// the real parser is `bundle`'s, and is tested on its own.
fn read_seed(text: &str) -> ([u8; 32], [u8; 32]) {
    let body: String = text.lines().filter(|l| !l.starts_with("-----")).collect();
    let blob = STANDARD.decode(body).unwrap();
    let at = blob.windows(11).position(|w| w == b"ssh-ed25519").unwrap();
    // After the public key's copy: ... "ssh-ed25519" (public section), then in the private section:
    // checkint x2, type, pub(32), priv(64) = seed || pub. Find the second occurrence.
    let second = blob[at + 11..].windows(11).position(|w| w == b"ssh-ed25519").unwrap() + at + 11;
    let mut p = second + 11;
    p += 4; // length of pub
    let public: [u8; 32] = blob[p..p + 32].try_into().unwrap();
    p += 32 + 4;
    let seed: [u8; 32] = blob[p..p + 32].try_into().unwrap();
    (seed, public)
}

#[allow(dead_code)]
pub(crate) fn path_str(p: &Path) -> &str {
    p.to_str().unwrap()
}

#[allow(dead_code)]
pub(crate) fn _unused(_: ServiceId) {}
