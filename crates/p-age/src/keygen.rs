//! The three `ssh-keygen` operations the broker needs and `p-act` does not
//! offer yet: verifying a plain-key signature (the sign-in's connection
//! document), signing in the broker's own namespace (the standing), and
//! telling which key signed a bare certificate.
//!
//! **To move to `p-act`.** Everything else the broker signs or verifies goes
//! through `p-act`; this module exists only so that the connections can be
//! built before `p-act` has them, and is small on purpose.

use std::ffi::OsStr;
use std::io::{self, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use p_act::sign::{Fingerprint, Namespace, PublicKey, looks_armoured};
use thiserror::Error;

/// Why an `ssh-keygen` operation failed.
#[derive(Debug, Error)]
pub enum KeygenError {
    #[error("cannot run ssh-keygen: {0}")]
    Io(#[from] io::Error),
    #[error("ssh-keygen refused: {0}")]
    Refused(String),
    #[error("the signature is not an armoured SSH signature")]
    NotArmoured,
    #[error("ssh-keygen printed no signing key for the certificate")]
    NoIssuer,
}

fn run(args: &[&OsStr], stdin: &[u8]) -> Result<Vec<u8>, KeygenError> {
    let mut child = Command::new("ssh-keygen")
        .args(args)
        .env("SSH_ASKPASS", "false")
        .env("SSH_ASKPASS_REQUIRE", "force")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut pipe = child.stdin.take().ok_or_else(|| io::Error::other("no stdin"))?;
    let output = std::thread::scope(|s| {
        s.spawn(move || {
            let _ = pipe.write_all(stdin);
        });
        child.wait_with_output()
    })?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        Err(KeygenError::Refused(if stderr.is_empty() { output.status.to_string() } else { stderr }))
    }
}

/// `ssh-keygen -Y verify` of `sig` over `data`, in `namespace`, against `key`
/// listed directly (not as a certificate authority) under `principal`.
pub fn verify_plain(
    namespace: Namespace,
    principal: &str,
    key: &PublicKey,
    sig: &str,
    data: &[u8],
) -> Result<(), KeygenError> {
    if !looks_armoured(sig) {
        return Err(KeygenError::NotArmoured);
    }
    let dir = tempfile::tempdir()?;
    let (allowed, sigfile) = (dir.path().join("allowed"), dir.path().join("sig"));
    std::fs::write(&allowed, format!("{principal} namespaces=\"{}\" {key}\n", namespace.as_str()))?;
    std::fs::write(&sigfile, sig)?;
    run(
        &[
            "-Y".as_ref(),
            "verify".as_ref(),
            "-f".as_ref(),
            allowed.as_os_str(),
            "-I".as_ref(),
            principal.as_ref(),
            "-n".as_ref(),
            namespace.as_str().as_ref(),
            "-s".as_ref(),
            sigfile.as_os_str(),
        ],
        data,
    )
    .map(drop)
}

/// `ssh-keygen -Y sign` of `data` in `namespace` with the key in `key_file`
/// (for a certified key, the `-cert.pub` file beside it, as `p-act`'s signer
/// does). The armoured signature.
pub fn sign(key_file: &Path, namespace: Namespace, data: &[u8]) -> Result<String, KeygenError> {
    let out = run(
        &[
            "-Y".as_ref(),
            "sign".as_ref(),
            "-f".as_ref(),
            key_file.as_os_str(),
            "-n".as_ref(),
            namespace.as_str().as_ref(),
        ],
        data,
    )?;
    let sig = String::from_utf8(out).map_err(|_| KeygenError::NotArmoured)?;
    if looks_armoured(&sig) { Ok(sig) } else { Err(KeygenError::NotArmoured) }
}

/// The fingerprint of the key that signed the certificate on the line `cert`
/// (a `-cert.pub` file's content). `ssh-keygen -L` reads the certificate
/// through the same code `sshd` does, which verifies the certificate's
/// signature against the key inside it and fails if it does not match; what is
/// returned is that key's fingerprint, for the caller to compare with the
/// issuer it expects.
pub fn certificate_issuer(cert: &str) -> Result<Fingerprint, KeygenError> {
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("cert.pub");
    std::fs::write(&file, format!("{}\n", cert.trim_end()))?;
    let out = run(&["-L".as_ref(), "-f".as_ref(), file.as_os_str()], b"")?;
    let text = String::from_utf8_lossy(&out);
    text.lines()
        .find_map(|l| l.trim().strip_prefix("Signing CA:"))
        .and_then(|rest| rest.split_whitespace().find(|w| w.starts_with("SHA256:")))
        .and_then(|fp| fp.parse().ok())
        .ok_or(KeygenError::NoIssuer)
}
