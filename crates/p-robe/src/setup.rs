//! `probe setup`: the service's key and its certificate, made with
//! `ssh-keygen`. **Stage 1 only.** In a site this is the roll-out's job: the
//! site's provisioning issues the certificate as root with the host's key,
//! renews it before it ends (30 days), and the service never reads the host
//! key (`doc/approvals.md`, section 5). Here whoever runs this reads the host
//! key, so it runs as root, once, and the certificate must be renewed by
//! running it again.

use std::path::Path;
use std::process::{Command, Stdio};

use crate::service::SERVICE_NAME;

/// How long a certificate is valid, as `ssh-keygen -V`.
const VALIDITY: &str = "+30d";

/// Makes `<out>/service-key` and `<out>/service-key-cert.pub`, certified by
/// `host_key` for `probe@<host>`.
///
/// # Errors
/// What `ssh-keygen` said, or why a file could not be prepared.
pub fn run(host_key: &Path, host: &str, out: &Path) -> Result<(), String> {
    let principal = format!("{SERVICE_NAME}@{host}");
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let key = out.join("service-key");
    if key.exists() {
        return Err(format!("{} exists; remove it to make a new key", key.display()));
    }
    keygen(&["-q", "-t", "ed25519", "-N", "", "-C", &principal, "-f", &path(&key)])?;
    // The principal is the one the request's signature is verified under
    // (`approval-formats.md`, section 7); `-O clear`: no login extension.
    keygen(&[
        "-q",
        "-s",
        &path(host_key),
        "-I",
        &principal,
        "-n",
        &principal,
        "-V",
        VALIDITY,
        "-O",
        "clear",
        &format!("{}.pub", path(&key)),
    ])?;
    std::fs::set_permissions(&key, std::os::unix::fs::PermissionsExt::from_mode(0o600)).map_err(|e| e.to_string())
}

fn path(p: &Path) -> String {
    p.display().to_string()
}

fn keygen(args: &[&str]) -> Result<(), String> {
    let output = Command::new("ssh-keygen")
        .args(args)
        .env("SSH_ASKPASS", "false")
        .env("SSH_ASKPASS_REQUIRE", "force")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run ssh-keygen: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!("ssh-keygen: {}", String::from_utf8_lossy(&output.stderr).trim()))
    }
}

/// What to tell the person who ran it.
pub const NOTE: &str = "Made the service's key and a certificate for it from the host key, valid 30 days. This is a stage-1 setup: in a site the roll-out of the site's provisioning does it, as root, and renews it; here it must be run again before the certificate ends.";
