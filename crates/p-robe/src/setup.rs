//! `probe setup`: the service's key and its certificate, made with `ssh-keygen`.
//! It is the same command for the first time and for every renewal: it **keeps the
//! service's key and replaces the certificate** (30 days). A root timer on the host
//! runs it with no arguments once 20 of the 30 days have passed (`SPEC.md`, "The two
//! parts"; `doc/approvals.md`, section 7). In a site the provisioning runs it once as
//! root; the service itself never reads the host key.
//!
//! The certificate is replaced by a rename, so the service, which reads it on every
//! signature (`ssh-keygen -Y sign` is given the certificate file), sees the old one or
//! the new one and never half of one, and needs no restart. A renewal that fails leaves
//! the old certificate as it was; a first run that fails leaves no key behind.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

use crate::service::SERVICE_NAME;

/// How long a certificate is valid, as `ssh-keygen -V`.
const VALIDITY: &str = "+30d";

/// What `run` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Done {
    /// A key and a certificate were made.
    Made,
    /// The key was kept and the certificate replaced.
    Renewed,
}

/// Makes `<out>/service-key` if it is not there, and replaces
/// `<out>/service-key-cert.pub` with a new certificate of `host_key` for
/// `probe@<host>`.
///
/// # Errors
/// What `ssh-keygen` said, or why a file could not be prepared.
pub fn run(host_key: &Path, host: &str, out: &Path) -> Result<Done, String> {
    let principal = format!("{SERVICE_NAME}@{host}");
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let (key, public, cert) = (out.join("service-key"), out.join("service-key.pub"), out.join("service-key-cert.pub"));
    let made = !key.exists();
    if made {
        keygen(&["-q", "-t", "ed25519", "-N", "", "-C", &principal, "-f", &path(&key)])?;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
    } else if !public.exists() {
        // The private half is there; the public half is derived from it.
        let derived = keygen_output(&["-y", "-f", &path(&key)])?;
        std::fs::write(&public, derived).map_err(|e| format!("{}: {e}", public.display()))?;
    }
    let issued = issue(host_key, &principal, out, &public, &cert, &key);
    if let (Err(_), true) = (&issued, made) {
        // A first run that failed leaves nothing half made.
        let _ = std::fs::remove_file(&key);
        let _ = std::fs::remove_file(&public);
    }
    issued?;
    Ok(if made { Done::Made } else { Done::Renewed })
}

/// Signs a copy of the public key in a directory of its own, and renames the certificate into place.
fn issue(host_key: &Path, principal: &str, out: &Path, public: &Path, cert: &Path, key: &Path) -> Result<(), String> {
    let work = out.join(format!(".renew-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir(&work).map_err(|e| format!("{}: {e}", work.display()))?;
    let result = (|| {
        let staged = work.join("service-key.pub");
        std::fs::copy(public, &staged).map_err(|e| e.to_string())?;
        // The principal is the one the request's signature is verified under
        // (`approval-formats.md`, section 7); `-O clear`: no login extension.
        keygen(&[
            "-q",
            "-s",
            &path(host_key),
            "-I",
            principal,
            "-n",
            principal,
            "-V",
            VALIDITY,
            "-O",
            "clear",
            &path(&staged),
        ])?;
        let fresh = work.join("service-key-cert.pub");
        // The new certificate belongs to whoever the key belongs to (the service's account, after a chown),
        // and is readable by it.
        let owner = key.metadata().map_err(|e| e.to_string())?;
        std::fs::set_permissions(&fresh, std::fs::Permissions::from_mode(0o644)).map_err(|e| e.to_string())?;
        // Not root's to keep: a failure to give it to the key's owner is not fatal on a host where this is not root.
        let _ = std::os::unix::fs::chown(&fresh, Some(owner.uid()), Some(owner.gid()));
        std::fs::rename(&fresh, cert).map_err(|e| format!("{}: {e}", cert.display()))
    })();
    let _ = std::fs::remove_dir_all(&work);
    result
}

fn path(p: &Path) -> String {
    p.display().to_string()
}

fn keygen(args: &[&str]) -> Result<(), String> {
    keygen_output(args).map(|_| ())
}

fn keygen_output(args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("ssh-keygen")
        .args(args)
        .env("SSH_ASKPASS", "false")
        .env("SSH_ASKPASS_REQUIRE", "force")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("cannot run ssh-keygen: {e}"))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!("ssh-keygen: {}", String::from_utf8_lossy(&output.stderr).trim()))
    }
}

/// What to tell the person who ran it.
#[must_use]
pub fn note(done: Done) -> &'static str {
    match done {
        Done::Made => {
            "Made the service's key and a certificate for it from the host key, valid 30 days. A root timer renews it: `probe setup` again, with no arguments, once 20 days have passed (the runbook has the unit files)."
        }
        Done::Renewed => {
            "Kept the service's key and replaced its certificate with a new one from the host key, valid 30 days."
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::days_left;

    fn host_key(dir: &Path) -> std::path::PathBuf {
        let key = dir.join("host");
        keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", &path(&key)]).unwrap();
        key
    }

    fn now() -> i64 {
        p_act::Timestamp::now().unwrap().unix()
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> =
            std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
        names.sort();
        names
    }

    #[test]
    fn the_first_run_makes_a_key_and_a_certificate_of_thirty_days_for_the_service_principal() {
        let dir = crate::testdir::new("setup");
        let host = host_key(&dir);
        let out = dir.join("probe");
        assert_eq!(run(&host, "a.example", &out), Ok(Done::Made));
        assert_eq!(files(&out), ["service-key", "service-key-cert.pub", "service-key.pub"], "no leftover of the work");
        assert_eq!(std::fs::metadata(out.join("service-key")).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(std::fs::metadata(out.join("service-key-cert.pub")).unwrap().permissions().mode() & 0o777, 0o644);
        assert!(matches!(days_left(&out.join("service-key-cert.pub"), now()), Ok(Some(29 | 30))));
        let listed = keygen_output(&["-L", "-f", &path(&out.join("service-key-cert.pub"))]).unwrap();
        assert!(String::from_utf8_lossy(&listed).contains("probe@a.example"));
    }

    #[test]
    fn the_second_run_keeps_the_key_and_replaces_the_certificate() {
        let dir = crate::testdir::new("setup");
        let host = host_key(&dir);
        let out = dir.join("probe");
        run(&host, "a.example", &out).unwrap();
        let (key, public, cert) = (
            std::fs::read(out.join("service-key")).unwrap(),
            std::fs::read(out.join("service-key.pub")).unwrap(),
            std::fs::read(out.join("service-key-cert.pub")).unwrap(),
        );
        assert_eq!(run(&host, "a.example", &out), Ok(Done::Renewed));
        assert_eq!(std::fs::read(out.join("service-key")).unwrap(), key, "the key is kept");
        assert_eq!(std::fs::read(out.join("service-key.pub")).unwrap(), public);
        assert_ne!(std::fs::read(out.join("service-key-cert.pub")).unwrap(), cert, "the certificate is new");
        assert_eq!(files(&out), ["service-key", "service-key-cert.pub", "service-key.pub"]);
        // Same command, run once more with the public half gone: derived from the private key.
        std::fs::remove_file(out.join("service-key.pub")).unwrap();
        assert_eq!(run(&host, "a.example", &out), Ok(Done::Renewed));
        assert_eq!(std::fs::read(out.join("service-key.pub")).unwrap(), public);
    }

    #[test]
    fn a_signer_made_before_the_renewal_signs_with_the_new_certificate_and_no_restart() {
        use p_act::sign::{Signer, sign_call, signature_certificate};
        use p_act::{Call, CallContent, CallId, ServiceId, Timestamp};
        let dir = crate::testdir::new("setup");
        let host = host_key(&dir);
        let out = dir.join("probe");
        run(&host, "a.example", &out).unwrap();
        // An old certificate that ends soon, in its place: as if 20 days had passed.
        let old = out.join("service-key-cert.pub");
        let staged = dir.join("short");
        std::fs::create_dir(&staged).unwrap();
        std::fs::copy(out.join("service-key.pub"), staged.join("service-key.pub")).unwrap();
        keygen(&[
            "-q",
            "-s",
            &path(&host),
            "-I",
            "probe@a.example",
            "-n",
            "probe@a.example",
            "-V",
            "+2d",
            "-O",
            "clear",
            &path(&staged.join("service-key.pub")),
        ])
        .unwrap();
        std::fs::copy(staged.join("service-key-cert.pub"), &old).unwrap();
        let signer = Signer::certified(out.join("service-key")).unwrap();
        let call = Call::compose(&CallContent {
            id: CallId::parse("3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11").unwrap(),
            deadline: Timestamp::from_unix(now() + 60).unwrap(),
            service: ServiceId { host: "a.example".into(), name: "probe".into() },
            action: "sys kit".into(),
            params: vec![],
            claim: None,
        })
        .unwrap();
        let before = signature_certificate(&sign_call(&signer, &call).unwrap()).unwrap().valid_before;
        run(&host, "a.example", &out).unwrap();
        let after = signature_certificate(&sign_call(&signer, &call).unwrap()).unwrap().valid_before;
        assert!(after > before + 20 * 86_400, "{before} -> {after}: the old signer used the new certificate");
    }

    #[test]
    fn a_renewal_that_fails_leaves_the_old_certificate_and_a_first_run_that_fails_leaves_no_key() {
        let dir = crate::testdir::new("setup");
        let host = host_key(&dir);
        let out = dir.join("probe");
        run(&host, "a.example", &out).unwrap();
        let cert = std::fs::read(out.join("service-key-cert.pub")).unwrap();
        let error = run(&dir.join("no-such-host-key"), "a.example", &out).unwrap_err();
        assert!(error.contains("ssh-keygen"), "{error}");
        assert_eq!(std::fs::read(out.join("service-key-cert.pub")).unwrap(), cert);
        assert_eq!(files(&out), ["service-key", "service-key-cert.pub", "service-key.pub"], "no leftover of the work");
        let fresh = dir.join("fresh");
        assert!(run(&dir.join("no-such-host-key"), "a.example", &fresh).is_err());
        assert_eq!(files(&fresh), Vec::<String>::new(), "nothing half made");
    }

    #[test]
    fn what_the_person_is_told_differs_for_a_renewal() {
        assert!(note(Done::Made).contains("20 days"));
        assert!(note(Done::Renewed).contains("Kept the service's key"));
    }
}
