//! `probe setup`: the service's key and its certificate, made with `ssh-keygen`.
//! It is the same command for the first time and for every renewal: it **keeps the
//! service's key and replaces the certificate** (30 days). A root timer on the host
//! runs it with no arguments once 20 of the 30 days have passed (`SPEC.md`, "The two
//! parts"; `doc/approvals.md`, section 7). In a site the provisioning runs it once as
//! root; the service itself never reads the host key.
//!
//! `--if-due` is the form the daily timer runs: it does nothing while more than 10 of the 30 days
//! remain, and renews otherwise, or at once when there is no certificate or the key changed. A
//! failed renewal is an error, so the timer's unit shows as failed and the next day tries again.
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

/// Renew when this many days or fewer remain.
pub const RENEW_WHEN_DAYS_LEFT: i64 = 10;

/// What `run` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Done {
    /// A key and a certificate were made.
    Made,
    /// The key was kept and the certificate replaced.
    Renewed,
}

/// Why a renewal is due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    NoKey,
    PublicKeyMissing,
    NoCertificate,
    /// The certificate is there and cannot be read.
    Unreadable(String),
    /// The certificate certifies another key than the service's.
    KeyChanged,
    /// The certificate has no end: not one this makes.
    NoEnd,
    /// Seconds left (negative once it has ended): not more than ten days.
    Remaining(i64),
}

/// Whether a renewal is due.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Due {
    /// More than ten days remain: seconds left.
    No(i64),
    Yes(Reason),
}

/// What is found in the directory of the key and the certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Found {
    /// The service's public key bytes: `None` if there is no key (or no public half).
    pub key: Option<Result<Vec<u8>, Reason>>,
    /// The certificate: `None` if absent.
    pub certificate: Option<Result<crate::certificate::Facts, String>>,
}

/// The rule: nothing while **more than** ten days remain; a renewal otherwise, and at once when there
/// is no key, no certificate, one that cannot be read or has no end, or one for another key.
#[must_use]
pub fn decide(found: &Found, now: i64) -> Due {
    match (&found.key, &found.certificate) {
        (None, _) => Due::Yes(Reason::NoKey),
        (Some(Err(reason)), _) => Due::Yes(reason.clone()),
        (Some(Ok(_)), None) => Due::Yes(Reason::NoCertificate),
        (Some(Ok(_)), Some(Err(why))) => Due::Yes(Reason::Unreadable(why.clone())),
        (Some(Ok(key)), Some(Ok(cert))) => {
            if &cert.subject != key {
                return Due::Yes(Reason::KeyChanged);
            }
            let Ok(end) = i64::try_from(cert.valid_before) else { return Due::Yes(Reason::NoEnd) };
            if cert.valid_before == u64::MAX {
                return Due::Yes(Reason::NoEnd);
            }
            let left = end - now;
            if left > RENEW_WHEN_DAYS_LEFT * 86_400 { Due::No(left) } else { Due::Yes(Reason::Remaining(left)) }
        }
    }
}

/// Looks at the key and the certificate in `out`.
#[must_use]
pub fn inspect(out: &Path) -> Found {
    let (key, public, cert) = (out.join("service-key"), out.join("service-key.pub"), out.join("service-key-cert.pub"));
    let key_found = if !key.exists() {
        None
    } else {
        Some(match std::fs::read_to_string(&public) {
            Err(_) => Err(Reason::PublicKeyMissing),
            Ok(text) => crate::certificate::ed25519_public(&text).map_err(Reason::Unreadable),
        })
    };
    let certificate = cert.exists().then(|| {
        std::fs::read_to_string(&cert)
            .map_err(|e| e.to_string())
            .and_then(|text| crate::certificate::facts(text.trim()))
    });
    Found { key: key_found, certificate }
}

/// What `run_if_due` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IfDue {
    /// Nothing: the whole days left.
    NotDue(i64),
    Did(Done, Reason),
}

/// The renewing form: `run` only when [`decide`] says it is due.
///
/// # Errors
/// What `run` says; a failed renewal is an error and the old certificate stays.
pub fn run_if_due(host_key: &Path, host: &str, out: &Path, now: i64) -> Result<IfDue, String> {
    match decide(&inspect(out), now) {
        Due::No(left) => Ok(IfDue::NotDue(left.div_euclid(86_400))),
        Due::Yes(reason) => run(host_key, host, out).map(|done| IfDue::Did(done, reason)),
    }
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

    // ---- the due rule, branch by branch ----------------------------------------------------

    fn cert_facts(subject: &[u8], ends_in: i64, now: i64) -> Found {
        Found {
            key: Some(Ok(b"key".to_vec())),
            certificate: Some(Ok(crate::certificate::Facts {
                valid_before: u64::try_from(now + ends_in).unwrap(),
                subject: subject.to_vec(),
            })),
        }
    }

    #[test]
    fn the_due_rule_does_nothing_while_more_than_ten_days_remain() {
        const DAY: i64 = 86_400;
        let now = 1_800_000_000;
        assert_eq!(decide(&cert_facts(b"key", 30 * DAY, now), now), Due::No(30 * DAY));
        assert_eq!(decide(&cert_facts(b"key", 20 * DAY, now), now), Due::No(20 * DAY));
        assert_eq!(decide(&cert_facts(b"key", 10 * DAY + 1, now), now), Due::No(10 * DAY + 1), "more than ten days");
        // Ten days or fewer: renew. Exactly ten is not "more than ten".
        assert_eq!(decide(&cert_facts(b"key", 10 * DAY, now), now), Due::Yes(Reason::Remaining(10 * DAY)));
        assert_eq!(decide(&cert_facts(b"key", 9 * DAY, now), now), Due::Yes(Reason::Remaining(9 * DAY)));
        assert_eq!(decide(&cert_facts(b"key", 1, now), now), Due::Yes(Reason::Remaining(1)));
        assert_eq!(decide(&cert_facts(b"key", 0, now), now), Due::Yes(Reason::Remaining(0)));
        assert_eq!(decide(&cert_facts(b"key", -5 * DAY, now), now), Due::Yes(Reason::Remaining(-5 * DAY)), "ended");
    }

    #[test]
    fn the_due_rule_renews_at_once_without_a_key_a_certificate_a_readable_one_or_for_the_key() {
        let now = 1_800_000_000;
        let good = cert_facts(b"key", 30 * 86_400, now);
        assert_eq!(decide(&Found { key: None, certificate: good.certificate.clone() }, now), Due::Yes(Reason::NoKey));
        assert_eq!(
            decide(&Found { key: Some(Err(Reason::PublicKeyMissing)), certificate: good.certificate.clone() }, now),
            Due::Yes(Reason::PublicKeyMissing)
        );
        assert_eq!(decide(&Found { key: good.key.clone(), certificate: None }, now), Due::Yes(Reason::NoCertificate));
        assert_eq!(
            decide(&Found { key: good.key.clone(), certificate: Some(Err("junk".into())) }, now),
            Due::Yes(Reason::Unreadable("junk".into()))
        );
        assert_eq!(
            decide(&cert_facts(b"another key", 30 * 86_400, now), now),
            Due::Yes(Reason::KeyChanged),
            "the key changed"
        );
        let mut endless = cert_facts(b"key", 0, now);
        endless.certificate.as_mut().unwrap().as_mut().unwrap().valid_before = u64::MAX;
        assert_eq!(decide(&endless, now), Due::Yes(Reason::NoEnd));
    }

    // ---- on files, with a real ssh-keygen ----------------------------------------------------

    /// Replaces the certificate by one that ends in `validity` (`ssh-keygen -V`), for the same key.
    fn certify(dir: &Path, host: &Path, out: &Path, validity: &str) {
        let staged = dir.join("staged");
        let _ = std::fs::remove_dir_all(&staged);
        std::fs::create_dir(&staged).unwrap();
        std::fs::copy(out.join("service-key.pub"), staged.join("service-key.pub")).unwrap();
        keygen(&[
            "-q",
            "-s",
            &path(host),
            "-I",
            "probe@a.example",
            "-n",
            "probe@a.example",
            "-V",
            validity,
            "-O",
            "clear",
            &path(&staged.join("service-key.pub")),
        ])
        .unwrap();
        std::fs::copy(staged.join("service-key-cert.pub"), out.join("service-key-cert.pub")).unwrap();
    }

    #[test]
    fn if_due_on_files_does_nothing_when_not_due_and_renews_when_due() {
        let dir = crate::testdir::new("setup");
        let host = host_key(&dir);
        let out = dir.join("probe");
        // Nothing there: made.
        assert!(matches!(run_if_due(&host, "a.example", &out, now()), Ok(IfDue::Did(Done::Made, Reason::NoKey))));
        // A fresh certificate: nothing is touched.
        let before =
            (std::fs::read(out.join("service-key")).unwrap(), std::fs::read(out.join("service-key-cert.pub")).unwrap());
        assert!(matches!(run_if_due(&host, "a.example", &out, now()), Ok(IfDue::NotDue(29 | 30))));
        assert_eq!(
            (std::fs::read(out.join("service-key")).unwrap(), std::fs::read(out.join("service-key-cert.pub")).unwrap()),
            before
        );
        // 11 days left: not due. 9 days left: due, the key kept, the certificate new and good for 30 days.
        certify(&dir, &host, &out, "+11d");
        assert!(matches!(run_if_due(&host, "a.example", &out, now()), Ok(IfDue::NotDue(10 | 11))));
        certify(&dir, &host, &out, "+9d");
        let (key, old) =
            (std::fs::read(out.join("service-key")).unwrap(), std::fs::read(out.join("service-key-cert.pub")).unwrap());
        assert!(matches!(
            run_if_due(&host, "a.example", &out, now()),
            Ok(IfDue::Did(Done::Renewed, Reason::Remaining(_)))
        ));
        assert_eq!(std::fs::read(out.join("service-key")).unwrap(), key);
        assert_ne!(std::fs::read(out.join("service-key-cert.pub")).unwrap(), old);
        assert!(matches!(crate::certificate::days_left(&out.join("service-key-cert.pub"), now()), Ok(Some(29 | 30))));
        // An ended certificate, a certificate that is junk, none: due.
        certify(&dir, &host, &out, "20200101Z:20200102Z");
        assert!(
            matches!(run_if_due(&host, "a.example", &out, now()), Ok(IfDue::Did(Done::Renewed, Reason::Remaining(left))) if left < 0)
        );
        std::fs::write(out.join("service-key-cert.pub"), "junk").unwrap();
        assert!(matches!(
            run_if_due(&host, "a.example", &out, now()),
            Ok(IfDue::Did(Done::Renewed, Reason::Unreadable(_)))
        ));
        std::fs::remove_file(out.join("service-key-cert.pub")).unwrap();
        assert!(matches!(
            run_if_due(&host, "a.example", &out, now()),
            Ok(IfDue::Did(Done::Renewed, Reason::NoCertificate))
        ));
    }

    #[test]
    fn if_due_renews_at_once_when_the_key_changed_and_a_failed_renewal_is_an_error_that_keeps_the_old_certificate() {
        let dir = crate::testdir::new("setup");
        let host = host_key(&dir);
        let out = dir.join("probe");
        run(&host, "a.example", &out).unwrap();
        // The service's key is replaced (and its public half): the certificate is for the old one.
        let other = dir.join("other");
        keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", &path(&other)]).unwrap();
        std::fs::copy(&other, out.join("service-key")).unwrap();
        std::fs::copy(dir.join("other.pub"), out.join("service-key.pub")).unwrap();
        assert!(matches!(
            run_if_due(&host, "a.example", &out, now()),
            Ok(IfDue::Did(Done::Renewed, Reason::KeyChanged))
        ));
        assert!(matches!(decide(&inspect(&out), now()), Due::No(_)), "the new certificate is for the new key");
        // Due, and the host key cannot be read: an error, the old certificate stays.
        certify(&dir, &host, &out, "+3d");
        let old = std::fs::read(out.join("service-key-cert.pub")).unwrap();
        let error = run_if_due(&dir.join("no-such-host-key"), "a.example", &out, now()).unwrap_err();
        assert!(error.contains("ssh-keygen"), "{error}");
        assert_eq!(std::fs::read(out.join("service-key-cert.pub")).unwrap(), old);
    }
}
