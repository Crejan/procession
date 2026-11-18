//! A certificate for one of the person's approval keys, as the standing carries it, judged by pledge itself:
//! it is accepted only if the site CA's signature verifies, for **this** pledge's key of that role, and the
//! name is `<person>:<role>` (`doc/approval-connections.md`, section 5, "certificates"). The broker's
//! signature on the standing is not what makes it good; the CA's is.
//!
//! How: the key holder signs a fixed probe with the approval key, the signature is armoured with the
//! certificate as the key (exactly as an approval will be), `p_act` reads the certificate out of it, and
//! `ssh-keygen -Y verify` checks the chain against a single CA line, as a service will. p-act has no function
//! for "verify this approval key's certificate"; this is the one place pledge does it, so that it can move.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p_act::sign::{PublicKey, signature_certificate};

use crate::agent::host_key::fingerprint;
use crate::approvals::APPROVAL_NAMESPACE;
use crate::shared::Shared;
use p_act::sign::Namespace;

const PROBE: &[u8] = b"pledge: certificate check, not a request";

/// What a good certificate is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Good {
    /// `confirmed` or `automatic`.
    pub role: &'static str,
    /// The certificate's wire blob.
    pub blob: Vec<u8>,
    /// When it ends (Unix time).
    pub valid_before: u64,
}

fn run_keygen(dir: &Path, principal: &str, ca: &PublicKey, armoured: &str) -> bool {
    let allowed = dir.join("allowed");
    let signature = dir.join("probe.sig");
    if std::fs::write(&allowed, format!("{principal} cert-authority,namespaces=\"{APPROVAL_NAMESPACE}\" {ca}\n"))
        .is_err()
        || std::fs::write(&signature, armoured).is_err()
    {
        return false;
    }
    let Ok(mut child) = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&allowed)
        .args(["-I", principal, "-n", APPROVAL_NAMESPACE, "-s"])
        .arg(&signature)
        .env("SSH_ASKPASS", "false")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(PROBE);
    }
    child.wait().is_ok_and(|status| status.success())
}

/// Judges `line` for `person` against `site_ca` at `now` (Unix time).
///
/// # Errors
///
/// The reason it is not good, as a short sentence without any value from the certificate.
pub fn check(shared: &Shared, line: &str, person: &str, site_ca: &PublicKey, now: i64) -> Result<Good, String> {
    let blob = line
        .split_whitespace()
        .nth(1)
        .and_then(|b64| STANDARD.decode(b64).ok())
        .ok_or("the certificate line does not read")?;
    for role in ["confirmed", "automatic"] {
        let Some(key) = shared.key_with_purpose(role) else { continue };
        // The seam refuses a blob that is not a key or certificate of the key's algorithm: not this pledge's.
        let Some(armoured) = crate::seam::sign(shared, &key.blob, &blob, Namespace::Approval, PROBE) else { continue };
        let Ok(cert) = signature_certificate(&armoured) else { continue };
        if cert.fingerprint.as_str() != fingerprint(&key.blob) {
            continue; // not this role's key
        }
        let principal = format!("{person}:{role}");
        if cert.principals != [principal.clone()] {
            return Err("the certificate does not name this person and role".into());
        }
        let n = u64::try_from(now).unwrap_or(0);
        if cert.valid_after > n || n >= cert.valid_before {
            return Err("the certificate is not valid now".into());
        }
        let dir = shared.work_dir.join(format!("cert-{}", std::process::id()));
        crate::paths::ensure_private_dir(&dir).map_err(|_| "no private directory to check in")?;
        let verified = run_keygen(&dir, &principal, site_ca, &armoured);
        let _ = std::fs::remove_dir_all(&dir);
        return if verified {
            Ok(Good { role, blob, valid_before: cert.valid_before })
        } else {
            Err("the site CA's signature does not verify".into())
        };
    }
    Err("the certificate is not for one of this pledge's approval keys".into())
}

#[cfg(test)]
mod tests {
    use std::process::Command;

    use super::*;
    use crate::holder::KeyType;
    use crate::shared::KeyMeta;
    use crate::testing::Rig;

    fn keygen(args: &[&str]) {
        let out = Command::new("ssh-keygen").args(args).stdin(Stdio::null()).output().expect("ssh-keygen");
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }

    fn now() -> i64 {
        i64::try_from(std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).expect("clock").as_secs())
            .expect("fits")
    }

    /// A rig with a confirmed and an automatic key, a site CA, and a function that certifies `role`'s key.
    struct World {
        rig: Rig,
        dir: crate::testing::TestDir,
        ca: PublicKey,
    }

    impl World {
        fn new() -> Self {
            let rig = Rig::live([], |_| {});
            for role in ["confirmed", "automatic"] {
                let meta = KeyMeta {
                    purpose: role.into(),
                    program: None,
                    use_: None,
                    comment: role.into(),
                    key_type: String::new(),
                    created: String::new(),
                };
                rig.shared.create_key(KeyType::Ed25519, meta).expect("key");
            }
            let dir = crate::testing::TestDir::new("certs");
            keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", &dir.path().join("ca").to_string_lossy()]);
            keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", &dir.path().join("other-ca").to_string_lossy()]);
            let ca = PublicKey::read(&dir.path().join("ca.pub")).expect("ca");
            Self { rig, dir, ca }
        }

        /// The certificate line the CA `ca_name` makes for the key of `role`, naming `principal`, valid as `validity`.
        fn certificate(&self, role: &str, ca_name: &str, principal: &str, validity: &str) -> String {
            let key = self.rig.shared.key_with_purpose(role).expect("key");
            let pub_file = self.dir.path().join(format!("{role}-{ca_name}.pub"));
            std::fs::write(&pub_file, format!("{}\n", key.public_line())).expect("write");
            keygen(&[
                "-q",
                "-s",
                &self.dir.path().join(ca_name).to_string_lossy(),
                "-I",
                "id",
                "-n",
                principal,
                "-V",
                validity,
                "-O",
                "clear",
                &pub_file.to_string_lossy(),
            ]);
            std::fs::read_to_string(self.dir.path().join(format!("{role}-{ca_name}-cert.pub")))
                .expect("cert")
                .trim()
                .to_owned()
        }

        fn check(&self, line: &str) -> Result<Good, String> {
            check(&self.rig.shared, line, "jan", &self.ca, now())
        }
    }

    #[test]
    fn a_certificate_is_good_only_for_this_pledges_key_the_right_name_and_the_site_ca() {
        let w = World::new();
        let confirmed = w.certificate("confirmed", "ca", "jan:confirmed", "-1m:+1h");
        let good = w.check(&confirmed).expect("good");
        assert_eq!(good.role, "confirmed");
        let automatic = w.certificate("automatic", "ca", "jan:automatic", "-1m:+1h");
        assert_eq!(w.check(&automatic).expect("good").role, "automatic");
        for (what, line, why) in [
            (
                "another person",
                w.certificate("confirmed", "ca", "eva:confirmed", "-1m:+1h"),
                "does not name this person and role",
            ),
            (
                "the other role's name",
                w.certificate("confirmed", "ca", "jan:automatic", "-1m:+1h"),
                "does not name this person and role",
            ),
            ("another CA", w.certificate("confirmed", "other-ca", "jan:confirmed", "-1m:+1h"), "does not verify"),
            (
                "an ended certificate",
                w.certificate("confirmed", "ca", "jan:confirmed", "20200101Z:20200102Z"),
                "not valid now",
            ),
            (
                "a garbage line",
                "ssh-ed25519-cert-v01@openssh.com AAAA jan:confirmed".to_owned(),
                "not for one of this pledge's",
            ),
            ("not a line", "nonsense".to_owned(), "does not read"),
        ] {
            let error = w.check(&line).expect_err(what);
            assert!(error.contains(why), "{what}: {error}");
        }
    }

    #[test]
    fn a_certificate_for_another_key_is_not_for_this_pledge() {
        let w = World::new();
        keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", &w.dir.path().join("stranger").to_string_lossy()]);
        keygen(&[
            "-q",
            "-s",
            &w.dir.path().join("ca").to_string_lossy(),
            "-I",
            "id",
            "-n",
            "jan:confirmed",
            "-V",
            "-1m:+1h",
            "-O",
            "clear",
            &w.dir.path().join("stranger.pub").to_string_lossy(),
        ]);
        let line = std::fs::read_to_string(w.dir.path().join("stranger-cert.pub")).expect("cert");
        assert!(w.check(line.trim()).expect_err("not ours").contains("not for one of this pledge's"));
    }
}
