//! A certificate for one of the person's approval keys, as the standing carries it, judged by pledge itself:
//! it is accepted only if the site CA's signature verifies, for **this** pledge's key of that role, and the
//! name is `<person>:<role>` (`doc/approval-connections.md`, section 5, "certificates"). The broker's
//! signature on the standing is not what makes it good; the CA's is. The judgement of the certificate itself
//! is `p_act::sign::verify_approval_certificate`; what is pledge's is whose key it is.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use p_act::Timestamp;
use p_act::sign::{ApprovalKind, PublicKey, SignError, verify_approval_certificate};

use crate::shared::Shared;

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

fn why(error: &SignError) -> &'static str {
    match error {
        SignError::WrongIssuer => "the site CA's signature does not verify",
        SignError::CertificateNotYetValid | SignError::CertificateExpired => "the certificate is not valid now",
        _ => "the certificate does not read as an approval key's",
    }
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
    let now = Timestamp::from_unix(now).ok_or("the clock is not usable")?;
    let cert = verify_approval_certificate(line, site_ca, now).map_err(|e| why(&e))?;
    let ours = ["confirmed", "automatic"].into_iter().find(|role| {
        shared
            .key_with_purpose(role)
            .and_then(|key| PublicKey::parse(&key.public_line()).ok())
            .is_some_and(|key| cert.certifies(&key))
    });
    let Some(role) = ours else { return Err("the certificate is not for one of this pledge's approval keys".into()) };
    let kind = if role == "confirmed" { ApprovalKind::Confirmed } else { ApprovalKind::Automatic };
    if cert.person != person || cert.kind != kind {
        return Err("the certificate does not name this person and role".into());
    }
    Ok(Good {
        role: if role == "confirmed" { "confirmed" } else { "automatic" },
        blob,
        valid_before: cert.valid_before,
    })
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};

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
            ("a garbage line", "ssh-ed25519-cert-v01@openssh.com AAAA jan:confirmed".to_owned(), "does not read"),
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
