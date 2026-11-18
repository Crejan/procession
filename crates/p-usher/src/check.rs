//! `p-usher --check`: read what the daemon would read and say, for each, what
//! would be refused and why. Run it before an upgrade; it changes nothing.

use std::path::Path;

use crate::accounts::Accounts;
use crate::config::Config;
use crate::secret::read_secret;

/// Everything that would stop the daemon from starting, one message each; empty when all is well.
/// Reads the configuration file (checked as the daemon checks it), resolves the users and groups it
/// names, and checks the SMTP password file when one is configured. It stops after a configuration
/// that cannot be read, since what else to read is not known then.
pub fn problems(config: &Path, explicit: bool, host: &str, accounts: &dyn Accounts) -> Vec<String> {
    let cfg = match Config::load(config, explicit) {
        Ok(c) => c,
        Err(e) => return vec![format!("{e:#}")],
    };
    let mut out = Vec::new();
    if let Err(e) = cfg.settings(host.to_string(), accounts) {
        out.push(format!("{e:#}"));
    }
    if let Some(email) = &cfg.email
        && email.username.is_some()
    {
        match &email.password_file {
            None => out.push("email.username needs email.password_file".into()),
            Some(file) => {
                if let Err(e) = read_secret(file) {
                    out.push(format!("email.password_file: {e:#}"));
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::accounts::StaticAccounts;

    fn write(dir: &Path, name: &str, mode: u32, text: &str) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, text).unwrap();
        std::fs::set_permissions(&p, PermissionsExt::from_mode(mode)).unwrap();
        p
    }

    fn accounts() -> StaticAccounts {
        StaticAccounts::default()
    }

    #[test]
    fn a_good_setup_has_no_problems() {
        let d = tempfile::tempdir().unwrap();
        let pw = write(d.path(), "pw", 0o600, "x");
        let cfg = write(
            d.path(),
            "p.toml",
            0o644,
            &format!("[email]\nrelay = \"mail\"\nfrom = \"a@b.c\"\nadmin = \"x@y.z\"\nusername = \"u\"\npassword_file = {:?}\n", pw.display().to_string()),
        );
        assert_eq!(problems(&cfg, true, "h", &accounts()), Vec::<String>::new());
    }

    #[test]
    fn every_refusal_is_named_with_its_fix() {
        let d = tempfile::tempdir().unwrap();
        let bad_cfg = write(d.path(), "bad.toml", 0o666, "");
        let p = problems(&bad_cfg, true, "h", &accounts());
        assert_eq!(p.len(), 1);
        assert!(p[0].contains("chmod 600"), "{p:?}");

        let pw = write(d.path(), "pw", 0o644, "x");
        let cfg = write(
            d.path(),
            "p.toml",
            0o644,
            &format!("[email]\nrelay = \"mail\"\nfrom = \"a@b.c\"\nadmin = \"x@y.z\"\nusername = \"u\"\npassword_file = {:?}\n", pw.display().to_string()),
        );
        let p = problems(&cfg, true, "h", &accounts());
        assert_eq!(p.len(), 1);
        assert!(p[0].starts_with("email.password_file:") && p[0].contains("chmod 600"), "{p:?}");

        let no_file = write(d.path(), "n.toml", 0o644, "[email]\nrelay = \"m\"\nfrom = \"a@b.c\"\nadmin = \"x@y.z\"\nusername = \"u\"\n");
        assert_eq!(problems(&no_file, true, "h", &accounts()), vec!["email.username needs email.password_file".to_string()]);
    }

    #[test]
    fn a_missing_default_file_is_fine_a_missing_named_one_is_not() {
        let d = tempfile::tempdir().unwrap();
        let none = d.path().join("none.toml");
        assert!(problems(&none, false, "h", &accounts()).is_empty());
        assert_eq!(problems(&none, true, "h", &accounts()).len(), 1);
    }
}
