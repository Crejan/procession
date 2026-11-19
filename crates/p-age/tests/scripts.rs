//! The owner's two-account check (`proposals/admin-group-check/`): it cannot run here (Linux, root, accounts), and has
//! never run. What can be checked is checked: the shell parses, the helpers that decide what root obeys and what the
//! preconditions accept behave as they should, nothing is written in a world-writable directory under a fixed name, and
//! the config and site file the script writes are read by this crate's own readers.

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;

fn dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("proposals/admin-group-check")
}

fn sh(script: &str) -> (bool, String) {
    let out = Command::new("sh").arg("-c").arg(script).output().unwrap();
    (out.status.success(), String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

fn scripts() -> Vec<PathBuf> {
    ["common.sh", "check-administrators.sh", "undo-administrators.sh", "find-artifact.sh"]
        .iter()
        .map(|n| dir().join(n))
        .collect()
}

#[test]
fn every_script_is_valid_shell_and_stops_on_unset_variables() {
    for path in scripts() {
        let out = Command::new("sh").arg("-n").arg(&path).output().unwrap();
        assert!(out.status.success(), "{}: {}", path.display(), String::from_utf8_lossy(&out.stderr));
    }
    for name in ["check-administrators.sh", "undo-administrators.sh"] {
        assert!(std::fs::read_to_string(dir().join(name)).unwrap().contains("\nset -u\n"), "{name}");
    }
}

#[test]
fn nothing_root_writes_or_obeys_is_in_a_world_writable_directory_or_found_by_guessing() {
    for path in scripts() {
        let text = std::fs::read_to_string(&path).unwrap();
        for bad in ["/tmp/", "/var/tmp", "ls -t", "target/debug", "$TMPDIR"] {
            assert!(!text.contains(bad), "{}: `{bad}`", path.display());
        }
    }
    let main = std::fs::read_to_string(dir().join("check-administrators.sh")).unwrap();
    assert!(
        main.contains("find-artifact.sh")
            || std::fs::read_to_string(dir().join("common.sh")).unwrap().contains("find-artifact.sh")
    );
    assert!(
        main.contains("--message-format=json")
            || std::fs::read_to_string(dir().join("common.sh")).unwrap().contains("--message-format=json")
    );
    // the script says in its head that it has never run
    assert!(main.contains("THIS HAS NEVER RUN"));
}

#[test]
fn the_ssh_version_precondition_reads_what_ssh_prints() {
    let check = |text: &str| sh(&format!(". '{}'; ssh_at_least_8_9 '{text}'", dir().join("common.sh").display())).0;
    assert!(check("OpenSSH_8.9p1 Ubuntu-3, OpenSSL 3.0.2"));
    assert!(check("OpenSSH_9.2p1 Debian-2+deb12u3, OpenSSL 3.0.15"));
    assert!(check("OpenSSH_10.0p2 Debian-7, OpenSSL 3.5.1"));
    assert!(!check("OpenSSH_8.8p1, OpenSSL 1.1.1"));
    assert!(!check("OpenSSH_7.9p1"));
    assert!(!check("something else"));
    assert!(!check(""));
}

#[test]
fn what_root_obeys_is_read_only_from_a_path_that_is_trusted() {
    let own = owner_uid();
    let root = tempfile::tempdir().unwrap();
    let ok = root.path().join("dir");
    std::fs::create_dir(&ok).unwrap();
    std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = ok.join("marker");
    std::fs::write(&file, "A=1\n").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let writable = root.path().join("writable");
    std::fs::write(&writable, "").unwrap();
    std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o666)).unwrap();
    let link = root.path().join("link");
    symlink(&file, &link).unwrap();
    // the test's own uid stands in for root's
    let ask = |what: &str| sh(&format!(". '{}'; TRUSTED_UID={own}; {what}", dir().join("common.sh").display())).0;
    assert!(ask(&format!("root_only '{}' d", ok.display())));
    assert!(ask(&format!("root_only '{}' f", file.display())));
    assert!(!ask(&format!("root_only '{}' d", file.display())), "a file is not a directory");
    assert!(!ask(&format!("root_only '{}' f", writable.display())), "writable by others");
    assert!(!ask(&format!("root_only '{}' f", link.display())), "a link is not followed");
    assert!(!ask(&format!("TRUSTED_UID=1234567; root_only '{}' f", file.display())), "another owner");
    for good in ["/var/lib/page-admin-check", "/usr/local/lib/page-admin-check"] {
        assert!(ask(&format!("sane_path '{good}'")), "{good}");
    }
    for bad in ["relative/path", "/etc", "/var/../etc/x", "/a/b\nc"] {
        assert!(
            !sh(&format!(". '{}'; sane_path \"$1\"", dir().join("common.sh").display())
                .replace("sane_path \"$1\"", &format!("sane_path '{bad}'")))
            .0,
            "{bad:?}"
        );
    }
}

fn owner_uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(env!("CARGO_MANIFEST_DIR")).unwrap().uid()
}

#[test]
fn the_files_the_script_writes_are_read_by_the_broker_that_will_read_them() {
    // The site file and the configuration as the script writes them (the same shape, with placeholder keys).
    let key = |n: u8| {
        use base64::Engine;
        let mut raw = vec![0, 0, 0, 11];
        raw.extend_from_slice(b"ssh-ed25519");
        raw.extend_from_slice(&[0, 0, 0, 32]);
        raw.extend_from_slice(&[n; 32]);
        format!("ssh-ed25519 {}", base64::engine::general_purpose::STANDARD.encode(raw))
    };
    let script = std::fs::read_to_string(dir().join("check-administrators.sh")).unwrap();
    // take the heredoc of the site file out of the script, so that a change to it is the thing tested
    let start = script.find("cat > \"$WORK/site.json\" <<JSON\n").unwrap() + "cat > \"$WORK/site.json\" <<JSON\n".len();
    let template = &script[start..start + script[start..].find("\nJSON\n").unwrap()];
    let mut text = template.to_owned();
    for (n, name) in ["confirmed", "automatic", "delegation", "connection", "host"].iter().enumerate() {
        text = text.replace(&format!("$(publine \"$WORK/jan-{name}.pub\")"), &key(u8::try_from(n).unwrap() + 1));
    }
    assert!(!text.contains('$'), "a placeholder is left: {text}");
    let site = p_age::site::Site::from_json(&text).unwrap_or_else(|e| panic!("{e}\n{text}"));
    assert!(site.person("jan").is_some());
    // the configuration's members are the broker's (an unknown member would be refused)
    let start = script.find("cat > \"$WORK/page.json\" <<JSON\n").unwrap() + "cat > \"$WORK/page.json\" <<JSON\n".len();
    let template = &script[start..start + script[start..].find("\nJSON\n").unwrap()];
    let config = template
        .replace("$ROOTDIR", "/r")
        .replace("$PRIVATE", "/p")
        .replace("$STATE", "/s")
        .replace("$GROUP", "pgchk-admins");
    let parsed: p_age::config::Config = serde_json::from_str(&config).unwrap_or_else(|e| panic!("{e}\n{config}"));
    assert_eq!(parsed.administrators_group.as_deref(), Some("pgchk-admins"));
}
