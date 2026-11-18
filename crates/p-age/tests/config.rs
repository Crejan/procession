//! The configuration file and the broker built from it. Nothing here listens: the sandbox cannot bind
//! TCP ports.

use p_age::config::{Config, ConfigError};

use std::os::unix::fs::PermissionsExt;

fn mode(path: &std::path::Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn write(dir: &std::path::Path, name: &str, text: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    mode(&path, 0o644);
    path
}

/// A directory only its owner may enter, as the state directory must be.
fn private_dir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    mode(dir.path(), 0o700);
    dir
}

const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

fn config_text(dir: &std::path::Path, extra: &str) -> String {
    let d = dir.display();
    format!(
        r#"{{"site":"{d}/site.json","listen":["127.0.0.1:0"],
            "tls_cert":"{d}/c.pem","tls_key":"{d}/k.pem","broker_key":"{d}/broker",
            "state_dir":"{d}","log":"{d}/log.jsonl"{extra}}}"#
    )
}

#[test]
fn a_configuration_builds_a_broker_with_defaults_for_what_is_left_out() {
    let dir = private_dir();
    write(
        dir.path(),
        "site.json",
        &format!(
            r#"{{"persons":[{{"name":"jan","enabled":true,"connection_key":"{KEY}","delegation_key":"{KEY}"}}],
                "hosts":[{{"name":"a.example","key":"{KEY}"}}]}}"#
        ),
    );
    let path = write(dir.path(), "page.json", &config_text(dir.path(), ""));
    let config = Config::read(&path).unwrap();
    assert_eq!(
        (config.max_waiting_per_agent, config.max_connections, config.max_connections_per_address),
        (5, 512, 16)
    );
    let broker = config.build().unwrap();
    assert_eq!(broker.held_count(), 0);
    assert!(dir.path().join("log.jsonl").exists(), "the log is opened");
}

#[test]
fn a_setting_can_be_changed_and_an_unknown_one_is_refused() {
    let dir = private_dir();
    let ok = write(dir.path(), "a.json", &config_text(dir.path(), r#","max_waiting_per_agent":2"#));
    assert_eq!(Config::read(&ok).unwrap().max_waiting_per_agent, 2);
    let bad = write(dir.path(), "b.json", &config_text(dir.path(), r#","max_waiting":2"#));
    assert!(matches!(Config::read(&bad), Err(ConfigError::Parse { .. })));
    assert!(Config::read(&dir.path().join("none.json")).is_err());
    let empty = write(
        dir.path(),
        "c.json",
        &config_text(dir.path(), "").replace(r#""listen":["127.0.0.1:0"],"#, r#""listen":[],"#),
    );
    assert!(matches!(Config::read(&empty), Err(ConfigError::NoAddress)));
}

#[test]
fn a_site_file_with_a_bad_key_a_bad_name_or_a_duplicate_is_refused() {
    use p_age::site::Site;
    let person = |name: &str, key: &str| {
        format!(r#"{{"name":"{name}","enabled":true,"connection_key":"{key}","delegation_key":"{KEY}"}}"#)
    };
    let site = |persons: String| format!(r#"{{"persons":[{persons}],"hosts":[]}}"#);
    assert!(Site::from_json(&site(person("jan", KEY))).is_ok());
    assert!(Site::from_json(&site(person("jan", "not a key"))).is_err());
    assert!(Site::from_json(&site(person("ja n", KEY))).is_err());
    assert!(Site::from_json(&site(person("jan:confirmed", KEY))).is_err(), "a name never has a colon");
    assert!(Site::from_json(&site(format!("{},{}", person("jan", KEY), person("jan", KEY)))).is_err());
    assert!(Site::from_json(&site(person("jan", &KEY.replace("ssh-ed25519", "ssh-rsa")))).is_err());
}

#[test]
fn a_configuration_or_site_file_that_anyone_but_its_owner_can_write_is_refused() {
    let dir = private_dir();
    let path = write(dir.path(), "page.json", &config_text(dir.path(), ""));
    for bad in [0o666, 0o664, 0o646, 0o622] {
        mode(&path, bad);
        assert!(matches!(Config::read(&path), Err(ConfigError::Perm(_))), "{bad:o}");
    }
    for good in [0o600, 0o640, 0o644, 0o400] {
        mode(&path, good);
        assert!(Config::read(&path).is_ok(), "{good:o}");
    }
    let site = write(dir.path(), "site.json", r#"{"persons":[],"hosts":[]}"#);
    assert!(p_age::site::Site::read(&site).is_ok());
    mode(&site, 0o666);
    assert!(p_age::site::Site::read(&site).is_err());
}

#[test]
fn the_register_on_disk_is_private_versioned_and_never_replaced_by_an_empty_one() {
    use p_age::core::{Core, StateError};
    let dir = private_dir();
    let path = dir.path().join("register.json");
    // no file: a first start
    assert!(Core::read_state(&path).is_ok());
    // a register that cannot be read whole is not started on
    std::fs::write(&path, "{ not json").unwrap();
    mode(&path, 0o600);
    assert!(matches!(Core::read_state(&path), Err(StateError::Parse { .. })));
    std::fs::write(&path, r#"{"v":2,"delegations":[],"blocked":["jan"]}"#).unwrap();
    assert!(matches!(Core::read_state(&path), Err(StateError::Version { v: 2, .. })));
    std::fs::write(&path, r#"{"delegations":[],"blocked":[]}"#).unwrap();
    assert!(Core::read_state(&path).is_err(), "no version member");
    std::fs::write(&path, r#"{"v":1,"delegations":[],"blocked":["jan"],"extra":1}"#).unwrap();
    assert!(Core::read_state(&path).is_err(), "unknown member");
    // one that others can read or write is refused, and so is a directory open to others
    std::fs::write(&path, r#"{"v":1,"delegations":[],"blocked":["jan"]}"#).unwrap();
    assert!(Core::read_state(&path).unwrap().is_blocked("jan"));
    mode(&path, 0o644);
    assert!(matches!(Core::read_state(&path), Err(StateError::Perm(_))));
    mode(&path, 0o600);
    mode(dir.path(), 0o755);
    assert!(matches!(Core::read_state(&path), Err(StateError::Perm(_))));
    mode(dir.path(), 0o700);
    // a directory that is not there is made, 0700
    let nested = dir.path().join("a").join("b");
    Core::read_state(&nested.join("register.json")).unwrap();
    assert_eq!(std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777, 0o700);
}

#[test]
fn a_register_that_cannot_be_read_stops_the_broker_from_being_built() {
    let dir = private_dir();
    write(dir.path(), "site.json", r#"{"persons":[],"hosts":[]}"#);
    let page = write(dir.path(), "page.json", &config_text(dir.path(), ""));
    let state = dir.path().join("register.json");
    std::fs::write(&state, "garbage").unwrap();
    mode(&state, 0o600);
    assert!(matches!(Config::read(&page).unwrap().build(), Err(ConfigError::State(_))));
}
