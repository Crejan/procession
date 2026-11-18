//! The configuration file and the broker built from it. Nothing here listens: the sandbox cannot bind
//! TCP ports.

use p_age::config::{Config, ConfigError};

fn write(dir: &std::path::Path, name: &str, text: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl";

fn config_text(dir: &std::path::Path, extra: &str) -> String {
    let d = dir.display();
    format!(
        r#"{{"site":"{d}/site.json","listen_services":"127.0.0.1:0","listen_pledges":"127.0.0.1:0",
            "tls_cert":"{d}/c.pem","tls_key":"{d}/k.pem","broker_key":"{d}/broker",
            "state_dir":"{d}","log":"{d}/log.jsonl"{extra}}}"#
    )
}

#[test]
fn a_configuration_builds_a_broker_with_defaults_for_what_is_left_out() {
    let dir = tempfile::tempdir().unwrap();
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
    let dir = tempfile::tempdir().unwrap();
    let ok = write(dir.path(), "a.json", &config_text(dir.path(), r#","max_waiting_per_agent":2"#));
    assert_eq!(Config::read(&ok).unwrap().max_waiting_per_agent, 2);
    let bad = write(dir.path(), "b.json", &config_text(dir.path(), r#","max_waiting":2"#));
    assert!(matches!(Config::read(&bad), Err(ConfigError::Parse { .. })));
    assert!(matches!(Config::read(&dir.path().join("none.json")), Err(ConfigError::Read { .. })));
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
