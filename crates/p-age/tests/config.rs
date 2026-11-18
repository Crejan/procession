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
            "state_dir":"{d}","site_ca":"{d}/site-ca.pub","log":"{d}/log.jsonl"{extra}}}"#
    )
}

#[test]
fn a_configuration_builds_a_broker_with_defaults_for_what_is_left_out() {
    let dir = private_dir();
    write(
        dir.path(),
        "site.json",
        &format!(
            r#"{{"v":1,"persons":[{{"name":"jan","enabled":true}}],"hosts":[{{"name":"a.example","key":"{KEY}"}}]}}"#
        ),
    );
    let path = write(dir.path(), "page.json", &config_text(dir.path(), ""));
    let config = Config::read(&path).unwrap();
    assert_eq!((config.waiting_per_agent, config.max_connections, config.max_connections_per_address), (5, 512, 16));
    // the first start is explicit: without a register the broker is not built
    assert!(matches!(config.build(), Err(ConfigError::State(_))));
    p_age::core::Core::init_state(&dir.path().join("register.json")).unwrap();
    // the site CA key is read (with the settings rule); the broker has no certificate here, and says so, but is built
    write(dir.path(), "site-ca.pub", KEY);
    let broker = config.build().unwrap();
    assert_eq!(broker.held_count(), 0);
    assert!(dir.path().join("log.jsonl").exists(), "the log is opened");
}

#[test]
fn a_setting_can_be_changed_and_an_unknown_one_is_refused() {
    let dir = private_dir();
    let ok = write(dir.path(), "a.json", &config_text(dir.path(), r#","waiting_per_agent":2"#));
    assert_eq!(Config::read(&ok).unwrap().waiting_per_agent, 2);
    // the old name is not an alias: refused as unknown
    let old = write(dir.path(), "old.json", &config_text(dir.path(), r#","max_waiting_per_agent":2"#));
    assert!(Config::read(&old).is_err());
    let bad = write(dir.path(), "b.json", &config_text(dir.path(), r#","max_waiting":2"#));
    assert!(matches!(Config::read(&bad), Err(ConfigError::Settings(_))));
    assert!(Config::read(&dir.path().join("none.json")).is_err());
    let empty = write(
        dir.path(),
        "c.json",
        &config_text(dir.path(), "").replace(r#""listen":["127.0.0.1:0"],"#, r#""listen":[],"#),
    );
    assert!(matches!(Config::read(&empty), Err(ConfigError::NoAddress)));
}

/// A public key line that differs with `n`.
fn key_line(n: u8) -> String {
    use base64::Engine as _;
    let mut blob = Vec::new();
    blob.extend(11u32.to_be_bytes());
    blob.extend(b"ssh-ed25519");
    blob.extend(32u32.to_be_bytes());
    blob.extend([n; 32]);
    format!("ssh-ed25519 {}", base64::engine::general_purpose::STANDARD.encode(blob))
}

/// A person's `keys` object with the four keys `first` to `first + 3`.
fn keys(first: u8) -> String {
    let row = |n: u8| format!(r#"{{"key":"{}","verified_on":"2026-11-10"}}"#, key_line(first + n));
    format!(
        r#""keys":{{"confirmed":{},"automatic":{},"delegation":{},"connection":{}}}"#,
        row(0),
        row(1),
        row(2),
        row(3)
    )
}

#[test]
fn a_site_file_with_a_bad_key_a_bad_name_or_a_duplicate_is_refused() {
    use p_age::site::Site;
    let person = |name: &str, keys: &str| format!(r#"{{"name":"{name}","enabled":true,{keys}}}"#);
    let site = |persons: String| format!(r#"{{"v":1,"persons":[{persons}],"hosts":[]}}"#);
    assert!(Site::from_json(&site(person("jan", &keys(1)))).is_ok());
    assert!(Site::from_json(&site(person("ja n", &keys(1)))).is_err());
    assert!(Site::from_json(&site(person("jan:confirmed", &keys(1)))).is_err(), "a name never has a colon");
    assert!(Site::from_json(&site(format!("{},{}", person("jan", &keys(1)), person("jan", &keys(5))))).is_err());
    let bad = keys(1).replacen(&key_line(1), "not a key", 1);
    assert!(Site::from_json(&site(person("jan", &bad))).is_err());
    let rsa = keys(1).replacen("ssh-ed25519", "ssh-rsa", 1);
    assert!(Site::from_json(&site(person("jan", &rsa))).is_err(), "only Ed25519 and ECDSA P-256");
}

#[test]
fn a_persons_four_keys_are_one_object_all_present_all_different_and_only_for_an_enabled_person() {
    use p_age::site::{Site, SiteError};
    let site = |person: String| format!(r#"{{"v":1,"persons":[{person}],"hosts":[]}}"#);
    let row = |n: u8| format!(r#"{{"key":"{}"}}"#, key_line(n));
    // a person need not have approval keys at all
    assert!(Site::from_json(&site(r#"{"name":"jan","enabled":true}"#.to_owned())).is_ok());
    // never a partial set
    for missing in ["confirmed", "automatic", "delegation", "connection"] {
        let members: Vec<String> = ["confirmed", "automatic", "delegation", "connection"]
            .iter()
            .enumerate()
            .filter(|(_, m)| **m != missing)
            .map(|(i, m)| format!(r#""{m}":{}"#, row(u8::try_from(i).unwrap() + 1)))
            .collect();
        let person = format!(r#"{{"name":"jan","enabled":true,"keys":{{{}}}}}"#, members.join(","));
        assert!(Site::from_json(&site(person)).is_err(), "without {missing}");
    }
    // no other member, no unknown purpose, a row is `{key, verified_on?}` and nothing else
    let extra = keys(1).replacen("}}", r#"}, "root": {"key":"x"}}"#, 1);
    assert!(Site::from_json(&site(format!(r#"{{"name":"jan","enabled":true,{extra}}}"#))).is_err());
    let row_extra = keys(1).replacen(r#""verified_on":"2026-11-10""#, r#""verified_on":"2026-11-10","note":"x""#, 1);
    assert!(Site::from_json(&site(format!(r#"{{"name":"jan","enabled":true,{row_extra}}}"#))).is_err());
    // `verified_on` is a date
    for bad in ["yesterday", "2026-13-01", "2026-11-32", "26-11-10", "2026/11/10"] {
        let k = keys(1).replacen("2026-11-10", bad, 1);
        assert!(Site::from_json(&site(format!(r#"{{"name":"jan","enabled":true,{k}}}"#))).is_err(), "{bad}");
    }
    // the four are four different keys
    let same = format!(
        r#""keys":{{"confirmed":{r},"automatic":{r},"delegation":{},"connection":{}}}"#,
        row(3),
        row(4),
        r = row(1)
    );
    assert!(matches!(
        Site::from_json(&site(format!(r#"{{"name":"jan","enabled":true,{same}}}"#))),
        Err(SiteError::KeysClash { .. })
    ));
    // no key is another person's, and none is a host's
    let two = format!(
        r#"{{"v":1,"persons":[{{"name":"jan","enabled":true,{}}},{{"name":"eva","enabled":true,{}}}],"hosts":[]}}"#,
        keys(1),
        keys(4) // 4 is jan's connection key
    );
    assert!(matches!(Site::from_json(&two), Err(SiteError::KeysClash { .. })));
    let host = format!(
        r#"{{"v":1,"persons":[{{"name":"jan","enabled":true,{}}}],"hosts":[{{"name":"a.example","key":"{}"}}]}}"#,
        keys(1),
        key_line(2)
    );
    assert!(matches!(Site::from_json(&host), Err(SiteError::KeysClash { .. })));
    // a person who is not enabled has no keys in the view the broker is given
    let off = format!(r#"{{"name":"jan","enabled":false,{}}}"#, keys(1));
    assert!(matches!(Site::from_json(&site(off)), Err(SiteError::KeysOnDisabled(_))));
    assert!(Site::from_json(&site(r#"{"name":"jan","enabled":false}"#.to_owned())).is_ok());
    // the shape of an earlier file (flat members) is refused: nothing is ignored
    let flat = format!(
        r#"{{"name":"jan","enabled":true,"connection_key":"{}","delegation_key":"{}"}}"#,
        key_line(1),
        key_line(2)
    );
    assert!(Site::from_json(&site(flat)).is_err());
}

#[test]
fn a_configuration_or_site_file_that_anyone_but_its_owner_can_write_is_refused() {
    let dir = private_dir();
    let path = write(dir.path(), "page.json", &config_text(dir.path(), ""));
    for bad in [0o666, 0o664, 0o646, 0o622] {
        mode(&path, bad);
        assert!(
            matches!(
                Config::read(&path),
                Err(ConfigError::Settings(p_act::settings::SettingsError::WritableByOthers { .. }))
            ),
            "{bad:o}"
        );
    }
    for good in [0o600, 0o640, 0o644, 0o400] {
        mode(&path, good);
        assert!(Config::read(&path).is_ok(), "{good:o}");
    }
    let site = write(dir.path(), "site.json", r#"{"v":1,"persons":[],"hosts":[]}"#);
    assert!(p_age::site::Site::read(&site).is_ok());
    mode(&site, 0o666);
    assert!(p_age::site::Site::read(&site).is_err());
}

#[test]
fn the_register_on_disk_is_private_versioned_and_never_replaced_by_an_empty_one() {
    use p_age::core::{Core, StateError};
    let dir = private_dir();
    let path = dir.path().join("register.json");
    // no file is no register: the start is refused, and `init` makes the first, once
    assert!(matches!(Core::read_state(&path), Err(StateError::Missing { .. })));
    Core::init_state(&path).unwrap();
    assert!(Core::read_state(&path).is_ok());
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(matches!(Core::init_state(&path), Err(StateError::Exists { .. })));
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
    Core::init_state(&nested.join("register.json")).unwrap();
    assert_eq!(std::fs::metadata(&nested).unwrap().permissions().mode() & 0o777, 0o700);
}

#[test]
fn a_register_that_cannot_be_read_stops_the_broker_from_being_built() {
    let dir = private_dir();
    write(dir.path(), "site.json", r#"{"v":1,"persons":[],"hosts":[]}"#);
    let page = write(dir.path(), "page.json", &config_text(dir.path(), ""));
    let state = dir.path().join("register.json");
    std::fs::write(&state, "garbage").unwrap();
    mode(&state, 0o600);
    assert!(matches!(Config::read(&page).unwrap().build(), Err(ConfigError::State(_))));
}

#[test]
fn the_settings_files_are_read_as_p_act_reads_them_one_object_and_nothing_else() {
    let dir = private_dir();
    let good = config_text(dir.path(), "");
    let refused = |text: String| {
        let path = write(dir.path(), "x.json", &text);
        Config::read(&path).is_err()
    };
    assert!(!refused(good.clone()));
    assert!(refused(format!("{good} trailing")), "text after the object");
    assert!(refused(format!("\u{feff}{good}")), "a byte order mark");
    assert!(refused(format!("[{good}]")), "not an object");
    assert!(refused(good.replacen("{", r#"{"waiting_per_agent":1,"waiting_per_agent":2,"#, 1)), "a member twice");
    assert!(refused(good.replacen("{", r#"{"surprise":1,"#, 1)), "an unknown member");
    // a file that is not a regular file (a link to a good one is a file; a directory is not)
    assert!(Config::read(dir.path()).is_err());
}

#[test]
fn a_site_file_whose_certificates_or_groups_a_standing_could_not_carry_is_refused_when_read() {
    use p_age::site::Site;
    let person =
        |extra: &str| format!(r#"{{"v":1,"persons":[{{"name":"jan","enabled":true,{}{extra}}}],"hosts":[]}}"#, keys(1));
    assert!(Site::from_json(&person(r#","groups":["ops","dev"]"#)).is_ok());
    assert!(Site::from_json(&person(r#","groups":["ops","ops"]"#)).is_ok(), "a duplicate is a set's one entry");
    assert!(Site::from_json(&person(r#","groups":["has space"]"#)).is_err());
    assert!(Site::from_json(&person(r#","groups":["a,b"]"#)).is_err());
    assert!(Site::from_json(&person(r#","groups":[""]"#)).is_err());
    assert!(Site::from_json(&person(r#","certificates":["not a certificate"]"#)).is_err());
}

#[test]
fn the_site_file_has_a_version_and_members_absent_empty_and_present_are_three_states() {
    use p_age::site::{Site, SiteError};
    let person = |name: &str| format!(r#"{{"name":"{name}","enabled":true}}"#);
    let file = |v: &str, members: &str| {
        format!(r#"{{{v}"persons":[{},{}],"hosts":[]{members}}}"#, person("jan"), person("eva"))
    };
    // a version, and only 1
    assert!(Site::from_json(&file(r#""v":1,"#, "")).is_ok());
    assert!(Site::from_json(&file("", "")).is_err(), "no version");
    assert!(matches!(Site::from_json(&file(r#""v":2,"#, "")), Err(SiteError::Version(2))));
    assert!(Site::from_json(&file(r#""v":"1","#, "")).is_err());
    // absent: the directory's
    let absent = Site::from_json(&file(r#""v":1,"#, "")).unwrap();
    assert_eq!(absent.members(), None);
    assert!(!absent.in_group("jan", "ops"), "a broker that does not know who is in a group answers no");
    // empty: nobody is in any group
    let empty = Site::from_json(&file(r#""v":1,"#, r#","members":{}"#)).unwrap();
    assert_eq!(empty.members().map(|m| m.len()), Some(0));
    assert!(!empty.in_group("jan", "ops"));
    // present: sorted, each once
    let some = Site::from_json(&file(r#""v":1,"#, r#","members":{"ops":["jan","eva","jan"],"dev":[]}"#)).unwrap();
    assert_eq!(some.members().unwrap()["ops"], ["eva", "jan"]);
    assert!(some.in_group("jan", "ops") && some.in_group("eva", "ops") && !some.in_group("jan", "dev"));
    assert!(!some.in_group("jan", "nogroup"));
    // `null` is neither: refused, so that a writer cannot confuse absent and empty
    assert!(Site::from_json(&file(r#""v":1,"#, r#","members":null"#)).is_err());
    // a member must be a person of the file, a group a name a standing can carry
    assert!(matches!(
        Site::from_json(&file(r#""v":1,"#, r#","members":{"ops":["nobody"]}"#)),
        Err(SiteError::BadMembers { .. })
    ));
    assert!(Site::from_json(&file(r#""v":1,"#, r#","members":{"has space":["jan"]}"#)).is_err());
    assert!(Site::from_json(&file(r#""v":1,"#, r#","members":["jan"]"#)).is_err());
}
