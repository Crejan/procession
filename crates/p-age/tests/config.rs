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
            r#"{{"v":1,"persons":[{{"name":"jan",{}}}],"hosts":[{{"name":"a.example","key":"{KEY}"}}]}}"#,
            keys(1)
        ),
    );
    write(
        dir.path(),
        "directory.json",
        r#"{"v":1,"source":"model","as_of":"2026-11-19T10:00:00Z","active":["jan"],"members":{}}"#,
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

/// `directory.json` with nobody active and no groups: enough for a site file that names none.
const EMPTY_DIRECTORY: &str = r#"{"v":1,"source":"model","as_of":"2026-11-19T10:00:00Z","active":[],"members":{}}"#;

fn pair(site: &str, directory: &str) -> Result<p_age::site::Site, p_age::site::LoadError> {
    p_age::site::Site::from_texts(site, directory, std::time::SystemTime::now())
}

#[test]
fn a_site_file_with_a_bad_key_a_bad_name_or_a_duplicate_is_refused() {
    let person = |name: &str, keys: &str| format!(r#"{{"name":"{name}",{keys}}}"#);
    let site = |persons: String| format!(r#"{{"v":1,"persons":[{persons}],"hosts":[]}}"#);
    assert!(pair(&site(person("jan", &keys(1))), EMPTY_DIRECTORY).is_ok());
    assert!(pair(&site(person("ja n", &keys(1))), EMPTY_DIRECTORY).is_err());
    assert!(pair(&site(person("jan:confirmed", &keys(1))), EMPTY_DIRECTORY).is_err(), "a name never has a colon");
    assert!(pair(&site(format!("{},{}", person("jan", &keys(1)), person("jan", &keys(5)))), EMPTY_DIRECTORY).is_err());
    let bad = keys(1).replacen(&key_line(1), "not a key", 1);
    assert!(pair(&site(person("jan", &bad)), EMPTY_DIRECTORY).is_err());
    let rsa = keys(1).replacen("ssh-ed25519", "ssh-rsa", 1);
    assert!(pair(&site(person("jan", &rsa)), EMPTY_DIRECTORY).is_err(), "only Ed25519 and ECDSA P-256");
}

#[test]
fn a_persons_four_keys_are_one_object_all_present_and_all_different_and_the_site_file_says_nothing_of_enabled() {
    use p_age::site::{LoadError, SiteError};
    let site = |person: String| format!(r#"{{"v":1,"persons":[{person}],"hosts":[]}}"#);
    let row = |n: u8| format!(r#"{{"key":"{}"}}"#, key_line(n));
    // a person of the site file has approval keys: a row without them is refused
    assert!(pair(&site(r#"{"name":"jan"}"#.to_owned()), EMPTY_DIRECTORY).is_err());
    // never a partial set
    for missing in ["confirmed", "automatic", "delegation", "connection"] {
        let members: Vec<String> = ["confirmed", "automatic", "delegation", "connection"]
            .iter()
            .enumerate()
            .filter(|(_, m)| **m != missing)
            .map(|(i, m)| format!(r#""{m}":{}"#, row(u8::try_from(i).unwrap() + 1)))
            .collect();
        let person = format!(r#"{{"name":"jan","keys":{{{}}}}}"#, members.join(","));
        assert!(pair(&site(person), EMPTY_DIRECTORY).is_err(), "without {missing}");
    }
    // no other member, no unknown purpose, a row is `{key, verified_on?}` and nothing else
    let extra = keys(1).replacen("}}", r#"}, "root": {"key":"x"}}"#, 1);
    assert!(pair(&site(format!(r#"{{"name":"jan",{extra}}}"#)), EMPTY_DIRECTORY).is_err());
    let row_extra = keys(1).replacen(r#""verified_on":"2026-11-10""#, r#""verified_on":"2026-11-10","note":"x""#, 1);
    assert!(pair(&site(format!(r#"{{"name":"jan",{row_extra}}}"#)), EMPTY_DIRECTORY).is_err());
    // `verified_on` is a date
    for bad in ["yesterday", "2026-13-01", "2026-11-32", "26-11-10", "2026/11/10"] {
        let k = keys(1).replacen("2026-11-10", bad, 1);
        assert!(pair(&site(format!(r#"{{"name":"jan",{k}}}"#)), EMPTY_DIRECTORY).is_err(), "{bad}");
    }
    // the four are four different keys
    let same = format!(
        r#""keys":{{"confirmed":{r},"automatic":{r},"delegation":{},"connection":{}}}"#,
        row(3),
        row(4),
        r = row(1)
    );
    assert!(matches!(
        pair(&site(format!(r#"{{"name":"jan",{same}}}"#)), EMPTY_DIRECTORY),
        Err(LoadError::Site(SiteError::KeysClash { .. }))
    ));
    // no key is another person's, and none is a host's
    let two = format!(
        r#"{{"v":1,"persons":[{{"name":"jan",{}}},{{"name":"eva",{}}}],"hosts":[]}}"#,
        keys(1),
        keys(4) // 4 is jan's connection key
    );
    assert!(matches!(pair(&two, EMPTY_DIRECTORY), Err(LoadError::Site(SiteError::KeysClash { .. }))));
    let host = format!(
        r#"{{"v":1,"persons":[{{"name":"jan",{}}}],"hosts":[{{"name":"a.example","key":"{}"}}]}}"#,
        keys(1),
        key_line(2)
    );
    assert!(matches!(pair(&host, EMPTY_DIRECTORY), Err(LoadError::Site(SiteError::KeysClash { .. }))));
    // the site file carries neither `enabled` nor `members`, on any kind: both are refused as unknown members
    assert!(pair(&site(format!(r#"{{"name":"jan","enabled":true,{}}}"#, keys(1))), EMPTY_DIRECTORY).is_err());
    let with_members = r#"{"v":1,"persons":[],"hosts":[],"members":{}}"#.to_owned();
    assert!(pair(&with_members, EMPTY_DIRECTORY).is_err());
    // the shape of an earlier file (flat keys) is refused: nothing is ignored
    let flat = format!(r#"{{"name":"jan","connection_key":"{}","delegation_key":"{}"}}"#, key_line(1), key_line(2));
    assert!(pair(&site(flat), EMPTY_DIRECTORY).is_err());
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
    let directory = write(dir.path(), "directory.json", EMPTY_DIRECTORY);
    let now = std::time::SystemTime::now();
    assert!(p_age::site::Site::read_pair(&site, &directory, now).is_ok());
    mode(&site, 0o666);
    assert!(p_age::site::Site::read_pair(&site, &directory, now).is_err(), "the site file is checked");
    mode(&site, 0o644);
    mode(&directory, 0o666);
    assert!(p_age::site::Site::read_pair(&site, &directory, now).is_err(), "so is directory.json");
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
    std::fs::write(&path, r#"{"v":2,"delegations":[],"blocked":[]}"#).unwrap();
    assert!(matches!(Core::read_state(&path), Err(StateError::Version { v: 2, .. })));
    std::fs::write(&path, r#"{"delegations":[],"blocked":[]}"#).unwrap();
    assert!(Core::read_state(&path).is_err(), "no version member");
    std::fs::write(&path, r#"{"v":1,"delegations":[],"blocked":["jan"],"extra":1}"#).unwrap();
    assert!(Core::read_state(&path).is_err(), "unknown member");
    // one that others can read or write is refused, and so is a directory open to others
    std::fs::write(
        &path,
        r#"{"v":1,"delegations":[],"blocked":[{"name":"jan","at":5,"by":{"kind":"administrator","uid":0}}]}"#,
    )
    .unwrap();
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
    write(dir.path(), "directory.json", EMPTY_DIRECTORY);
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
fn the_groups_a_site_file_names_are_names_a_standing_can_carry() {
    let site =
        |groups: &str| format!(r#"{{"v":1,"persons":[{{"name":"jan",{}}}],"hosts":[],"groups":{groups}}}"#, keys(1));
    let dir = |members: &str| {
        format!(r#"{{"v":1,"source":"model","as_of":"2026-11-19T10:00:00Z","active":["jan"],"members":{members}}}"#)
    };
    assert!(pair(&site(r#"["ops","dev"]"#), &dir(r#"{"ops":["jan"],"dev":[]}"#)).is_ok());
    assert!(pair(&site(r#"["ops","ops"]"#), &dir(r#"{"ops":[]}"#)).is_err(), "a group named twice");
    assert!(pair(&site(r#"["has space"]"#), &dir(r#"{"has space":[]}"#)).is_err());
    assert!(pair(&site(r#"["a,b"]"#), &dir(r#"{"a,b":[]}"#)).is_err());
    assert!(pair(&site(r#"[""]"#), &dir(r#"{"":[]}"#)).is_err());
    assert!(pair(&site(r#"[]"#).replace(r#""groups":[]"#, r#""certificates":["x"]"#), &dir("{}")).is_err());
}

/// `directory.json`: each refusal of the list, and what a good one gives.
#[test]
fn directory_json_is_refused_for_each_reason_on_the_list_and_gives_enabled_and_groups_when_good() {
    use p_age::site::{DirectoryError, LoadError};
    let site = format!(
        r#"{{"v":1,"persons":[{{"name":"jan",{}}},{{"name":"eva",{}}},{{"name":"off",{}}}],"hosts":[],"groups":["ops","dev"]}}"#,
        keys(1),
        keys(5),
        keys(9)
    );
    let file = |v: &str, source: &str, as_of: &str, active: &str, members: &str| {
        format!(r#"{{{v}"source":"{source}","as_of":"{as_of}","active":{active},"members":{members}}}"#)
    };
    let good =
        file(r#""v":1,"#, "model", "2026-11-19T10:00:00Z", r#"["jan","eva"]"#, r#"{"ops":["eva","jan"],"dev":[]}"#);
    let site_good = pair(&site, &good).unwrap();
    // enabled exactly if the site file has the row AND `active` has the name
    let enabled = |n: &str| site_good.person(n).map(|p| p.enabled);
    assert_eq!(
        (enabled("jan"), enabled("eva"), enabled("off"), enabled("nobody")),
        (Some(true), Some(true), Some(false), None)
    );
    assert_eq!(site_good.person("jan").unwrap().groups, ["ops"]);
    assert!(site_good.in_group("eva", "ops") && !site_good.in_group("jan", "dev"));
    let info = site_good.directory().unwrap();
    assert_eq!((info.source.as_str(), info.as_of.as_str()), ("model", "2026-11-19T10:00:00Z"));
    // the three kinds of source are the three it knows
    for source in ["freeipa", "hosted-ldap"] {
        assert!(
            pair(&site, &file(r#""v":1,"#, source, "2026-11-19T10:00:00Z", "[]", r#"{"ops":[],"dev":[]}"#)).is_ok()
        );
    }
    let refused = |text: String| match pair(&site, &text) {
        Err(LoadError::Directory(e)) => e,
        other => panic!("not refused as directory.json: {other:?}\n{text}"),
    };
    let ok_members = r#"{"ops":[],"dev":[]}"#;
    // missing `v`; a wrong one
    assert!(matches!(
        refused(file("", "model", "2026-11-19T10:00:00Z", "[]", ok_members)),
        DirectoryError::Settings(_)
    ));
    assert!(matches!(
        refused(file(r#""v":2,"#, "model", "2026-11-19T10:00:00Z", "[]", ok_members)),
        DirectoryError::Version(2)
    ));
    // an unknown member
    assert!(matches!(refused(good.replacen('{', r#"{"max_age":1,"#, 1)), DirectoryError::Settings(_)));
    // a group of the site file missing as a key; a key that is no group of the site file
    assert!(matches!(
        refused(file(r#""v":1,"#, "model", "2026-11-19T10:00:00Z", "[]", r#"{"ops":[]}"#)),
        DirectoryError::GroupMissing(g) if g == "dev"
    ));
    assert!(matches!(
        refused(file(r#""v":1,"#, "model", "2026-11-19T10:00:00Z", "[]", r#"{"ops":[],"dev":[],"extra":[]}"#)),
        DirectoryError::GroupUnknown(g) if g == "extra"
    ));
    // an unknown or repeated name, in `active` and in `members`
    assert!(matches!(
        refused(file(r#""v":1,"#, "model", "2026-11-19T10:00:00Z", r#"["nobody"]"#, ok_members)),
        DirectoryError::UnknownName { .. }
    ));
    assert!(matches!(
        refused(file(r#""v":1,"#, "model", "2026-11-19T10:00:00Z", r#"["jan","jan"]"#, ok_members)),
        DirectoryError::Repeated { .. }
    ));
    assert!(matches!(
        refused(file(r#""v":1,"#, "model", "2026-11-19T10:00:00Z", r#"["jan"]"#, r#"{"ops":["nobody"],"dev":[]}"#)),
        DirectoryError::UnknownName { .. }
    ));
    assert!(matches!(
        refused(file(r#""v":1,"#, "model", "2026-11-19T10:00:00Z", r#"["jan"]"#, r#"{"ops":["jan","jan"],"dev":[]}"#)),
        DirectoryError::Repeated { .. }
    ));
    // a member that is not in `active`
    assert!(matches!(
        refused(file(r#""v":1,"#, "model", "2026-11-19T10:00:00Z", r#"["jan"]"#, r#"{"ops":["eva"],"dev":[]}"#)),
        DirectoryError::NotActive { .. }
    ));
    // `as_of`: not a time, and more than 60 seconds ahead (a minute ahead is not: the clocks differ a little)
    assert!(matches!(refused(file(r#""v":1,"#, "model", "yesterday", "[]", ok_members)), DirectoryError::AsOf(_)));
    let ahead = |secs: u64| {
        let t = std::time::SystemTime::now() + std::time::Duration::from_secs(secs);
        let unix = i64::try_from(t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()).unwrap();
        p_act::Timestamp::from_unix(unix).unwrap().to_string()
    };
    assert!(matches!(refused(file(r#""v":1,"#, "model", &ahead(3600), "[]", ok_members)), DirectoryError::AsOfAhead));
    assert!(pair(&site, &file(r#""v":1,"#, "model", &ahead(30), "[]", ok_members)).is_ok());
    // an old file is not refused for its age: stage 2 does not age it
    assert!(pair(&site, &file(r#""v":1,"#, "model", "2001-01-01T00:00:00Z", "[]", ok_members)).is_ok());
    // a source it does not know
    assert!(matches!(
        refused(file(r#""v":1,"#, "ldap", "2026-11-19T10:00:00Z", "[]", ok_members)),
        DirectoryError::Source(_)
    ));
    // the site file's persons are unknown to the broker if the file does not have them: a name in `active` that the site file lacks is refused above
}

#[test]
fn when_one_of_the_two_files_is_refused_there_is_no_view_at_all_and_the_error_names_which() {
    let dir = private_dir();
    write(dir.path(), "site.json", &format!(r#"{{"v":1,"persons":[{{"name":"jan",{}}}],"hosts":[]}}"#, keys(1)));
    let page = write(dir.path(), "page.json", &config_text(dir.path(), ""));
    p_age::core::Core::init_state(&dir.path().join("register.json")).unwrap();
    write(dir.path(), "site-ca.pub", KEY);
    let config = Config::read(&page).unwrap();
    // directory.json missing, and then refused: the good site file alone is not a view
    let missing = config.build().err().expect("no directory.json").to_string();
    assert!(missing.starts_with("directory.json:"), "{missing}");
    write(
        dir.path(),
        "directory.json",
        r#"{"v":1,"source":"model","as_of":"2026-11-19T10:00:00Z","active":["nobody"],"members":{}}"#,
    );
    let refused = config.build().err().expect("an unknown name").to_string();
    assert!(refused.starts_with("directory.json:"), "{refused}");
    // and the other way: a good directory.json beside a refused site file names the site file
    write(dir.path(), "directory.json", EMPTY_DIRECTORY);
    write(dir.path(), "site.json", r#"{"v":1,"persons":[{"name":"jan"}],"hosts":[]}"#);
    let refused = config.build().err().expect("a bad site file").to_string();
    assert!(refused.starts_with("the site file:"), "{refused}");
    // both good: built
    write(dir.path(), "site.json", &format!(r#"{{"v":1,"persons":[{{"name":"jan",{}}}],"hosts":[]}}"#, keys(1)));
    assert!(config.build().is_ok());
}
