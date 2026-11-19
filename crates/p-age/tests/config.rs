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
    assert!(p_age::site::SiteBase::read(&site).is_ok());
    assert!(p_age::site::Directory::read(&directory, now).is_ok());
    mode(&site, 0o666);
    assert!(p_age::site::SiteBase::read(&site).is_err(), "the site file is checked");
    mode(&site, 0o644);
    mode(&directory, 0o666);
    assert!(p_age::site::Directory::read(&directory, now).is_err(), "so is directory.json");
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

/// `directory.json` is read **on its own**: what contradicts itself or its form is refused, whatever the site file says.
#[test]
fn directory_json_is_refused_only_for_what_contradicts_itself_or_its_form() {
    use p_age::site::{Directory, DirectoryError};
    let now = std::time::SystemTime::now();
    let file = |v: &str, source: &str, as_of: &str, active: &str, members: &str| {
        format!(r#"{{{v}"source":"{source}","as_of":"{as_of}","active":{active},"members":{members}}}"#)
    };
    let at = "2026-11-19T10:00:00Z";
    let refused = |text: String| match Directory::from_text(&text, now) {
        Err(e) => e,
        Ok(_) => panic!("not refused:\n{text}"),
    };
    assert!(
        Directory::from_text(
            &file(r#""v":1,"#, "model", at, r#"["jan","eva"]"#, r#"{"ops":["eva","jan"],"dev":[]}"#),
            now
        )
        .is_ok()
    );
    for source in ["freeipa", "hosted-ldap"] {
        assert!(Directory::from_text(&file(r#""v":1,"#, source, at, "[]", "{}"), now).is_ok());
    }
    // missing `v`; an unknown one; an unknown member of the object
    assert!(matches!(refused(file("", "model", at, "[]", "{}")), DirectoryError::Settings(_)));
    assert!(matches!(refused(file(r#""v":2,"#, "model", at, "[]", "{}")), DirectoryError::Version(2)));
    assert!(matches!(refused(file(r#""v":1,"max_age":1,"#, "model", at, "[]", "{}")), DirectoryError::Settings(_)));
    // `source` outside the three
    assert!(matches!(refused(file(r#""v":1,"#, "ldap", at, "[]", "{}")), DirectoryError::Source(_)));
    // `as_of` not UTC to the second, and more than 60 s ahead (30 s ahead is not: the clocks differ a little)
    assert!(matches!(refused(file(r#""v":1,"#, "model", "yesterday", "[]", "{}")), DirectoryError::AsOf(_)));
    assert!(matches!(
        refused(file(r#""v":1,"#, "model", "2026-11-19T10:00:00+01:00", "[]", "{}")),
        DirectoryError::AsOf(_)
    ));
    let ahead = |secs: u64| {
        let t = now + std::time::Duration::from_secs(secs);
        let unix = i64::try_from(t.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()).unwrap();
        p_act::Timestamp::from_unix(unix).unwrap().to_string()
    };
    assert!(matches!(refused(file(r#""v":1,"#, "model", &ahead(3600), "[]", "{}")), DirectoryError::AsOfAhead));
    assert!(Directory::from_text(&file(r#""v":1,"#, "model", &ahead(30), "[]", "{}"), now).is_ok());
    // an old file is not refused for its age: stage 2 does not age it
    assert!(Directory::from_text(&file(r#""v":1,"#, "model", "2001-01-01T00:00:00Z", "[]", "{}"), now).is_ok());
    // a name outside the character rules; a name repeated within one list; a key repeated; a member not in `active`
    assert!(matches!(refused(file(r#""v":1,"#, "model", at, r#"["a b"]"#, "{}")), DirectoryError::BadName { .. }));
    assert!(matches!(
        refused(file(r#""v":1,"#, "model", at, r#"["jan"]"#, r#"{"ops":["a b"]}"#)),
        DirectoryError::BadName { .. }
    ));
    assert!(matches!(
        refused(file(r#""v":1,"#, "model", at, "[]", r#"{"has space":[]}"#)),
        DirectoryError::BadName { .. }
    ));
    assert!(matches!(
        refused(file(r#""v":1,"#, "model", at, r#"["jan","jan"]"#, "{}")),
        DirectoryError::Repeated { .. }
    ));
    assert!(matches!(
        refused(file(r#""v":1,"#, "model", at, r#"["jan"]"#, r#"{"ops":["jan","jan"]}"#)),
        DirectoryError::Repeated { .. }
    ));
    assert!(matches!(
        refused(file(r#""v":1,"#, "model", at, "[]", r#"{"ops":[],"ops":[]}"#)),
        DirectoryError::Settings(_)
    ));
    assert!(matches!(
        refused(file(r#""v":1,"#, "model", at, r#"["jan"]"#, r#"{"ops":["eva"]}"#)),
        DirectoryError::NotActive { .. }
    ));
}

/// What the broker decides from is the intersection of the two files, computed at load; each difference only restricts.
#[test]
fn the_view_is_the_intersection_and_what_one_file_alone_knows_is_ignored_and_counted() {
    let site = |persons: &[&str], groups: &str| {
        let rows: Vec<String> = persons
            .iter()
            .enumerate()
            .map(|(i, n)| format!(r#"{{"name":"{n}",{}}}"#, keys(u8::try_from(i).unwrap() * 4 + 1)))
            .collect();
        format!(r#"{{"v":1,"persons":[{}],"hosts":[],"groups":{groups}}}"#, rows.join(","))
    };
    let directory = |active: &str, members: &str| {
        format!(r#"{{"v":1,"source":"model","as_of":"2026-11-19T10:00:00Z","active":{active},"members":{members}}}"#)
    };
    let enabled = |s: &p_age::site::Site, n: &str| s.person(n).map(|p| p.enabled);
    // both agree
    let both = pair(
        &site(&["jan", "eva", "off"], r#"["ops","dev"]"#),
        &directory(r#"["jan","eva"]"#, r#"{"ops":["eva","jan"],"dev":[]}"#),
    )
    .unwrap();
    assert_eq!(
        (enabled(&both, "jan"), enabled(&both, "eva"), enabled(&both, "off"), enabled(&both, "nobody")),
        (Some(true), Some(true), Some(false), None)
    );
    assert_eq!(both.person("jan").unwrap().groups, ["ops"]);
    assert!(both.in_group("eva", "ops") && !both.in_group("jan", "dev"));
    assert!(both.mismatch().is_empty());
    let info = both.directory().unwrap();
    assert_eq!((info.source.as_str(), info.as_of.as_str()), ("model", "2026-11-19T10:00:00Z"));
    // the site file loses a person while directory.json still names them: the person is gone at once
    let lost = pair(
        &site(&["eva", "off"], r#"["ops","dev"]"#),
        &directory(r#"["jan","eva"]"#, r#"{"ops":["eva","jan"],"dev":[]}"#),
    )
    .unwrap();
    assert_eq!((enabled(&lost, "jan"), enabled(&lost, "eva")), (None, Some(true)));
    assert!(
        !lost.in_group("jan", "ops") && lost.in_group("eva", "ops"),
        "a name under a key that is no person is ignored"
    );
    assert_eq!(lost.mismatch().names_not_in_site, ["jan"]);
    // the site file gains a group that directory.json does not have yet: it loads, the group is empty, and it is counted
    let gained = pair(
        &site(&["jan", "eva"], r#"["ops","dev","new"]"#),
        &directory(r#"["jan","eva"]"#, r#"{"ops":["jan"],"dev":[]}"#),
    )
    .unwrap();
    assert_eq!(gained.members().unwrap()["new"], Vec::<String>::new());
    assert_eq!(gained.mismatch().groups_without_members, ["new"]);
    // and the site file loses a group that directory.json still has: its key is ignored and counted
    let dropped =
        pair(&site(&["jan"], r#"["ops"]"#), &directory(r#"["jan"]"#, r#"{"ops":["jan"],"old":["jan"]}"#)).unwrap();
    assert!(dropped.members().unwrap().get("old").is_none() && dropped.in_group("jan", "ops"));
    assert_eq!(dropped.mismatch().groups_not_in_site, ["old"]);
    // directory.json with a stranger in `active` or `members`: it loads, the stranger is counted once
    let stranger =
        pair(&site(&["jan"], r#"["ops"]"#), &directory(r#"["jan","stranger"]"#, r#"{"ops":["jan","stranger"]}"#))
            .unwrap();
    assert_eq!(stranger.mismatch().names_not_in_site, ["stranger"]);
    assert_eq!(enabled(&stranger, "stranger"), None);
    // a person who is in the site file and not active is in no group, whatever `members` could say (and it cannot:
    // a member must be active)
    let off = pair(&site(&["jan", "off"], r#"["ops"]"#), &directory(r#"["jan"]"#, r#"{"ops":["jan"]}"#)).unwrap();
    assert!(off.person("off").unwrap().groups.is_empty() && !off.person("off").unwrap().enabled);
}

#[test]
fn at_start_the_site_file_is_required_and_directory_json_is_not_nobody_is_active_without_it() {
    let dir = private_dir();
    let site_text = format!(r#"{{"v":1,"persons":[{{"name":"jan",{}}}],"hosts":[]}}"#, keys(1));
    write(dir.path(), "site.json", &site_text);
    let page = write(dir.path(), "page.json", &config_text(dir.path(), ""));
    p_age::core::Core::init_state(&dir.path().join("register.json")).unwrap();
    write(dir.path(), "site-ca.pub", KEY);
    let config = Config::read(&page).unwrap();
    let now = std::time::SystemTime::now();
    let site = dir.path().join("site.json");
    let directory = dir.path().join("directory.json");
    // directory.json missing: the broker is built, nobody is active, and the view says why
    let view = p_age::site::Site::load(&site, &directory, now).unwrap();
    assert_eq!(view.person("jan").map(|p| p.enabled), Some(false));
    assert!(view.directory().is_none() && view.directory_problem().unwrap().starts_with("directory.json:"));
    assert!(config.build().is_ok(), "it starts, and clears nothing");
    // it looks the same as a directory that is too old: `page status` exits 5 (degraded) with a line of its own
    let status = p_age::core::Status {
        directory: None,
        directory_problem: view.directory_problem().map(str::to_owned),
        ..status_of(&view)
    };
    let (text, code) =
        p_age::admin::render(&p_age::admin::Command::Status, &p_age::admin::Reply::Status(Box::new(status)));
    assert_eq!(code, 5, "{text}");
    assert!(text.contains("directory: none (directory.json:") && text.contains("5  no valid directory.json"), "{text}");
    // refused on its own faults: the same
    write(
        dir.path(),
        "directory.json",
        r#"{"v":1,"source":"ldap","as_of":"2026-11-19T10:00:00Z","active":["jan"],"members":{}}"#,
    );
    let view = p_age::site::Site::load(&site, &directory, now).unwrap();
    assert_eq!(view.person("jan").map(|p| p.enabled), Some(false), "nobody is active on a file that is refused");
    assert!(view.directory_problem().is_some());
    assert!(config.build().is_ok());
    // a good one: jan is active
    write(
        dir.path(),
        "directory.json",
        r#"{"v":1,"source":"model","as_of":"2026-11-19T10:00:00Z","active":["jan"],"members":{}}"#,
    );
    let view = p_age::site::Site::load(&site, &directory, now).unwrap();
    assert_eq!((view.person("jan").map(|p| p.enabled), view.directory_problem()), (Some(true), None));
    // the site file is required: refused or missing, there is no broker, whatever directory.json says
    write(dir.path(), "site.json", r#"{"v":1,"persons":[{"name":"jan"}],"hosts":[]}"#);
    assert!(p_age::site::Site::load(&site, &directory, now).is_err());
    assert!(config.build().err().expect("a bad site file").to_string().starts_with("the site file:"));
    std::fs::remove_file(&site).unwrap();
    assert!(config.build().is_err());
}

/// A `Status` for a view, with nothing else wrong.
fn status_of(view: &p_age::site::Site) -> p_age::core::Status {
    p_age::core::Status {
        administrators: None,
        directory: view.directory().cloned(),
        directory_problem: None,
        directory_sets: view.mismatch().clone(),
        broker_uid: 501,
        keygen_unusable: None,
        degraded: None,
        pledges: 0,
        held: 0,
        delegations: 0,
        withdrawn: 0,
        blocked_persons: vec![],
        blocked_keys: vec![],
        broker_certificate: p_age::core::BrokerCertificateStatus {
            path: "/x".into(),
            valid: true,
            days_left: Some(3),
            failure: None,
        },
        certificates: None,
    }
}
