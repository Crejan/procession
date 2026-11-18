//! The certificates the broker carries to pledge: a separate input (a directory of `*-cert.pub` files, checked
//! against the site CA), with real keys and a real `ssh-keygen`.

mod common;

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::time::{Duration, SystemTime};

use common::*;
use p_age::admin::{Command, Reply, execute};
use p_age::certs::{self, CertificateInput};
use p_age::crypto::SshCrypto;
use p_age::testing::write_certificate;

fn now(w: &World) -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(w.clock.unix()).unwrap())
}

fn input(w: &World, dir: &Path) -> CertificateInput {
    CertificateInput { site_ca: w.keys.public(&w.site_ca), directory: dir.to_path_buf() }
}

fn load(w: &World, dir: &Path) -> certs::Loaded {
    certs::load(&input(w, dir), &w.site, &SshCrypto::new(&w.broker_key), now(w))
}

fn put(dir: &Path, name: &str, line: &str, mode: u32) {
    std::fs::create_dir_all(dir).unwrap();
    // whatever the umask: the directory is one the rule admits
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(dir.join(name), format!("{line}\n")).unwrap();
    std::fs::set_permissions(dir.join(name), std::fs::Permissions::from_mode(mode)).unwrap();
}

fn reason<'a>(loaded: &'a certs::Loaded, file: &str) -> &'a str {
    loaded
        .not_carried
        .iter()
        .find(|n| n.file == file)
        .unwrap_or_else(|| panic!("{file} is carried or unknown: {:?}", loaded.not_carried))
        .reason
        .as_str()
}

#[test]
fn what_the_directory_holds_is_checked_and_what_fails_is_not_carried_with_its_reason() {
    let w = World::new();
    let dir = w.keys.path("collection");
    let ca = &w.site_ca;
    let jan_confirmed_line = |principals: &str, validity: &str, options: &[&str]| {
        issue(&w, &w.jan_confirmed, ca, principals, validity, options)
    };
    // carried: a valid certificate for the key the site file lists for jan's confirmed purpose
    let ok = jan_confirmed_line("jan:confirmed", VALID, &[]);
    put(&dir, "jan-confirmed-cert.pub", &ok, 0o644);
    // the name of the file means nothing: this one is jan's automatic certificate under another name
    let automatic = issue(&w, &w.jan_automatic, ca, "jan:automatic", VALID, &[]);
    put(&dir, "whatever-cert.pub", &automatic, 0o644);
    // not carried, each for its reason
    let rogue = w.keys.key("rogue-ca");
    put(&dir, "other-ca-cert.pub", &issue(&w, &w.jan_confirmed, &rogue, "jan:confirmed", VALID, &[]), 0o644);
    put(&dir, "expired-cert.pub", &jan_confirmed_line("jan:confirmed", "20200101Z:20200102Z", &[]), 0o644);
    put(&dir, "future-cert.pub", &jan_confirmed_line("jan:confirmed", "20980101Z:20990101Z", &[]), 0o644);
    put(&dir, "no-purpose-cert.pub", &jan_confirmed_line("jan", VALID, &[]), 0o644);
    put(&dir, "critical-cert.pub", &jan_confirmed_line("jan:confirmed", VALID, &["force-command=ls"]), 0o644);
    put(&dir, "two-names-cert.pub", &jan_confirmed_line("jan:confirmed,jan:automatic", VALID, &[]), 0o644);
    put(&dir, "reserved-cert.pub", &jan_confirmed_line("broker:confirmed", VALID, &[]), 0o644);
    put(&dir, "stranger-cert.pub", &jan_confirmed_line("mallory:confirmed", VALID, &[]), 0o644);
    // the right person and purpose, but not the key the site file lists
    let other_key = w.keys.key("not-listed");
    std::fs::copy(format!("{}.pub", other_key.display()), w.keys.path("not-listed-copy.pub")).unwrap();
    let wrong_key = issue(&w, &other_key, ca, "jan:confirmed", VALID, &[]);
    put(&dir, "wrong-key-cert.pub", &wrong_key, 0o644);
    put(&dir, "two-lines-cert.pub", &format!("{ok}\n{ok}"), 0o644);
    put(&dir, "writable-cert.pub", &ok, 0o664);
    put(&dir, "empty-cert.pub", "", 0o644);
    symlink(dir.join("jan-confirmed-cert.pub"), dir.join("link-cert.pub")).unwrap();
    // not a certificate by its name: never opened, valid or not, and not reported either
    put(&dir, "plain.pub", &automatic, 0o644);
    put(&dir, "jan-cert.pub.bak", &automatic, 0o644);
    put(&dir, "-cert.pub", &ok, 0o644); // nothing before the suffix: no name

    let loaded = load(&w, &dir);
    assert_eq!(loaded.directory_refused, None);
    let lines: Vec<&str> = loaded.carried["jan"].iter().map(|c| c.line.as_str()).collect();
    assert_eq!(loaded.carried.len(), 1, "{:?}", loaded.carried.keys().collect::<Vec<_>>());
    assert_eq!(lines.len(), 2);
    assert!(lines.contains(&ok.as_str()) && lines.contains(&automatic.as_str()));
    let mut refused: Vec<&str> = loaded.not_carried.iter().map(|n| n.file.as_str()).collect();
    refused.sort_unstable();
    assert_eq!(
        refused,
        [
            "critical-cert.pub",
            "empty-cert.pub",
            "expired-cert.pub",
            "future-cert.pub",
            "link-cert.pub",
            "no-purpose-cert.pub",
            "other-ca-cert.pub",
            "reserved-cert.pub",
            "stranger-cert.pub",
            "two-lines-cert.pub",
            "two-names-cert.pub",
            "writable-cert.pub",
            "wrong-key-cert.pub",
        ]
    );
    assert_eq!(reason(&loaded, "expired-cert.pub"), "expired");
    assert_eq!(reason(&loaded, "future-cert.pub"), "not yet valid");
    assert!(reason(&loaded, "stranger-cert.pub").contains("not in the site file"));
    assert!(reason(&loaded, "wrong-key-cert.pub").contains("not the confirmed key the site file lists"));
    assert_eq!(reason(&loaded, "two-lines-cert.pub"), "not one line");
    assert_eq!(reason(&loaded, "link-cert.pub"), "not a regular file");
    assert!(
        reason(&loaded, "writable-cert.pub").contains("written by someone other"),
        "{}",
        reason(&loaded, "writable-cert.pub")
    );
    assert!(!reason(&loaded, "other-ca-cert.pub").is_empty() && !reason(&loaded, "critical-cert.pub").is_empty());
    // one that has not begun is read again when it does
    assert!(loaded.next_event.is_some());
}

#[test]
fn a_directory_that_fails_the_rule_is_refused_whole_and_nothing_is_carried() {
    let w = World::new();
    let dir = w.keys.path("open-dir");
    put(&dir, "jan-confirmed-cert.pub", &w.keys.cert_line(&w.jan_confirmed), 0o644);
    assert_eq!(load(&w, &dir).carried.len(), 1);
    for bad in [0o775, 0o757, 0o777] {
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(bad)).unwrap();
        let loaded = load(&w, &dir);
        assert!(loaded.directory_refused.is_some(), "{bad:o}");
        assert!(loaded.carried.is_empty() && loaded.not_carried.is_empty(), "{bad:o}");
    }
    // a directory that is not there, and one that is a file
    assert!(load(&w, &w.keys.path("nowhere")).directory_refused.is_some());
    put(w.keys.dir.path(), "a-file", "x", 0o644);
    assert!(load(&w, &w.keys.path("a-file")).directory_refused.is_some());
    // a link to a good directory is not the directory
    symlink(w.keys.path("collection-link-target"), w.keys.path("a-link")).ok();
    assert!(load(&w, &w.keys.path("a-link")).directory_refused.is_some());
}

#[tokio::test]
async fn the_standing_carries_the_certificates_of_its_person_and_nobody_elses() {
    let w = World::new();
    let mut jan = open_pledge(&w).await;
    let standing = jan.connect_as("jan", &w.jan_connection).await;
    let mut expected = vec![w.keys.cert_line(&w.jan_confirmed), w.keys.cert_line(&w.jan_automatic)];
    expected.sort();
    assert_eq!(standing["certificates"], serde_json::json!(expected));
    let mut eva = open_pledge(&w).await;
    let standing = eva.connect_as("eva", &w.eva_connection).await;
    assert_eq!(standing["certificates"].as_array().unwrap().len(), 2);
    assert!(!standing["certificates"].to_string().contains(&w.keys.cert_line(&w.jan_confirmed)));
    // `page status` counts them, and every enabled person is covered
    let Reply::Status(s) = execute(&w.broker, Command::Status).await else { panic!("status") };
    let c = s.certificates.unwrap();
    assert_eq!((c.carried, c.not_carried, c.directory_refused, c.uncovered.len()), (4, 0, false, 0));
}

#[tokio::test]
async fn the_directory_is_read_again_once_a_minute_when_it_changed_and_pledge_is_told() {
    let w = World::new();
    let mut jan = open_pledge(&w).await;
    jan.connect_as("jan", &w.jan_connection).await;
    // nothing changed: a minute on, no new standing
    w.clock.advance(61);
    w.broker.sweep().await;
    assert!(tokio::time::timeout(Duration::from_millis(400), jan.lines.read(None)).await.is_err());
    // a second certificate for jan's confirmed key (a renewal that overlaps the old one)
    let renewal = issue(&w, &w.jan_confirmed, &w.site_ca, "jan:confirmed", "20210101Z:20990101Z", &[]);
    write_certificate(&w.certs_dir, "jan", "confirmed-renewed", &renewal);
    // less than a minute since the last look: not yet
    w.clock.advance(30);
    w.broker.sweep().await;
    assert!(tokio::time::timeout(Duration::from_millis(300), jan.lines.read(None)).await.is_err());
    w.clock.advance(31);
    w.broker.sweep().await;
    let v = jan.recv().await;
    assert_eq!(v["type"], "notice");
    let standing = serde_json::from_slice::<serde_json::Value>(
        &base64::Engine::decode(&base64::engine::general_purpose::STANDARD, v["doc"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(standing["certificates"].as_array().unwrap().len(), 3);
    assert_eq!(standing["n"], 1);
    // a file removed: its certificate is no longer carried, and pledge is told
    std::fs::remove_file(w.certs_dir.join("jan-confirmed-renewed-cert.pub")).unwrap();
    w.clock.advance(61);
    w.broker.sweep().await;
    let v = jan.recv().await;
    let standing = serde_json::from_slice::<serde_json::Value>(
        &base64::Engine::decode(&base64::engine::general_purpose::STANDARD, v["doc"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(standing["certificates"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn a_certificate_that_ends_is_dropped_at_its_end_and_status_says_who_is_left_without() {
    let w = World::new();
    // jan's automatic certificate is replaced by one that lasts two more minutes
    std::fs::remove_file(w.certs_dir.join("jan-automatic-cert.pub")).unwrap();
    let short = issue(&w, &w.jan_automatic, &w.site_ca, "jan:automatic", "-1h:+2m", &[]);
    write_certificate(&w.certs_dir, "jan", "automatic", &short);
    let mut jan = open_pledge(&w).await;
    jan.connect_as("jan", &w.jan_connection).await;
    w.clock.advance(61);
    w.broker.sweep().await; // the directory changed: read again
    assert_eq!(jan.recv_type().await, "notice");
    let Reply::Status(s) = execute(&w.broker, Command::Status).await else { panic!("status") };
    assert!(s.certificates.unwrap().uncovered.is_empty());
    // two minutes on, it has ended: dropped, with no change to the directory
    w.clock.advance(120);
    w.broker.sweep().await;
    assert_eq!(jan.recv_type().await, "notice");
    let Reply::Status(s) = execute(&w.broker, Command::Status).await else { panic!("status") };
    assert_eq!(s.certificates.unwrap().uncovered, ["jan:automatic"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_status_exits_6_when_an_enabled_person_has_no_valid_certificate_and_5_comes_first() {
    let w = World::new();
    let _socket = serve_admin(&w);
    let config = config_file(&w);
    let (code, out, _) = page(&config, &["status"]).await;
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("certificates carried: 4") && out.contains("persons without a valid certificate: none"),
        "{out}"
    );
    // eva's confirmed certificate goes
    std::fs::remove_file(w.certs_dir.join("eva-confirmed-cert.pub")).unwrap();
    w.clock.advance(61);
    w.broker.sweep().await;
    let (code, out, _) = page(&config, &["status"]).await;
    assert_eq!(code, 6, "{out}");
    assert!(out.contains("persons without a valid certificate: eva:confirmed"), "{out}");
    // and when the register cannot be written too, 5 (degraded) comes first: one code, one meaning
    std::fs::set_permissions(w.keys.dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    if std::fs::File::create(w.keys.path("probe")).is_err() {
        w.broker.block_person("jan".into()).await;
        let (code, _, _) = page(&config, &["status"]).await;
        assert_eq!(code, 5);
    }
    std::fs::set_permissions(w.keys.dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let (_, help, _) = page(&config, &["status", "--help"]).await;
    assert!(help.contains("6  an enabled person has no valid certificate for a purpose"), "{help}");
}

#[test]
fn the_configuration_names_the_site_ca_and_may_name_the_directory() {
    use p_age::config::{Config, ConfigError};
    let w = World::new();
    let dir = w.keys.dir.path().display();
    let text = |extra: &str| {
        format!(
            r#"{{"site":"{dir}/site.json","listen":["127.0.0.1:0"],"tls_cert":"{dir}/c.pem","tls_key":"{dir}/k.pem","broker_key":"{dir}/broker","state_dir":"{dir}","log":"{dir}/log.jsonl"{extra}}}"#
        )
    };
    let path = w.keys.path("page.json");
    let write = |t: String| {
        std::fs::write(&path, t).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    };
    // the site CA key is required (the broker's own certificate is checked against it)
    write(text(""));
    assert!(matches!(Config::read(&path), Err(ConfigError::Settings(_))));
    write(text(&format!(r#","site_ca":"{dir}/site-ca.pub""#)));
    assert!(Config::read(&path).unwrap().certificates.is_none());
    // there is no member for the broker's certificate: its path is `<broker_key>-cert.pub`
    write(text(&format!(r#","site_ca":"{dir}/site-ca.pub","broker_certificate":"{dir}/broker-cert.pub""#)));
    assert!(matches!(Config::read(&path), Err(ConfigError::Settings(_))));
    // with the directory: the broker built from it carries the certificates
    SiteBuilder_write(&w);
    write(text(&format!(r#","site_ca":"{dir}/site-ca.pub","certificates":"{}""#, w.certs_dir.display())));
    let config = Config::read(&path).unwrap();
    std::fs::remove_file(w.keys.path("register.json")).unwrap();
    p_age::core::Core::init_state(&w.keys.path("register.json")).unwrap();
    let broker = config.build().unwrap();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let Reply::Status(s) = rt.block_on(execute(&broker, Command::Status)) else { panic!("status") };
    assert_eq!(s.certificates.unwrap().carried, 4);
    assert!(s.broker_certificate.valid);
    assert_eq!(s.broker_certificate.path, format!("{dir}/broker-cert.pub"));
    // a site CA key that others can write is refused, like a settings file
    std::fs::set_permissions(w.keys.path("site-ca.pub"), std::fs::Permissions::from_mode(0o666)).unwrap();
    assert!(matches!(config.build(), Err(ConfigError::SiteCa { .. })));
}

#[allow(non_snake_case)]
fn SiteBuilder_write(w: &World) {
    // the broker reads the site file the configuration names
    let line = |k: &Path| w.keys.public(k).to_string();
    p_age::testing::SiteBuilder::new()
        .person(p_age::testing::PersonSpec::new("jan").keys(
            &line(&w.jan_confirmed),
            &line(&w.jan_automatic),
            &line(&w.jan_delegation),
            &line(&w.jan_connection),
        ))
        .person(p_age::testing::PersonSpec::new("eva").keys(
            &line(&w.eva_confirmed),
            &line(&w.eva_automatic),
            &line(&w.eva_delegation),
            &line(&w.eva_connection),
        ))
        .host("a.example", &line(&w.host_key))
        .write(&w.keys.path("site.json"))
        .unwrap();
}

#[test]
fn the_site_file_has_no_certificates_member_any_more() {
    let w = World::new();
    let json = format!(
        r#"{{"v":1,"persons":[{{"name":"jan","enabled":true,"certificates":["{}"]}}],"hosts":[]}}"#,
        w.keys.cert_line(&w.jan_confirmed)
    );
    assert!(p_age::site::Site::from_json(&json).is_err(), "refused as unknown");
}
