//! The broker's own certificate: checked at start and once a minute for the name `broker`, the site CA, validity, no
//! critical option and no extension, and for the key the broker holds. A broker without a valid one issues no
//! clearance and no standing, and `page status` says so (exit 7).

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use common::*;
use p_act::sign::{Signer, sign_approval};
use p_age::admin::{Command, Reply, execute};

fn cert_file(w: &World) -> PathBuf {
    PathBuf::from(format!("{}-cert.pub", w.broker_key.display()))
}

/// Issue a new certificate for the broker's key in the place `ssh-keygen` finds it.
fn reissue(w: &World, ca: &std::path::Path, principals: &str, validity: &str, options: &[&str]) {
    let mut args =
        vec!["-q", "-s", ca.to_str().unwrap(), "-I", "broker", "-n", principals, "-V", validity, "-O", "clear"];
    for o in options {
        args.extend(["-O", o]);
    }
    let pub_file = format!("{}.pub", w.broker_key.display());
    args.push(&pub_file);
    w.keys.keygen(&args);
}

async fn recheck(w: &World) {
    w.clock.advance(61);
    w.broker.sweep().await;
}

async fn status(w: &World) -> p_age::core::BrokerCertificateStatus {
    let Reply::Status(s) = execute(&w.broker, Command::Status).await else { panic!("status") };
    s.broker_certificate
}

#[tokio::test]
async fn a_valid_certificate_is_checked_at_start_and_status_says_how_many_days_are_left() {
    let w = World::new();
    let s = status(&w).await;
    assert!(s.valid && s.failure.is_none());
    assert!(s.days_left.unwrap() > 1000, "{s:?}"); // the test certificates last until 2099
    // a certificate with ten days left
    reissue(&w, &w.site_ca, "broker", "-1h:+10d", &[]);
    recheck(&w).await;
    let s = status(&w).await;
    assert!(s.valid && (9..=10).contains(&s.days_left.unwrap()), "{s:?}");
}

#[tokio::test]
async fn each_way_a_certificate_can_be_wrong_is_a_broker_without_a_certificate_and_is_noticed_within_a_minute() {
    let w = World::new();
    let rogue = w.keys.key("rogue-ca");
    // what, who issued it, principals, validity, options, and the failure `status` must show
    type Case<'a> = (&'a str, PathBuf, &'a str, &'a str, Vec<&'a str>, &'a str);
    let cases: Vec<Case> = vec![
        ("expired", w.site_ca.clone(), "broker", "20200101Z:20200102Z", vec![], "expired"),
        ("not yet valid", w.site_ca.clone(), "broker", "20980101Z:20990101Z", vec![], "not-yet-valid"),
        ("another name", w.site_ca.clone(), "jan", VALID, vec![], "refused"),
        ("two names", w.site_ca.clone(), "broker,jan", VALID, vec![], "refused"),
        ("a person's purpose name", w.site_ca.clone(), "broker:confirmed", VALID, vec![], "refused"),
        ("a critical option", w.site_ca.clone(), "broker", VALID, vec!["force-command=ls"], "refused"),
        ("an extension", w.site_ca.clone(), "broker", VALID, vec!["extension:permit-pty"], "refused"),
        ("not the site CA", rogue, "broker", VALID, vec![], "refused"),
    ];
    for (what, ca, principals, validity, options, code) in cases {
        reissue(&w, &ca, principals, validity, &options);
        recheck(&w).await;
        let s = status(&w).await;
        assert!(!s.valid, "{what}: {s:?}");
        assert_eq!(s.failure, Some(code), "{what}");
        // and back to a good one
        reissue(&w, &w.site_ca, "broker", VALID, &[]);
        recheck(&w).await;
        assert!(status(&w).await.valid, "{what}: valid again");
    }
    // no file at all
    let saved = std::fs::read(cert_file(&w)).unwrap();
    std::fs::remove_file(cert_file(&w)).unwrap();
    recheck(&w).await;
    assert_eq!(status(&w).await.failure, Some("missing"));
    std::fs::write(cert_file(&w), saved).unwrap();
    // (whatever the umask: a certificate file others can write is refused, like any file of the settings rule)
    std::fs::set_permissions(cert_file(&w), std::fs::Permissions::from_mode(0o644)).unwrap();
    recheck(&w).await;
    assert!(status(&w).await.valid);
}

async fn nothing_for(c: &mut Client) {
    assert!(tokio::time::timeout(std::time::Duration::from_millis(400), c.lines.read(None)).await.is_err());
}

#[tokio::test]
async fn a_broker_that_is_not_ready_lets_a_pledge_in_without_a_standing_and_serves_only_what_restricts() {
    let w = World::new();
    let mut pledge = open_pledge(&w).await;
    pledge.connect_as("jan", &w.jan_connection).await;
    pledge
        .send_json(serde_json::json!({"schema_version":1,"type":"delegation","cert":w.keys.cert_line(&w.agent)}))
        .await;
    assert_eq!(pledge.recv_type().await, "registered");
    let fp = agent_fingerprint(&w);
    let submit = w.submit(1, 500);
    let mut service = open_service(&w);
    service.send(&submit_line(&submit)).await;
    assert_eq!(pledge.recv_type().await, "submit");

    // the certificate ends: the pledge that is connected is told `not-ready`, once
    reissue(&w, &w.site_ca, "broker", "20200101Z:20200102Z", &[]);
    recheck(&w).await;
    assert_eq!(pledge.recv().await, serde_json::json!({"schema_version":1,"type":"not-ready"}));
    w.clock.advance(61);
    w.broker.sweep().await;
    nothing_for(&mut pledge).await;

    // an approval that comes back: the service is answered `refused` `not-ready`, no clearance; the loss is logged
    let approval = sign_approval(&Signer::certified(&w.jan_confirmed).unwrap(), submit.request()).unwrap();
    pledge.send(&approval_line(hash_of(&submit), &approval)).await;
    let v = service.recv().await;
    assert_eq!(
        (v["type"].as_str(), v["result"].as_str(), v["by"].as_str(), v["reason"].as_str()),
        (Some("answer"), Some("refused"), Some("broker"), Some("not-ready"))
    );
    assert!(v.get("clearance").is_none() && v.get("approval").is_none());
    wait_logged(&w, 1).await;
    assert_eq!(w.log.entries()[0].result, "approval-lost:not-ready");
    // a service that comes back for it gets the same answer again
    let mut again = open_service(&w);
    again.send(&submit_line(&submit)).await;
    assert_eq!(again.recv().await["reason"], "not-ready");

    // a registration: `not-registered` with `unavailable`; nothing that permits is served
    let other = w.keys.certified("agent2", &w.jan_delegation, "jan", "-5m:+8h", &["extension:groups@procession=ops"]);
    pledge.send_json(serde_json::json!({"schema_version":1,"type":"delegation","cert":w.keys.cert_line(&other)})).await;
    let v = pledge.recv().await;
    assert_eq!((v["type"].as_str(), v["reason"].as_str()), (Some("not-registered"), Some("unavailable")));
    // a withdrawal is taken and answered as always
    pledge.send_json(serde_json::json!({"schema_version":1,"type":"withdraw","delegation":fp})).await;
    let v = pledge.recv().await;
    assert_eq!((v["type"].as_str(), v["stored"].as_bool()), (Some("withdrawn"), Some(true)));

    // a pledge that signs in is let in: `ready`, then `not-ready` in place of a standing, and the connection stays
    let mut eva = open_pledge(&w).await;
    eva.sign_in("eva", &w.eva_connection).await;
    assert_eq!(eva.recv_type().await, "ready");
    assert_eq!(eva.recv().await, serde_json::json!({"schema_version":1,"type":"not-ready"}));
    eva.send_json(serde_json::json!({"schema_version":1,"type":"ping"})).await;
    nothing_for(&mut eva).await;
    // an administrator's block is in force and nothing is sent that could not be vouched for
    w.broker.block_person("eva".into()).await;
    nothing_for(&mut eva).await;

    // the certificate is valid again: both pledges get the standing, without signing in again
    reissue(&w, &w.site_ca, "broker", VALID, &[]);
    recheck(&w).await;
    let v = pledge.recv().await;
    assert_eq!(v["type"], "notice");
    let v = eva.recv().await;
    assert_eq!(v["type"], "notice");
}

#[tokio::test]
async fn a_certificate_that_ends_between_two_looks_is_noticed_at_its_end_and_requests_wait_for_the_standing() {
    let w = World::new();
    reissue(&w, &w.site_ca, "broker", "-1h:+2m", &[]);
    recheck(&w).await; // the short certificate is the one in force now
    let mut pledge = open_pledge(&w).await;
    pledge.connect_as("jan", &w.jan_connection).await;
    pledge
        .send_json(serde_json::json!({"schema_version":1,"type":"delegation","cert":w.keys.cert_line(&w.agent)}))
        .await;
    assert_eq!(pledge.recv_type().await, "registered");
    // it ends with no look at the file between: the sweep (every second) sees the end
    w.clock.advance(125);
    w.broker.sweep().await;
    assert_eq!(pledge.recv_type().await, "not-ready");
    // a request that arrives now is held and not put to the pledge
    let submit = w.submit(1, 500);
    let mut service = open_service(&w);
    service.send(&submit_line(&submit)).await;
    wait_held(&w, 1).await;
    nothing_for(&mut pledge).await;
    // a valid certificate: the standing, and then the request that waited
    reissue(&w, &w.site_ca, "broker", VALID, &[]);
    recheck(&w).await;
    assert_eq!(pledge.recv_type().await, "notice");
    assert_eq!(pledge.recv_type().await, "submit");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_status_exits_7_without_a_valid_certificate_before_5_and_6() {
    let w = World::new();
    let _socket = serve_admin(&w);
    let config = config_file(&w);
    let (code, out, _) = page(&config, &["status"]).await;
    assert_eq!(code, 0, "{out}");
    assert!(
        out.contains("conditions: none") && out.contains("broker certificate (") && out.contains("-cert.pub): valid,"),
        "{out}"
    );
    // 6: eva has no confirmed certificate
    std::fs::remove_file(w.certs_dir.join("eva-confirmed-cert.pub")).unwrap();
    recheck(&w).await;
    assert_eq!(page(&config, &["status"]).await.0, 6);
    // 5 before 6: the register cannot be written
    std::fs::set_permissions(w.keys.dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    let can_lock = std::fs::File::create(w.keys.path("probe")).is_err();
    if can_lock {
        w.broker.block_person("jan".into()).await;
        assert_eq!(page(&config, &["status"]).await.0, 5);
    }
    // 7 before both: no certificate, nothing is cleared at all
    reissue_unlocked(&w, can_lock);
    recheck(&w).await;
    let (code, out, _) = page(&config, &["status"]).await;
    assert_eq!(code, 7, "{out}");
    assert!(
        out.contains("7  the broker has no valid certificate of its own (") && out.contains("): expired;"),
        "{out}"
    );
    // every condition that holds is a line, the gravest first: 7, then 5, then 6
    let lines: Vec<&str> =
        out.lines().filter(|l| l.starts_with("  7  ") || l.starts_with("  5  ") || l.starts_with("  6  ")).collect();
    assert_eq!(
        lines.iter().map(|l| &l[2..3]).collect::<Vec<_>>(),
        if can_lock { vec!["7", "5", "6"] } else { vec!["7", "6"] },
        "{out}"
    );
    // and the same list as an array
    let (code, json, _) = page(&config, &["status", "--format", "json"]).await;
    assert_eq!(code, 7);
    let list: serde_json::Value = serde_json::from_str(&json).unwrap();
    let codes: Vec<u64> = list.as_array().unwrap().iter().map(|c| c["code"].as_u64().unwrap()).collect();
    assert_eq!(codes, if can_lock { vec![7, 5, 6] } else { vec![7, 6] }, "{json}");
    assert_eq!(list[0]["condition"], "no-broker-certificate");
    assert_eq!(list[0]["detail"], "expired");
    let (_, help, _) = page(&config, &["status", "--help"]).await;
    assert!(help.contains("7  the broker has no valid certificate of its own: it issues no clearances"), "{help}");
    assert!(
        help.contains("The exit code of `status` is the gravest condition that holds, in the order 7, 5, 6"),
        "{help}"
    );
    assert!(help.contains("its lines are the complete list"), "{help}");
    std::fs::set_permissions(w.keys.dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
}

/// The certificate is replaced by an expired one while the directory may be locked: the key's files are in it, so unlock
/// for the moment (the register stays degraded if it was).
fn reissue_unlocked(w: &World, locked: bool) {
    if locked {
        std::fs::set_permissions(w.keys.dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    reissue(w, &w.site_ca, "broker", "20200101Z:20200102Z", &[]);
    if locked {
        std::fs::set_permissions(w.keys.dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    }
}
