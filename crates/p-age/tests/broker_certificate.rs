//! The broker's own certificate: checked at start and once a minute for the name `broker`, the site CA, validity, no
//! critical option and no extension, and for the key the broker holds. A broker without a valid one issues no
//! clearance and no standing, and `page status` says so (exit 7).

mod common;

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use common::*;
use p_act::exchange::{BrokerReason, ClearancePolicy, Message, Outcome, Refused};
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
    s.broker_certificate.expect("the broker's certificate is checked")
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
    recheck(&w).await;
    assert!(status(&w).await.valid);
}

#[tokio::test]
async fn a_broker_without_a_valid_certificate_issues_no_clearance_and_no_standing_and_recovers() {
    let w = World::new();
    let mut pledge = open_pledge(&w).await;
    pledge.connect_as("jan", &w.jan_connection).await;
    pledge
        .send_json(serde_json::json!({"schema_version":1,"type":"delegation","cert":w.keys.cert_line(&w.agent)}))
        .await;
    assert_eq!(pledge.recv_type().await, "registered");
    // the certificate ends: not at the next look but at its end, the broker does not sign
    reissue(&w, &w.site_ca, "broker", "20200101Z:20200102Z", &[]);
    let submit = w.submit(1, 500);
    let mut service = open_service(&w);
    service.send(&submit_line(&submit)).await;
    assert_eq!(pledge.recv_type().await, "submit");
    recheck(&w).await; // noticed
    let approval = sign_approval(&Signer::certified(&w.jan_confirmed).unwrap(), submit.request()).unwrap();
    pledge.send(&approval_line(hash_of(&submit), &approval)).await;
    let line = service.recv_raw().await.unwrap();
    let Message::Answer(answer) = Message::parse(&line, ClearancePolicy::Required).unwrap() else {
        panic!("an answer")
    };
    assert!(
        matches!(answer.outcome, Outcome::Refused(Refused::Broker(BrokerReason::Busy))),
        "an approval comes back and gets no clearance: {answer:?}"
    );
    // a pledge that signs in is told `busy` (no standing can be made that it could verify) and closed
    let mut again = open_pledge(&w).await;
    again.sign_in("jan", &w.jan_connection).await;
    let mut got = again.recv().await;
    while got["type"] == "ready" {
        got = again.recv().await;
    }
    assert_eq!(got["error"], "busy");
    // a good certificate again: noticed within a minute, and what was refused works
    reissue(&w, &w.site_ca, "broker", VALID, &[]);
    recheck(&w).await;
    let submit = w.submit(2, 500);
    let mut service = open_service(&w);
    service.send(&submit_line(&submit)).await;
    assert_eq!(pledge.recv_type().await, "submit");
    let approval = sign_approval(&Signer::certified(&w.jan_confirmed).unwrap(), submit.request()).unwrap();
    pledge.send(&approval_line(hash_of(&submit), &approval)).await;
    let line = service.recv_raw().await.unwrap();
    let Message::Answer(answer) = Message::parse(&line, ClearancePolicy::Required).unwrap() else {
        panic!("an answer")
    };
    assert!(matches!(answer.outcome, Outcome::Approved(_)), "{answer:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn page_status_exits_7_without_a_valid_certificate_before_5_and_6() {
    let w = World::new();
    let _socket = serve_admin(&w);
    let config = config_file(&w);
    let (code, out, _) = page(&config, &["status"]).await;
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("broker certificate: valid,") && out.contains("days left"), "{out}");
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
    assert!(out.contains("broker certificate: NOT valid (expired): no clearances are issued"), "{out}");
    let (_, help, _) = page(&config, &["status", "--help"]).await;
    assert!(help.contains("7  the broker has no valid certificate of its own: it issues no clearances"), "{help}");
    assert!(help.contains("returns 7, then 5, then 6"), "{help}");
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
