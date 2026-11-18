//! The administrator's verbs against a running broker: the real `page` binary, the real socket, a broker over
//! in-memory streams with real keys. A register that cannot be written is provoked by making the state
//! directory unwritable (skipped where the user can write anyway, i.e. root).

mod common;

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use common::*;
use p_act::exchange::{Outcome, Refused};
use p_act::sign::{Signer, sign_approval};
use p_age::admin::{Command, Reply, Target};

fn lock_state_dir(w: &World) -> bool {
    std::fs::set_permissions(w.keys.dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    std::fs::File::create(w.keys.path("probe")).is_err()
}

fn unlock_state_dir(w: &World) {
    std::fs::set_permissions(w.keys.dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
}

macro_rules! world {
    () => {{
        let w = World::new();
        let socket = serve_admin(&w);
        let config = config_file(&w);
        (w, socket, config)
    }};
}

fn notice_doc(v: &serde_json::Value) -> serde_json::Value {
    use base64::Engine as _;
    let doc = base64::engine::general_purpose::STANDARD.decode(v["doc"].as_str().unwrap()).unwrap();
    serde_json::from_slice(&doc).unwrap()
}

/// The next `notice` the pledge is sent, skipping nothing else (the tests read what they expect).
async fn next_standing(pledge: &mut Client) -> serde_json::Value {
    let v = pledge.recv().await;
    assert_eq!(v["type"], "notice", "{v}");
    notice_doc(&v)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_and_a_block_and_its_lifting_as_the_verbs_say_them() {
    let (w, _socket, config) = world!();
    let (code, out, _) = page(&config, &["status"]).await;
    assert_eq!(code, 0);
    assert!(
        out.contains("conditions: none")
            && out.contains("pledges connected: 0")
            && out.contains("blocked persons: none"),
        "{out}"
    );

    let (code, out, _) = page(&config, &["block", "jan"]).await;
    assert_eq!((code, out.as_str()), (0, "blocked and stored: jan"));
    // the block is in the broker that runs, and on disk
    let mut c = open_pledge(&w).await;
    c.sign_in("jan", &w.jan_connection).await;
    assert_eq!(c.recv().await["error"], "blocked");
    assert!(p_age::core::Core::read_state(&w.state).unwrap().is_blocked("jan"));
    let (_, out, _) = page(&config, &["status"]).await;
    assert!(out.contains("blocked persons: jan"), "{out}");

    let (code, out, _) = page(&config, &["unblock", "jan"]).await;
    assert_eq!((code, out.as_str()), (0, "unblocked and stored: jan"));
    let mut c = open_pledge(&w).await;
    c.connect_as("jan", &w.jan_connection).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connected_pledge_is_sent_a_new_standing_when_its_person_is_blocked_and_when_that_is_lifted() {
    let (w, _socket, config) = world!();
    let mut pledge = open_pledge(&w).await;
    let first = pledge.connect_as("jan", &w.jan_connection).await;
    assert_eq!((first["n"].as_u64(), first["blocked"].as_bool()), (Some(0), Some(false)));
    page(&config, &["block", "jan"]).await;
    let s = next_standing(&mut pledge).await;
    assert_eq!((s["n"].as_u64(), s["blocked"].as_bool()), (Some(1), Some(true)));
    page(&config, &["unblock", "jan"]).await;
    let s = next_standing(&mut pledge).await;
    assert_eq!((s["n"].as_u64(), s["blocked"].as_bool()), (Some(2), Some(false)));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn what_the_broker_does_not_know_is_refused_and_the_exit_is_not_zero() {
    let (_w, _socket, config) = world!();
    for (args, text) in [
        (vec!["block", "nobody"], "block refused: unknown-person"),
        (vec!["unblock", "nobody"], "unblock refused: unknown-person"),
        (vec!["block", "--key", "SHA256:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"], "block refused: unknown-key"),
        (
            vec!["unblock", "--key", "SHA256:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"],
            "unblock refused: unknown-key",
        ),
        (
            vec!["withdraw", "SHA256:ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"],
            "withdraw refused: unknown-delegation",
        ),
    ] {
        let (code, _, err) = page(&config, &args).await;
        assert_eq!((code, err.as_str()), (1, text), "{args:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_block_that_cannot_be_stored_says_so_and_stays_in_force_and_lifting_it_is_refused() {
    let (w, _socket, config) = world!();
    if !lock_state_dir(&w) {
        return;
    }
    let (code, _, err) = page(&config, &["block", "jan"]).await;
    assert_eq!(code, 4, "in force but not stored");
    assert!(err.starts_with("blocked, NOT stored: permission-denied"), "{err}");
    // in force all the same
    let mut c = open_pledge(&w).await;
    c.sign_in("jan", &w.jan_connection).await;
    assert_eq!(c.recv().await["error"], "blocked");
    // the broker is degraded, and status says so and exits 1
    let (code, out, _) = page(&config, &["status"]).await;
    assert_eq!(code, 5, "degraded");
    assert!(
        out.contains("5  the broker is degraded (permission-denied)") && out.contains("blocked persons: jan"),
        "{out}"
    );
    // lifting permits: refused, and the block stays
    let (code, _, err) = page(&config, &["unblock", "jan"]).await;
    assert_eq!((code, err.as_str()), (1, "unblock refused: the register cannot be written (permission-denied)"));
    assert!(w.broker.degraded().is_some());
    let (_, out, _) = page(&config, &["status"]).await;
    assert!(out.contains("blocked persons: jan"));
    // the disk comes back: lifting works, and the broker is no longer degraded
    unlock_state_dir(&w);
    let (code, out, _) = page(&config, &["unblock", "jan"]).await;
    assert_eq!((code, out.as_str()), (0, "unblocked and stored: jan"));
    let (code, out, _) = page(&config, &["status"]).await;
    assert_eq!(code, 0);
    assert!(out.contains("conditions: none"), "{out}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_withdrawal_by_the_administrator_ends_the_delegation_and_is_in_the_standing() {
    let (w, _socket, config) = world!();
    let mut pledge = open_pledge(&w).await;
    pledge.connect_as("jan", &w.jan_connection).await;
    pledge
        .send_json(serde_json::json!({"schema_version":1,"type":"delegation","cert":w.keys.cert_line(&w.agent)}))
        .await;
    assert_eq!(pledge.recv_type().await, "registered");
    let mut service = open_service(&w);
    service.send(&submit_line(&w.submit(1, 120))).await;
    assert_eq!(pledge.recv_type().await, "submit");
    let fp = agent_fingerprint(&w);
    let (code, out, _) = page(&config, &["withdraw", &fp]).await;
    assert_eq!((code, out), (0, format!("withdrawn and stored: {fp}")));
    // what waited is refused, the pledge is told to drop it and sent a standing that names the delegation
    assert_eq!(pledge.recv_type().await, "cancel");
    let standing = next_standing(&mut pledge).await;
    assert_eq!(standing["withdrawn"], serde_json::json!([fp]));
    let answer = service.recv().await;
    assert_eq!(answer["reason"], "delegation");
    // new requests under it are refused
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit(2, 120))).await;
    assert_eq!(s.recv().await["reason"], "delegation");
    // a withdrawal that cannot be stored is in force and says so
    if !lock_state_dir(&w) {
        return;
    }
    let (code, _, err) = page(&config, &["withdraw", &fp]).await;
    assert_eq!(code, 4);
    assert!(err.starts_with("withdrawn, NOT stored: permission-denied"), "{err}");
    unlock_state_dir(&w);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_the_connection_key_ends_the_pledge_that_signed_in_with_it_and_refuses_the_next() {
    let (w, _socket, config) = world!();
    let mut pledge = open_pledge(&w).await;
    pledge.connect_as("jan", &w.jan_connection).await;
    let fp = fingerprint(&w, &w.jan_connection);
    let (code, out, _) = page(&config, &["block", "--key", &fp]).await;
    assert_eq!((code, out), (0, format!("blocked and stored: {fp}")));
    assert_eq!(pledge.recv().await["error"], "blocked");
    pledge.expect_closed().await;
    let mut again = open_pledge(&w).await;
    again.sign_in("jan", &w.jan_connection).await;
    assert_eq!(again.recv().await["error"], "blocked");
    // eva, whose key it is not, signs in
    let mut eva = open_pledge(&w).await;
    eva.connect_as("eva", &w.eva_connection).await;
    let (code, out, _) = page(&config, &["unblock", "--key", &fp]).await;
    assert_eq!((code, out), (0, format!("unblocked and stored: {fp}")));
    let mut ok = open_pledge(&w).await;
    ok.connect_as("jan", &w.jan_connection).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_approval_by_a_blocked_key_is_given_no_clearance_and_the_pledge_is_told_the_key() {
    let (w, _socket, config) = world!();
    let mut pledge = open_pledge(&w).await;
    pledge.connect_as("jan", &w.jan_connection).await;
    pledge
        .send_json(serde_json::json!({"schema_version":1,"type":"delegation","cert":w.keys.cert_line(&w.agent)}))
        .await;
    assert_eq!(pledge.recv_type().await, "registered");
    let fp = fingerprint(&w, &w.jan_confirmed);
    let (code, _, _) = page(&config, &["block", "--key", &fp]).await;
    assert_eq!(code, 0);
    let standing = next_standing(&mut pledge).await;
    assert_eq!(standing["blocked_keys"], serde_json::json!([fp]), "a key of that person's");
    assert_eq!(standing["blocked"], false);
    // a request, approved with the blocked confirmed key: refused, no clearance
    let submit = w.submit(1, 120);
    let mut service = open_service(&w);
    service.send(&submit_line(&submit)).await;
    assert_eq!(pledge.recv_type().await, "submit");
    let approval = sign_approval(&Signer::certified(&w.jan_confirmed).unwrap(), submit.request()).unwrap();
    pledge.send(&approval_line(hash_of(&submit), &approval)).await;
    let line = service.recv_raw().await.unwrap();
    let p_act::exchange::Message::Answer(answer) =
        p_act::exchange::Message::parse(&line, p_act::exchange::ClearancePolicy::Required).unwrap()
    else {
        panic!("an answer")
    };
    assert!(
        matches!(answer.outcome, Outcome::Refused(Refused::Broker(p_act::exchange::BrokerReason::Person))),
        "{answer:?}"
    );
    // lifted, the same key's approval is cleared
    page(&config, &["unblock", "--key", &fp]).await;
    let standing = next_standing(&mut pledge).await;
    assert_eq!(standing["blocked_keys"], serde_json::json!([]));
    let submit = w.submit(2, 120);
    let mut service = open_service(&w);
    service.send(&submit_line(&submit)).await;
    assert_eq!(pledge.recv_type().await, "submit");
    let approval = sign_approval(&Signer::certified(&w.jan_confirmed).unwrap(), submit.request()).unwrap();
    pledge.send(&approval_line(hash_of(&submit), &approval)).await;
    let line = service.recv_raw().await.unwrap();
    let p_act::exchange::Message::Answer(answer) =
        p_act::exchange::Message::parse(&line, p_act::exchange::ClearancePolicy::Required).unwrap()
    else {
        panic!("an answer")
    };
    assert!(matches!(answer.outcome, Outcome::Approved(_)), "{answer:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn blocking_a_delegation_key_or_an_agent_key_stops_the_calls_under_it() {
    let (w, _socket, config) = world!();
    let mut pledge = open_pledge(&w).await;
    pledge.connect_as("jan", &w.jan_connection).await;
    pledge
        .send_json(serde_json::json!({"schema_version":1,"type":"delegation","cert":w.keys.cert_line(&w.agent)}))
        .await;
    assert_eq!(pledge.recv_type().await, "registered");
    // a request waits
    let mut waiting = open_service(&w);
    waiting.send(&submit_line(&w.submit(1, 120))).await;
    assert_eq!(pledge.recv_type().await, "submit");
    // the person's delegation key: what waits and what comes is refused as a delegation, and registering is `blocked`
    let dk = fingerprint(&w, &w.jan_delegation);
    assert_eq!(page(&config, &["block", "--key", &dk]).await.0, 0);
    assert_eq!(waiting.recv().await["reason"], "delegation");
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit(2, 120))).await;
    assert_eq!(s.recv().await["reason"], "delegation");
    let other = w.keys.certified("agent2", &w.jan_delegation, "jan", "-5m:+8h", &[]);
    pledge.send_json(serde_json::json!({"schema_version":1,"type":"delegation","cert":w.keys.cert_line(&other)})).await;
    let mut reply = pledge.recv().await;
    while reply["type"] == "notice" || reply["type"] == "cancel" {
        reply = pledge.recv().await;
    }
    assert_eq!((reply["type"].as_str(), reply["reason"].as_str()), (Some("not-registered"), Some("blocked")));
    assert_eq!(page(&config, &["unblock", "--key", &dk]).await.0, 0);
    // an agent's key is blocked like a withdrawal
    let ak = p_act::sign::agent_certificate(&w.keys.cert_line(&w.agent)).unwrap().delegation.to_string();
    assert_eq!(page(&config, &["block", "--key", &ak]).await.0, 0);
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit(3, 120))).await;
    assert_eq!(s.recv().await["reason"], "delegation");
}

// --- the channel ----------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_usage_and_a_missing_broker_have_their_own_exit_codes() {
    let w = World::new(); // no socket is bound
    let config = config_file(&w);
    assert_eq!(page(&config, &["block"]).await.0, 2);
    assert_eq!(page(&config, &["block", "a", "b"]).await.0, 2);
    assert_eq!(page(&config, &["block", "--key", "not-a-fingerprint"]).await.0, 2);
    assert_eq!(page(&config, &["status", "extra"]).await.0, 2);
    assert_eq!(page(&config, &["withdraw", "jan"]).await.0, 2);
    let (code, _, err) = page(&config, &["status"]).await;
    assert_eq!(code, 3);
    assert!(err.contains("no broker answers"), "{err}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_socket_is_private_one_command_per_connection_and_strict() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (w, socket, _config) = world!();
    assert_eq!(std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777, 0o600, "whatever the umask");
    // a line that is not a command: refused, and the connection ends
    for junk in [
        "not json",
        r#"{"schema_version":1,"type":"block"}"#,
        r#"{"schema_version":1,"type":"block","person":"jan","key":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#,
        r#"{"schema_version":2,"type":"status"}"#,
        r#"{"schema_version":1,"type":"status","extra":1}"#,
        r#"{"schema_version":1,"type":"block","person":"a b"}"#,
    ] {
        let mut s = tokio::net::UnixStream::connect(&socket).await.unwrap();
        s.write_all(format!("{junk}\n").as_bytes()).await.unwrap();
        let mut got = String::new();
        s.read_to_string(&mut got).await.unwrap();
        assert_eq!(got.trim_end(), r#"{"schema_version":1,"type":"refused","reason":"malformed"}"#, "{junk}");
    }
    // one command per connection: the second is not read
    let mut s = tokio::net::UnixStream::connect(&socket).await.unwrap();
    s.write_all(
        b"{\"schema_version\":1,\"type\":\"status\"}\n{\"schema_version\":1,\"type\":\"block\",\"person\":\"jan\"}\n",
    )
    .await
    .unwrap();
    let mut got = String::new();
    s.read_to_string(&mut got).await.unwrap();
    assert_eq!(got.lines().count(), 1);
    assert!(!p_age::core::Core::read_state(&w.state).unwrap().is_blocked("jan"));
    // a line over the limit gets no answer at all
    let mut s = tokio::net::UnixStream::connect(&socket).await.unwrap();
    s.write_all(&[vec![b'a'; 5000], b"\n".to_vec()].concat()).await.unwrap();
    let mut got = Vec::new();
    s.read_to_end(&mut got).await.unwrap();
    assert!(got.is_empty());
    // silence is closed (the wait is 10 s; here the client closes first and nothing is answered)
    let s = tokio::net::UnixStream::connect(&socket).await.unwrap();
    drop(s);
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_socket_is_replaced_and_one_that_answers_is_not() {
    let w = World::new();
    let dir = w.keys.dir.path();
    let path = p_age::admin::socket_path(dir);
    // left behind by a broker that died: nothing answers, so it is removed
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    assert!(path.exists());
    // (A test that runs `page` in another thread can fork while the old listener is still open and leave a copy of
    // it in the child for a moment, which makes the socket answer; that is the test's race, not the broker's: wait.)
    let mut bound = p_age::admin::bind(dir);
    for _ in 0..40 {
        if bound.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        bound = p_age::admin::bind(dir);
    }
    let listener = bound.unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    tokio::spawn(p_age::admin::serve(listener, std::sync::Arc::clone(&w.broker)));
    // a broker that answers: the second does not take its place
    assert!(matches!(p_age::admin::bind(dir), Err(p_age::admin::BindError::InUse(_))));
    assert!(path.exists());
}

#[test]
fn commands_and_answers_are_read_as_strictly_as_everything_else() {
    let fp: p_act::sign::Fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse().unwrap();
    for c in [
        Command::Status,
        Command::Block(Target::Person("jan".into())),
        Command::Unblock(Target::Key(fp.clone())),
        Command::Withdraw(fp.clone()),
    ] {
        let line = c.encode();
        assert_eq!(Command::parse(&line[..line.len() - 1]), Some(c));
    }
    let status = p_age::core::Status {
        degraded: Some("read-only"),
        pledges: 1,
        held: 2,
        delegations: 3,
        withdrawn: 1,
        blocked_persons: vec!["eva".into()],
        blocked_keys: vec![fp.to_string()],
        broker_certificate: p_age::core::BrokerCertificateStatus {
            path: "/etc/page/broker-cert.pub".into(),
            valid: false,
            days_left: None,
            failure: Some("expired"),
        },
        certificates: Some(p_age::core::CertificateStatus {
            carried: 3,
            not_carried: 1,
            directory_refused: false,
            uncovered: vec!["eva:automatic".into()],
        }),
    };
    for r in [
        Reply::Done(Ok(())),
        Reply::Done(Err("no-space")),
        Reply::Refused(p_age::admin::Refusal::Unavailable, Some("io")),
        Reply::Refused(p_age::admin::Refusal::UnknownKey, None),
        Reply::Status(status),
    ] {
        let line = r.encode();
        assert_eq!(Reply::parse(&line[..line.len() - 1]), Some(r));
    }
    // a reason the reader does not know is read as `io`, never passed on
    assert_eq!(
        Reply::parse(br#"{"schema_version":1,"type":"done","stored":false,"why":"anything at all"}"#),
        Some(Reply::Done(Err("io")))
    );
    assert_eq!(Reply::parse(br#"{"schema_version":1,"type":"refused","reason":"anything at all"}"#), None);
}

#[test]
fn a_peer_is_served_only_through_p_act_peer_and_one_whose_credentials_cannot_be_read_is_dropped() {
    use p_act::peer::{LOG_INTERVAL, Throttle};
    use p_age::admin::admit_peer;
    let mut throttle = Throttle::new("page", LOG_INTERVAL);
    let mut lines = Vec::new();
    // a socket pair: the peer is this very process, the broker's own user, and is admitted
    let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
    assert!(admit_peer(&a, &mut throttle, &mut |l| lines.push(l.to_owned())));
    assert!(lines.is_empty());
    // something whose credentials cannot be read (not a socket at all) is dropped, and the refusal is one line
    let file = std::fs::File::open("/dev/null").unwrap();
    assert!(!admit_peer(&file, &mut throttle, &mut |l| lines.push(l.to_owned())));
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("admin socket") && lines[0].contains("dropped"), "{lines:?}");
    // the policy is the broker's own user or root: `OwnUserOrRoot`, no list of users is needed
    assert_eq!(p_age::admin::POLICY, p_act::peer::Policy::OwnUserOrRoot);
    assert!(p_age::admin::POLICY.admits_with(0, 501) && p_age::admin::POLICY.admits_with(501, 501));
    assert!(!p_age::admin::POLICY.admits_with(502, 501));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_verbs_help_and_its_usage_say_what_the_exit_codes_mean() {
    let w = World::new();
    let config = config_file(&w);
    for verb in ["block", "unblock", "withdraw", "status"] {
        let (code, out, _) = page(&config, &[verb, "--help"]).await;
        assert_eq!(code, 0, "{verb}");
        for line in [
            "0  done (and stored, where something is stored)",
            "1  refused",
            "2  usage",
            "3  no broker answers",
            "4  in force but NOT stored (block, withdraw)",
            "5  the broker is degraded (`status` only)",
        ] {
            assert!(out.contains(line), "{verb}: {out}");
        }
    }
    let (code, _, err) = page(&config, &["block"]).await;
    assert_eq!(code, 2);
    assert!(err.contains("5  the broker is degraded"), "{err}");
}
