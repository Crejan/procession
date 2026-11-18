//! The two connections, with real signatures from `ssh-keygen`, over in-memory streams (the sandbox
//! cannot bind TCP ports; `tls.rs` runs the same lines inside real TLS, over memory too).

mod common;

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::*;
use p_act::exchange::{BrokerReason, By, ClearancePolicy, Message, Outcome, PledgeReason, Refused};
use p_act::sign::{
    ApprovalKind, ApprovalTrust, Namespace, Signer, sign_approval, verify_approval, verify_clearance, verify_request,
};
use p_act::{Clearance, Document};
use p_age::core::Settings;
use p_age::net::Timeouts;

fn parse(line: &[u8], policy: ClearancePolicy) -> Message {
    Message::parse(line, policy).unwrap()
}

async fn register(w: &World, pledge: &mut Client) {
    pledge
        .send_json(serde_json::json!({"schema_version":1,"type":"delegation","cert":w.keys.cert_line(&w.agent)}))
        .await;
    let reply = pledge.recv().await;
    assert_eq!(reply["type"], "registered", "{reply}");
}

/// The service reads one line and returns its answer as a message.
async fn service_answer(service: &mut Client) -> p_act::exchange::Answer {
    let line = service.recv_raw().await.expect("an answer");
    match parse(&line, ClearancePolicy::Required) {
        Message::Answer(a) => a,
        other => panic!("not an answer: {other:?}"),
    }
}

fn refusal(a: &p_act::exchange::Answer) -> BrokerReason {
    match &a.outcome {
        Outcome::Refused(Refused::Broker(r)) => *r,
        other => panic!("not a broker refusal: {other:?}"),
    }
}

// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_request_goes_through_and_the_service_can_verify_approval_and_clearance_itself() {
    let w = World::new();
    let mut pledge = open_pledge(&w);
    let standing = pledge.connect_as("jan", &w.jan_connection).await;
    assert_eq!(standing["n"], 0);
    register(&w, &mut pledge).await;

    let submit = w.submit(1, 120);
    let mut service = open_service(&w);
    service.send(&submit_line(&submit)).await;

    // pledge gets the request exactly as the service signed it, and can verify it itself
    let line = pledge.recv_raw().await.unwrap();
    let Message::Submit(got) = parse(&line, ClearancePolicy::Refused) else { panic!("a submit") };
    assert_eq!(got.request().as_bytes(), submit.request().as_bytes());
    verify_request(got.request(), got.request_sig(), &w.keys.public(&w.host_key)).unwrap();

    // pledge signs with the confirmed approval key and answers
    let approval = sign_approval(&Signer::certified(&w.jan_confirmed).unwrap(), got.request()).unwrap();
    pledge.send(&approval_line(got.hash(), &approval)).await;

    let answer = service_answer(&mut service).await;
    let Outcome::Approved(approved) = &answer.outcome else { panic!("approved: {answer:?}") };
    let ca = w.ca();
    assert_eq!(
        verify_approval(submit.request(), approved.approval(), ApprovalTrust::SiteCa(&ca)).unwrap(),
        ApprovalKind::Confirmed
    );
    let clearance = approved.clearance.as_ref().expect("a clearance");
    verify_clearance(&clearance.clearance, clearance.clearance_sig(), &ca).unwrap();
    assert!(clearance.clearance.covers(submit.request()));
    assert_eq!(clearance.clearance.at().unix(), w.clock.unix());

    // the service acknowledges, and the broker lets go
    service.send_json(serde_json::json!({"schema_version":1,"type":"ack","request":got.hash().to_string()})).await;
    service.expect_closed().await;
    assert_eq!(w.broker.held_count(), 0);
    let log = w.log.entries();
    assert_eq!(log.len(), 1);
    assert_eq!((log[0].result.as_str(), log[0].person.as_deref()), ("approval-returned", Some("jan")));
}

#[tokio::test]
async fn the_standing_is_signed_by_the_broker_in_its_own_namespace_and_only_there() {
    let w = World::new();
    let mut pledge = open_pledge(&w);
    let nonce = pledge.sign_in("jan", &w.jan_connection).await;
    assert_eq!(pledge.recv_type().await, "ready");
    let notice = pledge.recv().await;
    let doc = STANDARD.decode(notice["doc"].as_str().unwrap()).unwrap();
    let sig = notice["doc_sig"].as_str().unwrap();
    assert!(verify_as_broker(&w, Namespace::Broker, &doc, sig), "verifies as `broker` in broker-v1");
    assert!(!verify_as_broker(&w, Namespace::Clearance, &doc, sig), "never as a clearance");
    assert!(!verify_as_broker(&w, Namespace::Approval, &doc, sig));
    let standing: serde_json::Value = serde_json::from_slice(&doc).unwrap();
    assert_eq!(
        (standing["to"].as_str(), standing["nonce"].as_str(), standing["n"].as_u64()),
        (Some("jan"), Some(nonce.as_str()), Some(0))
    );
    assert_eq!((standing["blocked"].as_bool(), standing["groups"].clone()), (Some(false), serde_json::json!(["ops"])));
    // and a clearance's signature does not verify as a standing
    let clearance =
        Clearance::compose(w.submit(1, 60).request().hash(), p_act::Timestamp::from_unix(w.clock.unix()).unwrap())
            .unwrap();
    let csig = p_act::sign::sign_clearance(&Signer::certified(&w.broker_key).unwrap(), &clearance).unwrap();
    assert!(!verify_as_broker(&w, Namespace::Broker, clearance.as_bytes(), &p_act::sign::signature_to_base64(&csig)));
}

// --- sign-in ----------------------------------------------------------------

#[tokio::test]
async fn a_sign_in_that_does_not_verify_is_one_error_whatever_is_wrong() {
    let w = World::new();
    // the wrong key
    let mut c = open_pledge(&w);
    let nonce = c.recv().await["nonce"].as_str().unwrap().to_owned();
    c.send_json(signin_message("jan", &w.eva_connection, &nonce, BINDING)).await;
    assert_eq!(c.recv().await["error"], "signin");
    c.expect_closed().await;
    // another connection's nonce
    let mut c = open_pledge(&w);
    c.recv().await;
    c.send_json(signin_message("jan", &w.jan_connection, "bm90LXRoZS1ub25jZQ==", BINDING)).await;
    assert_eq!(c.recv().await["error"], "signin");
    // another connection's TLS binding
    let mut c = open_pledge(&w);
    let nonce = c.recv().await["nonce"].as_str().unwrap().to_owned();
    c.send_json(signin_message("jan", &w.jan_connection, &nonce, [8; 32])).await;
    assert_eq!(c.recv().await["error"], "signin");
    // a person the site does not have
    let mut c = open_pledge(&w);
    let nonce = c.recv().await["nonce"].as_str().unwrap().to_owned();
    c.send_json(signin_message("mallory", &w.jan_connection, &nonce, BINDING)).await;
    assert_eq!(c.recv().await["error"], "signin");
    // a sign-in signed in another namespace
    let mut c = open_pledge(&w);
    let nonce = c.recv().await["nonce"].as_str().unwrap().to_owned();
    let doc = p_age::wire::ConnectionDoc::compose("jan", &nonce, &STANDARD.encode(BINDING));
    let sig = p_age::keygen::sign(&w.jan_connection, Namespace::Request, &doc).unwrap();
    c.send_json(serde_json::json!({"schema_version":1,"type":"signin","doc":STANDARD.encode(&doc),"doc_sig":p_act::sign::signature_to_base64(&sig)})).await;
    assert_eq!(c.recv().await["error"], "signin");
    // something that is not a sign-in at all
    let mut c = open_pledge(&w);
    c.recv().await;
    c.send_json(serde_json::json!({"schema_version":1,"type":"ping"})).await;
    assert_eq!(c.recv().await["error"], "signin");
}

#[tokio::test]
async fn a_blocked_person_is_told_so_only_after_the_signature_verified() {
    let w = World::new();
    w.broker.block_person("jan".into()).await;
    let mut c = open_pledge(&w);
    let nonce = c.recv().await["nonce"].as_str().unwrap().to_owned();
    c.send_json(signin_message("jan", &w.eva_connection, &nonce, BINDING)).await;
    assert_eq!(c.recv().await["error"], "signin", "a wrong key learns nothing about blocks");
    let mut c = open_pledge(&w);
    c.sign_in("jan", &w.jan_connection).await;
    assert_eq!(c.recv().await["error"], "blocked");
    c.expect_closed().await;
}

#[tokio::test]
async fn a_second_connection_of_the_same_person_supersedes_the_first() {
    let w = World::new();
    let mut first = open_pledge(&w);
    first.connect_as("jan", &w.jan_connection).await;
    let mut second = open_pledge(&w);
    second.connect_as("jan", &w.jan_connection).await;
    assert_eq!(first.recv().await["error"], "superseded");
    first.expect_closed().await;
    // the broker sends to the new connection
    let mut service = open_service(&w);
    let mut p2 = second;
    register(&w, &mut p2).await;
    service.send(&submit_line(&w.submit(1, 120))).await;
    assert_eq!(p2.recv_type().await, "submit");
}

// --- waiting and reconnecting -------------------------------------------------

#[tokio::test]
async fn a_request_waits_for_a_pledge_that_is_away_and_comes_after_the_standing_when_it_returns() {
    let w = World::new();
    let mut pledge = open_pledge(&w);
    pledge.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut pledge).await;
    drop(pledge); // the machine goes to sleep
    tokio::time::sleep(Duration::from_millis(100)).await;

    let submit = w.submit(1, 120);
    let mut service = open_service(&w);
    service.send(&submit_line(&submit)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(w.broker.held_count(), 1);

    let mut pledge = open_pledge(&w);
    pledge.sign_in("jan", &w.jan_connection).await;
    let order = [pledge.recv_type().await, pledge.recv_type().await, pledge.recv_type().await];
    assert_eq!(order, ["ready", "notice", "submit"]);
    // the pledge answers, the service gets it
    let approval = sign_approval(&Signer::certified(&w.jan_confirmed).unwrap(), submit.request()).unwrap();
    pledge.send(&approval_line(hash_of(&submit), &approval)).await;
    assert!(matches!(service_answer(&mut service).await.outcome, Outcome::Approved(_)));
}

#[tokio::test]
async fn a_service_that_lost_its_connection_submits_the_same_bytes_and_gets_the_answer_it_missed() {
    let w = World::new();
    let mut pledge = open_pledge(&w);
    pledge.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut pledge).await;
    let submit = w.submit(1, 120);
    let mut service = open_service(&w);
    service.send(&submit_line(&submit)).await;
    assert_eq!(pledge.recv_type().await, "submit");
    drop(service); // the connection breaks; that does not cancel
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(w.broker.held_count(), 1);
    pledge.send(&answer_line(hash_of(&submit), Outcome::Declined)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut again = open_service(&w);
    again.send(&submit_line(&submit)).await;
    assert_eq!(service_answer(&mut again).await.outcome, Outcome::Declined);
    // pledge was not asked a second time
    pledge.send_json(serde_json::json!({"schema_version":1,"type":"ping"})).await;
    assert!(tokio::time::timeout(Duration::from_millis(200), pledge.lines.read(None)).await.is_err());
}

#[tokio::test]
async fn a_second_connection_for_the_same_request_takes_the_place_of_the_first() {
    let w = World::new();
    let mut pledge = open_pledge(&w);
    pledge.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut pledge).await;
    let submit = w.submit(1, 120);
    let mut first = open_service(&w);
    first.send(&submit_line(&submit)).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut second = open_service(&w);
    second.send(&submit_line(&submit)).await;
    assert_eq!(first.recv().await["error"], "superseded");
    assert_eq!(w.broker.held_count(), 1);
}

#[tokio::test]
async fn at_the_deadline_the_service_is_told_expired() {
    let w = World::new();
    let mut pledge = open_pledge(&w);
    pledge.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut pledge).await;
    let submit = w.submit(1, 60);
    let mut service = open_service(&w);
    service.send(&submit_line(&submit)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    w.clock.advance(61);
    w.broker.sweep().await;
    assert_eq!(service_answer(&mut service).await.outcome, Outcome::Expired(By::Broker));
    service.expect_closed().await;
    assert_eq!(w.broker.held_count(), 0);
    assert_eq!(w.log.entries()[0].result, "expired");
}

#[tokio::test]
async fn a_cancel_from_the_service_reaches_the_pledge() {
    let w = World::new();
    let mut pledge = open_pledge(&w);
    pledge.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut pledge).await;
    let submit = w.submit(1, 120);
    let mut service = open_service(&w);
    service.send(&submit_line(&submit)).await;
    assert_eq!(pledge.recv_type().await, "submit");
    service
        .send_json(serde_json::json!({"schema_version":1,"type":"cancel","request":hash_of(&submit).to_string()}))
        .await;
    let cancel = pledge.recv().await;
    assert_eq!(
        (cancel["type"].as_str(), cancel["request"].as_str()),
        (Some("cancel"), Some(hash_of(&submit).to_string().as_str()))
    );
    service.expect_closed().await;
    assert_eq!(w.broker.held_count(), 0);
}

// --- what is refused, and why ---------------------------------------------------

#[tokio::test]
async fn each_check_has_its_reason_and_the_first_failure_is_the_answer() {
    let w = World::new();
    let mut pledge = open_pledge(&w);
    pledge.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut pledge).await;

    // 0: a deadline that is past, or too far ahead
    for (n, due) in [(1, -5), (2, 700)] {
        let mut s = open_service(&w);
        s.send(&submit_line(&w.submit(n, due))).await;
        assert_eq!(refusal(&service_answer(&mut s).await), BrokerReason::Deadline, "due {due}");
        s.expect_closed().await;
    }
    // the tolerance is on the bound ahead only: 10 minutes and 30 seconds is let in, 11 minutes is not
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit(3, 630))).await;
    assert_eq!(pledge.recv_type().await, "submit");
    drop(s);

    // 1: a service key that no host of the site certified
    let other_host = w.keys.key("other-host");
    let stranger = w.keys.certified("stranger", &other_host, "probe@a.example", VALID, &[]);
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit_with(4, 120, &w.agent, &stranger))).await;
    assert_eq!(refusal(&service_answer(&mut s).await), BrokerReason::BadRequest);
    // 1: the right host key, the wrong service name
    let wrong_name = w.keys.certified("wrong-name", &w.host_key, "other@a.example", VALID, &[]);
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit_with(5, 120, &w.agent, &wrong_name))).await;
    assert_eq!(refusal(&service_answer(&mut s).await), BrokerReason::BadRequest);

    // 2: a call under a certificate of another delegation key
    let rogue_delegation = w.keys.key("rogue");
    let rogue_agent = w.keys.certified("rogue-agent", &rogue_delegation, "jan", "-5m:+8h", &[]);
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit_with(6, 120, &rogue_agent, &w.service))).await;
    assert_eq!(refusal(&service_answer(&mut s).await), BrokerReason::Delegation);
    // 2: a call under a delegation that was never registered
    let unregistered = w.keys.certified("unregistered", &w.jan_delegation, "jan", "-5m:+8h", &[]);
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit_with(7, 120, &unregistered, &w.service))).await;
    assert_eq!(refusal(&service_answer(&mut s).await), BrokerReason::Delegation);
    // 2: a call whose certificate names another person (eva), signed by jan's delegation key
    let not_jan = w.keys.certified("not-jan", &w.jan_delegation, "eva", "-5m:+8h", &[]);
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit_with(8, 120, &not_jan, &w.service))).await;
    assert_eq!(refusal(&service_answer(&mut s).await), BrokerReason::Delegation);

    let log: Vec<_> = w.log.entries().into_iter().map(|e| e.result).collect();
    assert_eq!(
        log,
        [
            "refused:deadline",
            "refused:deadline",
            "refused:bad-request",
            "refused:bad-request",
            "refused:delegation",
            "refused:delegation",
            "refused:delegation"
        ]
    );
}

#[tokio::test]
async fn a_request_that_does_not_parse_is_refused_for_the_hash_of_what_was_sent() {
    let w = World::new();
    let mut s = open_service(&w);
    let junk = b"{\"v\":1,\"type\":\"request\"}";
    let line = serde_json::json!({
        "schema_version":1,"type":"submit","request":STANDARD.encode(junk),
        "request_sig":STANDARD.encode(b"-----BEGIN SSH SIGNATURE-----\nU1NIU0lH\n-----END SSH SIGNATURE-----\n"),
    });
    s.send_json(line).await;
    let answer = service_answer(&mut s).await;
    assert_eq!(answer.request, p_act::DocumentHash::of(junk));
    assert_eq!(refusal(&answer), BrokerReason::BadRequest);
    // not base64 at all: there is no hash to answer for, so an error
    let mut s = open_service(&w);
    s.send_json(serde_json::json!({"schema_version":1,"type":"submit","request":"@@@","request_sig":"@@@"})).await;
    assert_eq!(s.recv().await["error"], "malformed-line");
    s.expect_closed().await;
}

#[tokio::test]
async fn a_service_gets_one_request_per_connection_and_no_answer_type_from_it() {
    let w = World::new();
    let mut pledge = open_pledge(&w);
    pledge.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut pledge).await;
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit(1, 120))).await;
    s.send(&submit_line(&w.submit(2, 120))).await;
    assert_eq!(s.recv().await["error"], "too-many-open");
    let mut s = open_service(&w);
    s.send(&answer_line(hash_of(&w.submit(1, 120)), Outcome::Declined)).await;
    assert_eq!(s.recv().await["error"], "unknown-type");
}

#[tokio::test]
async fn the_limit_per_agent_is_the_setting() {
    let w = World::with(Settings { max_waiting_per_agent: 2 }, Timeouts::default());
    let mut pledge = open_pledge(&w);
    pledge.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut pledge).await;
    let mut held = Vec::new();
    for n in 1..=2 {
        let mut s = open_service(&w);
        s.send(&submit_line(&w.submit(n, 120))).await;
        assert_eq!(pledge.recv_type().await, "submit");
        held.push(s);
    }
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit(3, 120))).await;
    assert_eq!(refusal(&service_answer(&mut s).await), BrokerReason::TooManyWaiting);
}

#[tokio::test]
async fn an_answer_that_is_not_for_this_person_or_not_held_changes_nothing() {
    let w = World::new();
    let mut jan = open_pledge(&w);
    jan.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut jan).await;
    let mut eva = open_pledge(&w);
    eva.connect_as("eva", &w.eva_connection).await;
    let submit = w.submit(1, 120);
    let mut service = open_service(&w);
    service.send(&submit_line(&submit)).await;
    assert_eq!(jan.recv_type().await, "submit");
    // eva's pledge answers for jan's request: ignored
    eva.send(&answer_line(hash_of(&submit), Outcome::Declined)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(w.broker.held_count(), 1);
    assert_eq!(w.log.entries().iter().map(|e| e.result.as_str()).collect::<Vec<_>>(), ["ignored:answer"]);
    jan.send(&answer_line(hash_of(&submit), Outcome::Refused(Refused::Pledge(PledgeReason::Ceiling)))).await;
    assert_eq!(service_answer(&mut service).await.outcome, Outcome::Refused(Refused::Pledge(PledgeReason::Ceiling)));
}

// --- delegations and withdrawals --------------------------------------------------

#[tokio::test]
async fn a_delegation_is_registered_from_its_certificate_alone_and_survives_a_restart() {
    let w = World::new();
    let mut pledge = open_pledge(&w);
    pledge.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut pledge).await;
    register(&w, &mut pledge).await; // again: nothing changes
    let fp = p_act::sign::agent_certificate(&w.keys.cert_line(&w.agent)).unwrap().delegation;
    let register = p_age::core::Core::read_state(&w.state);
    let now = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(w.clock.unix()).unwrap());
    assert_eq!(register.person_for(fp.as_str(), now), Ok("jan"));
}

#[tokio::test]
async fn a_certificate_that_does_not_qualify_is_not_registered() {
    let w = World::new();
    let mut jan = open_pledge(&w);
    jan.connect_as("jan", &w.jan_connection).await;
    let mut eva = open_pledge(&w);
    eva.connect_as("eva", &w.eva_connection).await;
    let reason =
        |v: serde_json::Value| (v["type"].as_str().unwrap().to_owned(), v["reason"].as_str().map(str::to_owned));
    let send = |cert: String| serde_json::json!({"schema_version":1,"type":"delegation","cert":cert});

    // another person's connection cannot register jan's delegation
    eva.send_json(send(w.keys.cert_line(&w.agent))).await;
    assert_eq!(reason(eva.recv().await), ("not-registered".into(), Some("not-yours".into())));
    // a certificate issued by a key that is not the person's delegation key
    let rogue = w.keys.key("rogue");
    let forged = w.keys.certified("forged", &rogue, "jan", "-5m:+8h", &["extension:groups@procession=ops"]);
    jan.send_json(send(w.keys.cert_line(&forged))).await;
    assert_eq!(reason(jan.recv().await), ("not-registered".into(), Some("bad-certificate".into())));
    // valid for more than 24 hours
    let long = w.keys.certified("long", &w.jan_delegation, "jan", "-5m:+30h", &[]);
    jan.send_json(send(w.keys.cert_line(&long))).await;
    assert_eq!(reason(jan.recv().await), ("not-registered".into(), Some("too-long".into())));
    // a certificate whose signature was changed after it was issued: it reads, and does not verify
    let line = w.keys.cert_line(&w.agent);
    let mut parts = line.split(' ');
    let (kind, b64) = (parts.next().unwrap(), parts.next().unwrap());
    let mut blob = STANDARD.decode(b64).unwrap();
    let last = blob.len() - 5;
    blob[last] ^= 1;
    jan.send_json(send(format!("{kind} {}", STANDARD.encode(&blob)))).await;
    assert_eq!(reason(jan.recv().await), ("not-registered".into(), Some("bad-certificate".into())));
    // not yet valid
    let later = w.keys.certified("later", &w.jan_delegation, "jan", "+1h:+5h", &[]);
    jan.send_json(send(w.keys.cert_line(&later))).await;
    assert_eq!(reason(jan.recv().await), ("not-registered".into(), Some("bad-certificate".into())));
    // a certificate that is not one an agent may have (formats 3.1): not readable, so no identifier to name
    let loginable = w.keys.certified("loginable", &w.jan_delegation, "jan", "-5m:+8h", &["extension:permit-pty"]);
    jan.send_json(send(w.keys.cert_line(&loginable))).await;
    assert_eq!(jan.recv().await["error"], "malformed-line");
}

#[tokio::test]
async fn a_withdrawal_stops_the_delegation_and_refuses_what_waits_under_it() {
    let w = World::new();
    let mut pledge = open_pledge(&w);
    pledge.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut pledge).await;
    let submit = w.submit(1, 120);
    let mut service = open_service(&w);
    service.send(&submit_line(&submit)).await;
    assert_eq!(pledge.recv_type().await, "submit");
    let fp = p_act::sign::agent_certificate(&w.keys.cert_line(&w.agent)).unwrap().delegation;
    pledge.send_json(serde_json::json!({"schema_version":1,"type":"withdraw","delegation":fp.to_string()})).await;
    assert_eq!(refusal(&service_answer(&mut service).await), BrokerReason::Delegation);
    assert_eq!(pledge.recv_type().await, "cancel", "the pledge is told to drop it too");
    // a new request under it is refused
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit(2, 120))).await;
    assert_eq!(refusal(&service_answer(&mut s).await), BrokerReason::Delegation);
    // and a sign-in afterwards is told of the withdrawal in the standing
    let mut again = open_pledge(&w);
    let standing = again.connect_as("jan", &w.jan_connection).await;
    assert_eq!(standing["withdrawn"], serde_json::json!([fp.to_string()]));
}

// --- lines, silence -----------------------------------------------------------------

#[tokio::test]
async fn a_line_that_is_too_long_ends_the_connection() {
    let w = World::new();
    let mut s = open_service(&w);
    let mut long = vec![b'a'; p_act::limits::MAX_EXCHANGE_LINE_BYTES + 10];
    long.push(b'\n');
    s.send(&long).await;
    assert_eq!(s.recv().await["error"], "line-too-long");
    s.expect_closed().await;
}

#[tokio::test]
async fn a_line_that_is_not_finished_in_time_and_a_silent_pledge_are_told_so() {
    let quick = Timeouts {
        line: Duration::from_millis(300),
        first_line: Duration::from_millis(300),
        signin: Duration::from_millis(300),
        pledge_silence: Duration::from_millis(500),
    };
    let w = World::with(Settings::default(), quick);
    // a service that sends nothing
    let mut s = open_service_on(&w.broker, quick);
    assert_eq!(s.recv().await["error"], "timeout");
    // a service that begins a line and does not finish it
    let mut s = open_service_on(&w.broker, quick);
    s.send(b"{\"schema_version\":1,").await;
    assert_eq!(s.recv().await["error"], "timeout");
    // a pledge that does not answer the challenge
    let mut p = open_pledge_on(&w.broker, BINDING, quick);
    assert_eq!(p.recv_type().await, "challenge");
    assert_eq!(p.recv().await["error"], "timeout");
    // a pledge that signs in and then says nothing: closed; with pings it stays
    let mut p = open_pledge_on(&w.broker, BINDING, quick);
    p.connect_as("jan", &w.jan_connection).await;
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        p.send_json(serde_json::json!({"schema_version":1,"type":"ping"})).await;
    }
    let mut quiet = open_pledge_on(&w.broker, BINDING, quick);
    quiet.connect_as("eva", &w.eva_connection).await;
    assert_eq!(quiet.recv().await["error"], "timeout");
    quiet.expect_closed().await;
}

#[tokio::test]
async fn a_pledge_may_not_send_what_only_the_broker_sends() {
    let w = World::new();
    let mut p = open_pledge(&w);
    p.connect_as("jan", &w.jan_connection).await;
    p.send(&submit_line(&w.submit(1, 120))).await;
    assert_eq!(p.recv().await["error"], "unknown-type");
    p.expect_closed().await;
}
