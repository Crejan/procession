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
    let mut pledge = open_pledge(&w).await;
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
    let mut pledge = open_pledge(&w).await;
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

// --- the first message --------------------------------------------------------

#[tokio::test]
async fn the_first_message_says_which_exchange_this_is() {
    let w = World::new();
    // anything but `submit` and `hello` is a malformed line, and the connection is closed
    for first in [
        serde_json::json!({"schema_version":1,"type":"ping"}),
        serde_json::json!({"schema_version":1,"type":"ack","request":hash_of(&w.submit(1, 120)).to_string()}),
        serde_json::json!({"schema_version":1,"type":"cancel","request":hash_of(&w.submit(1, 120)).to_string()}),
        serde_json::json!({"schema_version":1,"type":"signin","doc":"","doc_sig":""}),
        serde_json::json!({"schema_version":1,"type":"nonsense"}),
        serde_json::json!({"type":"hello"}),
        serde_json::json!([1, 2]),
    ] {
        let mut c = open_service(&w);
        c.send_json(first.clone()).await;
        assert_eq!(c.recv().await["error"], "malformed-line", "{first}");
        c.expect_closed().await;
    }
    // a hello that carries anything, or another version
    let mut c = open_service(&w);
    c.send_json(serde_json::json!({"schema_version":1,"type":"hello","person":"jan"})).await;
    assert_eq!(c.recv().await["error"], "malformed-line");
    let mut c = open_service(&w);
    c.send_json(serde_json::json!({"schema_version":2,"type":"hello"})).await;
    assert_eq!(c.recv().await["error"], "malformed-line", "nothing more is said than that this is no beginning");
    // a line that is not JSON
    let mut c = open_service(&w);
    c.send(b"hello\n").await;
    assert_eq!(c.recv().await["error"], "malformed-line");
    // a hello is answered with a challenge, and only then; a submit is a service's, on the same address
    let mut c = open_pledge(&w).await;
    assert_eq!(c.recv_type().await, "challenge");
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit(1, 120))).await;
    assert_eq!(service_answer(&mut s).await.request, hash_of(&w.submit(1, 120)));
}

#[tokio::test]
async fn a_connection_that_says_nothing_is_closed() {
    let quick = Timeouts {
        line: Duration::from_millis(300),
        first_line: Duration::from_millis(300),
        signin: Duration::from_millis(300),
        pledge_silence: Duration::from_millis(500),
    };
    let w = World::with(Settings::default(), quick);
    let mut c = open_raw_on(&w.broker, BINDING, quick);
    // the broker never speaks first: nothing is sent, the connection is closed
    c.expect_closed().await;
    // a connection that sends a first line too long is told `malformed-line` and nothing more
    let mut c = open_raw_on(&w.broker, BINDING, Timeouts::default());
    let mut long = vec![b'a'; p_act::limits::MAX_EXCHANGE_LINE_BYTES + 10];
    long.push(b'\n');
    c.send(&long).await;
    assert_eq!(c.recv().await["error"], "malformed-line");
    c.expect_closed().await;
    // a first line that is begun and not finished is closed without a word
    let mut c = open_raw_on(&w.broker, BINDING, quick);
    c.send(b"{\"schema_version\":1,").await;
    c.expect_closed().await;
}

// --- sign-in ----------------------------------------------------------------

#[tokio::test]
async fn a_sign_in_that_does_not_verify_is_one_error_whatever_is_wrong() {
    let w = World::new();
    // the wrong key
    let mut c = open_pledge(&w).await;
    let nonce = c.recv().await["nonce"].as_str().unwrap().to_owned();
    c.send_json(signin_message("jan", &w.eva_connection, &nonce, BINDING)).await;
    assert_eq!(c.recv().await["error"], "signin");
    c.expect_closed().await;
    // another connection's nonce
    let mut c = open_pledge(&w).await;
    c.recv().await;
    c.send_json(signin_message("jan", &w.jan_connection, "bm90LXRoZS1ub25jZQ==", BINDING)).await;
    assert_eq!(c.recv().await["error"], "signin");
    // another connection's TLS binding
    let mut c = open_pledge(&w).await;
    let nonce = c.recv().await["nonce"].as_str().unwrap().to_owned();
    c.send_json(signin_message("jan", &w.jan_connection, &nonce, [8; 32])).await;
    assert_eq!(c.recv().await["error"], "signin");
    // a person the site does not have
    let mut c = open_pledge(&w).await;
    let nonce = c.recv().await["nonce"].as_str().unwrap().to_owned();
    c.send_json(signin_message("mallory", &w.jan_connection, &nonce, BINDING)).await;
    assert_eq!(c.recv().await["error"], "signin");
    // a sign-in signed in another namespace
    let mut c = open_pledge(&w).await;
    let nonce = c.recv().await["nonce"].as_str().unwrap().to_owned();
    let doc = p_age::wire::ConnectionDoc::compose("jan", &nonce, &STANDARD.encode(BINDING));
    let sig = raw_sign(&w.jan_connection, Namespace::Request, &doc);
    c.send_json(serde_json::json!({"schema_version":1,"type":"signin","doc":STANDARD.encode(&doc),"doc_sig":p_act::sign::signature_to_base64(&sig)})).await;
    assert_eq!(c.recv().await["error"], "signin");
    // something that is not a sign-in at all
    let mut c = open_pledge(&w).await;
    c.recv().await;
    c.send_json(serde_json::json!({"schema_version":1,"type":"ping"})).await;
    assert_eq!(c.recv().await["error"], "signin");
}

#[tokio::test]
async fn a_blocked_person_is_told_so_only_after_the_signature_verified() {
    let w = World::new();
    w.broker.block_person("jan".into()).await;
    let mut c = open_pledge(&w).await;
    let nonce = c.recv().await["nonce"].as_str().unwrap().to_owned();
    c.send_json(signin_message("jan", &w.eva_connection, &nonce, BINDING)).await;
    assert_eq!(c.recv().await["error"], "signin", "a wrong key learns nothing about blocks");
    let mut c = open_pledge(&w).await;
    c.sign_in("jan", &w.jan_connection).await;
    assert_eq!(c.recv().await["error"], "blocked");
    c.expect_closed().await;
}

#[tokio::test]
async fn a_second_connection_of_the_same_person_supersedes_the_first() {
    let w = World::new();
    let mut first = open_pledge(&w).await;
    first.connect_as("jan", &w.jan_connection).await;
    let mut second = open_pledge(&w).await;
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
    let mut pledge = open_pledge(&w).await;
    pledge.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut pledge).await;
    drop(pledge); // the machine goes to sleep
    tokio::time::sleep(Duration::from_millis(100)).await;

    let submit = w.submit(1, 120);
    let mut service = open_service(&w);
    service.send(&submit_line(&submit)).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(w.broker.held_count(), 1);

    let mut pledge = open_pledge(&w).await;
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
    let mut pledge = open_pledge(&w).await;
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
    let mut pledge = open_pledge(&w).await;
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
    let mut pledge = open_pledge(&w).await;
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
    let mut pledge = open_pledge(&w).await;
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
    let mut pledge = open_pledge(&w).await;
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
    let mut pledge = open_pledge(&w).await;
    pledge.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut pledge).await;
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit(1, 120))).await;
    s.send(&submit_line(&w.submit(2, 120))).await;
    assert_eq!(s.recv().await["error"], "too-many-open");
    // a service sends no answer: as the first message it is no beginning, after a submit it is an error
    let mut s = open_service(&w);
    s.send(&answer_line(hash_of(&w.submit(3, 120)), Outcome::Declined)).await;
    assert_eq!(s.recv().await["error"], "malformed-line");
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit(4, 120))).await;
    s.send(&answer_line(hash_of(&w.submit(4, 120)), Outcome::Declined)).await;
    assert_eq!(s.recv().await["error"], "unknown-type");
}

#[tokio::test]
async fn the_limit_per_agent_is_the_setting() {
    let w = World::with(Settings { max_waiting_per_agent: 2 }, Timeouts::default());
    let mut pledge = open_pledge(&w).await;
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
    let mut jan = open_pledge(&w).await;
    jan.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut jan).await;
    let mut eva = open_pledge(&w).await;
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
    let mut pledge = open_pledge(&w).await;
    pledge.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut pledge).await;
    register(&w, &mut pledge).await; // again: nothing changes
    let fp = p_act::sign::agent_certificate(&w.keys.cert_line(&w.agent)).unwrap().delegation;
    let register = p_age::core::Core::read_state(&w.state).unwrap();
    let now = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(u64::try_from(w.clock.unix()).unwrap());
    assert_eq!(register.person_for(fp.as_str(), now), Ok("jan"));
}

#[tokio::test]
async fn a_certificate_that_does_not_qualify_is_not_registered() {
    let w = World::new();
    let mut jan = open_pledge(&w).await;
    jan.connect_as("jan", &w.jan_connection).await;
    let mut eva = open_pledge(&w).await;
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
    let mut pledge = open_pledge(&w).await;
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
    let mut again = open_pledge(&w).await;
    let standing = again.connect_as("jan", &w.jan_connection).await;
    assert_eq!(standing["withdrawn"], serde_json::json!([fp.to_string()]));
}

// --- lines, silence -----------------------------------------------------------------

#[tokio::test]
async fn a_line_that_is_too_long_ends_the_connection() {
    let w = World::new();
    // after the first message: a pledge that has signed in sends a line that is too long
    let mut s = open_pledge(&w).await;
    s.connect_as("jan", &w.jan_connection).await;
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
    // a connection that sends nothing, or begins a first line and does not finish it, is closed without a word
    // (a_connection_that_says_nothing_is_closed)
    // a pledge that does not answer the challenge
    let mut p = open_pledge_on(&w.broker, BINDING, quick).await;
    assert_eq!(p.recv_type().await, "challenge");
    assert_eq!(p.recv().await["error"], "timeout");
    // a pledge that signs in and then says nothing: closed; with pings it stays
    let mut p = open_pledge_on(&w.broker, BINDING, quick).await;
    p.connect_as("jan", &w.jan_connection).await;
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        p.send_json(serde_json::json!({"schema_version":1,"type":"ping"})).await;
    }
    let mut quiet = open_pledge_on(&w.broker, BINDING, quick).await;
    quiet.connect_as("eva", &w.eva_connection).await;
    assert_eq!(quiet.recv().await["error"], "timeout");
    quiet.expect_closed().await;
}

#[tokio::test]
async fn a_pledge_may_not_send_what_only_the_broker_sends() {
    let w = World::new();
    let mut p = open_pledge(&w).await;
    p.connect_as("jan", &w.jan_connection).await;
    p.send(&submit_line(&w.submit(1, 120))).await;
    assert_eq!(p.recv().await["error"], "unknown-type");
    p.expect_closed().await;
}

// --- what an unauthenticated peer can learn ---------------------------------------

#[tokio::test]
async fn an_unauthenticated_peer_learns_nothing_about_the_site_beyond_a_coarse_class() {
    let w = World::new();
    let mut pledge = open_pledge(&w).await;
    pledge.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut pledge).await; // jan's delegation is registered: a stranger must not be able to tell

    // A service is authenticated by the signature on its request. A stranger's request, whatever it names, is
    // `bad-request`: an unknown host, a known host with a key the host never certified, a registered person
    // and delegation, an unregistered one, a person the site does not have.
    let stranger = w.keys.key("stranger-service");
    let other_host = w.keys.key("elsewhere");
    let certified_elsewhere = w.keys.certified("elsewhere-service", &other_host, "probe@a.example", VALID, &[]);
    let nobody = w.keys.key("nobody-delegation");
    let nobody_agent = w.keys.certified("nobody-agent", &nobody, "mallory", "-5m:+8h", &[]);
    let unregistered = w.keys.certified("unregistered-agent", &w.jan_delegation, "jan", "-5m:+8h", &[]);
    let mut seen = Vec::new();
    for (n, agent, service) in [
        (1, &w.agent, &certified_elsewhere),
        (2, &unregistered, &certified_elsewhere),
        (3, &nobody_agent, &certified_elsewhere),
        (4, &w.agent, &w.keys.path("stranger-service")),
    ] {
        let _ = &stranger;
        let mut s = open_service(&w);
        let submit = if service == &w.keys.path("stranger-service") {
            // not even certified: signed with a plain key (the signature carries no certificate)
            let (call, call_sig) = w.call(n, 120, agent);
            let rating = p_act::rating::Rating::new(
                p_act::rating::Exposure::Open,
                p_act::rating::Damage::None,
                p_act::rating::Disruption::None,
            );
            let request = p_act::Request::compose(&call, &call_sig, rating).unwrap();
            let sig = raw_sign(service, Namespace::Request, request.as_bytes());
            p_act::exchange::Submit::new(request, &sig).unwrap()
        } else {
            w.submit_with(n, 120, agent, service)
        };
        s.send(&submit_line(&submit)).await;
        seen.push(refusal(&service_answer(&mut s).await));
    }
    assert_eq!(seen, [BrokerReason::BadRequest; 4]);
    // the check on the deadline comes before any signature and says only that: a past deadline is `deadline`
    // for a stranger as for anyone
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit_with(5, -5, &nobody_agent, &certified_elsewhere))).await;
    assert_eq!(refusal(&service_answer(&mut s).await), BrokerReason::Deadline);

    // A pledge is authenticated by the sign-in. Before it, every message but the sign-in is the same `signin`
    // error, whether or not it is one the broker knows.
    for message in [
        serde_json::json!({"schema_version":1,"type":"delegation","cert":w.keys.cert_line(&w.agent)}),
        serde_json::json!({"schema_version":1,"type":"withdraw","delegation":"SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}),
        serde_json::json!({"schema_version":1,"type":"nonsense"}),
    ] {
        let mut c = open_pledge(&w).await;
        c.recv().await;
        c.send_json(message).await;
        assert_eq!(c.recv().await["error"], "signin");
    }
}

// --- a register that cannot be written -------------------------------------------------

fn lock_state_dir(w: &World) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(w.keys.dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
    // as root the lock proves nothing: say so and skip
    std::fs::File::create(w.keys.path("probe")).is_err()
}

fn unlock_state_dir(w: &World) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(w.keys.dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[tokio::test]
async fn registering_is_refused_while_the_register_cannot_be_written_and_works_again_when_it_can() {
    let w = World::new();
    let mut pledge = open_pledge(&w).await;
    pledge.connect_as("jan", &w.jan_connection).await;
    let cert = w.keys.cert_line(&w.agent);
    if !lock_state_dir(&w) {
        return;
    }
    pledge.send_json(serde_json::json!({"schema_version":1,"type":"delegation","cert":cert})).await;
    // the document has no answer for this; `error busy` and the end is the nearest existing one
    assert_eq!(pledge.recv().await["error"], "busy");
    pledge.expect_closed().await;
    assert!(w.broker.degraded().is_some());
    // nothing was permitted: a request under that delegation is refused
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit(1, 120))).await;
    assert_eq!(refusal(&service_answer(&mut s).await), BrokerReason::Delegation);
    // the disk comes back: registering works and the broker is no longer degraded
    unlock_state_dir(&w);
    let mut again = open_pledge(&w).await;
    again.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut again).await;
    assert_eq!(w.broker.degraded(), None);
}

#[tokio::test]
async fn restricting_goes_on_while_the_register_cannot_be_written_and_pledge_is_told_nothing_extra() {
    let w = World::new();
    let mut pledge = open_pledge(&w).await;
    pledge.connect_as("jan", &w.jan_connection).await;
    register(&w, &mut pledge).await;
    let submit = w.submit(1, 120);
    let mut service = open_service(&w);
    service.send(&submit_line(&submit)).await;
    assert_eq!(pledge.recv_type().await, "submit");
    let fp = p_act::sign::agent_certificate(&w.keys.cert_line(&w.agent)).unwrap().delegation;
    if !lock_state_dir(&w) {
        return;
    }
    // a withdrawal from pledge: in force, and the only thing pledge is sent is the cancel it always gets
    pledge.send_json(serde_json::json!({"schema_version":1,"type":"withdraw","delegation":fp.to_string()})).await;
    assert_eq!(refusal(&service_answer(&mut service).await), BrokerReason::Delegation);
    assert_eq!(pledge.recv_type().await, "cancel");
    pledge.send_json(serde_json::json!({"schema_version":1,"type":"ping"})).await;
    assert!(tokio::time::timeout(Duration::from_millis(300), pledge.lines.read(None)).await.is_err(), "nothing else");
    assert!(w.broker.degraded().is_some());
    // an administrator's block: in force, and the answer says it is not stored
    let stored = w.broker.block_person("jan".into()).await;
    assert!(matches!(stored, p_age::core::Stored::No(_)), "{stored:?}");
    let mut s = open_service(&w);
    s.send(&submit_line(&w.submit(2, 120))).await;
    assert!(matches!(refusal(&service_answer(&mut s).await), BrokerReason::Person | BrokerReason::Delegation));
    // lifting is refused
    assert!(w.broker.unblock_person("jan".into()).await.is_err());
    unlock_state_dir(&w);
    assert!(w.broker.unblock_person("jan".into()).await.is_ok());
    assert_eq!(w.broker.degraded(), None);
}
