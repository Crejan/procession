//! The session with the broker, driven line by line with the broker's side played by the tests: real
//! signatures by `ssh-keygen` (a throwaway site CA, a broker key it certified), real approvals checked
//! against the CA. The conversation over real TLS against p-age's own code is `tests/broker_tls.rs`.

use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use p_act::broker::{
    ConnectionDocument, FromPledge, NotRegisteredReason, Secret32, Signed, Standing, StandingContent, ToPledge,
};
use p_act::exchange::{ClearancePolicy, Message, PledgeReason};
use p_act::rating::Rating;
use p_act::sign::{ApprovalKind, ApprovalTrust, PublicKey, verify_approval};
use p_act::{Document, Request};
use serde_json::{Value, json};

use crate::approvals_tests::{Lab, Svc, approval, hold, refusal, yes};
use crate::broker_link::{BrokerLink, End, RegisterError, Session, SessionConfig, backoff};
use crate::broker_state::Withdrawal;
use crate::control::Code;

const BINDING: Secret32 = [7; 32];
const NONCE: Secret32 = [9; 32];

fn keygen(args: &[&str]) {
    crate::approvals_tests::keygen(args);
}

/// The broker's side, and pledge's session on a live rig.
struct W {
    lab: Lab,
    link: Arc<BrokerLink>,
    out: Receiver<Vec<u8>>,
    session: Session,
    n: u64,
}

impl W {
    fn new() -> Self {
        let lab = Lab::stage2();
        let (tx, out) = mpsc::channel();
        let link = BrokerLink::new(tx);
        let _ = lab.rig.shared.link.set(Arc::clone(&link));
        let cfg = Arc::new(SessionConfig {
            person: "jan".into(),
            site_ca: PublicKey::parse(&lab.material.ca_line()).expect("ca"),
        });
        let session = Session::new(Arc::clone(&lab.rig.shared), Arc::clone(&link), cfg, BINDING);
        Self { lab, link, out, session, n: 0 }
    }

    fn disconnect(&mut self) {
        let cfg = Arc::new(SessionConfig {
            person: "jan".into(),
            site_ca: PublicKey::parse(&self.lab.material.ca_line()).expect("ca"),
        });
        self.session = Session::new(Arc::clone(&self.lab.rig.shared), Arc::clone(&self.link), cfg, BINDING);
        assert!(!self.link.is_ready());
    }

    fn feed(&mut self, message: &ToPledge) -> Result<Vec<Vec<u8>>, End> {
        let line = message.encode().expect("encodes");
        self.session.handle(line.strip_suffix(b"\n").unwrap_or(&line))
    }

    /// The sign-in: returns the line pledge sent in answer to the challenge.
    fn challenge(&mut self) -> Vec<u8> {
        let mut lines = self.feed(&ToPledge::Challenge(NONCE)).expect("challenge");
        assert_eq!(lines.len(), 1);
        lines.remove(0)
    }

    fn sign_in(&mut self) {
        if !self.link.is_ready() {
            self.challenge();
            self.feed(&ToPledge::Ready).expect("ready");
        }
    }

    fn certificate(&self, role: &str) -> String {
        let key = self.lab.rig.shared.key_with_purpose(role).expect("key");
        let dir = &self.lab.material.dir;
        let file = dir.path().join(format!("{role}-stage2.pub"));
        std::fs::write(&file, format!("{}\n", key.public_line())).expect("write");
        keygen(&[
            "-q",
            "-s",
            &dir.path().join("site-ca").to_string_lossy(),
            "-I",
            "id",
            "-n",
            &format!("jan:{role}"),
            "-V",
            "-1m:+1h",
            "-O",
            "clear",
            &file.to_string_lossy(),
        ]);
        std::fs::read_to_string(dir.path().join(format!("{role}-stage2-cert.pub"))).expect("cert").trim().to_owned()
    }

    fn content(&mut self) -> StandingContent {
        let n = self.n;
        self.n += 1;
        StandingContent {
            to: "jan".into(),
            nonce: NONCE,
            n,
            blocked: false,
            blocked_keys: vec![],
            withdrawn: vec![],
            certificates: vec![],
            groups: vec!["ops".into()],
        }
    }

    fn notice(&self, content: &StandingContent) -> ToPledge {
        let standing = Standing::compose(content).expect("standing");
        let sig = standing.sign(&self.lab.material.signer("broker")).expect("signed by the broker");
        ToPledge::Notice(Signed { doc: standing.as_bytes().to_vec(), sig })
    }

    fn send_standing(&mut self, content: &StandingContent) {
        let notice = self.notice(content);
        self.feed(&notice).expect("standing");
    }

    /// Signed in, with the two approval keys' certificates in the first standing.
    fn ready(&mut self) {
        self.sign_in();
        let mut content = self.content();
        content.certificates = vec![self.certificate("confirmed"), self.certificate("automatic")];
        self.send_standing(&content);
    }

    fn events(&self, name: &str) -> Vec<Value> {
        self.lab.rig.record().into_iter().filter(|e| e["event"] == name).collect()
    }

    fn written(&self) -> Vec<Vec<u8>> {
        std::iter::from_fn(|| self.out.try_recv().ok()).collect()
    }

    /// An agent under a delegation issued through the broker: signed in, a standing (without
    /// certificates), the registration answered, the bundle delivered.
    fn agent(&mut self) -> crate::approvals_tests::Agent {
        if !self.link.can_issue() {
            self.sign_in();
            let content = self.content();
            self.send_standing(&content);
        }
        let shared = Arc::clone(&self.lab.rig.shared);
        self.lab.rig.dialogs.push(yes());
        let args = Lab::start_args(
            &["admins"],
            Some(crate::approvals_tests::words("open", "none", "none")),
            Some(crate::approvals_tests::words("secret", "lasting", "outage")),
            Some(3600),
        );
        let started = thread::spawn(move || crate::agents::start(&shared, args));
        let line = wait_for_line(self);
        let FromPledge::Delegation(sent) =
            FromPledge::parse(line.strip_suffix(b"\n").expect("line")).expect("a registration")
        else {
            panic!("delegation")
        };
        self.feed(&ToPledge::Registered(sent.agent.delegation.clone())).expect("registered");
        let (data, delegation) = started.join().expect("thread").expect("issued");
        let signer = self.lab.write_bundle(&data, "agent-stage2");
        let id = delegation.id.clone();
        crate::agents::delivered(&self.lab.rig.shared, delegation).expect("delivered");
        crate::approvals_tests::Agent { id, signer }
    }

    fn verifies_with_ca(&self, request: &Request, approval: &str) -> ApprovalKind {
        let ca = PublicKey::parse(&self.lab.material.ca_line()).expect("ca");
        verify_approval(request, approval, ApprovalTrust::SiteCa(&ca))
            .expect("verifies against the site CA's single line")
    }
}

// ---------------------------------------------------------------------------

#[test]
fn the_sign_in_is_the_connection_document_signed_by_the_connection_key_over_this_connection() {
    let mut w = W::new();
    let line = w.challenge();
    let FromPledge::Signin(signed) = FromPledge::parse(line.strip_suffix(b"\n").expect("line")).expect("a sign-in")
    else {
        panic!("signin")
    };
    let doc = ConnectionDocument::parse_unverified(signed.doc.clone()).expect("document");
    assert_eq!(
        (doc.person(), doc.nonce(), doc.tls()),
        ("jan", &NONCE, &BINDING),
        "the broker's nonce and this connection's binding"
    );
    let key = w.lab.rig.shared.key_with_purpose("connection").expect("connection key");
    doc.verify(&PublicKey::parse(&key.public_line()).expect("key"), &signed.sig)
        .expect("verifies as connection-v1@procession with ssh-keygen");
    assert!(!w.link.is_ready(), "not ready until the broker says so");
}

#[test]
fn what_is_out_of_order_ends_the_connection_and_carried_is_ignored() {
    let mut w = W::new();
    assert!(matches!(w.feed(&ToPledge::Ready), Err(End::Protocol(_))), "ready before a challenge");
    let mut w = W::new();
    w.challenge();
    assert!(matches!(w.feed(&ToPledge::Challenge(NONCE)), Err(End::Protocol(_))), "a second challenge");
    let mut w = W::new();
    w.sign_in();
    assert!(w.link.is_ready());
    let content = w.content();
    let ToPledge::Notice(signed) = w.notice(&content) else { unreachable!("a notice") };
    };
    assert!(w.feed(&carried).expect("ignored, by type").is_empty());
    assert!(matches!(w.session.handle(b"not json"), Err(End::Protocol(_))));
    let mut w = W::new();
    w.sign_in();
    let error = Message::Error(p_act::exchange::ErrorMessage { error: p_act::exchange::ErrorCode::Timeout })
        .encode(ClearancePolicy::Refused)
        .expect("error");
    assert!(matches!(w.session.handle(error.strip_suffix(b"\n").expect("line")), Err(End::Protocol(_))));
}

#[test]
fn a_standing_counts_only_if_it_verifies_is_for_this_person_and_connection_and_is_newer() {
    let mut w = W::new();
    w.sign_in();
    let mut content = w.content();
    content.blocked = true;
    // Verifies, for this person and connection: accepted.
    w.send_standing(&content);
    assert!(w.lab.rig.shared.broker_state.is_blocked());
    assert!(w.link.can_issue());
    // Each way to be ignored, with the state unchanged.
    let mut lifted = w.content();
    lifted.blocked = false;
    let mut other_person = lifted.clone();
    other_person.to = "eva".into();
    let mut other_connection = lifted.clone();
    other_connection.nonce = [1; 32];
    let mut stale = lifted.clone();
    stale.n = 0;
    for (what, notice) in [
        ("another person", w.notice(&other_person)),
        ("another connection", w.notice(&other_connection)),
        ("not newer", w.notice(&stale)),
    ] {
        w.feed(&notice).expect("ignored, not an error");
        assert!(w.lab.rig.shared.broker_state.is_blocked(), "{what}");
    }
    // Not signed by the broker's key (signed by the site CA's own key: a different name): ignored.
    let standing = Standing::compose(&lifted).expect("standing");
    let sig = p_act::sign::sign_broker(
        &p_act::sign::Signer::plain(w.lab.material.dir.path().join("site-ca")),
        standing.as_bytes(),
    )
    .expect("signed");
    w.feed(&ToPledge::Notice(Signed { doc: standing.as_bytes().to_vec(), sig })).expect("ignored");
    assert!(w.lab.rig.shared.broker_state.is_blocked(), "not signed as `broker`");
    assert_eq!(w.events("standing-ignored").len(), 4);
    // The right one, newer: the absence of a restriction lifts it.
    w.send_standing(&lifted);
    assert!(!w.lab.rig.shared.broker_state.is_blocked());
}

#[test]
fn approvals_carry_the_certificate_and_verify_against_the_single_site_ca_line_and_not_before_one_is_held() {
    let mut w = W::new();
    let agent = w.agent();
    let (request, sig) = w.lab.make(&agent, &["a"], Rating::HARMLESS);
    // Signed in, but no certificate yet: not signed at all.
    w.sign_in();
    assert_eq!(refusal(&w.lab.connect().ask(&request, &sig)), PledgeReason::Unavailable);
    // The certificates arrive in the standing: now approved, as a service holding only the CA line verifies it.
    let mut content = w.content();
    content.certificates = vec![w.certificate("confirmed"), w.certificate("automatic")];
    w.send_standing(&content);
    let answer = w.lab.connect().ask(&request, &sig);
    assert_eq!(w.verifies_with_ca(&request, approval(&answer)), ApprovalKind::Automatic);
    // A confirmed approval too.
    w.lab.rig.dialogs.push(yes());
    w.lab.rig.dialogs.push(yes());
    let (asked, asked_sig) = w.lab.make(&agent, &["b"], crate::approvals_tests::INTERNAL);
    let answer = w.lab.connect().ask(&asked, &asked_sig);
    assert_eq!(w.verifies_with_ca(&asked, approval(&answer)), ApprovalKind::Confirmed);
}

#[test]
fn a_certificate_the_ca_did_not_sign_for_this_key_is_not_kept() {
    let mut w = W::new();
    w.sign_in();
    let mut content = w.content();
    let good = w.certificate("confirmed");
    // A certificate for the right key and name from another CA.
    let dir = &w.lab.material.dir;
    let key = w.lab.rig.shared.key_with_purpose("automatic").expect("key");
    std::fs::write(dir.path().join("rogue-auto.pub"), format!("{}\n", key.public_line())).expect("write");
    keygen(&[
        "-q",
        "-s",
        &dir.path().join("other-host").to_string_lossy(),
        "-I",
        "id",
        "-n",
        "jan:automatic",
        "-V",
        "-1m:+1h",
        "-O",
        "clear",
        &dir.path().join("rogue-auto.pub").to_string_lossy(),
    ]);
    let rogue = std::fs::read_to_string(dir.path().join("rogue-auto-cert.pub")).expect("cert").trim().to_owned();
    content.certificates = vec![good.clone(), rogue];
    w.send_standing(&content);
    let state = &w.lab.rig.shared.broker_state;
    assert_eq!(state.certificate_for("confirmed").as_deref(), Some(good.as_str()));
    assert!(
        state.certificate_for("automatic").is_none(),
        "the broker's signature on the standing does not make a certificate good"
    );
}

#[test]
fn a_block_and_a_withdrawal_in_a_standing_stop_asking_and_signing_and_a_restart_does_not_lift_them() {
    let mut w = W::new();
    let agent = w.agent();
    w.sign_in();
    let mut content = w.content();
    content.certificates = vec![w.certificate("confirmed"), w.certificate("automatic")];
    w.send_standing(&content);
    let (request, sig) = w.lab.make(&agent, &["a"], Rating::HARMLESS);
    approval(&w.lab.connect().ask(&request, &sig));
    // An administrator blocks the person: refused `blocked` (a passing condition: not kept).
    let mut blocked = w.content();
    blocked.certificates = content.certificates.clone();
    blocked.blocked = true;
    w.send_standing(&blocked);
    let (next, next_sig) = w.lab.make(&agent, &["b"], Rating::HARMLESS);
    assert_eq!(refusal(&w.lab.connect().ask(&next, &next_sig)), PledgeReason::Blocked);
    assert!(
        w.lab
            .rig
            .shared
            .approvals
            .answers
            .answer(&next.hash().to_string(), p_act::Timestamp::now().expect("clock").unix())
            .is_none()
    );
    // A restart: still blocked, until a newer verified standing says otherwise.
    w.lab.rig.restart();
    assert!(w.lab.rig.shared.broker_state.is_blocked());
    let (again, again_sig) = w.lab.make(&agent, &["c"], Rating::HARMLESS);
    assert_eq!(refusal(&w.lab.connect().ask(&again, &again_sig)), PledgeReason::Blocked);
}

#[test]
fn a_withdrawal_by_an_administrator_refuses_what_waits_and_what_comes() {
    let mut w = W::new();
    let agent = w.agent();
    w.sign_in();
    let mut content = w.content();
    content.certificates = vec![w.certificate("confirmed"), w.certificate("automatic")];
    w.send_standing(&content);
    // A request waits for the person.
    w.lab.rig.dialogs.push(hold());
    let (waiting, waiting_sig) = w.lab.make(&agent, &["w"], crate::approvals_tests::INTERNAL);
    let mut svc: Svc = w.lab.connect();
    svc.submit(&waiting, &waiting_sig);
    thread::sleep(Duration::from_millis(400));
    // The administrator withdraws the delegation.
    let mut withdrawn = w.content();
    withdrawn.certificates = content.certificates.clone();
    withdrawn.withdrawn = vec![agent.id.parse().expect("fingerprint")];
    w.send_standing(&withdrawn);
    assert_eq!(
        refusal(&svc.answer()),
        PledgeReason::DelegationWithdrawn,
        "the waiting request is refused, its dialog closed"
    );
    let (next, next_sig) = w.lab.make(&agent, &["n"], Rating::HARMLESS);
    assert_eq!(refusal(&svc.ask(&next, &next_sig)), PledgeReason::DelegationWithdrawn);
}

#[test]
fn a_request_from_the_broker_is_answered_on_the_connection_and_cancel_closes_its_dialog() {
    let mut w = W::new();
    let agent = w.agent();
    w.ready();
    // submit from the broker; the answer goes out on the link.
    let (request, _) = w.lab.make(&agent, &["x"], Rating::HARMLESS);
    let submit = p_act::exchange::Submit::new(request.clone(), &sig_for(&w, &request)).expect("submit");
    w.feed(&ToPledge::Exchange(Box::new(Message::Submit(submit)))).expect("submit");
    let line = wait_for_line(&w);
    let Message::Answer(answer) =
        Message::parse(line.strip_suffix(b"\n").expect("line"), ClearancePolicy::Refused).expect("answer")
    else {
        panic!("an answer")
    };
    assert_eq!(answer.request, request.hash());
    let p_act::exchange::Outcome::Approved(approved) = answer.outcome else { panic!("approved") };
    assert_eq!(w.verifies_with_ca(&request, approved.approval()), ApprovalKind::Automatic);
    assert_eq!(w.lab.entries()[0]["via"], "broker", "the record says it came by the broker");
    // A request that waits: cancel from the broker closes it, no answer follows.
    w.lab.rig.dialogs.push(hold());
    let (waiting, _) = w.lab.make(&agent, &["y"], crate::approvals_tests::INTERNAL);
    let submit = p_act::exchange::Submit::new(waiting.clone(), &sig_for(&w, &waiting)).expect("submit");
    w.feed(&ToPledge::Exchange(Box::new(Message::Submit(submit)))).expect("submit");
    thread::sleep(Duration::from_millis(400));
    w.feed(&ToPledge::Exchange(Box::new(Message::Cancel(p_act::exchange::Cancel { request: waiting.hash() }))))
        .expect("cancel");
    thread::sleep(Duration::from_millis(500));
    assert!(w.written().is_empty(), "no answer follows a cancel");
    assert!(w.lab.results().iter().any(|(r, _)| r == "cancelled"));
}

fn sig_for(w: &W, request: &Request) -> String {
    p_act::sign::sign_request(&w.lab.material.signer("svc"), request).expect("service signature")
}

fn wait_for_line(w: &W) -> Vec<u8> {
    w.out.recv_timeout(Duration::from_secs(10)).expect("a line on the link")
}

#[test]
fn an_answer_made_for_an_older_connection_is_not_written_to_a_newer_one() {
    let mut w = W::new();
    let agent = w.agent();
    w.ready();
    w.lab.rig.dialogs.push(hold());
    let (waiting, _) = w.lab.make(&agent, &["old"], crate::approvals_tests::INTERNAL);
    let submit = p_act::exchange::Submit::new(waiting.clone(), &sig_for(&w, &waiting)).expect("submit");
    w.feed(&ToPledge::Exchange(Box::new(Message::Submit(submit)))).expect("submit");
    thread::sleep(Duration::from_millis(300));
    // The connection ends and a new one begins (a newer generation); the old responder is stale.
    let cfg = Arc::new(SessionConfig {
        person: "jan".into(),
        site_ca: PublicKey::parse(&w.lab.material.ca_line()).expect("ca"),
    });
    let _newer = Session::new(Arc::clone(&w.lab.rig.shared), Arc::clone(&w.link), cfg, BINDING);
    w.lab.rig.shared.approvals.refuse_waiting(|_| true, PledgeReason::Blocked);
    thread::sleep(Duration::from_millis(500));
    assert!(
        w.written().is_empty(),
        "the old connection's answer is not sent on the new one; the request is submitted again and answered from the store"
    );
}

#[test]
fn registration_waits_for_the_broker_and_maps_every_answer() {
    let mut w = W::new();
    // Without a connection, nothing is registered.
    assert_eq!(w.link.register("ssh-ed25519-cert-v01@openssh.com AAAA", "SHA256:x"), Err(RegisterError::Unavailable));
    w.ready();
    let mut lab_agent = w.agent();
    let delegation = w.lab.rig.shared.approvals.delegations.get(&lab_agent.id).expect("a delegation");
    let _ = &mut lab_agent;
    for (answer, expected) in [
        (Some(ToPledgeKind::Registered), Ok(())),
        (Some(ToPledgeKind::Refused(NotRegisteredReason::NotYours)), Err(RegisterError::Refused("not-yours"))),
        (Some(ToPledgeKind::Refused(NotRegisteredReason::Unavailable)), Err(RegisterError::Unavailable)),
    ] {
        let link = Arc::clone(&w.link);
        let (cert, id) = (delegation.certificate.clone(), delegation.id.clone());
        let handle = thread::spawn(move || link.register(&cert, &id));
        let line = wait_for_line(&w);
        let FromPledge::Delegation(sent) =
            FromPledge::parse(line.strip_suffix(b"\n").expect("line")).expect("a delegation message")
        else {
            panic!("delegation")
        };
        assert_eq!(sent.certificate, delegation.certificate);
        let id: p_act::sign::Fingerprint = delegation.id.parse().expect("fingerprint");
        let reply = match answer.expect("some") {
            ToPledgeKind::Registered => ToPledge::Registered(id),
            ToPledgeKind::Refused(reason) => ToPledge::NotRegistered { delegation: id, reason },
        };
        w.feed(&reply).expect("answer");
        assert_eq!(handle.join().expect("thread"), expected);
    }
}

enum ToPledgeKind {
    Registered,
    Refused(NotRegisteredReason),
}

#[test]
fn issuing_with_a_broker_needs_the_connection_a_standing_and_a_registration_and_never_issues_local_only() {
    let mut w = W::new();
    // Not connected: refused, nothing issued.
    w.lab.rig.dialogs.push(yes());
    let args = Lab::start_args(&[], None, None, None);
    assert_eq!(crate::agents::start(&w.lab.rig.shared, args).err(), Some(Code::BrokerUnavailable));
    // Signed in but no standing on this connection yet: still not.
    w.sign_in();
    w.lab.rig.dialogs.push(yes());
    assert_eq!(
        crate::agents::start(&w.lab.rig.shared, Lab::start_args(&[], None, None, None)).err(),
        Some(Code::BrokerUnavailable)
    );
    // With a standing: issued, registered (the answer is `registered`), bundle handed over.
    let content = w.content();
    w.send_standing(&content);
    let started = {
        let shared = Arc::clone(&w.lab.rig.shared);
        w.lab.rig.dialogs.push(yes());
        thread::spawn(move || crate::agents::start(&shared, Lab::start_args(&["ops"], None, None, None)))
    };
    let line = wait_for_line(&w);
    let FromPledge::Delegation(sent) =
        FromPledge::parse(line.strip_suffix(b"\n").expect("line")).expect("a registration")
    else {
        panic!("delegation")
    };
    w.feed(&ToPledge::Registered(sent.agent.delegation.clone())).expect("registered");
    let (data, delegation) = started.join().expect("thread").expect("issued after the registration");
    assert!(data["bundle"].is_string());
    assert!(
        w.lab.rig.shared.approvals.delegations.get(&delegation.id).is_none(),
        "it exists only from agents.delivered"
    );
    // A refusal by the broker: nothing handed over.
    let shared = Arc::clone(&w.lab.rig.shared);
    w.lab.rig.dialogs.push(yes());
    let refused = thread::spawn(move || crate::agents::start(&shared, Lab::start_args(&[], None, None, None)));
    let line = wait_for_line(&w);
    let FromPledge::Delegation(sent) =
        FromPledge::parse(line.strip_suffix(b"\n").expect("line")).expect("a registration")
    else {
        panic!("delegation")
    };
    w.feed(&ToPledge::NotRegistered {
        delegation: sent.agent.delegation.clone(),
        reason: NotRegisteredReason::BadCertificate,
    })
    .expect("refused");
    assert_eq!(refused.join().expect("thread").err(), Some(Code::BrokerRefused));
}

#[test]
fn a_registration_for_a_bundle_never_delivered_is_withdrawn_at_the_broker_until_stored() {
    let mut w = W::new();
    w.ready();
    let id = w.agent().id;
    let _ = w.written();
    crate::agents::abandoned(&w.lab.rig.shared, &id);
    let line = wait_for_line(&w);
    assert!(
        matches!(FromPledge::parse(line.strip_suffix(b"\n").expect("line")), Ok(FromPledge::Withdraw(f)) if f.as_str() == id)
    );
    let shared = Arc::clone(&w.lab.rig.shared);
    let state = &shared.broker_state;
    assert_eq!(state.withdrawal(&id), Some(Withdrawal::InForce));
    assert!(w.events("delegation-not-delivered").len() == 1);
    // `stored: false`: in force at the broker, not stored: noted, and sent again at the next sign-in.
    w.feed(&ToPledge::Withdrawn { delegation: id.parse().expect("fp"), stored: false }).expect("withdrawn");
    assert_eq!(state.withdrawal(&id), Some(Withdrawal::InForce));
    assert!(w.events("withdrawal-not-stored").is_empty(), "nothing changed, nothing recorded");
    let again = W::new_session_on(&w);
    let resent = again;
    assert!(resent.iter().any(|l| matches!(FromPledge::parse(l.strip_suffix(b"\n").expect("line")), Ok(FromPledge::Withdraw(f)) if f.as_str() == id)), "re-sent at the sign-in");
    w.feed(&ToPledge::Withdrawn { delegation: id.parse().expect("fp"), stored: true }).expect("stored");
    assert_eq!(state.withdrawal(&id), Some(Withdrawal::Stored));
    assert_eq!(w.events("withdrawal-stored").len(), 1);
    assert!(state.unstored_withdrawals().is_empty(), "no more re-sending");
}

impl W {
    /// A new connection's session: sign in again; the lines sent at `ready`.
    fn new_session_on(w: &W) -> Vec<Vec<u8>> {
        let cfg = Arc::new(SessionConfig {
            person: "jan".into(),
            site_ca: PublicKey::parse(&w.lab.material.ca_line()).expect("ca"),
        });
        let mut session = Session::new(Arc::clone(&w.lab.rig.shared), Arc::clone(&w.link), cfg, BINDING);
        let encode = |m: &ToPledge| m.encode().expect("encodes");
        let strip = |l: Vec<u8>| l.strip_suffix(b"\n").map(<[u8]>::to_vec).unwrap_or(l);
        session.handle(&strip(encode(&ToPledge::Challenge(NONCE)))).expect("challenge");
        session.handle(&strip(encode(&ToPledge::Ready))).expect("ready")
    }
}

#[test]
fn a_person_withdrawing_while_disconnected_is_told_to_the_broker_at_the_next_sign_in_and_shown() {
    let mut w = W::new();
    let agent = w.agent();
    let delegation = agent.id.clone();
    // Not connected (the session of the connection that ended is dropped): withdrawn here at once; the broker has not been told.
    w.disconnect();
    crate::agents::withdraw(&w.lab.rig.shared, &delegation).expect("withdrawn");
    assert_eq!(w.lab.rig.shared.broker_state.withdrawal(&delegation), Some(Withdrawal::NotTold));
    let listed = crate::agents::list(&w.lab.rig.shared);
    assert_eq!(listed["delegations"][0]["state"], "withdrawn");
    assert_eq!(listed["delegations"][0]["broker"], "not told");
    // The next sign-in: told.
    let lines = W::new_session_on(&w);
    assert!(lines.iter().any(|l| matches!(FromPledge::parse(l.strip_suffix(b"\n").expect("line")), Ok(FromPledge::Withdraw(f)) if f.as_str() == delegation)));
    assert_eq!(crate::agents::list(&w.lab.rig.shared)["delegations"][0]["broker"], "not stored yet");
}

#[test]
fn reconnecting_waits_longer_and_longer_up_to_a_minute_and_a_good_connection_starts_over() {
    let d = |s: f64| Duration::from_secs_f64(s);
    assert_eq!(backoff(d(1.0), false, 0.0), d(2.0));
    assert_eq!(backoff(d(2.0), false, 0.0), d(4.0));
    assert_eq!(backoff(d(40.0), false, 0.0), d(60.0));
    assert_eq!(backoff(d(60.0), false, 0.0), d(60.0));
    assert_eq!(backoff(d(60.0), true, 0.0), d(1.0));
    assert_eq!(backoff(d(2.0), false, 1.0), d(5.0), "jitter adds up to a quarter");
    assert_eq!(json!(backoff(d(1.0), false, 5.0).as_millis() <= 2500), json!(true), "and no more");
}

#[test]
fn a_blocked_approval_key_is_not_signed_with_and_the_record_says_which_and_why() {
    let mut w = W::new();
    let agent = w.agent();
    w.ready();
    for (role, mode_rating) in [("automatic", Rating::HARMLESS), ("confirmed", crate::approvals_tests::INTERNAL)] {
        let key = w.lab.rig.shared.key_with_purpose(role).expect("key");
        let mut content = w.content();
        content.certificates = vec![w.certificate("confirmed"), w.certificate("automatic")];
        content.blocked_keys = vec![key.fingerprint.parse().expect("fingerprint")];
        w.send_standing(&content);
        let (request, sig) = w.lab.make(&agent, &[role], mode_rating);
        assert_eq!(
            refusal(&w.lab.connect().ask(&request, &sig)),
            PledgeReason::Blocked,
            "{role}: the agent hears the coarse class"
        );
        let entry = w.lab.entries().into_iter().rev().find(|e| e["type"] == "request").expect("entry");
        assert_eq!(entry["reason"], "blocked");
        assert!(
            entry["why"].as_str().is_some_and(|why| why.contains(role) && why.contains("blocked by the broker")),
            "{entry}"
        );
        // Lifted by a newer standing that no longer lists it.
        let mut lifted = w.content();
        lifted.certificates = content.certificates.clone();
        w.send_standing(&lifted);
    }
}

#[test]
fn a_blocked_delegation_key_issues_nothing_and_signs_nothing_under_what_it_issued() {
    let mut w = W::new();
    let agent = w.agent();
    let key = w.lab.rig.shared.key_with_purpose("delegation").expect("key");
    let mut content = w.content();
    content.certificates = vec![w.certificate("confirmed"), w.certificate("automatic")];
    content.blocked_keys = vec![key.fingerprint.parse().expect("fingerprint")];
    w.send_standing(&content);
    w.lab.rig.dialogs.push(yes());
    assert_eq!(
        crate::agents::start(&w.lab.rig.shared, Lab::start_args(&[], None, None, None)).err(),
        Some(Code::Refused)
    );
    assert_eq!(w.events("issuing-refused").len(), 1);
    let (request, sig) = w.lab.make(&agent, &["d"], Rating::HARMLESS);
    assert_eq!(refusal(&w.lab.connect().ask(&request, &sig)), PledgeReason::Blocked);
}

#[test]
fn a_refused_sign_in_for_a_blocked_connection_key_is_its_own_ending_and_not_one_to_retry_in_a_loop() {
    let mut w = W::new();
    w.challenge();
    let blocked = ToPledge::Exchange(Box::new(Message::Error(p_act::exchange::ErrorMessage {
        error: p_act::exchange::ErrorCode::Blocked,
    })));
    assert!(matches!(w.feed(&blocked), Err(End::Blocked)));
    // The same word on a connection that is up is not a sign-in refusal.
    let mut up = W::new();
    up.sign_in();
    assert!(matches!(up.feed(&blocked), Err(End::Protocol(_))));
}

#[test]
fn the_tls_client_is_what_the_contract_names() {
    // The version and provider the code builds are the words of p-act's constants.
    assert_eq!(p_act::broker::TLS_PROTOCOL_VERSION, "TLSv1.3");
    assert_eq!(p_act::broker::TLS_CRYPTO_PROVIDER, "ring");
    crate::broker_link::client_config(include_str!("../testdata/tls_root.pem")).expect("config");
}
