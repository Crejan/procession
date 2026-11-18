//! pledge's connection to the broker against p-age's real code, over real TLS 1.3 (rustls on both sides) on
//! Unix sockets under `/tmp/claude` or the system's temporary directory. The sandbox cannot bind TCP, so
//! `TcpStream::connect`, name resolution and real-network timeouts are what these tests never ran.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use p_act::Document as _;
use p_act::exchange::{ClearancePolicy, Message, Outcome, Submit};
use p_act::rating::Rating;
use p_act::sign::{ApprovalKind, ApprovalTrust, PublicKey, verify_approval};
use p_age::net::{Broker, Lines, serve_tls};
use p_age::testing::{BrokerSetup, PersonSpec, SiteBuilder, TestBroker, TestPki, socket_dir, write_certificate};
use tokio::io::AsyncWriteExt;

use crate::approvals_tests::{Lab, yes};
use crate::broker_link::{self, BrokerLink, DynTransport, SessionConfig, TlsTransport};
use crate::broker_state::Withdrawal;

/// The broker's clock: the real time, which a test can move to a date its own certificate is not valid at.
struct MovableClock(std::sync::atomic::AtomicI64);

impl p_age::net::Clock for MovableClock {
    fn now(&self) -> std::time::SystemTime {
        std::time::UNIX_EPOCH + Duration::from_secs(u64::try_from(self.0.load(Ordering::SeqCst)).unwrap_or(0))
    }
}

/// A broker serving TLS on a Unix socket, and the way to cut its connections.
struct Site2 {
    rt: tokio::runtime::Runtime,
    broker: Arc<Broker>,
    socket: PathBuf,
    root_pem: String,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
    clock: Arc<MovableClock>,
}

impl Site2 {
    /// `delegation_key` is what the site says jan's delegations are certified by.
    fn new(lab: &Lab, delegation_key: &str) -> Self {
        let dir = lab.material.dir.path();
        let line = |name: &str| std::fs::read_to_string(dir.join(name)).expect("key").trim().to_owned();
        let connection = lab.rig.shared.key_with_purpose("connection").expect("connection key").public_line();
        for role in ["confirmed", "automatic"] {
            {
                let key = lab.rig.shared.key_with_purpose(role).expect("key");
                std::fs::write(dir.join(format!("{role}-tls.pub")), format!("{}\n", key.public_line())).expect("write");
                crate::approvals_tests::keygen(&[
                    "-q",
                    "-s",
                    &dir.join("site-ca").to_string_lossy(),
                    "-I",
                    role,
                    "-n",
                    &format!("jan:{role}"),
                    "-V",
                    "-1m:+1h",
                    "-O",
                    "clear",
                    &dir.join(format!("{role}-tls.pub")).to_string_lossy(),
                ]);
                write_certificate(&dir.join("certificates"), "jan", role, &line(&format!("{role}-tls-cert.pub")));
            }
        }
        let public = |role: &str| lab.rig.shared.key_with_purpose(role).expect("key").public_line();
        let site = SiteBuilder::new()
            .person(
                PersonSpec::new("jan")
                    .keys(&public("confirmed"), &public("automatic"), delegation_key, &connection)
                    .groups(&["ops"]),
            )
            .host("a.example", &lab.material.host_line())
            .build()
            .expect("site");
        let clock = Arc::new(MovableClock(std::sync::atomic::AtomicI64::new(crate::approvals_tests::now())));
        let TestBroker { broker, .. } = BrokerSetup::new(site, dir.join("broker"), dir.join("state"))
            .certificates(PublicKey::parse(&lab.material.ca_line()).expect("site ca"), dir.join("certificates"))
            .clock(clock.clone())
            .start();
        let pki = TestPki::new(&["broker.test"]);
        let acceptor = pki.acceptor();
        let ca = pki;

        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("runtime");
        let base = socket_dir();
        static N: AtomicUsize = AtomicUsize::new(0);
        let socket = base.join(format!("pl-tls-{}-{}.sock", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
        let _ = std::fs::remove_file(&socket);
        let listener = {
            let _guard = rt.enter();
            tokio::net::UnixListener::bind(&socket).expect("bind")
        };
        let tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>> = Arc::default();
        let (accept_broker, accept_tasks) = (Arc::clone(&broker), Arc::clone(&tasks));
        rt.spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let task = tokio::spawn(serve_tls(stream, acceptor.clone(), Arc::clone(&accept_broker)));
                accept_tasks.lock().expect("tasks").push(task);
            }
        });
        Self { rt, broker, socket, root_pem: ca.root_pem.clone(), tasks, clock }
    }

    /// The broker closes every connection it holds.
    fn cut(&self) {
        for task in self.tasks.lock().expect("tasks").drain(..) {
            task.abort();
        }
    }

    /// pledge's side: a connection through real TLS to the broker, counted.
    fn link(&self, lab: &Lab, person: &str, attempts: Arc<AtomicUsize>) -> Arc<BrokerLink> {
        let tls = broker_link::client_config(&self.root_pem).expect("client config");
        let socket = self.socket.clone();
        let connect = Box::new(move || -> std::io::Result<Box<dyn DynTransport>> {
            attempts.fetch_add(1, Ordering::SeqCst);
            let stream = std::os::unix::net::UnixStream::connect(&socket)?;
            let name = rustls::pki_types::ServerName::try_from("broker.test").map_err(std::io::Error::other)?;
            Ok(Box::new(TlsTransport::connect(Arc::clone(&tls), name, stream, Duration::from_secs(10))?))
        });
        let cfg =
            SessionConfig { person: person.into(), site_ca: PublicKey::parse(&lab.material.ca_line()).expect("ca") };
        let link = broker_link::start(&lab.rig.shared, cfg, connect);
        let _ = lab.rig.shared.link.set(Arc::clone(&link));
        link
    }

    /// A service's connection (in memory: the service side is not what is tested here): submits, hears the answer.
    fn ask(&self, submit: &Submit) -> Message {
        let (client, server) = tokio::io::duplex(1 << 20);
        self.rt.block_on(async {
            tokio::spawn(p_age::net::serve_connection(server, [3; 32], Arc::clone(&self.broker)));
            let (rd, mut wr) = tokio::io::split(client);
            wr.write_all(&Message::Submit(submit.clone()).encode(ClearancePolicy::Refused).expect("encodes"))
                .await
                .expect("write");
            let mut lines = Lines::new(rd, Duration::from_secs(20));
            let line = lines.read(None).await.expect("read").expect("an answer");
            // A service in stage 2 reads `approved` with the broker's clearance.
            Message::parse(&line, ClearancePolicy::Required).expect("a message")
        })
    }
}

fn eventually(what: &str, mut f: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(15);
    while Instant::now() < end {
        if f() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("not within 15 s: {what}");
}

fn delegation_key(lab: &Lab) -> String {
    lab.rig.shared.key_with_purpose("delegation").expect("delegation key").public_line()
}

/// A lab, a broker over TLS that knows it, and the link between them, as far as `can_issue`.
fn world() -> (Lab, Site2, Arc<BrokerLink>) {
    let lab = Lab::stage2();
    let site = Site2::new(&lab, &delegation_key(&lab));
    let link = site.link(&lab, "jan", Arc::default());
    eventually("signed in, with a standing", || link.can_issue());
    (lab, site, link)
}

#[test]
fn pledge_signs_in_over_tls_gets_the_standing_and_keeps_the_certificates_the_broker_carries() {
    let (lab, _site, link) = world();
    assert!(link.is_ready());
    let state = &lab.rig.shared.broker_state;
    assert!(state.certificate_for("confirmed").is_some() && state.certificate_for("automatic").is_some());
    assert!(!state.is_blocked());
    // The flag is set before the event is written: wait for the event.
    eventually("the standing is in the record", || lab.rig.record().iter().any(|e| e["event"] == "standing-accepted"));
}

#[test]
fn a_delegation_is_registered_a_request_goes_through_the_broker_and_the_approval_verifies_against_the_site_ca() {
    let (mut lab, site, _link) = world();
    // `agents start` registers with the real broker; the bundle is handed over only after `registered`.
    let agent = lab.default_agent();
    let (request, sig) = lab.make(&agent, &["a"], Rating::HARMLESS);
    let submit = Submit::new(request.clone(), &sig).expect("submit");
    // A service submits to the broker; the broker forwards to the connected pledge; the answer comes back.
    let Message::Answer(answer) = site.ask(&submit) else { panic!("an answer") };
    assert_eq!(answer.request, request.hash());
    let Outcome::Approved(approved) = answer.outcome else { panic!("approved, got {:?}", answer.outcome) };
    let ca = PublicKey::parse(&lab.material.ca_line()).expect("ca");
    assert_eq!(
        verify_approval(&request, approved.approval(), ApprovalTrust::SiteCa(&ca)).expect("verifies"),
        ApprovalKind::Automatic,
        "p-age's broker and pledge agree on what an approval is"
    );
    assert_eq!(lab.entries().last().expect("entry")["via"], "broker");
    // The same request again: answered from what pledge kept, no second dialog.
    let Message::Answer(again) = site.ask(&submit) else { panic!("an answer") };
    assert!(matches!(again.outcome, Outcome::Approved(_)));
}

#[test]
fn a_delegation_the_site_does_not_certify_is_refused_by_the_broker_and_nothing_is_issued() {
    let lab = Lab::stage2();
    let site =
        Site2::new(&lab, std::fs::read_to_string(lab.material.dir.path().join("other-host.pub")).expect("key").trim());
    let link = site.link(&lab, "jan", Arc::default());
    eventually("standing", || link.can_issue());
    lab.rig.dialogs.push(yes());
    let args = Lab::start_args(&["ops"], None, None, None);
    assert_eq!(crate::agents::start(&lab.rig.shared, args).err(), Some(crate::control::Code::BrokerRefused));
}

#[test]
fn a_person_the_broker_does_not_know_by_this_key_never_gets_in_and_pledge_tries_again_later() {
    let lab = Lab::stage2();
    let site = Site2::new(&lab, &delegation_key(&lab));
    let attempts = Arc::new(AtomicUsize::new(0));
    // Signs in as a person whose connection key is another one: the broker refuses the sign-in.
    let link = site.link(&lab, "eva", Arc::clone(&attempts));
    eventually("a second attempt after the pause", || attempts.load(Ordering::SeqCst) >= 2);
    assert!(!link.can_issue());
    assert!(!lab.rig.shared.broker_state.is_blocked());
}

#[test]
fn a_connection_the_broker_cuts_is_made_again_and_signed_in_again() {
    let lab = Lab::stage2();
    let site = Site2::new(&lab, &delegation_key(&lab));
    let attempts = Arc::new(AtomicUsize::new(0));
    let link = site.link(&lab, "jan", Arc::clone(&attempts));
    eventually("ready", || link.can_issue());
    site.cut();
    eventually("not ready after the cut", || !link.can_issue());
    eventually("ready again", || link.can_issue() && attempts.load(Ordering::SeqCst) >= 2);
}

#[test]
fn a_block_by_an_administrator_reaches_pledge_in_the_standing_and_lifting_it_does_too() {
    let (lab, site, _link) = world();
    let stored = site.rt.block_on(site.broker.block_person("jan".into()));
    let _ = stored;
    eventually("blocked in pledge", || lab.rig.shared.broker_state.is_blocked());
    site.rt.block_on(site.broker.unblock_person("jan".into())).expect("unblocked");
    eventually("not blocked in pledge", || !lab.rig.shared.broker_state.is_blocked());
}

#[test]
fn a_withdrawal_is_told_to_the_broker_and_followed_until_the_broker_has_stored_it() {
    let (mut lab, _site, _link) = world();
    let agent = lab.default_agent();
    crate::agents::withdraw(&lab.rig.shared, &agent.id).expect("withdrawn");
    eventually("stored at the broker", || {
        lab.rig.shared.broker_state.withdrawal(&agent.id) == Some(Withdrawal::Stored)
    });
}

#[test]
fn a_broker_whose_certificate_ends_tells_a_connected_pledge_not_ready_once_and_the_connection_stays() {
    let lab = Lab::stage2();
    let site = Site2::new(&lab, &delegation_key(&lab));
    let attempts = Arc::new(AtomicUsize::new(0));
    let link = site.link(&lab, "jan", Arc::clone(&attempts));
    eventually("a standing", || link.can_issue());
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    let state = &lab.rig.shared.broker_state;
    let held = state.certificate_for("confirmed");
    assert!(held.is_some());
    // The broker's own certificate ends (its clock passes the end of it): `not-ready`, once, the connection stays.
    site.clock.0.store(4_200_000_000, Ordering::SeqCst);
    site.rt.block_on(site.broker.sweep());
    eventually("not ready", || !link.can_issue());
    assert!(link.is_ready(), "still signed in on the same connection");
    assert_eq!(lab.rig.record().iter().filter(|e| e["event"] == "broker-not-ready").count(), 1);
    assert_eq!(state.certificate_for("confirmed"), held, "what pledge holds stays");
    lab.rig.dialogs.push(yes());
    assert_eq!(
        crate::agents::start(&lab.rig.shared, Lab::start_args(&[], None, None, None)).err(),
        Some(crate::control::Code::BrokerUnavailable),
        "nothing is issued without a verified standing"
    );
}

#[test]
fn a_pledge_let_in_by_a_broker_that_cannot_vouch_gets_the_standing_later_without_a_sign_in() {
    let lab = Lab::stage2();
    let site = Site2::new(&lab, &delegation_key(&lab));
    // The broker's clock is before its certificate's start: it lets the pledge in and cannot vouch.
    site.clock.0.store(1_560_000_000, Ordering::SeqCst);
    let attempts = Arc::new(AtomicUsize::new(0));
    let link = site.link(&lab, "jan", Arc::clone(&attempts));
    eventually("signed in without a standing", || lab.rig.record().iter().any(|e| e["event"] == "broker-not-ready"));
    assert!(link.is_ready() && !link.can_issue());
    lab.rig.dialogs.push(yes());
    assert_eq!(
        crate::agents::start(&lab.rig.shared, Lab::start_args(&[], None, None, None)).err(),
        Some(crate::control::Code::BrokerUnavailable)
    );
    // Its certificate becomes valid: the standing comes on the same connection.
    site.clock.0.store(crate::approvals_tests::now(), Ordering::SeqCst);
    site.rt.block_on(site.broker.sweep());
    eventually("the standing", || link.can_issue());
    assert_eq!(attempts.load(Ordering::SeqCst), 1, "no new sign-in");
}
