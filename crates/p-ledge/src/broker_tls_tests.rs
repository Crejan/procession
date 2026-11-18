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
use p_age::core::{Core, Settings};
use p_age::crypto::SshCrypto;
use p_age::log::MemoryLog;
use p_age::net::{Broker, Lines, SystemClock, Timeouts, serve_tls};
use p_age::site::Site;
use p_age::tls::server_config;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use serde_json::json;
use tokio::io::AsyncWriteExt;

use crate::approvals_tests::{Lab, yes};
use crate::broker_link::{self, BrokerLink, DynTransport, SessionConfig, TlsTransport};
use crate::broker_state::Withdrawal;

/// A broker serving TLS on a Unix socket, and the way to cut its connections.
struct Site2 {
    rt: tokio::runtime::Runtime,
    broker: Arc<Broker>,
    socket: PathBuf,
    root_pem: String,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

impl Site2 {
    /// `delegation_key` is what the site says jan's delegations are certified by.
    fn new(lab: &Lab, delegation_key: &str) -> Self {
        let dir = lab.material.dir.path();
        // p-age keeps its register in a private directory.
        std::fs::set_permissions(dir, std::os::unix::fs::PermissionsExt::from_mode(0o700)).expect("chmod");
        let line = |name: &str| std::fs::read_to_string(dir.join(name)).expect("key").trim().to_owned();
        let connection = lab.rig.shared.key_with_purpose("connection").expect("connection key").public_line();
        let certificates: Vec<String> = ["confirmed", "automatic"]
            .iter()
            .map(|role| {
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
                line(&format!("{role}-tls-cert.pub"))
            })
            .collect();
        let key = |role: &str| {
            let public = lab.rig.shared.key_with_purpose(role).expect("key").public_line();
            json!({"key": public, "verified_on": "2026-11-10"})
        };
        let site = json!({
            "persons": [{"name": "jan", "enabled": true, "groups": ["ops"], "certificates": certificates,
                         "keys": {"confirmed": key("confirmed"), "automatic": key("automatic"),
                                  "delegation": {"key": delegation_key, "verified_on": "2026-11-10"},
                                  "connection": {"key": connection, "verified_on": "2026-11-10"}}}],
            "hosts": [{"name": "a.example", "key": lab.material.host_line()}],
        });
        let site = Arc::new(Site::from_json(&site.to_string()).expect("site"));
        let state = dir.join("register.json");
        Core::init_state(&state).expect("state");
        let crypto = Arc::new(SshCrypto::new(dir.join("broker")));
        let core = Core::new(
            Arc::clone(&site),
            Settings::default(),
            Core::read_state(&state).expect("read state"),
            Some(state),
            crypto.clone(),
            Box::new(MemoryLog::default()),
        );
        let broker = Broker::new(core, crypto, site, Arc::new(SystemClock), Timeouts::default(), 8);

        let ca_key = KeyPair::generate().expect("key");
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("params");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).expect("ca");
        let server_key = KeyPair::generate().expect("key");
        let server = CertificateParams::new(vec!["broker.test".to_owned()])
            .expect("params")
            .signed_by(&server_key, &Issuer::new(ca_params, &ca_key))
            .expect("server cert");
        let acceptor = tokio_rustls::TlsAcceptor::from(
            server_config(server.pem().as_bytes(), server_key.serialize_pem().as_bytes()).expect("server config"),
        );

        let rt = tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("runtime");
        std::fs::create_dir_all("/tmp/claude").ok();
        let base = if std::path::Path::new("/tmp/claude").is_dir() {
            PathBuf::from("/tmp/claude")
        } else {
            std::env::temp_dir()
        };
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
        Self { rt, broker, socket, root_pem: ca.pem(), tasks }
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
    assert!(lab.rig.record().iter().any(|e| e["event"] == "standing-accepted"));
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
