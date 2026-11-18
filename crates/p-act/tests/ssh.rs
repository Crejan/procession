//! The signatures against a real `ssh-keygen`, with keys made in a temporary
//! directory. Nothing here touches anything outside it, and nothing prompts:
//! keys have no passphrase and no command has a terminal to ask on.

use p_act::broker::{
    ConnectionDocument, DelegationMessage, FromPledge, Signed, Standing, StandingContent, StandingError, ToPledge,
};
use p_act::exchange::{ErrorCode, ExchangeError};
use p_act::rating::{Damage, Disruption, Exposure, Rating};
use p_act::sign::{
    ApprovalCertificate, check_approval_certificate, verify_approval_certificate, verify_approval_certificate_for,
};
use p_act::sign::{
    ApprovalKind, ApprovalTrust, Fingerprint, Namespace, PublicKey, SignError, Signer, agent_certificate,
    is_reserved_namespace, request_person, sign_approval, sign_call, sign_clearance, sign_request, signature_agent,
    signature_certificate, signature_fingerprint, signature_from_base64, signature_person, signature_to_base64,
    verify_approval, verify_call, verify_call_agent, verify_clearance, verify_request,
};
use p_act::sign::{
    certificate_issuer, sign_broker, sign_connection, verify_agent_certificate, verify_broker, verify_connection,
};
use p_act::{Call, CallContent, CallId, Clearance, Document, Request, ServiceId, Timestamp};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;

// `Z`: UTC, not the machine's zone.
const VALID: &str = "20200101Z:20990101Z";
const EXPIRED: &str = "20200101Z:20200102Z";

struct Keys {
    dir: TempDir,
}

impl Keys {
    fn new() -> Keys {
        Keys { dir: tempfile::tempdir().unwrap() }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn keygen(&self, args: &[&str]) {
        let out =
            Command::new("ssh-keygen").args(args).stdin(Stdio::null()).output().expect("these tests need ssh-keygen");
        assert!(out.status.success(), "ssh-keygen {args:?}: {}", String::from_utf8_lossy(&out.stderr));
    }

    /// A new Ed25519 key without passphrase; its private file's path.
    fn key(&self, name: &str) -> PathBuf {
        let path = self.path(name);
        self.keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", path.to_str().unwrap()]);
        path
    }

    /// A new ECDSA P-256 key without passphrase; its private file's path.
    fn ecdsa_key(&self, name: &str) -> PathBuf {
        let path = self.path(name);
        self.keygen(&["-q", "-t", "ecdsa", "-b", "256", "-N", "", "-C", "", "-f", path.to_str().unwrap()]);
        path
    }

    /// A key certified by `ca` for `principals` (comma-separated), valid as `validity`.
    fn certified(&self, name: &str, ca: &Path, principals: &str, validity: &str) -> Signer {
        self.certified_with(name, ca, principals, validity, &[])
    }

    /// As `certified`, issued like pledge does: `-O clear`, then `options`.
    fn certified_with(&self, name: &str, ca: &Path, principals: &str, validity: &str, options: &[&str]) -> Signer {
        let key = self.key(name);
        let pub_file = format!("{}.pub", key.display());
        let mut args =
            vec!["-q", "-s", ca.to_str().unwrap(), "-I", name, "-n", principals, "-V", validity, "-O", "clear"];
        for o in options {
            args.extend(["-O", o]);
        }
        args.push(&pub_file);
        self.keygen(&args);
        Signer::certified(key).unwrap()
    }

    fn public(&self, key: &Path) -> PublicKey {
        PublicKey::read(&PathBuf::from(format!("{}.pub", key.display()))).unwrap()
    }
}

fn call_content(service: &str, host: &str) -> CallContent {
    CallContent {
        id: CallId::parse("3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11").unwrap(),
        deadline: "2026-11-11T15:06:05Z".parse().unwrap(),
        service: ServiceId { host: host.into(), name: service.into() },
        action: "rt procs".into(),
        params: vec!["pid=4711".into()],
        claim: Some("checking why the control loop misses cycles".into()),
    }
}

const INTERNAL: Rating = Rating::new(Exposure::Internal, Damage::None, Disruption::None);

/// Sign `data` in a namespace of the test's choosing, as another document type would.
fn raw_sign(signer_key: &Path, namespace: &str, data: &[u8]) -> String {
    use std::io::Write;
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-n", namespace, "-f"])
        .arg(signer_key)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A child that has already stopped reading (it failed) closes its end: the write then fails with `Broken pipe`,
    // which says nothing; its exit status and standard error do.
    let _ = child.stdin.take().unwrap().write_all(data);
    let out = child.wait_with_output().unwrap();
    // An empty namespace is refused by `ssh-keygen` before it reads a byte ("missing namespace"): no signature, and the
    // write above is a race the child wins under load. Every other namespace must sign.
    assert_eq!(
        out.status.success(),
        !namespace.is_empty(),
        "ssh-keygen -Y sign: {}: {}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn is_rejected<T: std::fmt::Debug>(r: Result<T, SignError>) -> bool {
    matches!(r, Err(SignError::Rejected { .. }))
}

// ---------------------------------------------------------------------------
// The call, under a delegation
// ---------------------------------------------------------------------------

struct Delegation {
    keys: Keys,
    key: PathBuf,
    call: Call,
    sig: String,
}

fn delegation(person: &str) -> Delegation {
    let keys = Keys::new();
    let key = keys.key("delegation");
    let agent = keys.certified("agent", &key, person, VALID);
    let call = Call::compose(&call_content("probe", "a.example")).unwrap();
    let sig = sign_call(&agent, &call).unwrap();
    Delegation { keys, key, call, sig }
}

#[test]
fn a_call_verifies_under_the_delegation_and_names_its_person() {
    let d = delegation("alice");
    assert!(d.sig.starts_with("-----BEGIN SSH SIGNATURE-----\n") && d.sig.ends_with("-----END SSH SIGNATURE-----\n"));
    assert_eq!(verify_call(&d.call, &d.sig, &d.keys.public(&d.key)).unwrap(), "alice");
    assert_eq!(signature_person(&d.sig).unwrap(), "alice");
}

#[test]
fn a_call_is_refused_for_the_wrong_key_changed_bytes_namespace_expiry_and_no_certificate() {
    let d = delegation("alice");
    let delegation_key = d.keys.public(&d.key);

    // Another person's delegation key.
    let other = d.keys.key("other-delegation");
    assert!(is_rejected(verify_call(&d.call, &d.sig, &d.keys.public(&other))));

    // Changed bytes: any other call, and the same call with one byte different.
    let mut changed = call_content("probe", "a.example");
    changed.params = vec!["pid=4712".into()];
    assert!(is_rejected(verify_call(&Call::compose(&changed).unwrap(), &d.sig, &delegation_key)));
    let mut spaced = d.call.as_bytes().to_vec();
    spaced.insert(1, b' ');
    assert!(is_rejected(verify_call(&Call::parse(spaced).unwrap(), &d.sig, &delegation_key)));

    // Another namespace: the agent's key signing the call's bytes as a request, an approval, a clearance.
    for namespace in
        ["request-v1@procession", "approval-v1@procession", "clearance-v1@procession", "call-v2@procession", ""]
    {
        let sig =
            raw_sign(&d.keys.path("agent-cert.pub").with_file_name("agent-cert.pub"), namespace, d.call.as_bytes());
        if sig.is_empty() {
            continue; // ssh-keygen itself refuses an empty namespace
        }
        assert!(is_rejected(verify_call(&d.call, &sig, &delegation_key)), "{namespace}");
    }

    // An expired delegation.
    let expired = d.keys.certified("expired-agent", &d.key, "alice", EXPIRED);
    let sig = sign_call(&expired, &d.call).unwrap();
    assert!(is_rejected(verify_call(&d.call, &sig, &delegation_key)));

    // Signed by a key without a certificate: no person to name.
    let plain = Signer::plain(d.keys.key("loose"));
    let sig = sign_call(&plain, &d.call).unwrap();
    assert!(matches!(verify_call(&d.call, &sig, &delegation_key), Err(SignError::NotCertified)));
    assert!(matches!(Signer::certified(d.keys.path("loose")), Err(SignError::NotCertified)));

    // Garbage in place of a signature.
    for sig in ["", "not a signature", "-----BEGIN SSH SIGNATURE-----\nAAAA\n-----END SSH SIGNATURE-----\n"] {
        assert!(verify_call(&d.call, sig, &delegation_key).is_err(), "{sig:?}");
    }
}

#[test]
fn certified_needs_the_certificate_beside_the_key() {
    let keys = Keys::new();
    let key = keys.key("loose");
    assert!(matches!(Signer::certified(&key), Err(SignError::NotCertified)));
}

#[test]
fn an_agent_certificate_must_name_exactly_one_person() {
    let keys = Keys::new();
    let ca = keys.key("delegation");
    let call = Call::compose(&call_content("probe", "a.example")).unwrap();
    let sig = sign_call(&keys.certified("two", &ca, "alice,bob", VALID), &call).unwrap();
    assert!(matches!(signature_person(&sig), Err(SignError::PrincipalCount { found: 2 })));
    // The call does not verify either: there is no one person to verify under.
    assert!(matches!(verify_call(&call, &sig, &keys.public(&ca)), Err(SignError::PrincipalCount { .. })));
    // A name `ssh-keygen` would read as a pattern is not a person's name.
    let sig = sign_call(&keys.certified("star", &ca, "*", VALID), &call).unwrap();
    assert!(matches!(signature_person(&sig), Err(SignError::BadPrincipal(p)) if p == "*"));
}

#[test]
fn the_certificate_in_a_signature_is_read_without_an_allowed_signers_file() {
    let d = delegation("alice");
    let cert = signature_certificate(&d.sig).unwrap();
    assert_eq!(cert.key_id, "agent");
    assert_eq!(cert.principals, ["alice"]);
    assert_eq!(
        Timestamp::from_unix(i64::try_from(cert.valid_after).unwrap()).unwrap().to_string(),
        "2020-01-01T00:00:00Z"
    );
    assert_eq!(
        Timestamp::from_unix(i64::try_from(cert.valid_before).unwrap()).unwrap().to_string(),
        "2099-01-01T00:00:00Z"
    );
}

// ---------------------------------------------------------------------------
// The request, under a host key's certificate
// ---------------------------------------------------------------------------

struct Host {
    keys: Keys,
    host_key: PathBuf,
    service: Signer,
}

fn host() -> Host {
    let keys = Keys::new();
    let host_key = keys.key("ssh_host_ed25519_key");
    let service = keys.certified("service", &host_key, "probe@a.example", VALID);
    Host { keys, host_key, service }
}

fn request(d: &Delegation, rating: Rating) -> Request {
    Request::compose(&d.call, &d.sig, rating).unwrap()
}

#[test]
fn a_request_verifies_under_its_services_name_on_its_host() {
    let d = delegation("alice");
    let h = host();
    let request = request(&d, INTERNAL);
    let sig = sign_request(&h.service, &request).unwrap();
    verify_request(&request, &sig, &h.keys.public(&h.host_key)).unwrap();
}

#[test]
fn a_request_is_refused_for_another_service_host_key_bytes_namespace_and_expiry() {
    let d = delegation("alice");
    let h = host();
    let host_key = h.keys.public(&h.host_key);
    let request = request(&d, INTERNAL);

    // Signed by another service of the same host, or by the same name on another host.
    for name in ["other@a.example", "probe@b.example", "probe", "*@a.example", "probe@a.example,other@a.example"] {
        let other = h.keys.certified(&format!("svc-{name}").replace(['@', '*', ','], "_"), &h.host_key, name, VALID);
        let sig = sign_request(&other, &request).unwrap();
        assert!(is_rejected(verify_request(&request, &sig, &host_key)) || name.contains(','), "{name}");
    }

    // Certified by another host key.
    let impostor = h.keys.key("other-host");
    let service = h.keys.certified("impostor-service", &impostor, "probe@a.example", VALID);
    assert!(is_rejected(verify_request(&request, &sign_request(&service, &request).unwrap(), &host_key)));

    // A request whose call names a different service than the signer: the name comes from the call inside.
    let other_call = Call::compose(&call_content("probe", "b.example")).unwrap();
    let for_b = Request::compose(&other_call, &d.sig, INTERNAL).unwrap();
    let sig_for_a = sign_request(&h.service, &request).unwrap();
    assert!(is_rejected(verify_request(&for_b, &sig_for_a, &host_key)));

    // Changed bytes: the rating is part of what is signed.
    let sig = sign_request(&h.service, &request).unwrap();
    let rated_worse = self::request(&d, Rating::WORST);
    assert!(is_rejected(verify_request(&rated_worse, &sig, &host_key)));

    // Another namespace.
    let as_approval = raw_sign(&h.keys.path("service-cert.pub"), "approval-v1@procession", request.as_bytes());
    assert!(is_rejected(verify_request(&request, &as_approval, &host_key)));

    // Expired.
    let expired = h.keys.certified("expired-service", &h.host_key, "probe@a.example", EXPIRED);
    assert!(is_rejected(verify_request(&request, &sign_request(&expired, &request).unwrap(), &host_key)));
}

// ---------------------------------------------------------------------------
// The approval and the clearance, under a site CA
// ---------------------------------------------------------------------------

struct Site {
    keys: Keys,
    ca: PathBuf,
    confirmed: Signer,
    automatic: Signer,
    broker: Signer,
}

fn site() -> Site {
    let keys = Keys::new();
    let ca = keys.key("site-ca");
    let confirmed = keys.certified("alice-confirmed", &ca, "alice:confirmed", VALID);
    let automatic = keys.certified("alice-automatic", &ca, "alice:automatic", VALID);
    let broker = keys.certified("broker", &ca, "broker", VALID);
    Site { keys, ca, confirmed, automatic, broker }
}

#[test]
fn an_approval_verifies_and_says_which_key_signed() {
    let d = delegation("alice");
    let s = site();
    let ca = s.keys.public(&s.ca);
    let trust = ApprovalTrust::SiteCa(&ca);
    let request = request(&d, INTERNAL);
    assert_eq!(request_person(&request).unwrap(), "alice");

    let confirmed = sign_approval(&s.confirmed, &request).unwrap();
    assert_eq!(verify_approval(&request, &confirmed, trust).unwrap(), ApprovalKind::Confirmed);
    let automatic = sign_approval(&s.automatic, &request).unwrap();
    assert_eq!(verify_approval(&request, &automatic, trust).unwrap(), ApprovalKind::Automatic);
}

#[test]
fn an_automatic_approval_is_not_accepted_at_the_top_of_a_scale() {
    let d = delegation("alice");
    let s = site();
    let ca = s.keys.public(&s.ca);
    for top in [
        Rating::new(Exposure::Secret, Damage::None, Disruption::None),
        Rating::new(Exposure::Open, Damage::Lasting, Disruption::None),
        Rating::new(Exposure::Open, Damage::None, Disruption::Outage),
        Rating::WORST,
    ] {
        let request = request(&d, top);
        let automatic = sign_approval(&s.automatic, &request).unwrap();
        assert!(
            matches!(
                verify_approval(&request, &automatic, ApprovalTrust::SiteCa(&ca)),
                Err(SignError::AutomaticNotAcceptable)
            ),
            "{top:?}"
        );
        let confirmed = sign_approval(&s.confirmed, &request).unwrap();
        assert_eq!(
            verify_approval(&request, &confirmed, ApprovalTrust::SiteCa(&ca)).unwrap(),
            ApprovalKind::Confirmed,
            "{top:?}"
        );
    }
}

#[test]
fn an_approval_is_refused_for_another_person_the_broker_other_requests_namespaces_and_expiry() {
    let d = delegation("alice");
    let s = site();
    let ca = s.keys.public(&s.ca);
    let trust = ApprovalTrust::SiteCa(&ca);
    let request = request(&d, INTERNAL);

    // Another person's approval key: the name is not the call's person.
    let bob = s.keys.certified("bob-confirmed", &s.ca, "bob:confirmed", VALID);
    assert!(is_rejected(verify_approval(&request, &sign_approval(&bob, &request).unwrap(), trust)));

    // A person certified without the ending, or with the wrong one.
    for name in ["alice", "alice:confirmed-ish", "alice:other", ":confirmed"] {
        let odd = s.keys.certified(&format!("odd-{name}").replace(':', "_"), &s.ca, name, VALID);
        assert!(is_rejected(verify_approval(&request, &sign_approval(&odd, &request).unwrap(), trust)), "{name}");
    }

    // The broker's key and a person's key are not each other's.
    assert!(is_rejected(verify_approval(&request, &sign_approval(&s.broker, &request).unwrap(), trust)));
    let clearance = Clearance::compose(request.hash(), Timestamp::from_unix(1_794_409_445).unwrap()).unwrap();
    assert!(is_rejected(verify_clearance(&clearance, &sign_clearance(&s.confirmed, &clearance).unwrap(), &ca)));
    assert!(is_rejected(verify_clearance(&clearance, &sign_clearance(&s.automatic, &clearance).unwrap(), &ca)));

    // Over another request, over a changed one.
    let approval = sign_approval(&s.confirmed, &request).unwrap();
    let other = self::request(&d, Rating::new(Exposure::Open, Damage::None, Disruption::None));
    assert!(is_rejected(verify_approval(&other, &approval, trust)));

    // Another namespace: the same key signing the request as a clearance, or as a call.
    for namespace in ["clearance-v1@procession", "call-v1@procession", "request-v1@procession"] {
        let sig = raw_sign(&s.keys.path("alice-confirmed-cert.pub"), namespace, request.as_bytes());
        assert!(is_rejected(verify_approval(&request, &sig, trust)), "{namespace}");
    }

    // Another CA, and an expired certificate.
    let other_ca = s.keys.key("other-ca");
    assert!(is_rejected(verify_approval(&request, &approval, ApprovalTrust::SiteCa(&s.keys.public(&other_ca)))));
    let expired = s.keys.certified("alice-expired", &s.ca, "alice:confirmed", EXPIRED);
    assert!(is_rejected(verify_approval(&request, &sign_approval(&expired, &request).unwrap(), trust)));

    // The call's person comes from the call's signature: a request whose call was signed for bob
    // is approved only by bob.
    let for_bob = {
        let bobs_agent = delegation("bob");
        Request::compose(&bobs_agent.call, &bobs_agent.sig, INTERNAL).unwrap()
    };
    assert!(is_rejected(verify_approval(&for_bob, &sign_approval(&s.confirmed, &for_bob).unwrap(), trust)));
    assert_eq!(
        verify_approval(&for_bob, &sign_approval(&bob, &for_bob).unwrap(), trust).unwrap(),
        ApprovalKind::Confirmed
    );
}

#[test]
fn in_the_first_stage_the_persons_two_keys_are_listed_directly() {
    let d = delegation("alice");
    let keys = Keys::new();
    let (confirmed, automatic) = (keys.key("confirmed"), keys.key("automatic"));
    let (confirmed_pub, automatic_pub) = (keys.public(&confirmed), keys.public(&automatic));
    let trust = ApprovalTrust::PersonKeys { person: "alice", confirmed: &confirmed_pub, automatic: &automatic_pub };
    let request = request(&d, INTERNAL);

    let confirmed_sig = sign_approval(&Signer::plain(&confirmed), &request).unwrap();
    assert_eq!(verify_approval(&request, &confirmed_sig, trust).unwrap(), ApprovalKind::Confirmed);
    let automatic_sig = sign_approval(&Signer::plain(&automatic), &request).unwrap();
    assert_eq!(verify_approval(&request, &automatic_sig, trust).unwrap(), ApprovalKind::Automatic);

    // The two keys are told apart by the name they verify under: the automatic key does not
    // pass for the confirmed one, and is not accepted at the top of a scale.
    let worst = self::request(&d, Rating::WORST);
    let on_worst = sign_approval(&Signer::plain(&automatic), &worst).unwrap();
    assert!(matches!(verify_approval(&worst, &on_worst, trust), Err(SignError::AutomaticNotAcceptable)));

    // A stranger's key.
    let stranger = Signer::plain(keys.key("stranger"));
    assert!(is_rejected(verify_approval(&request, &sign_approval(&stranger, &request).unwrap(), trust)));
}

#[test]
fn person_keys_say_whose_they_are_and_refuse_another_persons_request() {
    // Two persons' delegations: one set of approval keys, alice's, and a request for each person's agent.
    let alices = delegation("alice");
    let bobs = delegation("bob");
    let keys = Keys::new();
    let (confirmed, automatic) = (keys.key("confirmed"), keys.key("automatic"));
    let (confirmed_pub, automatic_pub) = (keys.public(&confirmed), keys.public(&automatic));
    let for_alice = request(&alices, INTERNAL);
    let for_bob = request(&bobs, INTERNAL);
    let sign = |key: &Path, r: &Request| sign_approval(&Signer::plain(key), r).unwrap();

    let alice_trust =
        ApprovalTrust::PersonKeys { person: "alice", confirmed: &confirmed_pub, automatic: &automatic_pub };
    for (key, kind) in [(&confirmed, ApprovalKind::Confirmed), (&automatic, ApprovalKind::Automatic)] {
        assert_eq!(verify_approval(&for_alice, &sign(key, &for_alice), alice_trust).unwrap(), kind);
        // The right keys, a validly signed approval of exactly this request, but the call is bob's.
        let sig = sign(key, &for_bob);
        assert!(matches!(verify_approval(&for_bob, &sig, alice_trust), Err(SignError::ApprovalForAnotherPerson)));
    }
    // The same keys declared as bob's approve bob's request and refuse alice's.
    let bob_trust = ApprovalTrust::PersonKeys { person: "bob", confirmed: &confirmed_pub, automatic: &automatic_pub };
    assert_eq!(verify_approval(&for_bob, &sign(&confirmed, &for_bob), bob_trust).unwrap(), ApprovalKind::Confirmed);
    assert!(matches!(
        verify_approval(&for_alice, &sign(&confirmed, &for_alice), bob_trust),
        Err(SignError::ApprovalForAnotherPerson)
    ));
    // The person is checked before the signature: a signature that would not verify either way names the person's mismatch.
    assert!(matches!(verify_approval(&for_bob, "garbage", alice_trust), Err(SignError::ApprovalForAnotherPerson)));
    // A trust that names no usable person is refused, not read as a pattern.
    for bad in ["", "*", "alice,bob", "a b", "alice:confirmed"] {
        let trust = ApprovalTrust::PersonKeys { person: bad, confirmed: &confirmed_pub, automatic: &automatic_pub };
        assert!(
            matches!(
                verify_approval(&for_alice, &sign(&confirmed, &for_alice), trust),
                Err(SignError::BadPrincipal(_))
            ),
            "{bad:?}"
        );
    }
    // The site CA's trust names no person: the person is the call's and the certificate's name must agree, as before.
    let site = site();
    let ca = site.keys.public(&site.ca);
    let bob = site.keys.certified("bob-confirmed", &site.ca, "bob:confirmed", VALID);
    assert!(is_rejected(verify_approval(
        &for_alice,
        &sign_approval(&bob, &for_alice).unwrap(),
        ApprovalTrust::SiteCa(&ca)
    )));
    assert!(verify_approval(&for_bob, &sign_approval(&bob, &for_bob).unwrap(), ApprovalTrust::SiteCa(&ca)).is_ok());
}

#[test]
fn a_clearance_verifies_as_the_broker_and_nothing_else() {
    let d = delegation("alice");
    let s = site();
    let ca = s.keys.public(&s.ca);
    let request = request(&d, INTERNAL);
    let clearance = Clearance::compose(request.hash(), Timestamp::from_unix(1_794_409_481).unwrap()).unwrap();
    let sig = sign_clearance(&s.broker, &clearance).unwrap();
    verify_clearance(&clearance, &sig, &ca).unwrap();
    assert!(clearance.covers(&request));

    // Changed bytes.
    let later = Clearance::compose(request.hash(), Timestamp::from_unix(1_794_409_482).unwrap()).unwrap();
    assert!(is_rejected(verify_clearance(&later, &sig, &ca)));
    // Another CA.
    assert!(is_rejected(verify_clearance(&clearance, &sig, &s.keys.public(&s.keys.key("other-ca")))));
    // An approval signature is not a clearance, nor the reverse.
    let approval = sign_approval(&s.broker, &request).unwrap();
    assert!(is_rejected(verify_clearance(&clearance, &approval, &ca)));
    let trust = ApprovalTrust::SiteCa(&ca);
    assert!(is_rejected(verify_approval(&request, &sig, trust)));
    // A key certified under another name is not the broker.
    let not_broker = s.keys.certified("not-broker", &s.ca, "brokers", VALID);
    assert!(is_rejected(verify_clearance(&clearance, &sign_clearance(&not_broker, &clearance).unwrap(), &ca)));
    // Expired.
    let expired = s.keys.certified("old-broker", &s.ca, "broker", EXPIRED);
    assert!(is_rejected(verify_clearance(&clearance, &sign_clearance(&expired, &clearance).unwrap(), &ca)));
}

// ---------------------------------------------------------------------------
// The whole exchange, and the keys
// ---------------------------------------------------------------------------

#[test]
fn one_exchange_from_call_to_clearance() {
    let delegation_keys = Keys::new();
    let delegation_key = delegation_keys.key("delegation");
    let agent = delegation_keys.certified("agent", &delegation_key, "alice", VALID);
    let host = host();
    let site = site();
    let ca = site.keys.public(&site.ca);

    // The agent calls.
    let call = Call::compose(&call_content("probe", "a.example")).unwrap();
    let call_sig = sign_call(&agent, &call).unwrap();

    // The service receives call bytes and signature, checks them, and writes a request around them.
    let received = Call::parse(call.as_bytes()).unwrap();
    verify_call(&received, &call_sig, &delegation_keys.public(&delegation_key)).unwrap();
    let request = Request::compose(&received, &call_sig, INTERNAL).unwrap();
    let request_sig = sign_request(&host.service, &request).unwrap();

    // The broker and pledge parse what the service sent, and verify all of it.
    let at_pledge = Request::parse(request.as_bytes()).unwrap();
    verify_request(&at_pledge, &request_sig, &host.keys.public(&host.host_key)).unwrap();
    verify_call(at_pledge.call(), at_pledge.call_sig(), &delegation_keys.public(&delegation_key)).unwrap();
    assert_eq!(at_pledge.call().as_bytes(), call.as_bytes());

    // Pledge approves, the broker clears, the service accepts both.
    let approval = sign_approval(&site.automatic, &at_pledge).unwrap();
    let clearance = Clearance::compose(at_pledge.hash(), Timestamp::now().unwrap()).unwrap();
    let clearance_sig = sign_clearance(&site.broker, &clearance).unwrap();
    assert_eq!(verify_approval(&request, &approval, ApprovalTrust::SiteCa(&ca)).unwrap(), ApprovalKind::Automatic);
    verify_clearance(&Clearance::parse(clearance.as_bytes()).unwrap(), &clearance_sig, &ca).unwrap();
    assert!(clearance.covers(&request));
}

#[test]
fn public_keys_are_plain_lines_and_nothing_else() {
    let keys = Keys::new();
    let key = keys.key("k");
    let line = std::fs::read_to_string(format!("{}.pub", key.display())).unwrap();
    let parsed = PublicKey::parse(&format!("{} with a comment\n", line.trim_end())).unwrap();
    assert_eq!(parsed, keys.public(&key));
    assert_eq!(parsed.to_string().split(' ').count(), 2, "no comment");

    let parts: Vec<&str> = line.split_whitespace().collect();
    for bad in [
        String::new(),
        "ssh-ed25519".into(),
        format!("ssh-ed25519 !!!{}", parts[1]),
        format!("ssh-rsa {}", parts[1]),                         // type and blob disagree
        format!("cert-authority {} {}", parts[0], parts[1]),     // options in front
        format!("{}\nroot {} {}", parts[0], parts[0], parts[1]), // a second line is not a comment
    ] {
        assert!(PublicKey::parse(&bad).is_err(), "{bad:?}");
    }

    // A certificate is not an anchor.
    let ca = keys.key("ca");
    let _ = keys.certified("subject", &ca, "alice", VALID);
    assert!(PublicKey::read(&keys.path("subject-cert.pub")).is_err());
}

#[test]
fn ssh_keygen_is_not_asked_anything() {
    // A key with a passphrase cannot be used without a terminal: it fails, it does not hang.
    let keys = Keys::new();
    let key = keys.path("locked");
    keys.keygen(&["-q", "-t", "ed25519", "-N", "secret", "-f", key.to_str().unwrap()]);
    let call = Call::compose(&call_content("probe", "a.example")).unwrap();
    assert!(sign_call(&Signer::plain(&key), &call).is_err());
}

// ---------------------------------------------------------------------------
// ECDSA P-256: the Secure Enclave's key type, here with keys in files
// ---------------------------------------------------------------------------

impl Keys {
    fn certify(&self, key: &Path, ca: &Path, id: &str, principals: &str) -> Signer {
        let pub_file = format!("{}.pub", key.display());
        self.keygen(&[
            "-q",
            "-s",
            ca.to_str().unwrap(),
            "-I",
            id,
            "-n",
            principals,
            "-V",
            VALID,
            "-O",
            "clear",
            &pub_file,
        ]);
        Signer::certified(key).unwrap()
    }
}

#[test]
fn an_ed25519_agent_under_a_p256_delegation_key() {
    let keys = Keys::new();
    let delegation = keys.ecdsa_key("delegation");
    let agent = keys.certified("agent", &delegation, "alice", VALID);
    let call = Call::compose(&call_content("probe", "a.example")).unwrap();
    let sig = sign_call(&agent, &call).unwrap();
    assert_eq!(verify_call(&call, &sig, &keys.public(&delegation)).unwrap(), "alice");
    assert_eq!(signature_person(&sig).unwrap(), "alice");
    let cert = signature_certificate(&sig).unwrap();
    assert_eq!((cert.key_id.as_str(), cert.principals.as_slice()), ("agent", ["alice".to_owned()].as_slice()));
    // The wrong P-256 key, and another call, are refused.
    assert!(is_rejected(verify_call(&call, &sig, &keys.public(&keys.ecdsa_key("other")))));
    let mut changed = call_content("probe", "a.example");
    changed.action = "rt other".into();
    assert!(is_rejected(verify_call(&Call::compose(&changed).unwrap(), &sig, &keys.public(&delegation))));
}

#[test]
fn an_agent_certificate_for_a_p256_key_is_refused_everywhere() {
    let keys = Keys::new();
    let ca = keys.ecdsa_key("ca");
    let agent_key = keys.ecdsa_key("agent");
    let agent = keys.certify(&agent_key, &ca, "agent", "alice");
    let call = Call::compose(&call_content("probe", "a.example")).unwrap();
    let sig = sign_call(&agent, &call).unwrap();
    // An agent's key is Ed25519, always: every function that reads an agent's certificate refuses this one,
    // with an error that names the type.
    let named = |e: SignError| matches!(e, SignError::AgentKeyNotEd25519(t) if t == "ecdsa-sha2-nistp256");
    assert!(named(verify_call(&call, &sig, &keys.public(&ca)).unwrap_err()));
    assert!(named(verify_call_agent(&call, &sig, &keys.public(&ca)).unwrap_err()));
    assert!(named(signature_agent(&sig).unwrap_err()));
    assert!(named(signature_person(&sig).unwrap_err()));
    let request = request(&delegation("alice"), INTERNAL);
    let on_p256 = Request::compose(&call, &sig, INTERNAL).unwrap();
    assert!(named(request_person(&on_p256).unwrap_err()));
    assert!(request_person(&request).is_ok());
    // The raw reading, which judges nothing, still shows it.
    let cert = signature_certificate(&sig).unwrap();
    assert_eq!((cert.valid_before, cert.key_type.as_str(), cert.cert_type), (4_070_908_800, "ecdsa-sha2-nistp256", 1));
}

#[test]
fn approvals_by_p256_keys_under_ed25519_and_p256_site_cas() {
    let d = delegation("alice");
    let keys = Keys::new();
    let request = request(&d, INTERNAL);
    assert_eq!(request_person(&request).unwrap(), "alice");
    for (label, ca) in [("ed25519-ca", keys.key("ca-ed")), ("p256-ca", keys.ecdsa_key("ca-p256"))] {
        let ca_pub = keys.public(&ca);
        let trust = ApprovalTrust::SiteCa(&ca_pub);
        let confirmed_key = keys.ecdsa_key(&format!("confirmed-{label}"));
        let automatic_key = keys.ecdsa_key(&format!("automatic-{label}"));
        let confirmed = keys.certify(&confirmed_key, &ca, "c", "alice:confirmed");
        let automatic = keys.certify(&automatic_key, &ca, "a", "alice:automatic");

        let sig = sign_approval(&confirmed, &request).unwrap();
        assert_eq!(verify_approval(&request, &sig, trust).unwrap(), ApprovalKind::Confirmed, "{label}");
        let sig = sign_approval(&automatic, &request).unwrap();
        assert_eq!(verify_approval(&request, &sig, trust).unwrap(), ApprovalKind::Automatic, "{label}");
        // The certificate in the approval names the person's key use, and is readable.
        assert_eq!(signature_certificate(&sig).unwrap().principals, ["alice:automatic"]);
        assert!(signature_person(&sig).is_err(), "a name with a ':' is not a person's name");

        // Refusals as before: the top of a scale, another CA, another request.
        let worst = self::request(&d, Rating::WORST);
        let sig = sign_approval(&automatic, &worst).unwrap();
        assert!(matches!(verify_approval(&worst, &sig, trust), Err(SignError::AutomaticNotAcceptable)), "{label}");
        let other_ca = keys.public(&keys.ecdsa_key(&format!("elsewhere-{label}")));
        let sig = sign_approval(&confirmed, &request).unwrap();
        assert!(is_rejected(verify_approval(&request, &sig, ApprovalTrust::SiteCa(&other_ca))), "{label}");
        assert!(is_rejected(verify_approval(&worst, &sig, trust)), "{label}");
    }
}

#[test]
fn a_p256_broker_and_plain_p256_anchors() {
    let d = delegation("alice");
    let keys = Keys::new();
    let ca = keys.ecdsa_key("ca");
    let broker = keys.certify(&keys.ecdsa_key("broker"), &ca, "broker", "broker");
    let request = request(&d, INTERNAL);
    let clearance = Clearance::compose(request.hash(), Timestamp::from_unix(1_794_409_481).unwrap()).unwrap();
    let sig = sign_clearance(&broker, &clearance).unwrap();
    verify_clearance(&clearance, &sig, &keys.public(&ca)).unwrap();

    // Stage 1: plain P-256 approval keys listed directly.
    let (c, a) = (keys.ecdsa_key("c"), keys.ecdsa_key("a"));
    let (c_pub, a_pub) = (keys.public(&c), keys.public(&a));
    let trust = ApprovalTrust::PersonKeys { person: "alice", confirmed: &c_pub, automatic: &a_pub };
    let sig = sign_approval(&Signer::plain(&c), &request).unwrap();
    assert_eq!(verify_approval(&request, &sig, trust).unwrap(), ApprovalKind::Confirmed);
    let sig = sign_approval(&Signer::plain(&a), &request).unwrap();
    assert_eq!(verify_approval(&request, &sig, trust).unwrap(), ApprovalKind::Automatic);
}

#[test]
fn other_key_types_are_refused_with_their_own_error() {
    let keys = Keys::new();
    let rsa = keys.path("rsa");
    keys.keygen(&["-q", "-t", "rsa", "-b", "2048", "-N", "", "-C", "", "-f", rsa.to_str().unwrap()]);
    let line = std::fs::read_to_string(format!("{}.pub", rsa.display())).unwrap();
    assert!(matches!(PublicKey::parse(&line), Err(SignError::UnsupportedKeyType(t)) if t == "ssh-rsa"));
    let p384 = keys.path("p384");
    keys.keygen(&["-q", "-t", "ecdsa", "-b", "384", "-N", "", "-C", "", "-f", p384.to_str().unwrap()]);
    let line = std::fs::read_to_string(format!("{}.pub", p384.display())).unwrap();
    assert!(matches!(PublicKey::parse(&line), Err(SignError::UnsupportedKeyType(t)) if t == "ecdsa-sha2-nistp384"));
    assert!(
        PublicKey::parse(&std::fs::read_to_string(format!("{}.pub", keys.ecdsa_key("p256").display())).unwrap())
            .is_ok()
    );

    // A certificate whose subject key is RSA is refused when read, not mis-parsed.
    let ca = keys.key("ca");
    let agent = keys.certify(&rsa, &ca, "agent", "alice");
    let call = Call::compose(&call_content("probe", "a.example")).unwrap();
    let sig = sign_call(&agent, &call).unwrap();
    assert!(
        matches!(signature_person(&sig), Err(SignError::UnsupportedKeyType(t)) if t == "ssh-rsa-cert-v01@openssh.com")
    );
}

// ---------------------------------------------------------------------------
// The agent's certificate (formats section 3.1)
// ---------------------------------------------------------------------------

fn agent_sig(keys: &Keys, ca: &Path, principals: &str, options: &[&str]) -> (String, Call) {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let agent = keys.certified_with(&format!("agent-{n}"), ca, principals, VALID, options);
    let call = Call::compose(&call_content("probe", "a.example")).unwrap();
    (sign_call(&agent, &call).unwrap(), call)
}

#[test]
fn the_groups_are_read_beside_the_person() {
    let keys = Keys::new();
    for (label, ca) in [("ed25519", keys.key("ca")), ("p256", keys.ecdsa_key("ca-p256"))] {
        let (sig, call) = agent_sig(&keys, &ca, "alice", &["extension:groups@procession=admins,diag-readers"]);
        let agent = signature_agent(&sig).unwrap();
        assert_eq!(agent.person, "alice", "{label}");
        assert_eq!(agent.groups, ["admins", "diag-readers"], "{label}");
        assert!(agent.key_id.starts_with("agent-"));
        let verified = verify_call_agent(&call, &sig, &keys.public(&ca)).unwrap();
        assert_eq!(verified, agent);
        // The service's function gives the person only.
        assert_eq!(verify_call(&call, &sig, &keys.public(&ca)).unwrap(), "alice");
        assert_eq!(signature_person(&sig).unwrap(), "alice");
        // One group is a list of one.
        let (sig, _) = agent_sig(&keys, &ca, "alice", &["extension:groups@procession=admins"]);
        assert_eq!(signature_agent(&sig).unwrap().groups, ["admins"]);
    }
}

#[test]
fn no_extension_means_no_groups() {
    let keys = Keys::new();
    let ca = keys.key("ca");
    let (sig, call) = agent_sig(&keys, &ca, "alice", &[]);
    let agent = verify_call_agent(&call, &sig, &keys.public(&ca)).unwrap();
    assert!(agent.groups.is_empty());
    let cert = signature_certificate(&sig).unwrap();
    assert!(cert.extensions.is_empty() && cert.critical_options.is_empty());
}

#[test]
fn bad_groups_are_refused() {
    let keys = Keys::new();
    let ca = keys.key("ca");
    for (value, why) in [
        ("b,a", "not sorted"),
        ("a,a", "a duplicate"),
        ("a,,b", "an empty name"),
        (",a", "an empty name"),
        ("a,", "an empty name"),
        ("", "an empty name"),
        ("a, b", "a space in a name"),
        ("a,B", "not sorted"),
    ] {
        let (sig, call) = agent_sig(&keys, &ca, "alice", &[&format!("extension:groups@procession={value}")]);
        assert!(
            matches!(signature_agent(&sig), Err(SignError::BadGroups(w)) if w == why),
            "{value:?}: {:?}",
            signature_agent(&sig)
        );
        assert!(matches!(verify_call(&call, &sig, &keys.public(&ca)), Err(SignError::BadGroups(_))), "{value:?}");
        assert!(signature_person(&sig).is_err(), "{value:?}");
    }
}

#[test]
fn other_extensions_and_critical_options_are_refused() {
    let keys = Keys::new();
    let ca = keys.key("ca");
    // Issued without `-O clear`: ssh-keygen's default login extensions are in it.
    let agent = {
        let key = keys.key("login-agent");
        keys.keygen(&[
            "-q",
            "-s",
            ca.to_str().unwrap(),
            "-I",
            "x",
            "-n",
            "alice",
            "-V",
            VALID,
            &format!("{}.pub", key.display()),
        ]);
        Signer::certified(key).unwrap()
    };
    let call = Call::compose(&call_content("probe", "a.example")).unwrap();
    let sig = sign_call(&agent, &call).unwrap();
    assert!(matches!(signature_agent(&sig), Err(SignError::UnknownExtension(e)) if e.starts_with("permit-")));
    assert!(matches!(verify_call(&call, &sig, &keys.public(&ca)), Err(SignError::UnknownExtension(_))));
    // The raw reading still shows them.
    assert!(signature_certificate(&sig).unwrap().extensions.iter().any(|(n, _)| n == "permit-pty"));

    // An unknown extension of our own namespace, next to the groups.
    let (sig, _) = agent_sig(&keys, &ca, "alice", &["extension:groups@procession=a", "extension:other@procession=1"]);
    assert!(matches!(signature_agent(&sig), Err(SignError::UnknownExtension(e)) if e == "other@procession"));

    // A critical option.
    for option in ["force-command=/bin/true", "source-address=10.0.0.0/8"] {
        let (sig, call) = agent_sig(&keys, &ca, "alice", &["extension:groups@procession=a", option]);
        let name = option.split('=').next().unwrap();
        assert!(matches!(signature_agent(&sig), Err(SignError::CriticalOption(n)) if n == name), "{option}");
        assert!(matches!(verify_call(&call, &sig, &keys.public(&ca)), Err(SignError::CriticalOption(_))), "{option}");
    }
}

#[test]
fn a_person_is_at_most_64_characters() {
    let keys = Keys::new();
    let ca = keys.key("ca");
    let (sig, _) = agent_sig(&keys, &ca, &"a".repeat(64), &[]);
    assert_eq!(signature_person(&sig).unwrap(), "a".repeat(64));
    let (sig, _) = agent_sig(&keys, &ca, &"a".repeat(65), &[]);
    assert!(matches!(signature_person(&sig), Err(SignError::BadPrincipal(_))));
}

#[test]
fn an_rsa_issuer_or_host_key_is_refused_with_its_type_named() {
    let keys = Keys::new();
    let rsa = keys.path("rsa");
    keys.keygen(&["-q", "-t", "rsa", "-b", "2048", "-N", "", "-C", "", "-f", rsa.to_str().unwrap()]);

    // An RSA issuer of an Ed25519 key: the certificate says so, and is refused.
    let (sig, _) = agent_sig(&keys, &rsa, "alice", &[]);
    assert!(matches!(signature_agent(&sig), Err(SignError::UnsupportedKeyType(t)) if t == "ssh-rsa"));
    assert!(matches!(signature_certificate(&sig), Err(SignError::UnsupportedKeyType(t)) if t == "ssh-rsa"));

    // An RSA host key: not a `PublicKey`, so no request verifies under it.
    let line = std::fs::read_to_string(format!("{}.pub", rsa.display())).unwrap();
    assert!(matches!(PublicKey::parse(&line), Err(SignError::UnsupportedKeyType(t)) if t == "ssh-rsa"));
    let d = delegation("alice");
    let service = keys.certified("service", &rsa, "probe@a.example", VALID);
    let request = request(&d, INTERNAL);
    let sig = sign_request(&service, &request).unwrap();
    assert!(matches!(signature_certificate(&sig), Err(SignError::UnsupportedKeyType(t)) if t == "ssh-rsa"));
}

#[test]
fn signatures_travel_as_base64_of_their_armour() {
    let d = delegation("alice");
    let encoded = signature_to_base64(&d.sig);
    assert!(!encoded.contains('\n') && encoded.starts_with("LS0tLS1CRUdJTiBTU0ggU0lHTkFUVVJFLS0tLS0K"));
    assert_eq!(signature_from_base64(&encoded).unwrap(), d.sig);
    for bad in ["", "!!!!", encoded.trim_end_matches('='), &signature_to_base64("not armour")] {
        if bad == encoded.trim_end_matches('=') && !encoded.ends_with('=') {
            continue;
        }
        assert!(matches!(signature_from_base64(bad), Err(SignError::MalformedSignature)), "{bad:?}");
    }
    // A request carries it so, and gives the armoured text back, which still verifies.
    let request = request(&d, INTERNAL);
    let parsed = Request::parse(request.as_bytes()).unwrap();
    assert_eq!(parsed.call_sig(), d.sig);
    verify_call(parsed.call(), parsed.call_sig(), &d.keys.public(&d.key)).unwrap();
}

// ---------------------------------------------------------------------------
// The site CA's two lines (formats section 7)
// ---------------------------------------------------------------------------

#[test]
fn the_site_ca_lines_accept_exactly_the_three_names() {
    let d = delegation("alice");
    let keys = Keys::new();
    let request = request(&d, INTERNAL);
    let clearance = Clearance::compose(request.hash(), Timestamp::from_unix(1_794_409_481).unwrap()).unwrap();
    for (label, ca) in [("ed25519", keys.key("ca")), ("p256", keys.ecdsa_key("ca-p256"))] {
        let ca_pub = keys.public(&ca);
        let trust = ApprovalTrust::SiteCa(&ca_pub);
        let count = std::cell::Cell::new(0);
        let named = |name: &str| {
            count.set(count.get() + 1);
            keys.certified(&format!("{label}-{}", count.get()), &ca, name, VALID)
        };

        // The three names that verify, each only where it belongs.
        assert_eq!(
            verify_approval(&request, &sign_approval(&named("alice:confirmed"), &request).unwrap(), trust).unwrap(),
            ApprovalKind::Confirmed
        );
        assert_eq!(
            verify_approval(&request, &sign_approval(&named("alice:automatic"), &request).unwrap(), trust).unwrap(),
            ApprovalKind::Automatic
        );
        let broker = named("broker");
        verify_clearance(&clearance, &sign_clearance(&broker, &clearance).unwrap(), &ca_pub).unwrap();

        // Any other name verifies nowhere.
        for other in [
            "alice",
            "alice:other",
            "alice:",
            ":confirmed",
            "alice:confirmed:automatic",
            "broker:confirmed",
            "alicé:confirmed",
            "bob:confirmed",
        ] {
            let signer = named(other);
            assert!(
                is_rejected(verify_approval(&request, &sign_approval(&signer, &request).unwrap(), trust)),
                "{label} approval {other}"
            );
            assert!(
                is_rejected(verify_clearance(&clearance, &sign_clearance(&signer, &clearance).unwrap(), &ca_pub)),
                "{label} clearance {other}"
            );
        }
        // `broker` is not a person, and a person is not the broker.
        assert!(is_rejected(verify_approval(&request, &sign_approval(&broker, &request).unwrap(), trust)));
        for person in ["alice:confirmed", "alice:automatic"] {
            let signer = named(person);
            assert!(
                is_rejected(verify_clearance(&clearance, &sign_clearance(&signer, &clearance).unwrap(), &ca_pub)),
                "{person}"
            );
        }
    }
}

#[test]
fn the_site_ca_lines_as_written_are_accepted_by_ssh_keygen_itself() {
    // The two lines of the formats document, verbatim, in one file, checked with ssh-keygen directly.
    let keys = Keys::new();
    let ca = keys.key("ca");
    let ca_pub = keys.public(&ca);
    let allowed = keys.path("allowed");
    std::fs::write(
        &allowed,
        format!(
            "*:confirmed,*:automatic cert-authority,namespaces=\"approval-v1@procession\" {ca_pub}\nbroker cert-authority,namespaces=\"clearance-v1@procession\" {ca_pub}\n"
        ),
    )
    .unwrap();
    keys.certified("c", &ca, "bob:confirmed", VALID);
    keys.certified("a", &ca, "bob:automatic", VALID);
    keys.certified("b", &ca, "broker", VALID);
    let data = b"data";
    for (key, namespace, id, ok) in [
        ("c", "approval-v1@procession", "bob:confirmed", true),
        ("a", "approval-v1@procession", "bob:automatic", true),
        ("b", "clearance-v1@procession", "broker", true),
        ("c", "approval-v1@procession", "bob:automatic", false),
        ("a", "approval-v1@procession", "bob:confirmed", false),
        ("c", "approval-v1@procession", "bob", false),
        ("b", "approval-v1@procession", "broker", false),
        ("c", "clearance-v1@procession", "bob:confirmed", false),
        ("c", "clearance-v1@procession", "broker", false),
        ("b", "approval-v1@procession", "bob:confirmed", false),
    ] {
        let sig = raw_sign(&keys.path(&format!("{key}-cert.pub")), namespace, data);
        let sig_file = keys.path("sig");
        std::fs::write(&sig_file, sig).unwrap();
        let mut child = Command::new("ssh-keygen")
            .args(["-Y", "verify", "-f"])
            .arg(&allowed)
            .args(["-I", id, "-n", namespace, "-s"])
            .arg(&sig_file)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        // `ssh-keygen` may refuse before it reads (`Broken pipe` here): its exit status is the verdict.
        let _ = std::io::Write::write_all(&mut child.stdin.take().unwrap(), data);
        assert_eq!(child.wait().unwrap().success(), ok, "{key} {namespace} {id}");
    }
}

#[test]
fn the_same_key_under_both_names_is_refused() {
    let d = delegation("alice");
    let keys = Keys::new();
    let key = keys.key("only");
    let key_pub = keys.public(&key);
    let trust = ApprovalTrust::PersonKeys { person: "alice", confirmed: &key_pub, automatic: &key_pub };
    let request = request(&d, INTERNAL);
    let sig = sign_approval(&Signer::plain(&key), &request).unwrap();
    assert!(matches!(verify_approval(&request, &sig, trust), Err(SignError::SameApprovalKey)));
    // Also for a request that would otherwise be accepted automatically, and for the P-256 key.
    let p256 = keys.ecdsa_key("p256");
    let p256_pub = keys.public(&p256);
    let trust = ApprovalTrust::PersonKeys { person: "alice", confirmed: &p256_pub, automatic: &p256_pub };
    let sig = sign_approval(&Signer::plain(&p256), &request).unwrap();
    assert!(matches!(verify_approval(&request, &sig, trust), Err(SignError::SameApprovalKey)));
}

// ---------------------------------------------------------------------------
// Fingerprints, and the reserved namespaces
// ---------------------------------------------------------------------------

/// What `ssh-keygen -l -f <file>` prints as the fingerprint.
fn keygen_fingerprint(file: &Path) -> String {
    let out = Command::new("ssh-keygen").args(["-l", "-f"]).arg(file).stdin(Stdio::null()).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let line = String::from_utf8(out.stdout).unwrap();
    line.split_whitespace().nth(1).unwrap().to_owned()
}

fn pub_file(key: &Path) -> PathBuf {
    PathBuf::from(format!("{}.pub", key.display()))
}

#[test]
fn a_public_keys_fingerprint_is_what_ssh_keygen_prints() {
    let keys = Keys::new();
    for (label, key) in [("ed25519", keys.key("e")), ("p256", keys.ecdsa_key("p"))] {
        let expected = keygen_fingerprint(&pub_file(&key));
        let fingerprint = keys.public(&key).fingerprint();
        assert_eq!(fingerprint.as_str(), expected, "{label}");
        assert_eq!(fingerprint.to_string().parse::<Fingerprint>().unwrap(), fingerprint);
        // The key behind a plain signature.
        let call = Call::compose(&call_content("probe", "a.example")).unwrap();
        let sig = sign_call(&Signer::plain(&key), &call).unwrap();
        assert_eq!(signature_fingerprint(&sig).unwrap(), fingerprint, "{label}");
    }
}

#[test]
fn a_certified_keys_fingerprint_is_that_of_the_key_not_of_the_certificate() {
    let keys = Keys::new();
    for (label, ca, agent_key) in [
        ("ed25519 under ed25519", keys.key("ca1"), keys.key("a1")),
        ("ed25519 under p256", keys.ecdsa_key("ca2"), keys.key("a2")),
        ("p256 under ed25519", keys.key("ca3"), keys.ecdsa_key("a3")),
        ("p256 under p256", keys.ecdsa_key("ca4"), keys.ecdsa_key("a4")),
    ] {
        let signer = keys.certify(&agent_key, &ca, "agent", "alice");
        let call = Call::compose(&call_content("probe", "a.example")).unwrap();
        let sig = sign_call(&signer, &call).unwrap();
        let expected = keygen_fingerprint(&pub_file(&agent_key));
        assert_eq!(signature_fingerprint(&sig).unwrap().as_str(), expected, "{label}");
        assert_eq!(signature_certificate(&sig).unwrap().fingerprint.as_str(), expected, "{label}");
        let agent = verify_call_agent(&call, &sig, &keys.public(&ca));
        if label.starts_with("p256 under") {
            assert!(matches!(agent, Err(SignError::AgentKeyNotEd25519(_))), "{label}");
        } else {
            assert_eq!(agent.unwrap().delegation.as_str(), expected, "{label}");
        }
        assert_ne!(expected, keys.public(&ca).fingerprint().as_str(), "the issuer is another key");
    }
}

#[test]
fn a_delegation_is_known_by_its_agents_key_alone() {
    // Two certificates for one key (two delegations over time) have one fingerprint; two keys never do.
    let keys = Keys::new();
    let ca = keys.key("ca");
    let key = keys.key("agent");
    let first = keys.certify(&key, &ca, "first", "alice");
    let second = keys.certify(&key, &ca, "second", "alice");
    let call = Call::compose(&call_content("probe", "a.example")).unwrap();
    let (a, b) = (
        signature_fingerprint(&sign_call(&first, &call).unwrap()),
        signature_fingerprint(&sign_call(&second, &call).unwrap()),
    );
    assert_eq!(a.unwrap(), b.unwrap());
    let other = keys.certify(&keys.key("other"), &ca, "x", "alice");
    assert_ne!(
        signature_fingerprint(&sign_call(&other, &call).unwrap()).unwrap().as_str(),
        keygen_fingerprint(&pub_file(&key))
    );
}

#[test]
fn fingerprints_of_other_things_are_refused() {
    for bad in [
        "",
        "SHA256:",
        "sha256:abc",
        "MD5:aa:bb",
        &format!("SHA256:{}", "a".repeat(42)),
        &format!("SHA256:{}=", "a".repeat(43)),
        &format!("SHA256:{}", "a".repeat(44)),
    ] {
        assert!(matches!(bad.parse::<Fingerprint>(), Err(SignError::MalformedFingerprint(_))), "{bad:?}");
    }
    assert!("SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse::<Fingerprint>().is_ok());
    // A signature by another key type is refused with the type named.
    let keys = Keys::new();
    let rsa = keys.path("rsa");
    keys.keygen(&["-q", "-t", "rsa", "-b", "2048", "-N", "", "-C", "", "-f", rsa.to_str().unwrap()]);
    let call = Call::compose(&call_content("probe", "a.example")).unwrap();
    let sig = sign_call(&Signer::plain(&rsa), &call).unwrap();
    assert!(matches!(signature_fingerprint(&sig), Err(SignError::UnsupportedKeyType(t)) if t == "ssh-rsa"));
    assert!(matches!(signature_fingerprint("not a signature"), Err(SignError::MalformedSignature)));
}

#[test]
fn every_namespace_of_the_system_is_reserved_and_nothing_else_is() {
    let names: Vec<&str> = Namespace::ALL.iter().map(|n| n.as_str()).collect();
    assert_eq!(
        names,
        [
            "call-v1@procession",
            "request-v1@procession",
            "approval-v1@procession",
            "clearance-v1@procession",
            "connection-v1@procession",
            "broker-v1@procession",
            "hosts-v1@procession",
        ]
    );
    for name in names {
        assert!(is_reserved_namespace(name), "{name}");
    }
    // A future one, and odd spellings of the ending, are reserved too.
    for reserved in ["anything-v9@procession", "x@procession", "@procession", "call-v1@PROCESSION", "a@Procession"] {
        assert!(is_reserved_namespace(reserved), "{reserved}");
    }
    for free in [
        "",
        "file",
        "git",
        "ssh",
        "procession",
        "call-v1@procession.example",
        "call-v1@procession ",
        "@procession@x",
        "x@processio",
        "x@procession\n",
        "example.com",
        "call-v1@processioN-x",
    ] {
        assert!(!is_reserved_namespace(free), "{free:?}");
    }
}

// ---------------------------------------------------------------------------
// The agent's certificate as a bare line, and the numbers programs share
// ---------------------------------------------------------------------------

fn cert_line_and_sig(keys: &Keys, ca: &Path, principals: &str, options: &[&str]) -> (String, String) {
    static COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = format!("line-agent-{n}");
    let signer = keys.certified_with(&name, ca, principals, VALID, options);
    let line = std::fs::read_to_string(keys.path(&format!("{name}-cert.pub"))).unwrap().trim_end().to_owned();
    let call = Call::compose(&call_content("probe", "a.example")).unwrap();
    (line, sign_call(&signer, &call).unwrap())
}

#[test]
fn a_bare_certificate_line_is_judged_as_the_one_in_a_signature_is() {
    let keys = Keys::new();
    for (label, ca) in [("ed25519", keys.key("ca")), ("p256", keys.ecdsa_key("ca-p256"))] {
        // Accepted: the same agent from the line and from a signature, with the validity.
        let (line, sig) = cert_line_and_sig(&keys, &ca, "alice", &["extension:groups@procession=admins,diag"]);
        let agent = agent_certificate(&line).unwrap();
        assert_eq!(agent, signature_agent(&sig).unwrap(), "{label}");
        assert_eq!(
            (agent.person.as_str(), agent.groups.as_slice()),
            ("alice", ["admins".to_owned(), "diag".to_owned()].as_slice())
        );
        assert_eq!((agent.valid_after, agent.valid_before), (1_577_836_800, 4_070_908_800));
        assert!(agent_certificate(&format!("{line} a comment")).is_ok(), "a comment after the base64 is allowed");
        // Refused with the same error as `signature_agent` gives.
        for (principals, options) in [
            ("alice,bob", vec![]),
            ("*", vec![]),
            ("alice", vec!["force-command=/bin/true"]),
            ("alice", vec!["extension:other@x=1"]),
            ("alice", vec!["extension:groups@procession=b,a"]),
            ("alice", vec!["extension:groups@procession=a,a"]),
            ("alice", vec!["extension:groups@procession=a,,b"]),
        ] {
            let (line, sig) = cert_line_and_sig(&keys, &ca, principals, &options);
            let (from_line, from_sig) = (agent_certificate(&line).unwrap_err(), signature_agent(&sig).unwrap_err());
            assert_eq!(from_line.to_string(), from_sig.to_string(), "{label} {principals} {options:?}");
        }
    }
    // The certified key must be Ed25519, with an error that names the type; also for a P-256 certificate line.
    let ca = keys.key("ca-for-p256-subject");
    let subject = keys.ecdsa_key("p256-agent");
    keys.certify(&subject, &ca, "agent", "alice");
    let line = std::fs::read_to_string(format!("{}-cert.pub", subject.display())).unwrap();
    assert!(
        matches!(agent_certificate(line.trim_end()), Err(SignError::AgentKeyNotEd25519(t)) if t == "ecdsa-sha2-nistp256")
    );
    // An RSA issuer is refused with its type named; a host certificate is not an agent's.
    let rsa = keys.path("rsa-ca");
    keys.keygen(&["-q", "-t", "rsa", "-b", "2048", "-N", "", "-C", "", "-f", rsa.to_str().unwrap()]);
    let (line, _) = cert_line_and_sig(&keys, &rsa, "alice", &[]);
    assert!(matches!(agent_certificate(&line), Err(SignError::UnsupportedKeyType(t)) if t == "ssh-rsa"));
    let host = keys.key("host-agent");
    keys.keygen(&[
        "-q",
        "-s",
        keys.path("ca").to_str().unwrap(),
        "-I",
        "h",
        "-h",
        "-n",
        "alice",
        "-V",
        VALID,
        pub_file(&host).to_str().unwrap(),
    ]);
    let host_line = std::fs::read_to_string(format!("{}-cert.pub", host.display())).unwrap();
    assert!(matches!(agent_certificate(host_line.trim_end()), Err(SignError::NotUserCertificate)));
}

#[test]
fn what_is_not_a_certificate_line_is_refused_as_such() {
    let keys = Keys::new();
    let ca = keys.key("ca");
    let (line, _) = cert_line_and_sig(&keys, &ca, "alice", &[]);
    let b64 = line.split(' ').nth(1).unwrap().to_owned();
    let plain = std::fs::read_to_string(pub_file(&ca)).unwrap();
    for bad in [
        String::new(),
        "ssh-ed25519-cert-v01@openssh.com".to_owned(),
        format!("ssh-ed25519-cert-v01@openssh.com {}", b64.replacen('A', "!", 1)),
        format!("ssh-ed25519-cert-v02@openssh.com {b64}"),
        format!("ecdsa-sha2-nistp256-cert-v01@openssh.com {b64}"),
        format!("{line}\n"),
        format!("{line}\x07"),
        format!("{line}\nssh-ed25519-cert-v01@openssh.com {b64}"),
        plain.trim_end().to_owned(),
    ] {
        assert!(
            matches!(
                agent_certificate(&bad),
                Err(SignError::MalformedCertificateLine | SignError::MalformedSignature | SignError::NotCertified)
            ),
            "{bad:?}"
        );
    }
}

#[test]
fn the_shared_numbers_are_the_documents() {
    use p_act::limits::*;
    assert_eq!(
        (MAX_CALL_BYTES, MAX_REQUEST_BYTES, MAX_CLEARANCE_BYTES, MAX_EXCHANGE_LINE_BYTES),
        (16 * 1024, 32 * 1024, 1024, 96 * 1024)
    );
    assert_eq!((MAX_PARAMS, MAX_PARAM_BYTES, MAX_CLAIM_CHARS, MAX_PARAMS_SHOWN_CHARS), (64, 512, 200, 2000));
    assert_eq!((MAX_DEADLINE_AHEAD_SECONDS, CLOCK_TOLERANCE_SECONDS, CLEARANCE_VALID_SECONDS), (600, 60, 60));
    assert_eq!(
        (DEFAULT_DELEGATION_SECONDS, MAX_DELEGATION_SECONDS, MAX_BUNDLE_BYTES),
        (8 * 3600, 24 * 3600, 64 * 1024)
    );
}

// ---------------------------------------------------------------------------
// The sign-in, what the broker says in its own name, and who issued a certificate
// ---------------------------------------------------------------------------

#[test]
fn a_sign_in_verifies_by_a_plain_key_in_the_connection_namespace_only() {
    let keys = Keys::new();
    let document = br#"{"v":1,"type":"connection","person":"jan","nonce":"AAAA","tls":"BBBB"}"#;
    for (label, key) in [("ed25519", keys.key("conn-e")), ("p256", keys.ecdsa_key("conn-p"))] {
        let public = keys.public(&key);
        let sig = sign_connection(&Signer::plain(&key), document).unwrap();
        verify_connection("jan", &public, &sig, document).unwrap_or_else(|e| panic!("{label}: {e}"));
        // Refused: another key, changed bytes, another namespace, a plain-key signature that is garbage.
        // A plain key's signature carries no name: the person is whoever the caller lists this key for, so a
        // different `person` with the same key verifies. Binding person to key is the site project's, through
        // the key the caller passes.
        assert!(verify_connection("bob", &public, &sig, document).is_ok(), "{label}");
        let other = keys.public(&keys.key(&format!("other-{label}")));
        assert!(is_rejected(verify_connection("jan", &other, &sig, document)), "{label}");
        assert!(is_rejected(verify_connection("jan", &public, &sig, b"changed")), "{label}");
        for namespace in [
            "approval-v1@procession",
            "clearance-v1@procession",
            "broker-v1@procession",
            "call-v1@procession",
            "request-v1@procession",
        ] {
            let wrong = raw_sign(&key, namespace, document);
            assert!(is_rejected(verify_connection("jan", &public, &wrong, document)), "{label} {namespace}");
        }
        assert!(
            matches!(
                verify_connection("jan", &public, "not a signature", document),
                Err(SignError::MalformedSignature)
            ),
            "{label}"
        );
        // A name that `ssh-keygen` would read as a pattern is not a person.
        for bad in ["", "*", "jan,bob", "a b", "jan:confirmed", &"a".repeat(65)] {
            assert!(
                matches!(verify_connection(bad, &public, &sig, document), Err(SignError::BadPrincipal(_))),
                "{label} {bad:?}"
            );
        }
        // It is not a clearance, a standing, or an approval either.
        let site = site();
        assert!(is_rejected(verify_broker(&keys.public(&site.ca), &sig, document)));
    }
}

#[test]
fn a_sign_in_by_a_certified_key_is_refused_as_such() {
    // The connection key is a plain key (approvals.md section 5): a signature that carries a certificate is not one,
    // whether or not `ssh-keygen` would match the certified key against the plain line.
    let keys = Keys::new();
    let ca = keys.key("ca");
    let key = keys.key("certified-conn");
    keys.certify(&key, &ca, "c", "jan");
    let signer = Signer::certified(&key).unwrap();
    let document = b"doc";
    let sig = sign_connection(&signer, document).unwrap();
    assert!(matches!(
        verify_connection("jan", &keys.public(&key), &sig, document),
        Err(SignError::UnexpectedCertificate)
    ));
    // The CA's key does not stand in for it either.
    assert!(
        is_rejected(verify_connection("jan", &keys.public(&ca), &sig, document))
            || matches!(
                verify_connection("jan", &keys.public(&ca), &sig, document),
                Err(SignError::UnexpectedCertificate)
            )
    );
}

#[test]
fn what_the_broker_says_verifies_as_broker_in_the_broker_namespace_only() {
    let keys = Keys::new();
    let standing = br#"{"v":1,"type":"standing","n":4}"#;
    for (label, ca) in [("ed25519 ca", keys.key("ca-e")), ("p256 ca", keys.ecdsa_key("ca-p"))] {
        let ca_pub = keys.public(&ca);
        let name = |n: &str, principals: &str| keys.certified(&format!("{label}-{n}"), &ca, principals, VALID);
        let broker = name("broker", "broker");
        let sig = sign_broker(&broker, standing).unwrap();
        verify_broker(&ca_pub, &sig, standing).unwrap();
        // Changed bytes, another CA, expired, not certified, the namespace of another document.
        assert!(is_rejected(verify_broker(&ca_pub, &sig, b"changed")), "{label}");
        assert!(
            is_rejected(verify_broker(&keys.public(&keys.ecdsa_key(&format!("elsewhere-{label}"))), &sig, standing)),
            "{label}"
        );
        let expired = keys.certified(&format!("{label}-old"), &ca, "broker", EXPIRED);
        assert!(is_rejected(verify_broker(&ca_pub, &sign_broker(&expired, standing).unwrap(), standing)), "{label}");
        let plain = Signer::plain(keys.key(&format!("{label}-plain")));
        assert!(is_rejected(verify_broker(&ca_pub, &sign_broker(&plain, standing).unwrap(), standing)), "{label}");
        for namespace in
            ["clearance-v1@procession", "approval-v1@procession", "connection-v1@procession", "hosts-v1@procession"]
        {
            let wrong = raw_sign(&keys.path(&format!("{label}-broker-cert.pub")), namespace, standing);
            assert!(is_rejected(verify_broker(&ca_pub, &wrong, standing)), "{label} {namespace}");
        }
        // Not under any other name: a person's, `brokers`, `broker:confirmed`.
        for other in ["jan:confirmed", "jan:automatic", "jan", "brokers", "broker:confirmed", "hosts"] {
            let signer = name(&other.replace(':', "_"), other);
            assert!(
                is_rejected(verify_broker(&ca_pub, &sign_broker(&signer, standing).unwrap(), standing)),
                "{label} {other}"
            );
        }
        // And the broker's standing is not a clearance, nor a clearance a standing.
        let request = request(&delegation("alice"), INTERNAL);
        let clearance = Clearance::compose(request.hash(), Timestamp::from_unix(1_794_409_481).unwrap()).unwrap();
        assert!(is_rejected(verify_clearance(&clearance, &sig, &ca_pub)), "{label}");
        let as_clearance = sign_clearance(&broker, &clearance).unwrap();
        assert!(is_rejected(verify_broker(&ca_pub, &as_clearance, clearance.as_bytes())), "{label}");
    }
}

/// The `-cert.pub` line of a key certified by `ca`, the key's public file, and the CA's.
fn agent_line(keys: &Keys, ca: &Path, name: &str, principals: &str, validity: &str) -> String {
    keys.certified_with(name, ca, principals, validity, &["extension:groups@procession=admins"]);
    std::fs::read_to_string(keys.path(&format!("{name}-cert.pub"))).unwrap().trim_end().to_owned()
}

#[test]
fn the_issuer_of_a_bare_certificate_is_found_and_matches_the_claim() {
    let keys = Keys::new();
    for (label, ca) in [("ed25519", keys.key("ca-e")), ("p256", keys.ecdsa_key("ca-p"))] {
        let line = agent_line(&keys, &ca, &format!("agent-{label}"), "alice", VALID);
        let ca_pub = keys.public(&ca);
        let issuer = certificate_issuer(&line).unwrap();
        assert_eq!(issuer, ca_pub.fingerprint(), "{label}");
        assert_eq!(issuer.as_str(), keygen_fingerprint(&pub_file(&ca)), "{label}");
        // The parsed claim is the same key, so it is available without a subprocess when nothing needs verifying.
        let blob_issuer = p_act::sign::signature_certificate(
            &sign_call(
                &Signer::certified(keys.path(&format!("agent-{label}"))).unwrap(),
                &Call::compose(&call_content("probe", "a.example")).unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
        .issuer;
        assert_eq!(blob_issuer, issuer, "{label}");
        // Checked in full: the rules of section 3.1 and the issuer.
        let agent = verify_agent_certificate(&line, &ca_pub).unwrap();
        assert_eq!(
            (agent.person.as_str(), agent.groups.as_slice()),
            ("alice", ["admins".to_owned()].as_slice()),
            "{label}"
        );
        let other = keys.public(&keys.key(&format!("other-{label}")));
        assert!(matches!(verify_agent_certificate(&line, &other), Err(SignError::WrongIssuer)), "{label}");
        assert!(
            matches!(
                verify_agent_certificate(&line, &keys.public(&keys.ecdsa_key(&format!("other-p-{label}")))),
                Err(SignError::WrongIssuer)
            ),
            "{label}"
        );
        // A comment after the base64 is not signed and changes nothing.
        assert_eq!(certificate_issuer(&format!("{line} any comment")).unwrap(), issuer);
        // Validity is not judged: an expired certificate has its issuer too, and says when it ended.
        let old = agent_line(&keys, &ca, &format!("old-{label}"), "alice", EXPIRED);
        assert_eq!(certificate_issuer(&old).unwrap(), issuer);
        assert_eq!(verify_agent_certificate(&old, &ca_pub).unwrap().valid_before, 1_577_923_200);
        // The section 3.1 rules come first, with their own errors.
        let two = agent_line(&keys, &ca, &format!("two-{label}"), "alice,bob", VALID);
        assert!(
            matches!(verify_agent_certificate(&two, &ca_pub), Err(SignError::PrincipalCount { found: 2 })),
            "{label}"
        );
    }
    // Not a line, not a certificate, an RSA issuer.
    for bad in ["", "garbage", "ssh-ed25519-cert-v01@openssh.com AAAA"] {
        assert!(certificate_issuer(bad).is_err(), "{bad:?}");
    }
}

/// Flip one bit of byte `i` of the certificate's wire form and write the line again.
fn flipped(line: &str, i: usize) -> String {
    use base64::Engine as _;
    let mut parts = line.splitn(3, ' ');
    let (kind, b64) = (parts.next().unwrap(), parts.next().unwrap());
    let mut blob = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
    blob[i] ^= 0x01;
    format!("{kind} {}", base64::engine::general_purpose::STANDARD.encode(blob))
}

#[test]
fn a_tampered_certificate_is_never_given_an_issuer() {
    // `ssh-keygen -L` is trusted to verify the certificate's signature. Checked here, for every byte of two
    // certificates (one under each kind of CA): a flipped bit anywhere in the wire form gives no issuer.
    use base64::Engine as _;
    let keys = Keys::new();
    for (label, ca) in [("ed25519", keys.key("ca-e")), ("p256", keys.ecdsa_key("ca-p"))] {
        let line = agent_line(&keys, &ca, &format!("tamper-{label}"), "alice", VALID);
        let blob = base64::engine::general_purpose::STANDARD.decode(line.split(' ').nth(1).unwrap()).unwrap();
        assert!(certificate_issuer(&line).is_ok());
        let mut accepted = vec![];
        for i in 0..blob.len() {
            if certificate_issuer(&flipped(&line, i)).is_ok() {
                accepted.push(i);
            }
        }
        assert!(
            accepted.is_empty(),
            "{label}: a flipped bit in byte(s) {accepted:?} of {} still gave an issuer",
            blob.len()
        );
        // Also cut short, and with the signature of another certificate by the same CA put in place.
        for cut in [1, 10, blob.len() / 2, blob.len() - 1] {
            let short = format!(
                "{} {}",
                line.split(' ').next().unwrap(),
                base64::engine::general_purpose::STANDARD.encode(&blob[..cut])
            );
            assert!(certificate_issuer(&short).is_err(), "{label} cut at {cut}");
        }
        let second = agent_line(&keys, &ca, &format!("second-{label}"), "mallory", VALID);
        let second_blob = base64::engine::general_purpose::STANDARD.decode(second.split(' ').nth(1).unwrap()).unwrap();
        // The first certificate's body (to the signature) with the second's signature: the signature is over the wrong bytes.
        let tail = 4 + u32::from_be_bytes(second_blob[second_blob.len() - 4 - 4..][..4].try_into().unwrap()) as usize; // not exact: only a probe
        let _ = tail;
        let spliced: Vec<u8> =
            blob[..blob.len() - 32].iter().chain(&second_blob[second_blob.len() - 32..]).copied().collect();
        let spliced = format!(
            "{} {}",
            line.split(' ').next().unwrap(),
            base64::engine::general_purpose::STANDARD.encode(spliced)
        );
        assert!(certificate_issuer(&spliced).is_err(), "{label} spliced signature");
    }
}

// ---------------------------------------------------------------------------
// The broker's signed documents: the connection document and the standing
// ---------------------------------------------------------------------------

#[test]
fn a_sign_in_from_document_to_verification() {
    let keys = Keys::new();
    let (nonce, tls) = ([5u8; 32], [6u8; 32]);
    for (label, key) in [("ed25519", keys.key("c-e")), ("p256", keys.ecdsa_key("c-p"))] {
        let public = keys.public(&key);
        // pledge writes and signs; the message carries the bytes and the armoured signature, decoded.
        let doc = ConnectionDocument::compose("jan", &nonce, &tls).unwrap();
        let sig = doc.sign(&Signer::plain(&key)).unwrap();
        let line = FromPledge::Signin(Signed { doc: doc.as_bytes().to_vec(), sig }).encode().unwrap();
        // The broker reads the line, reads the person out of the document (unverified), verifies, then checks the connection.
        let FromPledge::Signin(received) = FromPledge::parse(&line[..line.len() - 1]).unwrap() else { panic!() };
        let read = ConnectionDocument::parse_unverified(received.doc.clone()).unwrap();
        assert_eq!(read.person(), "jan");
        read.verify(&public, &received.sig).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert!(read.is_for(&nonce, &tls), "{label}");
        assert!(!read.is_for(&[1u8; 32], &tls) && !read.is_for(&nonce, &[1u8; 32]), "{label}");
        // Not verified by another key, by changed bytes, or from another namespace.
        assert!(is_rejected(read.verify(&keys.public(&keys.key(&format!("other-{label}"))), &received.sig)), "{label}");
        let changed = ConnectionDocument::compose("jan", &[9u8; 32], &tls).unwrap();
        assert!(is_rejected(changed.verify(&public, &received.sig)), "{label}");
        let wrong = raw_sign(&key, "broker-v1@procession", doc.as_bytes());
        assert!(is_rejected(doc.verify(&public, &wrong)), "{label}");
    }
}

fn standing_content(nonce: [u8; 32]) -> StandingContent {
    StandingContent {
        to: "jan".into(),
        nonce,
        n: 0,
        blocked: false,
        blocked_keys: vec![],
        withdrawn: vec!["SHA256:Qm3AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse().unwrap()],
        certificates: vec![],
        groups: vec!["ops".into(), "rt".into()],
    }
}

#[test]
fn a_standing_is_signed_by_the_broker_and_read_only_after_it_verifies() {
    let keys = Keys::new();
    let nonce = [5u8; 32];
    for (label, ca) in [("ed25519 ca", keys.key("sca-e")), ("p256 ca", keys.ecdsa_key("sca-p"))] {
        let ca_pub = keys.public(&ca);
        let broker = keys.certified(&format!("{label}-broker"), &ca, "broker", VALID);
        let standing = Standing::compose(&standing_content(nonce)).unwrap();
        let sig = standing.sign(&broker).unwrap();
        // Through a `notice` line as pledge receives it.
        let line = ToPledge::Notice(Signed { doc: standing.as_bytes().to_vec(), sig }).encode().unwrap();
        let ToPledge::Notice(received) = ToPledge::parse(&line[..line.len() - 1]).unwrap() else { panic!() };
        let verified = Standing::parse_verified(received.doc.clone(), &received.sig, &ca_pub).unwrap();
        assert_eq!(verified, standing, "{label}");
        assert!(verified.accepted_by("jan", &nonce, None), "{label}");
        assert!(!verified.accepted_by("jan", &[1u8; 32], None), "a standing carried to another connection: {label}");
        // Refused before it is read: changed bytes, another CA, a person's certificate, the namespace of a clearance, a plain key.
        let mut changed = standing.as_bytes().to_vec();
        let last = changed.len() - 3;
        changed[last] ^= 1;
        assert!(
            matches!(
                Standing::parse_verified(changed, &received.sig, &ca_pub),
                Err(StandingError::Signature(SignError::Rejected { .. }))
            ),
            "{label}"
        );
        let other_ca = keys.public(&keys.ecdsa_key(&format!("elsewhere-{label}")));
        assert!(
            matches!(
                Standing::parse_verified(standing.as_bytes().to_vec(), &received.sig, &other_ca),
                Err(StandingError::Signature(_))
            ),
            "{label}"
        );
        let person = keys.certified(&format!("{label}-person"), &ca, "jan:confirmed", VALID);
        assert!(
            Standing::parse_verified(standing.as_bytes().to_vec(), &standing.sign(&person).unwrap(), &ca_pub).is_err(),
            "{label}"
        );
        let as_clearance =
            raw_sign(&keys.path(&format!("{label}-broker-cert.pub")), "clearance-v1@procession", standing.as_bytes());
        assert!(Standing::parse_verified(standing.as_bytes().to_vec(), &as_clearance, &ca_pub).is_err(), "{label}");
        let plain = Signer::plain(keys.key(&format!("{label}-plain")));
        assert!(
            Standing::parse_verified(standing.as_bytes().to_vec(), &standing.sign(&plain).unwrap(), &ca_pub).is_err(),
            "{label}"
        );
        // Signed but not a standing: verified first, then refused as a document.
        let junk = br#"{"v":1,"type":"standing"}"#.to_vec();
        let junk_sig = p_act::sign::sign_broker(&broker, &junk).unwrap();
        assert!(
            matches!(Standing::parse_verified(junk, &junk_sig, &ca_pub), Err(StandingError::Document(_))),
            "{label}"
        );
        // A clearance's signature is not a standing's, nor the reverse.
        let request = request(&delegation("alice"), INTERNAL);
        let clearance = Clearance::compose(request.hash(), Timestamp::from_unix(1_794_409_481).unwrap()).unwrap();
        assert!(is_rejected(verify_clearance(&clearance, &standing.sign(&broker).unwrap(), &ca_pub)), "{label}");
    }
}

#[test]
fn a_delegation_message_carries_a_certificate_read_with_the_rules_of_section_3_1() {
    let keys = Keys::new();
    let ca = keys.key("dca");
    let ca_pub = keys.public(&ca);
    let (line, _) = cert_line_and_sig(&keys, &ca, "alice", &["extension:groups@procession=admins,diag"]);
    // pledge writes the message, the broker reads it back.
    let written = FromPledge::Delegation(DelegationMessage {
        certificate: line.clone(),
        agent: agent_certificate(&line).unwrap(),
    })
    .encode()
    .unwrap();
    let FromPledge::Delegation(d) = FromPledge::parse(&written[..written.len() - 1]).unwrap() else { panic!() };
    assert_eq!(d.certificate, line);
    assert_eq!(
        (d.agent.person.as_str(), d.agent.groups.as_slice()),
        ("alice", ["admins".to_owned(), "diag".to_owned()].as_slice())
    );
    // The broker then checks the issuer against the person's delegation key.
    assert_eq!(verify_agent_certificate(&d.certificate, &ca_pub).unwrap().delegation, d.agent.delegation);
    assert!(matches!(
        verify_agent_certificate(&d.certificate, &keys.public(&keys.key("other-dca"))),
        Err(SignError::WrongIssuer)
    ));
    // A certificate that breaks 3.1 in its form is `error malformed-line`, with no fingerprint to answer under.
    for (principals, options) in [
        ("alice,bob", vec![]),
        ("alice", vec!["force-command=/bin/true"]),
        ("alice", vec!["extension:groups@procession=b,a"]),
    ] {
        let (bad, _) = cert_line_and_sig(&keys, &ca, principals, &options);
        let wire = format!(r#"{{"schema_version":1,"type":"delegation","cert":"{bad}"}}"#);
        let e = FromPledge::parse(wire.as_bytes()).unwrap_err();
        assert!(matches!(e, ExchangeError::BadCertificate(_)), "{principals} {options:?}");
        assert_eq!(e.code(), Some(ErrorCode::MalformedLine));
    }
}

// ---------------------------------------------------------------------------
// An approval key's certificate, against the site CA
// ---------------------------------------------------------------------------

fn at(s: &str) -> Timestamp {
    s.parse().unwrap()
}

/// A key of the given type, certified by `ca` for `principals` (comma-separated), as the CA's issuer writes it
/// (`-O clear`), with the options given; the certificate line and the key's public part.
fn approval_cert(
    keys: &Keys,
    ca: &Path,
    name: &str,
    p256: bool,
    principals: &str,
    validity: &str,
    options: &[&str],
) -> (String, PublicKey) {
    let key = if p256 { keys.ecdsa_key(name) } else { keys.key(name) };
    let mut args = vec!["-q", "-s", ca.to_str().unwrap(), "-I", name, "-n", principals, "-V", validity, "-O", "clear"];
    for o in options {
        args.extend(["-O", o]);
    }
    let pub_file = format!("{}.pub", key.display());
    args.push(&pub_file);
    keys.keygen(&args);
    let line = std::fs::read_to_string(format!("{}-cert.pub", key.display())).unwrap().trim_end().to_owned();
    (line, keys.public(&key))
}

#[test]
fn an_approval_certificate_verifies_against_the_site_ca_for_every_key_combination() {
    let keys = Keys::new();
    let now = at("2026-11-11T15:00:00Z");
    for (ca_label, ca) in [("ed25519 ca", keys.key("ca-e")), ("p256 ca", keys.ecdsa_key("ca-p"))] {
        let ca_pub = keys.public(&ca);
        for (key_label, p256) in [("ed25519 key", false), ("p256 key", true)] {
            for (suffix, kind) in [("confirmed", ApprovalKind::Confirmed), ("automatic", ApprovalKind::Automatic)] {
                let name = format!("{ca_label}-{key_label}-{suffix}").replace(' ', "-");
                let (line, key) = approval_cert(&keys, &ca, &name, p256, &format!("alice:{suffix}"), VALID, &[]);
                let cert: ApprovalCertificate =
                    verify_approval_certificate(&line, &ca_pub, now).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!((cert.person.as_str(), cert.kind), ("alice", kind), "{name}");
                assert!(cert.certifies(&key), "{name}");
                assert!(!cert.certifies(&ca_pub), "{name}: the CA's own key is not what it certifies");
                assert_eq!(cert.key_id, name);
                assert_eq!((cert.valid_after, cert.valid_before), (1_577_836_800, 4_070_908_800));
                // A comment after the base64 is not signed and changes nothing; another CA does not vouch for it.
                assert!(verify_approval_certificate(&format!("{line} a comment"), &ca_pub, now).is_ok(), "{name}");
                let other_ca = keys.public(&keys.key(&format!("other-{name}")));
                assert!(
                    matches!(verify_approval_certificate(&line, &other_ca, now), Err(SignError::WrongIssuer)),
                    "{name}"
                );
                let other_p256 = keys.public(&keys.ecdsa_key(&format!("other-p-{name}")));
                assert!(
                    matches!(verify_approval_certificate(&line, &other_p256, now), Err(SignError::WrongIssuer)),
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn an_approval_certificate_is_judged_at_the_time_the_caller_gives() {
    let keys = Keys::new();
    let ca = keys.key("ca");
    let ca_pub = keys.public(&ca);
    let (line, _) = approval_cert(&keys, &ca, "k", true, "alice:confirmed", "20200101Z:20200102Z", &[]);
    // From its start (inclusive) to its end (exclusive).
    assert!(matches!(
        verify_approval_certificate(&line, &ca_pub, at("2019-12-31T23:59:59Z")),
        Err(SignError::CertificateNotYetValid)
    ));
    assert!(verify_approval_certificate(&line, &ca_pub, at("2020-01-01T00:00:00Z")).is_ok());
    assert!(verify_approval_certificate(&line, &ca_pub, at("2020-01-01T23:59:59Z")).is_ok());
    assert!(matches!(
        verify_approval_certificate(&line, &ca_pub, at("2020-01-02T00:00:00Z")),
        Err(SignError::CertificateExpired)
    ));
    assert!(matches!(
        verify_approval_certificate(&line, &ca_pub, at("2026-11-11T15:00:00Z")),
        Err(SignError::CertificateExpired)
    ));
    // A time before 1970 is not a time that makes a certificate valid.
    assert!(matches!(
        verify_approval_certificate(&line, &ca_pub, at("0001-01-01T00:00:00Z")),
        Err(SignError::CertificateNotYetValid)
    ));
    // "Forever".
    let (forever, _) = approval_cert(&keys, &ca, "forever", false, "alice:automatic", "always:forever", &[]);
    assert!(verify_approval_certificate(&forever, &ca_pub, at("9999-12-31T23:59:59Z")).is_ok());
}

#[test]
fn only_an_approval_keys_name_is_accepted() {
    let keys = Keys::new();
    let ca = keys.key("ca");
    let ca_pub = keys.public(&ca);
    let now = at("2026-11-11T15:00:00Z");
    for (principals, label) in [
        ("alice", "a person without the ending"),
        ("alice:other", "another ending"),
        ("alice:Confirmed", "another case"),
        ("alice:", "an empty ending"),
        (":confirmed", "no person"),
        ("alice:confirmed:automatic", "two endings"),
        ("al ice:confirmed", "a space"),
        ("al*ce:confirmed", "a pattern"),
        ("alice@host:confirmed", "an at sign"),
        ("broker", "the broker's name"),
        ("hosts", "the hosts name"),
        ("probe@a.example", "a service's name"),
    ] {
        let (line, _) =
            approval_cert(&keys, &ca, &format!("n-{}", label.replace(' ', "-")), true, principals, VALID, &[]);
        assert!(
            matches!(verify_approval_certificate(&line, &ca_pub, now), Err(SignError::NotAnApprovalName(_))),
            "{label}: {:?}",
            verify_approval_certificate(&line, &ca_pub, now)
        );
    }
    for reserved in ["broker:confirmed", "broker:automatic", "hosts:confirmed"] {
        let (line, _) = approval_cert(&keys, &ca, &reserved.replace(':', "-"), true, reserved, VALID, &[]);
        assert!(
            matches!(verify_approval_certificate(&line, &ca_pub, now), Err(SignError::ReservedName(_))),
            "{reserved}"
        );
    }
    let (two, _) = approval_cert(&keys, &ca, "two", true, "alice:confirmed,alice:automatic", VALID, &[]);
    assert!(matches!(verify_approval_certificate(&two, &ca_pub, now), Err(SignError::PrincipalCount { found: 2 })));
    let long = approval_cert(&keys, &ca, "long", true, &format!("{}:confirmed", "a".repeat(65)), VALID, &[]).0;
    assert!(matches!(verify_approval_certificate(&long, &ca_pub, now), Err(SignError::NotAnApprovalName(_))));
}

#[test]
fn an_approval_certificate_with_anything_else_is_refused() {
    let keys = Keys::new();
    let ca = keys.key("ca");
    let ca_pub = keys.public(&ca);
    let now = at("2026-11-11T15:00:00Z");
    // A critical option, a host certificate, an RSA key, an RSA issuer.
    let (restricted, _) =
        approval_cert(&keys, &ca, "restricted", true, "alice:confirmed", VALID, &["force-command=/bin/true"]);
    assert!(
        matches!(verify_approval_certificate(&restricted, &ca_pub, now), Err(SignError::CriticalOption(n)) if n == "force-command")
    );
    let host = keys.ecdsa_key("host-key");
    keys.keygen(&[
        "-q",
        "-s",
        ca.to_str().unwrap(),
        "-I",
        "h",
        "-h",
        "-n",
        "alice:confirmed",
        "-V",
        VALID,
        pub_file(&host).to_str().unwrap(),
    ]);
    let host_line = std::fs::read_to_string(format!("{}-cert.pub", host.display())).unwrap();
    assert!(matches!(
        verify_approval_certificate(host_line.trim_end(), &ca_pub, now),
        Err(SignError::NotUserCertificate)
    ));
    let rsa = keys.path("rsa");
    keys.keygen(&["-q", "-t", "rsa", "-b", "2048", "-N", "", "-C", "", "-f", rsa.to_str().unwrap()]);
    keys.keygen(&[
        "-q",
        "-s",
        ca.to_str().unwrap(),
        "-I",
        "r",
        "-n",
        "alice:confirmed",
        "-V",
        VALID,
        pub_file(&rsa).to_str().unwrap(),
    ]);
    let rsa_line = std::fs::read_to_string(format!("{}-cert.pub", rsa.display())).unwrap();
    assert!(
        matches!(verify_approval_certificate(rsa_line.trim_end(), &ca_pub, now), Err(SignError::UnsupportedKeyType(t)) if t == "ssh-rsa-cert-v01@openssh.com")
    );
    let (by_rsa, _) = approval_cert(&keys, &rsa, "by-rsa", true, "alice:confirmed", VALID, &[]);
    assert!(
        matches!(verify_approval_certificate(&by_rsa, &ca_pub, now), Err(SignError::UnsupportedKeyType(t)) if t == "ssh-rsa")
    );
    // Default extensions (no `-O clear`) are refused (approval-formats.md section 3.2).
    let key = keys.ecdsa_key("with-extensions");
    keys.keygen(&[
        "-q",
        "-s",
        ca.to_str().unwrap(),
        "-I",
        "x",
        "-n",
        "alice:confirmed",
        "-V",
        VALID,
        pub_file(&key).to_str().unwrap(),
    ]);
    let line = std::fs::read_to_string(format!("{}-cert.pub", key.display())).unwrap();
    assert!(matches!(
        verify_approval_certificate(line.trim_end(), &ca_pub, now),
        Err(SignError::SiteCertificateExtension(_))
    ));
    // An agent's certificate is not an approval key's, and the reverse.
    let (agent, _) = cert_line_and_sig(&keys, &ca, "alice", &[]);
    assert!(matches!(verify_approval_certificate(&agent, &ca_pub, now), Err(SignError::NotAnApprovalName(_))));
    let (approval, _) = approval_cert(&keys, &ca, "approval", false, "alice:confirmed", VALID, &[]);
    assert!(signature_agent_line_is_refused(&approval));
    // Not a certificate line.
    for bad in ["", "garbage", &format!("{approval}\n"), &format!("{approval}\x07"), "ssh-ed25519 AAAA"] {
        assert!(verify_approval_certificate(bad, &ca_pub, now).is_err(), "{bad:?}");
    }
}

fn signature_agent_line_is_refused(line: &str) -> bool {
    agent_certificate(line).is_err()
}

#[test]
fn a_tampered_approval_certificate_is_never_accepted() {
    use base64::Engine as _;
    let keys = Keys::new();
    let now = at("2026-11-11T15:00:00Z");
    for (label, ca, p256) in [("ed25519 ca", keys.key("ca-e"), true), ("p256 ca", keys.ecdsa_key("ca-p"), false)] {
        let ca_pub = keys.public(&ca);
        let (line, _) =
            approval_cert(&keys, &ca, &format!("t-{}", label.replace(' ', "-")), p256, "alice:confirmed", VALID, &[]);
        assert!(verify_approval_certificate(&line, &ca_pub, now).is_ok());
        let blob = base64::engine::general_purpose::STANDARD.decode(line.split(' ').nth(1).unwrap()).unwrap();
        let mut accepted = vec![];
        for i in 0..blob.len() {
            if verify_approval_certificate(&flipped(&line, i), &ca_pub, now).is_ok() {
                accepted.push(i);
            }
        }
        assert!(accepted.is_empty(), "{label}: a flipped bit in byte(s) {accepted:?} was accepted");
    }
}

#[test]
fn an_approval_certificate_for_a_given_person_and_role_and_without_the_time() {
    let keys = Keys::new();
    let ca = keys.key("ca");
    let ca_pub = keys.public(&ca);
    let now = at("2026-11-11T15:00:00Z");
    let (line, key) = approval_cert(&keys, &ca, "k", true, "jan:confirmed", VALID, &[]);
    // For exactly this person and role.
    let cert = verify_approval_certificate_for(&line, &ca_pub, "jan", ApprovalKind::Confirmed, now).unwrap();
    assert!(cert.certifies(&key));
    for (person, kind) in [
        ("jan", ApprovalKind::Automatic),
        ("eva", ApprovalKind::Confirmed),
        ("ja", ApprovalKind::Confirmed),
        ("jan:confirmed", ApprovalKind::Confirmed),
    ] {
        assert!(
            matches!(
                verify_approval_certificate_for(&line, &ca_pub, person, kind, now),
                Err(SignError::NotTheExpectedName)
            ),
            "{person} {kind:?}"
        );
    }
    // The time is the caller's: the check without it accepts an ended certificate, and says when it ended.
    let (ended, _) = approval_cert(&keys, &ca, "ended", false, "jan:automatic", "20200101Z:20200102Z", &[]);
    let cert = check_approval_certificate(&ended, &ca_pub).unwrap();
    assert_eq!((cert.valid_after, cert.valid_before), (1_577_836_800, 1_577_923_200));
    assert!(matches!(cert.valid_at(now), Err(SignError::CertificateExpired)));
    assert!(matches!(cert.valid_at(at("2019-12-31T23:59:59Z")), Err(SignError::CertificateNotYetValid)));
    assert!(cert.valid_at(at("2020-01-01T12:00:00Z")).is_ok());
    // But everything else is still judged without the time: the name, the issuer and the signature.
    let other = keys.public(&keys.key("other-ca"));
    assert!(matches!(check_approval_certificate(&ended, &other), Err(SignError::WrongIssuer)));
    let (bad_name, _) = approval_cert(&keys, &ca, "bad", false, "jan", "20200101Z:20200102Z", &[]);
    assert!(matches!(check_approval_certificate(&bad_name, &ca_pub), Err(SignError::NotAnApprovalName(_))));
}

#[test]
fn bytes_after_a_certificates_signature_are_refused_because_the_signature_does_not_cover_them() {
    use base64::Engine as _;
    let keys = Keys::new();
    let ca = keys.key("ca");
    let ca_pub = keys.public(&ca);
    let (line, _) = approval_cert(&keys, &ca, "k", true, "jan:confirmed", VALID, &[]);
    let mut parts = line.splitn(3, ' ');
    let (kind, b64) = (parts.next().unwrap(), parts.next().unwrap());
    let mut blob = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
    blob.push(0);
    let with_trailer = format!("{kind} {}", base64::engine::general_purpose::STANDARD.encode(&blob));
    assert!(matches!(check_approval_certificate(&with_trailer, &ca_pub), Err(SignError::CertificateTrailingData)));
    assert!(matches!(agent_certificate(&with_trailer), Err(SignError::CertificateTrailingData)));
    assert!(matches!(certificate_issuer(&with_trailer), Err(SignError::CertificateTrailingData)));
    // And the same certificate without it is accepted.
    assert!(check_approval_certificate(&line, &ca_pub).is_ok());
}

/// `name`'s key certified by `ca` for `principals` as `ssh-keygen` does by default: **without `-O clear`**, so the
/// login extensions (`permit-pty` and four more) are in it; or with `-O clear` and then one more extension.
fn certified_loosely(keys: &Keys, name: &str, ca: &Path, principals: &str, extra: Option<&str>) -> (Signer, String) {
    let key = keys.key(name);
    let pub_file = format!("{}.pub", key.display());
    let mut args = vec!["-q", "-s", ca.to_str().unwrap(), "-I", name, "-n", principals, "-V", VALID];
    if let Some(extra) = extra {
        args.extend(["-O", "clear", "-O", extra]);
    }
    args.push(&pub_file);
    keys.keygen(&args);
    let line = std::fs::read_to_string(format!("{}-cert.pub", key.display())).unwrap().trim_end().to_owned();
    (Signer::certified(key).unwrap(), line)
}

#[test]
fn a_certificate_the_site_ca_issued_with_an_extension_is_refused_everywhere_it_is_verified() {
    let d = delegation("alice");
    let s = site();
    let keys = &s.keys;
    let ca = keys.public(&s.ca);
    let now = at("2026-11-11T15:00:00Z");
    let request = request(&d, INTERNAL);
    let clearance = Clearance::compose(request.hash(), Timestamp::from_unix(1_794_409_481).unwrap()).unwrap();
    let standing = br#"{"v":1,"type":"standing","n":4}"#;
    // With `-O clear` (s.confirmed, s.broker are made like that) everything is accepted; the loose ones are refused.
    for (how, extra) in [("the defaults", None), ("one extension", Some("permit-pty"))] {
        let tag = how.replace(' ', "-");
        let (confirmed, line) = certified_loosely(keys, &format!("c-{tag}"), &s.ca, "alice:confirmed", extra);
        let (broker, _) = certified_loosely(keys, &format!("b-{tag}"), &s.ca, "broker", extra);
        let is_extension = |r: Result<(), SignError>| matches!(r, Err(SignError::SiteCertificateExtension(_)));
        // The signature is good in every case: it is the extension alone that is refused.
        let approval = sign_approval(&confirmed, &request).unwrap();
        assert!(is_extension(verify_approval(&request, &approval, ApprovalTrust::SiteCa(&ca)).map(|_| ())), "{how}");
        assert!(
            is_extension(verify_clearance(&clearance, &sign_clearance(&broker, &clearance).unwrap(), &ca)),
            "{how}"
        );
        assert!(is_extension(verify_broker(&ca, &sign_broker(&broker, standing).unwrap(), standing)), "{how}");
        // The bare certificate, in all three forms.
        let line = line.as_str();
        assert!(
            matches!(verify_approval_certificate(line, &ca, now), Err(SignError::SiteCertificateExtension(_))),
            "{how}"
        );
        assert!(matches!(check_approval_certificate(line, &ca), Err(SignError::SiteCertificateExtension(_))), "{how}");
        assert!(
            matches!(
                verify_approval_certificate_for(line, &ca, "alice", ApprovalKind::Confirmed, now),
                Err(SignError::SiteCertificateExtension(_))
            ),
            "{how}"
        );
    }
    // The name of the extension is in the message and nothing of its data.
    let (e, _) = certified_loosely(keys, "c-named", &s.ca, "alice:confirmed", Some("permit-pty"));
    let err = verify_approval(&request, &sign_approval(&e, &request).unwrap(), ApprovalTrust::SiteCa(&ca)).unwrap_err();
    assert!(err.to_string().contains("`permit-pty`") && err.to_string().contains("-O clear"), "{err}");
    // And the same certificates issued with `-O clear` are accepted by all of them.
    let request_sig = sign_approval(&s.confirmed, &request).unwrap();
    assert!(verify_approval(&request, &request_sig, ApprovalTrust::SiteCa(&ca)).is_ok());
    assert!(verify_clearance(&clearance, &sign_clearance(&s.broker, &clearance).unwrap(), &ca).is_ok());
    assert!(verify_broker(&ca, &sign_broker(&s.broker, standing).unwrap(), standing).is_ok());
}

#[test]
fn the_brokers_own_certificate_verifies_bare_for_the_name_broker_only() {
    use p_act::sign::{check_broker_certificate, verify_broker_certificate};
    let keys = Keys::new();
    let now = at("2026-11-11T15:00:00Z");
    for (label, ca) in [("ed25519 ca", keys.key("bca-e")), ("p256 ca", keys.ecdsa_key("bca-p"))] {
        let ca_pub = keys.public(&ca);
        let tag = label.replace(' ', "-");
        let (line, key) = approval_cert(&keys, &ca, &format!("{tag}-broker"), false, "broker", VALID, &[]);
        let cert = verify_broker_certificate(&line, &ca_pub, now).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert!(cert.certifies(&key) && !cert.certifies(&ca_pub), "{label}");
        assert_eq!((cert.valid_after, cert.valid_before), (1_577_836_800, 4_070_908_800));
        // A P-256 broker key too.
        let (p256, key256) = approval_cert(&keys, &ca, &format!("{tag}-broker256"), true, "broker", VALID, &[]);
        assert!(verify_broker_certificate(&p256, &ca_pub, now).unwrap().certifies(&key256), "{label}");
        // The time is the caller's.
        let (old, _) = approval_cert(&keys, &ca, &format!("{tag}-old"), false, "broker", "20200101Z:20200102Z", &[]);
        assert!(matches!(verify_broker_certificate(&old, &ca_pub, now), Err(SignError::CertificateExpired)));
        let ended = check_broker_certificate(&old, &ca_pub).unwrap();
        assert!(ended.valid_at(at("2020-01-01T12:00:00Z")).is_ok(), "{label}");
        assert!(matches!(ended.valid_at(at("2019-12-31T23:59:59Z")), Err(SignError::CertificateNotYetValid)));
        // Another CA; another name (a person's, a host's, two principals); with an extension or a critical option.
        let other = keys.public(&keys.key(&format!("other-{tag}")));
        assert!(matches!(verify_broker_certificate(&line, &other, now), Err(SignError::WrongIssuer)), "{label}");
        for (name, principals) in [
            ("p", "alice:confirmed"),
            ("q", "brokers"),
            ("r", "alice"),
            ("s", "hosts"),
            ("t", "broker,alice"),
            ("u", "Broker"),
        ] {
            let (bad, _) = approval_cert(&keys, &ca, &format!("{tag}-{name}"), false, principals, VALID, &[]);
            let e = verify_broker_certificate(&bad, &ca_pub, now).unwrap_err();
            assert!(
                matches!(e, SignError::NotBrokerName(_) | SignError::PrincipalCount { .. }),
                "{label} {principals}: {e}"
            );
        }
        let (forced, _) =
            approval_cert(&keys, &ca, &format!("{tag}-force"), false, "broker", VALID, &["force-command=/bin/true"]);
        assert!(
            matches!(verify_broker_certificate(&forced, &ca_pub, now), Err(SignError::CriticalOption(_))),
            "{label}"
        );
        let (ext, _) = approval_cert(&keys, &ca, &format!("{tag}-ext"), false, "broker", VALID, &["permit-pty"]);
        assert!(
            matches!(verify_broker_certificate(&ext, &ca_pub, now), Err(SignError::SiteCertificateExtension(_))),
            "{label}"
        );
        // A person's approval certificate is not the broker's, and the reverse.
        let (person, _) = approval_cert(&keys, &ca, &format!("{tag}-person"), false, "alice:confirmed", VALID, &[]);
        assert!(verify_broker_certificate(&person, &ca_pub, now).is_err());
        assert!(matches!(verify_approval_certificate(&line, &ca_pub, now), Err(SignError::NotAnApprovalName(_))));
        // Bytes after the signature, a host certificate, and garbage.
        assert!(verify_broker_certificate("garbage", &ca_pub, now).is_err());
        assert!(verify_broker_certificate(&format!("{line}\n"), &ca_pub, now).is_err());
    }
}
