//! The signatures against a real `ssh-keygen`, with keys made in a temporary
//! directory. Nothing here touches anything outside it, and nothing prompts:
//! keys have no passphrase and no command has a terminal to ask on.

use p_act::rating::{Damage, Disruption, Exposure, Rating};
use p_act::sign::{
    ApprovalKind, ApprovalTrust, Fingerprint, Namespace, PublicKey, SignError, Signer, is_reserved_namespace,
    request_person, sign_approval, sign_call, sign_clearance, sign_request, signature_agent, signature_certificate,
    signature_fingerprint, signature_from_base64, signature_person, signature_to_base64, verify_approval, verify_call,
    verify_call_agent, verify_clearance, verify_request,
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
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(data).unwrap();
    String::from_utf8(child.wait_with_output().unwrap().stdout).unwrap()
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
    let trust = ApprovalTrust::PersonKeys { confirmed: &confirmed_pub, automatic: &automatic_pub };
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

    // A stranger's key, and the wrong person (the keys are alice's).
    let stranger = Signer::plain(keys.key("stranger"));
    assert!(is_rejected(verify_approval(&request, &sign_approval(&stranger, &request).unwrap(), trust)));
    let bobs = delegation("bob");
    let for_bob = Request::compose(&bobs.call, &bobs.sig, INTERNAL).unwrap();
    let alice_signs_bobs = sign_approval(&Signer::plain(&confirmed), &for_bob).unwrap();
    // The lines are named for the person the request names, so the lines of this test accept
    // the keys under bob's name: a stage-1 file lists exactly one person, and it is that
    // person's call that is approved. A different person's key is the stranger case above.
    assert!(verify_approval(&for_bob, &alice_signs_bobs, trust).is_ok());
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
    let trust = ApprovalTrust::PersonKeys { confirmed: &c_pub, automatic: &a_pub };
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
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), data).unwrap();
        assert_eq!(child.wait().unwrap().success(), ok, "{key} {namespace} {id}");
    }
}

#[test]
fn the_same_key_under_both_names_is_refused() {
    let d = delegation("alice");
    let keys = Keys::new();
    let key = keys.key("only");
    let key_pub = keys.public(&key);
    let trust = ApprovalTrust::PersonKeys { confirmed: &key_pub, automatic: &key_pub };
    let request = request(&d, INTERNAL);
    let sig = sign_approval(&Signer::plain(&key), &request).unwrap();
    assert!(matches!(verify_approval(&request, &sig, trust), Err(SignError::SameApprovalKey)));
    // Also for a request that would otherwise be accepted automatically, and for the P-256 key.
    let p256 = keys.ecdsa_key("p256");
    let p256_pub = keys.public(&p256);
    let trust = ApprovalTrust::PersonKeys { confirmed: &p256_pub, automatic: &p256_pub };
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
