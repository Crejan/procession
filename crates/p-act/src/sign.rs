//! Signing and verifying with `ssh-keygen -Y sign` and `-Y verify`, with the
//! namespaces and allowed-signers lines of formats section 7.
//!
//! One function per document type and direction. A signature is the armoured
//! SSHSIG text `ssh-keygen` writes; what it covers is a document's
//! [`Document::as_bytes`], nothing else.
//!
//! # Who the person is
//!
//! A call's person is the principal of the agent's certificate, which is
//! inside `call_sig`. A service cannot verify that certificate (approvals.md,
//! section 5), so it needs the name without an allowed-signers file to ask
//! about, which rules out `ssh-keygen -Y find-principals`: that answers from
//! the lines of such a file, and it is the name that would have to be in the
//! line. [`signature_person`] therefore reads the certificate out of the
//! SSHSIG blob itself. What it returns is a claim until a verification under
//! that name succeeds: [`verify_call`] does exactly that, and the approval's
//! verification ([`verify_approval`]) is what proves the person to a service.
//!
//! Only Ed25519 certificates are read: the agent's key is made by pledge, and
//! an unknown key type is refused, not guessed at.

use crate::call::Call;
use crate::clearance::Clearance;
use crate::error::ParseError;
use crate::hash::Document;
use crate::request::Request;
use crate::text;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use thiserror::Error;

const BEGIN: &str = "-----BEGIN SSH SIGNATURE-----\n";
const END: &str = "\n-----END SSH SIGNATURE-----\n";
const KEYGEN: &str = "ssh-keygen";

/// The namespace of each signed document type. A signature for one can never
/// verify as another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    Call,
    Request,
    Approval,
    Clearance,
}

impl Namespace {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Namespace::Call => "call-v1@procession",
            Namespace::Request => "request-v1@procession",
            Namespace::Approval => "approval-v1@procession",
            Namespace::Clearance => "clearance-v1@procession",
        }
    }
}

/// Why signing or verifying failed.
#[derive(Debug, Error)]
pub enum SignError {
    #[error("signature is not an armoured SSH signature")]
    MalformedSignature,
    #[error("`{0}` is not a public key line")]
    MalformedPublicKey(String),
    #[error("the signing key is not certified")]
    NotCertified,
    #[error("certificate of key type `{0}` is not supported")]
    UnsupportedKeyType(String),
    #[error("the agent's certificate names {found} principals, not exactly one")]
    PrincipalCount { found: usize },
    #[error("`{0}` is not a usable name for a person")]
    BadPrincipal(String),
    #[error("an automatic approval is not accepted for a request rated at the top of a scale")]
    AutomaticNotAcceptable,
    #[error("cannot run ssh-keygen: {0}")]
    Run(#[from] io::Error),
    #[error("ssh-keygen failed ({status}): {stderr}")]
    Tool { status: String, stderr: String },
    #[error("signature rejected: {stderr}")]
    Rejected { stderr: String },
    #[error(transparent)]
    Document(#[from] ParseError),
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

/// A public key as one `<type> <base64>` line, without comment or options, so
/// that it can stand in an allowed-signers line and nothing else can ride
/// along. Certificates are refused: an anchor is a plain key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey(String);

impl PublicKey {
    /// From a `.pub` file's line: `<type> <base64> [comment]`.
    pub fn parse(line: &str) -> Result<PublicKey, SignError> {
        let bad = || SignError::MalformedPublicKey(line.trim_end().to_owned());
        let mut parts = line.split_ascii_whitespace();
        let (Some(kind), Some(b64)) = (parts.next(), parts.next()) else { return Err(bad()) };
        let blob = STANDARD.decode(b64).map_err(|_| bad())?;
        let mut r = Reader(&blob);
        let embedded = r.string().ok_or_else(bad)?;
        let name_ok =
            kind.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'@' | b'.'));
        if embedded != kind.as_bytes() || !name_ok || kind.contains("-cert-v01@") {
            return Err(bad());
        }
        Ok(PublicKey(format!("{kind} {b64}")))
    }

    /// Read a `.pub` file.
    pub fn read(path: &Path) -> Result<PublicKey, SignError> {
        PublicKey::parse(&std::fs::read_to_string(path)?)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A private key file to sign with, and its certificate if it has one.
#[derive(Debug, Clone)]
pub struct Signer {
    file: PathBuf,
}

impl Signer {
    /// Sign with the private key in `key`, which must not need a passphrase.
    #[must_use]
    pub fn plain(key: impl Into<PathBuf>) -> Signer {
        Signer { file: key.into() }
    }

    /// Sign with the private key in `key` and the certificate beside it,
    /// `<key>-cert.pub`, as OpenSSH names it. The signature then contains the
    /// certificate. Fails if there is none.
    pub fn certified(key: impl Into<PathBuf>) -> Result<Signer, SignError> {
        let mut cert: OsString = key.into().into_os_string();
        cert.push("-cert.pub");
        let cert = PathBuf::from(cert);
        if cert.is_file() { Ok(Signer { file: cert }) } else { Err(SignError::NotCertified) }
    }

    fn sign(&self, namespace: Namespace, bytes: &[u8]) -> Result<String, SignError> {
        let out = run(
            &[
                OsStr::new("-Y"),
                "sign".as_ref(),
                "-f".as_ref(),
                self.file.as_os_str(),
                "-n".as_ref(),
                namespace.as_str().as_ref(),
            ],
            bytes,
        )?;
        let sig = String::from_utf8(out).map_err(|_| SignError::MalformedSignature)?;
        if looks_armoured(&sig) { Ok(sig) } else { Err(SignError::MalformedSignature) }
    }
}

// ---------------------------------------------------------------------------
// Running ssh-keygen
// ---------------------------------------------------------------------------

/// Run `ssh-keygen args` with `stdin` as its input and no terminal input; its
/// standard output on success.
fn run(args: &[&OsStr], stdin: &[u8]) -> Result<Vec<u8>, SignError> {
    let mut child = Command::new(KEYGEN)
        .args(args)
        // A key that wants a passphrase must fail, not ask on the terminal: the "askpass program" is `false`.
        .env("SSH_ASKPASS", "false")
        .env("SSH_ASKPASS_REQUIRE", "force")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut pipe = child.stdin.take().ok_or_else(|| io::Error::other("no stdin"))?;
    // Written on the side so that a full pipe cannot deadlock; a tool that stops reading early is seen in its exit status.
    let output = std::thread::scope(|s| {
        s.spawn(move || {
            let _ = pipe.write_all(stdin);
        });
        child.wait_with_output()
    })?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(SignError::Tool {
            status: output.status.to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
        })
    }
}

/// `ssh-keygen -Y verify -f <allowed> -I <principal> -n <namespace> -s <sig> < data`
fn verify(namespace: Namespace, allowed: &str, principal: &str, sig: &str, data: &[u8]) -> Result<(), SignError> {
    if !looks_armoured(sig) {
        return Err(SignError::MalformedSignature);
    }
    let dir = tempfile::tempdir()?;
    let (allowed_file, sig_file) = (dir.path().join("allowed"), dir.path().join("sig"));
    std::fs::write(&allowed_file, allowed)?;
    std::fs::write(&sig_file, sig)?;
    let args: [&OsStr; 9] = [
        "-Y".as_ref(),
        "verify".as_ref(),
        "-f".as_ref(),
        allowed_file.as_os_str(),
        "-I".as_ref(),
        principal.as_ref(),
        "-n".as_ref(),
        namespace.as_str().as_ref(),
        "-s".as_ref(),
    ];
    match run(&[&args[..], &[sig_file.as_os_str()]].concat(), data) {
        Err(SignError::Tool { stderr, status }) => {
            // ssh-keygen says why on stderr or, for "Could not verify signature.", on stdout, which `run` drops.
            Err(SignError::Rejected { stderr: if stderr.is_empty() { status } else { stderr } })
        }
        other => other.map(drop),
    }
}

/// `<principals> cert-authority,namespaces="<namespaces>" <key>`
fn ca_line(principals: &str, namespaces: &[Namespace], key: &PublicKey) -> String {
    let namespaces: Vec<_> = namespaces.iter().map(|n| n.as_str()).collect();
    format!("{principals} cert-authority,namespaces=\"{}\" {key}\n", namespaces.join(","))
}

/// `<principal> namespaces="<namespace>" <key>`: a key listed directly (stage 1).
fn key_line(principal: &str, namespace: Namespace, key: &PublicKey) -> String {
    format!("{principal} namespaces=\"{}\" {key}\n", namespace.as_str())
}

// ---------------------------------------------------------------------------
// Reading the person out of a signature
// ---------------------------------------------------------------------------

/// Whether `sig` has the shape of an armoured SSH signature. Says nothing of
/// whether it verifies.
#[must_use]
pub fn looks_armoured(sig: &str) -> bool {
    sig.strip_prefix(BEGIN).and_then(|rest| rest.strip_suffix(END.strip_prefix('\n').unwrap_or(END))).is_some_and(
        |body| {
            !body.is_empty()
                && body.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'\n'))
        },
    )
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = tail;
        Some(head)
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()?;
        self.take(usize::try_from(n).ok()?)
    }
}

/// What a certificate inside a signature says about itself. Unverified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub key_id: String,
    pub principals: Vec<String>,
    /// Seconds since the Unix epoch.
    pub valid_after: u64,
    /// Seconds since the Unix epoch.
    pub valid_before: u64,
}

/// The certificate inside an armoured SSHSIG, read, not verified.
pub fn signature_certificate(sig: &str) -> Result<Certificate, SignError> {
    let bad = || SignError::MalformedSignature;
    if !looks_armoured(sig) {
        return Err(bad());
    }
    let body: String = sig[BEGIN.len()..sig.len() - END.len() + 1].split('\n').collect();
    let blob = STANDARD.decode(body).map_err(|_| bad())?;
    let mut r = Reader(&blob);
    if r.take(6) != Some(b"SSHSIG") || r.u32() != Some(1) {
        return Err(bad());
    }
    let mut key = Reader(r.string().ok_or_else(bad)?);
    let kind = String::from_utf8_lossy(key.string().ok_or_else(bad)?).into_owned();
    if !kind.contains("-cert-v01@") {
        return Err(SignError::NotCertified);
    }
    if kind != "ssh-ed25519-cert-v01@openssh.com" {
        return Err(SignError::UnsupportedKeyType(kind));
    }
    // nonce, public key (Ed25519: one string), serial, type, key id, principals, validity.
    let _nonce = key.string().ok_or_else(bad)?;
    let _public_key = key.string().ok_or_else(bad)?;
    let _serial = key.u64().ok_or_else(bad)?;
    let _type = key.u32().ok_or_else(bad)?;
    let key_id = String::from_utf8(key.string().ok_or_else(bad)?.to_vec()).map_err(|_| bad())?;
    let mut list = Reader(key.string().ok_or_else(bad)?);
    let mut principals = Vec::new();
    while !list.0.is_empty() {
        principals.push(String::from_utf8(list.string().ok_or_else(bad)?.to_vec()).map_err(|_| bad())?);
    }
    let valid_after = key.u64().ok_or_else(bad)?;
    let valid_before = key.u64().ok_or_else(bad)?;
    Ok(Certificate { key_id, principals, valid_after, valid_before })
}

/// The person an agent's signature names: the one principal of its
/// certificate. A claim until a verification under that name succeeds.
pub fn signature_person(sig: &str) -> Result<String, SignError> {
    let principals = signature_certificate(sig)?.principals;
    match <[String; 1]>::try_from(principals) {
        Ok([person]) if text::is_name(&person) => Ok(person),
        Ok([other]) => Err(SignError::BadPrincipal(other)),
        Err(many) => Err(SignError::PrincipalCount { found: many.len() }),
    }
}

/// The person the request's call was signed for, read from `call_sig`: a
/// claim, to be proved by the approval, not by this.
pub fn request_person(request: &Request) -> Result<String, SignError> {
    signature_person(request.call_sig())
}

// ---------------------------------------------------------------------------
// The four document types
// ---------------------------------------------------------------------------

/// Sign a call with the agent's key, certified by its person's delegation key.
pub fn sign_call(signer: &Signer, call: &Call) -> Result<String, SignError> {
    signer.sign(Namespace::Call, call.as_bytes())
}

/// Verify a call's signature against the person's `delegation_key`, under the
/// principal in the agent's certificate. Returns that person. Checks the
/// certificate's validity as `ssh-keygen` does.
pub fn verify_call(call: &Call, sig: &str, delegation_key: &PublicKey) -> Result<String, SignError> {
    let person = signature_person(sig)?;
    let allowed = ca_line(&person, &[Namespace::Call], delegation_key);
    verify(Namespace::Call, &allowed, &person, sig, call.as_bytes())?;
    Ok(person)
}

/// Sign a request with the service's key, certified by its host's key.
pub fn sign_request(signer: &Signer, request: &Request) -> Result<String, SignError> {
    signer.sign(Namespace::Request, request.as_bytes())
}

/// Verify a request's signature against `host_key`, under the principal
/// `<service>@<host>` of the call inside the request. A request signed by any
/// other service or host does not verify.
pub fn verify_request(request: &Request, sig: &str, host_key: &PublicKey) -> Result<(), SignError> {
    let principal = request.call().service().principal();
    let allowed = ca_line(&principal, &[Namespace::Request], host_key);
    verify(Namespace::Request, &allowed, &principal, sig, request.as_bytes())
}

/// What stands behind a person's approvals.
#[derive(Debug, Clone, Copy)]
pub enum ApprovalTrust<'a> {
    /// The site CA's key, which certified `<person>:confirmed` and `<person>:automatic`.
    SiteCa(&'a PublicKey),
    /// The one person's two approval keys, listed directly (stage 1: no site CA).
    PersonKeys { confirmed: &'a PublicKey, automatic: &'a PublicKey },
}

/// Which of a person's approval keys signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalKind {
    Confirmed,
    Automatic,
}

impl ApprovalKind {
    fn suffix(self) -> &'static str {
        match self {
            ApprovalKind::Confirmed => "confirmed",
            ApprovalKind::Automatic => "automatic",
        }
    }
}

/// An approval is the signature over the request's bytes. `signer` holds the
/// person's confirmed or automatic approval key, certified by the site CA.
pub fn sign_approval(signer: &Signer, request: &Request) -> Result<String, SignError> {
    signer.sign(Namespace::Approval, request.as_bytes())
}

/// Verify an approval of exactly this request by the person its call names
/// (read from `call_sig`, see [`request_person`]). A confirmed approval is
/// always accepted; an automatic one only for a request rated below the top
/// of every scale. Returns which key signed.
pub fn verify_approval(request: &Request, sig: &str, trust: ApprovalTrust<'_>) -> Result<ApprovalKind, SignError> {
    let person = request_person(request)?;
    let attempt = |kind: ApprovalKind| {
        let principal = format!("{person}:{}", kind.suffix());
        let allowed = match trust {
            ApprovalTrust::SiteCa(ca) => ca_line("*", &[Namespace::Approval], ca),
            ApprovalTrust::PersonKeys { confirmed, automatic } => key_line(
                &principal,
                Namespace::Approval,
                if kind == ApprovalKind::Confirmed { confirmed } else { automatic },
            ),
        };
        verify(Namespace::Approval, &allowed, &principal, sig, request.as_bytes())
    };
    match attempt(ApprovalKind::Confirmed) {
        Ok(()) => Ok(ApprovalKind::Confirmed),
        Err(confirmed_failed) => match attempt(ApprovalKind::Automatic) {
            Ok(()) if request.rating().needs_confirmation() => Err(SignError::AutomaticNotAcceptable),
            Ok(()) => Ok(ApprovalKind::Automatic),
            Err(_) => Err(confirmed_failed),
        },
    }
}

/// Sign a clearance with the broker's key, certified by the site CA as `broker`.
pub fn sign_clearance(signer: &Signer, clearance: &Clearance) -> Result<String, SignError> {
    signer.sign(Namespace::Clearance, clearance.as_bytes())
}

/// Verify a clearance against the site CA, under the name `broker`. Whether it
/// is fresh, and whether it covers the request at hand ([`Clearance::covers`]),
/// is the caller's to check.
pub fn verify_clearance(clearance: &Clearance, sig: &str, site_ca: &PublicKey) -> Result<(), SignError> {
    let allowed = ca_line("*", &[Namespace::Clearance], site_ca);
    verify(Namespace::Clearance, &allowed, "broker", sig, clearance.as_bytes())
}
