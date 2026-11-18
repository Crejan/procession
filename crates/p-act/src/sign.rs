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
//! Certificates whose subject key is Ed25519 or ECDSA P-256 are read; the key
//! that signed a certificate is not parsed, so it may be of either type too.
//! Any other key type is refused with [`SignError::UnsupportedKeyType`], not
//! guessed at.

use crate::call::Call;
use crate::clearance::Clearance;
use crate::error::ParseError;
use crate::hash::Document;
use crate::request::Request;
use crate::sshsig::SshsigSigner;
use crate::text;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use ring::digest::{SHA256, digest};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use thiserror::Error;

const BEGIN: &str = "-----BEGIN SSH SIGNATURE-----\n";
const END: &str = "\n-----END SSH SIGNATURE-----\n";
const KEYGEN: &str = "ssh-keygen";
/// The key types p-act accepts as public keys, and as the subject of a certificate it reads.
const SUPPORTED_KEYS: [&str; 2] = ["ssh-ed25519", "ecdsa-sha2-nistp256"];

/// The namespace of each signed document type. A signature for one can never
/// verify as another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Namespace {
    Call,
    Request,
    Approval,
    Clearance,
    /// pledge's sign-in to the broker, with the person's connection key.
    Connection,
    /// What the broker says to a pledge in its own name.
    Broker,
    /// The list of hosts' keys (formats section 6.1).
    Hosts,
}

/// The ending that reserves an SSHSIG namespace for this system.
pub const RESERVED_SUFFIX: &str = "@procession";

/// Whether `namespace` is reserved for this system: it ends in `@procession`.
/// pledge's SSH agent socket refuses a signature in any such namespace, for
/// every key. The comparison ignores ASCII case, which only makes it wider:
/// `ssh-keygen` compares namespaces exactly, so a differently cased one is
/// never ours, but nobody should be able to say it is allowed by being odd.
#[must_use]
pub fn is_reserved_namespace(namespace: &str) -> bool {
    let (n, suffix) = (namespace.as_bytes(), RESERVED_SUFFIX.as_bytes());
    n.len() >= suffix.len() && n[n.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
}

impl Namespace {
    /// Every namespace of the system.
    pub const ALL: [Namespace; 7] = [
        Namespace::Call,
        Namespace::Request,
        Namespace::Approval,
        Namespace::Clearance,
        Namespace::Connection,
        Namespace::Broker,
        Namespace::Hosts,
    ];

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Namespace::Call => "call-v1@procession",
            Namespace::Request => "request-v1@procession",
            Namespace::Approval => "approval-v1@procession",
            Namespace::Clearance => "clearance-v1@procession",
            Namespace::Connection => "connection-v1@procession",
            Namespace::Broker => "broker-v1@procession",
            Namespace::Hosts => "hosts-v1@procession",
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
    #[error("an agent's key must be Ed25519, this one is `{0}`")]
    AgentKeyNotEd25519(String),
    #[error("an agent's certificate must be a user certificate")]
    NotUserCertificate,
    #[error("the agent's certificate has the critical option `{0}`")]
    CriticalOption(String),
    #[error(
        "the certificate has the extension `{0}`; certificates the site CA issues carry none (issue them with `-O clear`)"
    )]
    SiteCertificateExtension(String),
    #[error("the agent's certificate has the extension `{0}`, only `groups@procession` is allowed")]
    UnknownExtension(String),
    #[error("the agent's certificate has a bad `groups@procession`: {0}")]
    BadGroups(&'static str),
    #[error("`{0}` is not a fingerprint like SHA256:<43 base64 characters>")]
    MalformedFingerprint(String),
    #[error("the certificate has bytes after its signature, which the signature does not cover")]
    CertificateTrailingData,
    #[error("the certificate is for another person or role than the one expected")]
    NotTheExpectedName,
    #[error("the certificate is not valid yet")]
    CertificateNotYetValid,
    #[error("the certificate has expired")]
    CertificateExpired,
    #[error("`{0}` is not an approval key's name, `<person>:confirmed` or `<person>:automatic`")]
    NotAnApprovalName(String),
    #[error("`{0}` is a name the site CA must never certify for a person")]
    ReservedName(String),
    #[error("a signer's raw signature is refused: {0}")]
    RawSignature(&'static str),
    #[error("the key holder failed: {0}")]
    Holder(String),
    #[error("the signature carries a certificate, and a plain key was expected")]
    UnexpectedCertificate,
    #[error("ssh-keygen did not accept the certificate: {0}")]
    CertificateNotVerified(String),
    #[error("ssh-keygen printed no signing key for the certificate")]
    NoIssuer,
    #[error("the certificate was signed by another key than the one expected")]
    WrongIssuer,
    #[error("the request's call is another person's than the one these approval keys belong to")]
    ApprovalForAnotherPerson,
    #[error("not a certificate line: `<type> <base64> [comment]`")]
    MalformedCertificateLine,
    #[error("the confirmed and the automatic approval key are the same key")]
    SameApprovalKey,
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
    /// The public key of a key's wire form (a key's, not a certificate's), if it is of a supported type.
    pub(crate) fn from_blob(blob: &[u8]) -> Result<PublicKey, SignError> {
        let kind = key_type(blob).ok_or_else(|| SignError::MalformedPublicKey(String::new()))?;
        PublicKey::parse(&format!("{kind} {}", STANDARD.encode(blob)))
    }

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
        if !SUPPORTED_KEYS.contains(&kind) {
            return Err(SignError::UnsupportedKeyType(kind.to_owned()));
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

/// A key's fingerprint as `ssh-keygen -l` prints it: `SHA256:` and the
/// unpadded base64 of the SHA-256 of the public key's wire form. A
/// certificate's key is fingerprinted without its certificate, so a key has
/// one fingerprint however it is certified. A delegation is known by the
/// fingerprint of its agent's key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fingerprint(String);

impl Fingerprint {
    pub(crate) fn of_blob(blob: &[u8]) -> Fingerprint {
        Fingerprint(format!("SHA256:{}", STANDARD_NO_PAD.encode(digest(&SHA256, blob))))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::str::FromStr for Fingerprint {
    type Err = SignError;

    fn from_str(s: &str) -> Result<Self, SignError> {
        let ok = s
            .strip_prefix("SHA256:")
            .is_some_and(|b| b.len() == 43 && b.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'+' | b'/')));
        if ok { Ok(Fingerprint(s.to_owned())) } else { Err(SignError::MalformedFingerprint(s.to_owned())) }
    }
}

impl PublicKey {
    #[must_use]
    pub fn fingerprint(&self) -> Fingerprint {
        // Validated at construction: `<type> <base64 of a blob>`.
        let blob = self.0.split(' ').nth(1).and_then(|b| STANDARD.decode(b).ok()).unwrap_or_default();
        Fingerprint::of_blob(&blob)
    }
}

impl SshsigSigner for Signer {
    fn sign(&self, namespace: Namespace, message: &[u8]) -> Result<String, SignError> {
        self.sign_with_keygen(namespace, message)
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

    fn sign_with_keygen(&self, namespace: Namespace, bytes: &[u8]) -> Result<String, SignError> {
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

pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = (self.0.get(..n)?, self.0.get(n..)?);
        self.0 = tail;
        Some(head)
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    pub(crate) fn u64(&mut self) -> Option<u64> {
        Some(u64::from_be_bytes(self.take(8)?.try_into().ok()?))
    }

    pub(crate) fn string(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()?;
        self.take(usize::try_from(n).ok()?)
    }
}

/// What a certificate inside a signature says about itself. Unverified, and
/// not judged: [`signature_agent`] applies the rules for an agent's certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub key_id: String,
    pub principals: Vec<String>,
    /// Seconds since the Unix epoch.
    pub valid_after: u64,
    /// Seconds since the Unix epoch.
    pub valid_before: u64,
    /// Critical options: name and raw data.
    pub critical_options: Vec<(String, Vec<u8>)>,
    /// Extensions: name and data. The data of an extension with a value is that value, unwrapped.
    pub extensions: Vec<(String, Vec<u8>)>,
    /// Fingerprint of the certified key.
    pub fingerprint: Fingerprint,
    /// The certified key's type, like `ssh-ed25519`.
    pub key_type: String,
    /// 1 for a user certificate, 2 for a host certificate.
    pub cert_type: u32,
    /// The fingerprint of the key the certificate says signed it. **A claim**: nothing was verified.
    /// [`certificate_issuer`] has `ssh-keygen` verify the certificate's signature.
    pub issuer: Fingerprint,
    /// The certified key's wire form, without the certificate.
    pub key_blob: Vec<u8>,
}

pub(crate) fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&u32::try_from(s.len()).unwrap_or(u32::MAX).to_be_bytes());
    out.extend_from_slice(s);
}

/// The name of the extension that carries a delegation's groups.
pub const GROUPS_EXTENSION: &str = "groups@procession";

/// Name/data pairs of a certificate's option or extension list. The data is a
/// string, which for a value is itself a string; an empty one has no value.
fn name_data_list(list: &[u8], unwrap_value: bool) -> Option<Vec<(String, Vec<u8>)>> {
    let mut r = Reader(list);
    let mut out = Vec::new();
    while !r.0.is_empty() {
        let name = String::from_utf8(r.string()?.to_vec()).ok()?;
        let data = r.string()?;
        let data = if unwrap_value && !data.is_empty() {
            let mut inner = Reader(data);
            let value = inner.string()?;
            if !inner.0.is_empty() {
                return None;
            }
            value
        } else {
            data
        };
        out.push((name, data.to_vec()));
    }
    Some(out)
}

/// The type name of a public key blob.
pub(crate) fn key_type(blob: &[u8]) -> Option<String> {
    String::from_utf8(Reader(blob).string()?.to_vec()).ok()
}

/// The public key blob inside an armoured SSHSIG: a certificate for a
/// certified key, else the plain key.
fn signature_key_blob(sig: &str) -> Result<Vec<u8>, SignError> {
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
    Ok(r.string().ok_or_else(bad)?.to_vec())
}

/// The fingerprint of the key that made `sig`: of the certified key if the
/// signature carries a certificate, else of the plain key. Read, not
/// verified; only Ed25519 and ECDSA P-256 are read.
pub fn signature_fingerprint(sig: &str) -> Result<Fingerprint, SignError> {
    let blob = signature_key_blob(sig)?;
    let kind = key_type(&blob).ok_or(SignError::MalformedSignature)?;
    if kind.contains("-cert-v01@") {
        return Ok(signature_certificate(sig)?.fingerprint);
    }
    if !SUPPORTED_KEYS.contains(&kind.as_str()) {
        return Err(SignError::UnsupportedKeyType(kind));
    }
    Ok(Fingerprint::of_blob(&blob))
}

/// The certificate inside an armoured SSHSIG, read, not verified. The key it
/// certifies and the key that issued it must both be of a supported type.
pub fn signature_certificate(sig: &str) -> Result<Certificate, SignError> {
    certificate_from_blob(&signature_key_blob(sig)?)
}

/// Read a certificate from its wire form (the blob of a `-cert.pub` line, or
/// the public key field of a signature). Not verified.
pub(crate) fn certificate_from_blob(blob: &[u8]) -> Result<Certificate, SignError> {
    let bad = || SignError::MalformedSignature;
    let mut key = Reader(blob);
    let kind = String::from_utf8_lossy(key.string().ok_or_else(bad)?).into_owned();
    if !kind.contains("-cert-v01@") {
        return Err(SignError::NotCertified);
    }
    // The subject key's fields differ by type: Ed25519 has one string, ECDSA a curve and a point.
    let key_fields = match kind.as_str() {
        "ssh-ed25519-cert-v01@openssh.com" => 1,
        "ecdsa-sha2-nistp256-cert-v01@openssh.com" => 2,
        _ => return Err(SignError::UnsupportedKeyType(kind)),
    };
    // nonce, public key, serial, type, key id, principals, validity, options, extensions, reserved, issuer key.
    let _nonce = key.string().ok_or_else(bad)?;
    // The certified key's wire form without the certificate: its plain type, then the same fields.
    let mut plain = Vec::new();
    put_string(&mut plain, kind.trim_end_matches("-cert-v01@openssh.com").as_bytes());
    for _ in 0..key_fields {
        put_string(&mut plain, key.string().ok_or_else(bad)?);
    }
    let _serial = key.u64().ok_or_else(bad)?;
    let cert_type = key.u32().ok_or_else(bad)?;
    let key_id = String::from_utf8(key.string().ok_or_else(bad)?.to_vec()).map_err(|_| bad())?;
    let mut list = Reader(key.string().ok_or_else(bad)?);
    let mut principals = Vec::new();
    while !list.0.is_empty() {
        principals.push(String::from_utf8(list.string().ok_or_else(bad)?.to_vec()).map_err(|_| bad())?);
    }
    let valid_after = key.u64().ok_or_else(bad)?;
    let valid_before = key.u64().ok_or_else(bad)?;
    let critical_options = name_data_list(key.string().ok_or_else(bad)?, false).ok_or_else(bad)?;
    let extensions = name_data_list(key.string().ok_or_else(bad)?, true).ok_or_else(bad)?;
    let _reserved = key.string().ok_or_else(bad)?;
    let issuer_blob = key.string().ok_or_else(bad)?;
    let issuer = key_type(issuer_blob).ok_or_else(bad)?;
    if !SUPPORTED_KEYS.contains(&issuer.as_str()) {
        return Err(SignError::UnsupportedKeyType(issuer));
    }
    let issuer = Fingerprint::of_blob(issuer_blob);
    // The signature is the last field and the end of the certificate: what follows is not covered by it.
    let _signature = key.string().ok_or_else(bad)?;
    if !key.0.is_empty() {
        return Err(SignError::CertificateTrailingData);
    }
    let fingerprint = Fingerprint::of_blob(&plain);
    let key_type = kind.trim_end_matches("-cert-v01@openssh.com").to_owned();
    Ok(Certificate {
        key_id,
        principals,
        valid_after,
        valid_before,
        critical_options,
        extensions,
        fingerprint,
        key_type,
        cert_type,
        issuer,
        key_blob: plain,
    })
}

/// What an agent's certificate says (formats section 3.1): the person it acts
/// for and the groups of its delegation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Agent {
    /// The one principal: for a service, the only thing it needs.
    pub person: String,
    /// From the extension `groups@procession`; sorted, without duplicates; empty if there is none.
    pub groups: Vec<String>,
    /// The certificate's free label, for dialogs and the record; never to decide on.
    pub key_id: String,
    /// The fingerprint of the agent's key: the delegation's identifier.
    pub delegation: Fingerprint,
    /// The certificate's validity, seconds since the epoch. Not judged here: `ssh-keygen` does when it verifies.
    pub valid_after: u64,
    pub valid_before: u64,
}

/// The person and groups of the agent's certificate inside `sig`, if it keeps
/// to section 3.1: exactly one principal, a person's name; no critical
/// option; no extension but a well-formed `groups@procession`. A claim until a
/// verification succeeds ([`verify_call_agent`]).
pub fn signature_agent(sig: &str) -> Result<Agent, SignError> {
    agent_from_certificate(signature_certificate(sig)?)
}

/// The wire form of the certificate on a `-cert.pub` line: `<type> <base64> [comment]`, the type inside
/// the blob being the one named. Not judged.
pub(crate) fn certificate_line_blob(line: &str) -> Result<Vec<u8>, SignError> {
    let bad = || SignError::MalformedCertificateLine;
    if line.bytes().any(|b| b < b' ' || b == 0x7f) {
        return Err(bad());
    }
    let mut parts = line.split(' ');
    let (kind, b64) = (parts.next().ok_or_else(bad)?, parts.next().ok_or_else(bad)?);
    let blob = STANDARD.decode(b64).map_err(|_| bad())?;
    if Reader(&blob).string() != Some(kind.as_bytes()) {
        return Err(bad());
    }
    Ok(blob)
}

/// The formats section 3.1 rules applied to a bare certificate line (a `-cert.pub` file's content), the
/// same rules and errors as [`signature_agent`] applies to the certificate inside a signature: exactly
/// one principal, a person's name; no critical option; no extension but a well-formed
/// `groups@procession`; **the certified key is Ed25519**; a user certificate; the issuing key Ed25519
/// or P-256. For pledge to check a certificate before it hands it out, and for the broker to check one
/// at registration. Validity is reported in the result, not judged.
pub fn agent_certificate(line: &str) -> Result<Agent, SignError> {
    agent_from_certificate(certificate_from_blob(&certificate_line_blob(line)?)?)
}

/// The section 3.1 rules for an agent's certificate, on one already read. The
/// certified key must be Ed25519, always: pledge makes it, and the signer in
/// the sandbox refuses any other.
pub(crate) fn agent_from_certificate(cert: Certificate) -> Result<Agent, SignError> {
    if cert.key_type != "ssh-ed25519" {
        return Err(SignError::AgentKeyNotEd25519(cert.key_type));
    }
    if cert.cert_type != 1 {
        return Err(SignError::NotUserCertificate);
    }
    if let Some((name, _)) = cert.critical_options.first() {
        return Err(SignError::CriticalOption(name.clone()));
    }
    let mut groups = None;
    for (name, data) in &cert.extensions {
        if name != GROUPS_EXTENSION {
            return Err(SignError::UnknownExtension(name.clone()));
        }
        if groups.replace(parse_groups(data)?).is_some() {
            return Err(SignError::BadGroups("the extension appears twice"));
        }
    }
    let person = match <[String; 1]>::try_from(cert.principals) {
        Ok([person]) if text::is_name(&person) => person,
        Ok([other]) => return Err(SignError::BadPrincipal(other)),
        Err(many) => return Err(SignError::PrincipalCount { found: many.len() }),
    };
    Ok(Agent {
        person,
        groups: groups.unwrap_or_default(),
        key_id: cert.key_id,
        delegation: cert.fingerprint,
        valid_after: cert.valid_after,
        valid_before: cert.valid_before,
    })
}

fn parse_groups(value: &[u8]) -> Result<Vec<String>, SignError> {
    let value = std::str::from_utf8(value).map_err(|_| SignError::BadGroups("not UTF-8"))?;
    let groups: Vec<String> = value.split(',').map(str::to_owned).collect();
    for g in &groups {
        if g.is_empty() {
            return Err(SignError::BadGroups("an empty name"));
        }
        text::check("groups", g).map_err(|_| SignError::BadGroups("a control or bidirectional character"))?;
        if g.contains(char::is_whitespace) {
            return Err(SignError::BadGroups("a space in a name"));
        }
    }
    // Strictly increasing is sorted and without duplicates at once.
    if let Some(pair) = groups.windows(2).find(|w| w[0] >= w[1]) {
        return Err(SignError::BadGroups(if pair[0] == pair[1] { "a duplicate" } else { "not sorted" }));
    }
    Ok(groups)
}

/// The person an agent's signature names: [`signature_agent`] without the groups.
pub fn signature_person(sig: &str) -> Result<String, SignError> {
    signature_agent(sig).map(|a| a.person)
}

/// A signature as it is carried inside another document: the base64
/// (standard alphabet, padded) of its armoured bytes.
#[must_use]
pub fn signature_to_base64(armoured: &str) -> String {
    STANDARD.encode(armoured)
}

/// The armoured signature in `encoded`, which must be padded standard base64
/// of text that looks armoured.
pub fn signature_from_base64(encoded: &str) -> Result<String, SignError> {
    let bytes = STANDARD.decode(encoded).map_err(|_| SignError::MalformedSignature)?;
    let sig = String::from_utf8(bytes).map_err(|_| SignError::MalformedSignature)?;
    if looks_armoured(&sig) { Ok(sig) } else { Err(SignError::MalformedSignature) }
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
pub fn sign_call(signer: &(impl SshsigSigner + ?Sized), call: &Call) -> Result<String, SignError> {
    signer.sign(Namespace::Call, call.as_bytes())
}

/// Verify a call's signature against the person's `delegation_key`, under the
/// principal in the agent's certificate. Returns that person. Checks the
/// certificate's validity as `ssh-keygen` does.
pub fn verify_call(call: &Call, sig: &str, delegation_key: &PublicKey) -> Result<String, SignError> {
    verify_call_agent(call, sig, delegation_key).map(|a| a.person)
}

/// As [`verify_call`], and the groups of the delegation too, for the broker.
/// The certificate must keep to formats section 3.1.
pub fn verify_call_agent(call: &Call, sig: &str, delegation_key: &PublicKey) -> Result<Agent, SignError> {
    let agent = signature_agent(sig)?;
    let allowed = ca_line(&agent.person, &[Namespace::Call], delegation_key);
    verify(Namespace::Call, &allowed, &agent.person, sig, call.as_bytes())?;
    Ok(agent)
}

/// Sign a request with the service's key, certified by its host's key.
pub fn sign_request(signer: &(impl SshsigSigner + ?Sized), request: &Request) -> Result<String, SignError> {
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
    /// The one person's two approval keys, listed directly (stage 1: no site CA). `person` says whose
    /// they are: a request whose call is another person's is refused ([`SignError::ApprovalForAnotherPerson`]),
    /// since the keys prove nothing about a person the trust does not name.
    PersonKeys { person: &'a str, confirmed: &'a PublicKey, automatic: &'a PublicKey },
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
pub fn sign_approval(signer: &(impl SshsigSigner + ?Sized), request: &Request) -> Result<String, SignError> {
    signer.sign(Namespace::Approval, request.as_bytes())
}

/// Verify an approval of exactly this request by the person its call names
/// (read from `call_sig`, see [`request_person`]). A confirmed approval is
/// always accepted; an automatic one only for a request rated below the top
/// of every scale. Returns which key signed.
pub fn verify_approval(request: &Request, sig: &str, trust: ApprovalTrust<'_>) -> Result<ApprovalKind, SignError> {
    let person = request_person(request)?;
    if let ApprovalTrust::PersonKeys { person: whose, confirmed, automatic } = trust {
        // One key under both names would make every automatic approval verify as confirmed.
        if confirmed == automatic {
            return Err(SignError::SameApprovalKey);
        }
        if !text::is_name(whose) {
            return Err(SignError::BadPrincipal(whose.to_owned()));
        }
        // These keys are `whose`; the call must be `whose` too, or an approval by the right keys covers another person's request.
        if person != whose {
            return Err(SignError::ApprovalForAnotherPerson);
        }
    }
    let signed = |kind: ApprovalKind| {
        let principal = format!("{person}:{}", kind.suffix());
        let allowed = match trust {
            ApprovalTrust::SiteCa(ca) => ca_line("*:confirmed,*:automatic", &[Namespace::Approval], ca),
            ApprovalTrust::PersonKeys { confirmed, automatic, .. } => key_line(
                &principal,
                Namespace::Approval,
                if kind == ApprovalKind::Confirmed { confirmed } else { automatic },
            ),
        };
        verify(Namespace::Approval, &allowed, &principal, sig, request.as_bytes())
    };
    let attempt = |kind: ApprovalKind| {
        signed(kind)?;
        // Signed by a key certified by the site CA: its certificate has no option or extension.
        if matches!(trust, ApprovalTrust::SiteCa(_)) {
            site_certificate_in(sig)?;
        }
        Ok::<(), SignError>(())
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
pub fn sign_clearance(signer: &(impl SshsigSigner + ?Sized), clearance: &Clearance) -> Result<String, SignError> {
    signer.sign(Namespace::Clearance, clearance.as_bytes())
}

/// Verify a clearance against the site CA, under the name `broker`. Whether it
/// is fresh, and whether it covers the request at hand ([`Clearance::covers`]),
/// is the caller's to check.
pub fn verify_clearance(clearance: &Clearance, sig: &str, site_ca: &PublicKey) -> Result<(), SignError> {
    let allowed = ca_line("broker", &[Namespace::Clearance], site_ca);
    verify(Namespace::Clearance, &allowed, "broker", sig, clearance.as_bytes())?;
    site_certificate_in(sig)
}

// ---------------------------------------------------------------------------
// The sign-in, and what the broker says in its own name
// ---------------------------------------------------------------------------

/// Sign a connection document (`approval-connections.md` section 5, sign-in) with the person's
/// connection key, a plain key: `connection-v1@procession`.
pub fn sign_connection(signer: &(impl SshsigSigner + ?Sized), document: &[u8]) -> Result<String, SignError> {
    signer.sign(Namespace::Connection, document)
}

/// Verify a sign-in's signature over the connection document's bytes: `connection-v1@procession`, by
/// `connection_key` as listed directly for `person` (a plain line, not a certificate authority). The
/// signature must not carry a certificate: the key is plain (`approvals.md` section 5). A plain key's
/// signature carries no name, so `person` is only the label this key is listed under: the caller binds
/// person to key by choosing which key to pass (the one the site project has for that person). What the
/// document says (the person, the nonce, the TLS binding) is the caller's to check.
pub fn verify_connection(
    person: &str,
    connection_key: &PublicKey,
    sig: &str,
    document: &[u8],
) -> Result<(), SignError> {
    if !text::is_name(person) {
        return Err(SignError::BadPrincipal(person.to_owned()));
    }
    // `ssh-keygen` would match the certified key against a plain line; this key is not certified, so a certificate is refused.
    if key_type(&signature_key_blob(sig)?).is_some_and(|t| t.contains("-cert-v01@")) {
        return Err(SignError::UnexpectedCertificate);
    }
    let allowed = key_line(person, Namespace::Connection, connection_key);
    verify(Namespace::Connection, &allowed, person, sig, document)
}

/// Sign what the broker says in its own name (the standing) with the broker's key, certified by the
/// site CA as `broker`: `broker-v1@procession`.
pub fn sign_broker(signer: &(impl SshsigSigner + ?Sized), document: &[u8]) -> Result<String, SignError> {
    signer.sign(Namespace::Broker, document)
}

/// Verify what the broker says in its own name, as pledge does: `broker-v1@procession`, under the name
/// `broker`, against the site CA's key. A person's key, certified for a person, does not verify here.
pub fn verify_broker(site_ca: &PublicKey, sig: &str, document: &[u8]) -> Result<(), SignError> {
    let allowed = ca_line("broker", &[Namespace::Broker], site_ca);
    verify(Namespace::Broker, &allowed, "broker", sig, document)?;
    site_certificate_in(sig)
}

// ---------------------------------------------------------------------------
// Which key issued a bare certificate
// ---------------------------------------------------------------------------

/// The fingerprint of the key that **signed** the certificate on `line`, found by `ssh-keygen -L`. That
/// command reads the certificate through the code `sshd` uses, which verifies the certificate's
/// signature against the signing key inside it and refuses the certificate if it does not match; so what
/// comes back is the issuer of a certificate whose signature is good, and a certificate with a damaged
/// byte anywhere is an error ([`SignError::CertificateNotVerified`]), as the tests here show for every
/// byte of one. It does not look at validity. The caller compares the fingerprint with the issuer it
/// expects, or uses [`verify_agent_certificate`].
pub fn certificate_issuer(line: &str) -> Result<Fingerprint, SignError> {
    // Judge the shape first: one line, no control character, the type inside the blob the one named.
    let blob = certificate_line_blob(line)?;
    let claimed = certificate_from_blob(&blob)?.issuer;
    let dir = tempfile::tempdir()?;
    let file = dir.path().join("cert.pub");
    std::fs::write(&file, format!("{line}\n"))?;
    let out = match run(&["-L".as_ref(), "-f".as_ref(), file.as_os_str()], b"") {
        Ok(out) => out,
        Err(SignError::Tool { stderr, status }) => {
            return Err(SignError::CertificateNotVerified(if stderr.is_empty() { status } else { stderr }));
        }
        Err(other) => return Err(other),
    };
    let text = String::from_utf8_lossy(&out);
    let printed: Fingerprint = text
        .lines()
        .find_map(|l| l.trim().strip_prefix("Signing CA:"))
        .and_then(|rest| rest.split_whitespace().find(|w| w.starts_with("SHA256:")))
        .and_then(|fp| fp.parse().ok())
        .ok_or(SignError::NoIssuer)?;
    // What `ssh-keygen` verified against and what the blob says are one key.
    if printed != claimed {
        return Err(SignError::WrongIssuer);
    }
    Ok(printed)
}

/// An agent's certificate checked in full, as pledge does before it hands one out and the broker at
/// registration: the section 3.1 rules ([`agent_certificate`]: one principal, no critical option, only a
/// well-formed `groups@procession`, the certified key Ed25519, a user certificate), **and** its
/// signature is good and made by `delegation_key` ([`certificate_issuer`]). The validity is in the
/// result (`valid_after`, `valid_before`) and is the caller's to judge.
pub fn verify_agent_certificate(line: &str, delegation_key: &PublicKey) -> Result<Agent, SignError> {
    let agent = agent_certificate(line)?;
    if certificate_issuer(line)? != delegation_key.fingerprint() {
        return Err(SignError::WrongIssuer);
    }
    Ok(agent)
}

// ---------------------------------------------------------------------------
// An approval key's certificate, against the site CA
// ---------------------------------------------------------------------------

/// What a verified certificate of an approval key says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalCertificate {
    /// The person: the part of the one principal before the `:`.
    pub person: String,
    /// `confirmed` or `automatic`: the part after it.
    pub kind: ApprovalKind,
    /// The key the certificate certifies (Ed25519 or ECDSA P-256).
    pub key: PublicKey,
    /// The certificate's label; never to decide on.
    pub key_id: String,
    /// Seconds since the Unix epoch.
    pub valid_after: u64,
    /// Seconds since the Unix epoch (the largest value for "forever").
    pub valid_before: u64,
}

impl ApprovalCertificate {
    /// Whether this certificate is for `key`.
    #[must_use]
    pub fn certifies(&self, key: &PublicKey) -> bool {
        self.key == *key
    }

    /// Whether `now` is within the certificate's validity: at or after its start, before its end (the end is exclusive,
    /// as `ssh-keygen` treats it).
    pub fn valid_at(&self, now: crate::time::Timestamp) -> Result<(), SignError> {
        let now = u64::try_from(now.unix()).unwrap_or(0);
        if now < self.valid_after {
            Err(SignError::CertificateNotYetValid)
        } else if now >= self.valid_before {
            Err(SignError::CertificateExpired)
        } else {
            Ok(())
        }
    }
}

/// The names the site CA must never certify for a person (formats section 7).
const RESERVED_PERSONS: [&str; 2] = ["broker", "hosts"];

fn shown(s: &str) -> String {
    s.chars().take(64).collect()
}

/// A certificate of an approval key, as the issuer made it (the line of a `-cert.pub` file), checked against the
/// site CA's key `site_ca` at the time `now`, for pledge loading certificates from a standing or from disk and for
/// the broker's separate input. It is accepted only if **all** of this holds:
///
/// - it is one certificate line, of an Ed25519 or ECDSA P-256 key, issued by an Ed25519 or P-256 key;
/// - it is a user certificate with **one** principal, `<person>:confirmed` or `<person>:automatic`, `<person>` being a
///   person's name and not one the CA never certifies (`broker`, `hosts`), and **no critical option**;
/// - **its signature is good and is the site CA's, and no other key's**: `ssh-keygen -L` verifies the certificate's
///   signature and the issuer it prints is compared with `site_ca` ([`certificate_issuer`]);
/// - `now` is not before its start and before its end (the caller gives the time; ends are exclusive, as `ssh-keygen`
///   treats them).
///
/// Which key it certifies, and for whom, is in the result: the caller checks it is the key and the person it expects
/// ([`ApprovalCertificate::certifies`], `person`). Extensions are not judged: the documents say nothing of them for
/// approval keys.
pub fn verify_approval_certificate(
    line: &str,
    site_ca: &PublicKey,
    now: crate::time::Timestamp,
) -> Result<ApprovalCertificate, SignError> {
    let cert = check_approval_certificate(line, site_ca)?;
    cert.valid_at(now)?;
    Ok(cert)
}

/// As [`verify_approval_certificate`], and the certificate must be for exactly `person` and `kind`: its one principal is
/// `<person>:<kind>`. This is what pledge asks for a certificate of its own person's key.
pub fn verify_approval_certificate_for(
    line: &str,
    site_ca: &PublicKey,
    person: &str,
    kind: ApprovalKind,
    now: crate::time::Timestamp,
) -> Result<ApprovalCertificate, SignError> {
    let cert = verify_approval_certificate(line, site_ca, now)?;
    if cert.person == person && cert.kind == kind { Ok(cert) } else { Err(SignError::NotTheExpectedName) }
}

/// A certificate the site CA issues (an approval key's, the broker's) carries **no critical option and no extension**
/// (`approval-formats.md` section 3.2): what is not specified must not be there, since some other consumer of OpenSSH
/// certificates might honour it.
fn no_option_or_extension(cert: &Certificate) -> Result<(), SignError> {
    if let Some((name, _)) = cert.critical_options.first() {
        return Err(SignError::CriticalOption(shown(name)));
    }
    if let Some((name, _)) = cert.extensions.first() {
        return Err(SignError::SiteCertificateExtension(shown(name)));
    }
    Ok(())
}

/// After a signature by a site-CA-certified key verified: the certificate inside it has no option or extension.
fn site_certificate_in(sig: &str) -> Result<(), SignError> {
    no_option_or_extension(&signature_certificate(sig)?)
}

/// Everything of [`verify_approval_certificate`] except the time: the shape, the name, the issuer and the signature. The
/// caller judges validity itself, from `valid_after` and `valid_before` or [`ApprovalCertificate::valid_at`].
pub fn check_approval_certificate(line: &str, site_ca: &PublicKey) -> Result<ApprovalCertificate, SignError> {
    let cert = certificate_from_blob(&certificate_line_blob(line)?)?;
    if cert.cert_type != 1 {
        return Err(SignError::NotUserCertificate);
    }
    no_option_or_extension(&cert)?;
    let principal = match <[String; 1]>::try_from(cert.principals.clone()) {
        Ok([p]) => p,
        Err(many) => return Err(SignError::PrincipalCount { found: many.len() }),
    };
    let (person, kind) = match principal.rsplit_once(':') {
        Some((person, "confirmed")) => (person, ApprovalKind::Confirmed),
        Some((person, "automatic")) => (person, ApprovalKind::Automatic),
        _ => return Err(SignError::NotAnApprovalName(shown(&principal))),
    };
    if !text::is_name(person) {
        return Err(SignError::NotAnApprovalName(shown(&principal)));
    }
    if RESERVED_PERSONS.contains(&person) {
        return Err(SignError::ReservedName(person.to_owned()));
    }
    // The signature and the issuer, by `ssh-keygen`, before anything of the certificate is believed.
    if certificate_issuer(line)? != site_ca.fingerprint() {
        return Err(SignError::WrongIssuer);
    }
    Ok(ApprovalCertificate {
        person: person.to_owned(),
        kind,
        key: PublicKey::from_blob(&cert.key_blob)?,
        key_id: cert.key_id,
        valid_after: cert.valid_after,
        valid_before: cert.valid_before,
    })
}
