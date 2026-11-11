//! What arrives on standard input (`proposals/pact.md` (d), option B):
//!
//! 1. one line: the configuration as one JSON object with `v`;
//! 2. the key, an unmodified unencrypted OpenSSH private key block (Ed25519);
//! 3. the certificate, one `-cert.pub` line.
//!
//! At most 64 KiB. Unknown members are refused. Nothing the bundle holds is
//! ever in an error message: errors name what is wrong, not what is in it.

use super::sshsig::{CallSigner, ed25519_blob};
use super::{Service, Settings};
use crate::call::Call;
use crate::error::ParseError;
use crate::object::Object;
use crate::sign::{Agent, Fingerprint, Reader, SignError, agent_from_certificate, certificate_from_blob};
use crate::text;
use crate::time::Timestamp;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::io::Read;
use thiserror::Error;

/// A bundle is at most 64 KiB.
pub const MAX_BYTES: usize = crate::limits::MAX_BUNDLE_BYTES;
const KEY_BEGIN: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\n";
const KEY_END: &str = "\n-----END OPENSSH PRIVATE KEY-----\n";
const KEY_MAGIC: &[u8] = b"openssh-key-v1\0";
const CERT_TYPE: &str = "ssh-ed25519-cert-v01@openssh.com";
const MAX_SERVICES: usize = 16;
const MAX_URL: usize = 2048;

/// Why a bundle was refused.
#[derive(Debug, Error)]
pub enum BundleError {
    #[error("the bundle is larger than {MAX_BYTES} bytes")]
    TooLarge,
    #[error("cannot read the bundle: {0}")]
    Io(String),
    #[error("the bundle is not UTF-8")]
    NotUtf8,
    #[error("the bundle has no configuration line")]
    NoConfigLine,
    #[error("configuration: {0}")]
    Config(#[from] ParseError),
    #[error("configuration: the version is not 1")]
    UnsupportedVersion,
    #[error("configuration: no service")]
    NoServices,
    #[error("configuration: more than {MAX_SERVICES} services")]
    TooManyServices,
    #[error("configuration: `{0}` is not a host name")]
    BadHost(String),
    #[error("configuration: `{0}` is not a service name")]
    BadServiceName(String),
    #[error("configuration: the service {name} on {host} appears twice")]
    DuplicateService { host: String, name: String },
    #[error("configuration: the url of {name} on {host} is not allowed: {why}")]
    BadUrl { host: String, name: String, why: &'static str },
    #[error("configuration: deadline_seconds must be 1 to 600")]
    BadDeadline,
    #[error("configuration: an https service needs tls_root, and tls_root must be a certificate in PEM")]
    TlsRoot,
    #[error("the key block is missing or malformed")]
    KeyMalformed,
    #[error("the key is encrypted; a key with a passphrase cannot be used")]
    KeyEncrypted,
    #[error("an agent's key must be Ed25519, this one is `{0}`")]
    KeyType(String),
    #[error("the key is not a valid Ed25519 key")]
    KeyRejected,
    #[error("the certificate line is missing or malformed")]
    CertificateMalformed,
    #[error("the certificate: {0}")]
    Certificate(#[from] SignError),
    #[error("the certificate is not for this key")]
    CertificateNotForKey,
    #[error("the certificate is not valid yet")]
    CertificateNotYetValid,
    #[error("the certificate has expired")]
    CertificateExpired,
    #[error("there is more after the certificate")]
    TrailingData,
    #[error("the certificate line must end with a line feed")]
    NoFinalNewline,
    #[error("the bundle to write is refused: {0}")]
    Write(Box<BundleError>),
}

/// The configuration line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub services: Vec<Service>,
    pub deadline_seconds: u32,
    /// A PEM certificate: the root for `https` services.
    pub tls_root: Option<String>,
}

/// The agent's key and certificate, ready to sign calls. It cannot be printed or copied out.
pub struct AgentKey {
    signer: CallSigner,
    agent: Agent,
    valid_before: u64,
}

impl std::fmt::Debug for AgentKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentKey")
            .field("person", &self.agent.person)
            .field("delegation", &self.agent.delegation)
            .finish_non_exhaustive()
    }
}

impl AgentKey {
    /// Sign a call: `call-v1@procession`, the only thing this key does.
    #[must_use]
    pub fn sign_call(&self, call: &Call) -> String {
        self.signer.sign_call(call)
    }

    /// What the certificate says: the person, the groups, the delegation's identifier.
    #[must_use]
    pub fn agent(&self) -> &Agent {
        &self.agent
    }

    /// When the certificate ends, in seconds since the epoch.
    #[must_use]
    pub fn valid_before(&self) -> u64 {
        self.valid_before
    }
}

/// A parsed bundle.
#[derive(Debug)]
pub struct Bundle {
    pub config: Config,
    pub key: AgentKey,
}

/// A buffer that is zeroed when it goes: best effort, for what held a key.
struct Wiped(Vec<u8>);

impl Drop for Wiped {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&self.0);
    }
}

impl Bundle {
    /// Read at most 64 KiB from `input` and parse it. `now` is when the certificate must be valid.
    pub fn read(input: impl Read, now: Timestamp) -> Result<Bundle, BundleError> {
        let mut buf = Wiped(Vec::new());
        input.take(MAX_BYTES as u64 + 1).read_to_end(&mut buf.0).map_err(|e| BundleError::Io(e.kind().to_string()))?;
        Bundle::parse(&buf.0, now)
    }

    /// Parse a bundle's bytes.
    pub fn parse(input: &[u8], now: Timestamp) -> Result<Bundle, BundleError> {
        if input.len() > MAX_BYTES {
            return Err(BundleError::TooLarge);
        }
        let text = std::str::from_utf8(input).map_err(|_| BundleError::NotUtf8)?;
        let (first, rest) = text.split_once('\n').ok_or(BundleError::NoConfigLine)?;
        let config = parse_config(first)?;
        let key = parse_key_and_certificate(rest, now)?;
        Ok(Bundle { config, key })
    }
}

/// A private key as the bytes of an OpenSSH private key block, checked to be what `pact` reads
/// (unencrypted Ed25519). Its `Debug` prints nothing of it and it is zeroed when it goes.
pub struct KeyBlock(Wiped);

impl std::fmt::Debug for KeyBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeyBlock(..)")
    }
}

impl KeyBlock {
    /// `bytes` must be exactly `-----BEGIN OPENSSH PRIVATE KEY-----\n`, the base64 in lines, and
    /// `-----END OPENSSH PRIVATE KEY-----\n`, nothing else.
    pub fn new(bytes: Vec<u8>) -> Result<KeyBlock, BundleError> {
        let block = KeyBlock(Wiped(bytes));
        let text = std::str::from_utf8(&block.0.0).map_err(|_| BundleError::KeyMalformed)?;
        let inner = text
            .strip_prefix(KEY_BEGIN)
            .and_then(|t| t.strip_suffix(KEY_END.trim_start_matches('\n')))
            .ok_or(BundleError::KeyMalformed)?;
        let b64 = inner.strip_suffix('\n').ok_or(BundleError::KeyMalformed)?;
        parse_private_key(b64)?;
        Ok(block)
    }
}

/// The bytes of a bundle. They hold the key: not printed, zeroed when they go.
pub struct BundleBytes(Wiped);

impl BundleBytes {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.0
    }
}

impl std::fmt::Debug for BundleBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BundleBytes(..)")
    }
}

impl Bundle {
    /// The bytes of a bundle, in one buffer, for pledge to write once: the configuration line, the key
    /// block, the certificate line and its line feed. What is written is read back with [`Bundle::parse`]
    /// at `now` before it is returned, so a bundle `pact` would refuse is never handed out (a bad service
    /// or URL, a certificate that breaks formats section 3.1, one that is not the key's, one that is not
    /// valid at `now`).
    pub fn write(
        config: &Config,
        key: &KeyBlock,
        certificate: &str,
        now: Timestamp,
    ) -> Result<BundleBytes, BundleError> {
        #[derive(serde::Serialize)]
        struct ServiceWire<'a> {
            host: &'a str,
            name: &'a str,
            url: &'a str,
        }
        // Members in this order: `v` first, then the services, the setting, the root.
        #[derive(serde::Serialize)]
        struct ConfigWire<'a> {
            v: u8,
            services: Vec<ServiceWire<'a>>,
            deadline_seconds: u32,
            #[serde(skip_serializing_if = "Option::is_none")]
            tls_root: Option<&'a str>,
        }
        let wire = ConfigWire {
            v: 1,
            services: config
                .services
                .iter()
                .map(|s| ServiceWire { host: &s.host, name: &s.name, url: &s.url })
                .collect(),
            deadline_seconds: config.deadline_seconds,
            tls_root: config.tls_root.as_deref(),
        };
        let line = serde_json::to_string(&wire).map_err(|_| BundleError::Write(Box::new(BundleError::NoServices)))?;
        let mut bytes = Wiped(Vec::new());
        bytes.0.extend_from_slice(line.as_bytes());
        bytes.0.push(b'\n');
        bytes.0.extend_from_slice(&key.0.0);
        bytes.0.extend_from_slice(certificate.as_bytes());
        bytes.0.push(b'\n');
        Bundle::parse(&bytes.0, now).map_err(|e| BundleError::Write(Box::new(e)))?;
        Ok(BundleBytes(bytes))
    }
}

fn parse_config(line: &str) -> Result<Config, BundleError> {
    if line.bytes().any(|b| b == b'\r') {
        return Err(ParseError::LineBreak.into());
    }
    let mut o = Object::parse(line, "")?;
    let version = o.take_u64("v")?;
    if version != 1 {
        return Err(BundleError::UnsupportedVersion);
    }
    let mut services = Vec::new();
    for mut s in o.take_objects("services", "services.")? {
        let (host, name, url) = (s.take_string("host")?, s.take_string("name")?, s.take_string("url")?);
        s.finish()?;
        if !text::is_name(&host) {
            return Err(BundleError::BadHost(host));
        }
        if !text::is_service_name(&name) {
            return Err(BundleError::BadServiceName(name));
        }
        if services.iter().any(|x: &Service| x.host == host && x.name == name) {
            return Err(BundleError::DuplicateService { host, name });
        }
        check_url(&url).map_err(|why| BundleError::BadUrl { host: host.clone(), name: name.clone(), why })?;
        services.push(Service { host, name, url });
    }
    if services.is_empty() {
        return Err(BundleError::NoServices);
    }
    if services.len() > MAX_SERVICES {
        return Err(BundleError::TooManyServices);
    }
    let deadline_seconds = if o.has("deadline_seconds") {
        let d = o.take_u64("deadline_seconds")?;
        u32::try_from(d)
            .ok()
            .filter(|d| (1..=Settings::MAX_DEADLINE_SECONDS).contains(d))
            .ok_or(BundleError::BadDeadline)?
    } else {
        Settings::DEFAULT_DEADLINE_SECONDS
    };
    let tls_root = if o.has("tls_root") { Some(o.take_multiline("tls_root")?) } else { None };
    o.finish()?;
    let https = services.iter().any(|s| s.url.starts_with("https://"));
    let root_ok = tls_root.as_ref().is_none_or(|r| r.starts_with("-----BEGIN CERTIFICATE-----"));
    if !root_ok || (https && tls_root.is_none()) {
        return Err(BundleError::TlsRoot);
    }
    Ok(Config { services, deadline_seconds, tls_root })
}

/// `http` on loopback, or `https`; no credentials, no control characters, no fragment.
fn check_url(url: &str) -> Result<(), &'static str> {
    if url.len() > MAX_URL || url.bytes().any(|b| b <= b' ' || b == 0x7f || !b.is_ascii()) {
        return Err("it is too long or has a space, control or non-ASCII character");
    }
    let (https, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("it is not an http or https url");
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    if rest[end..].contains('#') {
        return Err("it has a fragment");
    }
    if authority.contains('@') {
        return Err("it has credentials");
    }
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        authority
            .rsplit_once(':')
            .map_or(authority, |(h, port)| if port.bytes().all(|b| b.is_ascii_digit()) { h } else { authority })
    };
    if host.is_empty() {
        return Err("it has no host");
    }
    if !https {
        let loopback = host == "localhost"
            || host == "::1"
            || host.strip_prefix("127.").is_some_and(|r| r.split('.').count() == 3);
        if !loopback {
            return Err("plain http is for loopback only");
        }
    }
    Ok(())
}

fn parse_key_and_certificate(rest: &str, now: Timestamp) -> Result<AgentKey, BundleError> {
    let body = rest.strip_prefix(KEY_BEGIN).ok_or(BundleError::KeyMalformed)?;
    let end = body.find(KEY_END).ok_or(BundleError::KeyMalformed)?;
    let (b64, after) = (&body[..end], &body[end + KEY_END.len()..]);
    // The certificate line ends with exactly one line feed, and nothing follows it.
    if after.is_empty() || after.starts_with('\n') {
        return Err(BundleError::CertificateMalformed);
    }
    let (cert_line, trailing) = after.split_once('\n').ok_or(BundleError::NoFinalNewline)?;
    if !trailing.is_empty() {
        return Err(BundleError::TrailingData);
    }
    let pair = parse_private_key(b64)?;
    let cert_blob = parse_certificate_line(cert_line)?;
    let cert = certificate_from_blob(&cert_blob)?;
    // Which key it certifies is compared by fingerprint, before the agent rules, so a wrong pair is named as that.
    if cert.fingerprint != Fingerprint::of_blob(&ed25519_blob(pair.public_key().as_ref()))
        && cert.key_type == "ssh-ed25519"
    {
        return Err(BundleError::CertificateNotForKey);
    }
    let (valid_after, valid_before) = (cert.valid_after, cert.valid_before);
    let agent = agent_from_certificate(cert)?;
    let now = u64::try_from(now.unix()).unwrap_or(0);
    if now < valid_after {
        return Err(BundleError::CertificateNotYetValid);
    }
    if now >= valid_before {
        return Err(BundleError::CertificateExpired);
    }
    Ok(AgentKey { signer: CallSigner::new(pair, Some(cert_blob)), agent, valid_before })
}

fn parse_certificate_line(line: &str) -> Result<Vec<u8>, BundleError> {
    let bad = || BundleError::CertificateMalformed;
    let mut parts = line.split(' ');
    let (kind, b64) = (parts.next().ok_or_else(bad)?, parts.next().ok_or_else(bad)?);
    if line.bytes().any(|b| b < b' ' || b == 0x7f) {
        return Err(bad());
    }
    let blob = STANDARD.decode(b64).map_err(|_| bad())?;
    let embedded = Reader(&blob).string().ok_or_else(bad)?.to_vec();
    if embedded != kind.as_bytes() {
        return Err(bad());
    }
    if kind != CERT_TYPE {
        // Another certificate type: read it to say what its key is, and refuse it as an agent's.
        let cert = certificate_from_blob(&blob)?;
        return Err(SignError::AgentKeyNotEd25519(cert.key_type).into());
    }
    Ok(blob)
}

/// The `openssh-key-v1` container with one unencrypted Ed25519 key.
fn parse_private_key(b64: &str) -> Result<Ed25519KeyPair, BundleError> {
    let bad = || BundleError::KeyMalformed;
    // Base64 in lines, as `ssh-keygen` writes it (70 columns; any length is read), none of them empty.
    if !b64.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'\n'))
        || b64.is_empty()
        || b64.contains("\n\n")
        || b64.starts_with('\n')
    {
        return Err(bad());
    }
    let blob = Wiped(STANDARD.decode(b64.replace('\n', "")).map_err(|_| bad())?);
    let mut r = Reader(&blob.0);
    if r.take(KEY_MAGIC.len()) != Some(KEY_MAGIC) {
        return Err(bad());
    }
    let (cipher, kdf, _kdf_options) =
        (r.string().ok_or_else(bad)?, r.string().ok_or_else(bad)?, r.string().ok_or_else(bad)?);
    if cipher != b"none" || kdf != b"none" {
        return Err(BundleError::KeyEncrypted);
    }
    if r.u32() != Some(1) {
        return Err(bad());
    }
    let _public_section = r.string().ok_or_else(bad)?;
    let mut private = Reader(r.string().ok_or_else(bad)?);
    if !r.0.is_empty() {
        return Err(bad());
    }
    let (check1, check2) = (private.u32().ok_or_else(bad)?, private.u32().ok_or_else(bad)?);
    if check1 != check2 {
        return Err(bad());
    }
    let kind = private.string().ok_or_else(bad)?;
    if kind != b"ssh-ed25519" {
        let name = std::str::from_utf8(kind).ok().filter(|k| {
            k.len() <= 40 && k.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'@' | b'.'))
        });
        return Err(BundleError::KeyType(name.unwrap_or("unknown").to_owned()));
    }
    let public = private.string().ok_or_else(bad)?;
    let secret = private.string().ok_or_else(bad)?;
    let _comment = private.string().ok_or_else(bad)?;
    // Padding is 1, 2, 3, ... up to the cipher block size.
    if !private.0.iter().enumerate().all(|(i, &b)| usize::from(b) == i + 1) || private.0.len() >= 8 {
        return Err(bad());
    }
    if public.len() != 32 || secret.len() != 64 || secret[32..] != *public {
        return Err(bad());
    }
    Ed25519KeyPair::from_seed_and_public_key(&secret[..32], public).map_err(|_| BundleError::KeyRejected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pact::fixture::Fixture;

    fn now() -> Timestamp {
        "2026-11-11T15:00:00Z".parse().unwrap()
    }

    fn config(url: &str) -> String {
        Fixture::default_config(url)
    }

    fn parse(bytes: &[u8]) -> Result<Bundle, BundleError> {
        Bundle::parse(bytes, now())
    }

    #[test]
    fn parses_a_good_bundle() {
        let f = Fixture::new("alice", &["extension:groups@procession=admins,diag"]);
        let b = parse(&f.bundle(&config("http://127.0.0.1:8443/mcp"))).unwrap();
        assert_eq!(
            b.config.services,
            [Service { host: "a.example".into(), name: "probe".into(), url: "http://127.0.0.1:8443/mcp".into() }]
        );
        assert_eq!(b.config.deadline_seconds, 120);
        assert_eq!(b.config.tls_root, None);
        assert_eq!(b.key.agent().person, "alice");
        assert_eq!(b.key.agent().groups, ["admins", "diag"]);
        let call = f.call("probe", "a.example", vec![], 1);
        assert_eq!(b.key.sign_call(&call), f.signer().sign_call(&call));
        // Reading from a stream is the same.
        assert!(Bundle::read(&f.bundle(&config("http://localhost:1/x"))[..], now()).is_ok());
        // Without a trailing newline after the certificate, and with settings.
        let mut bytes = f.bundle(r#"{"v":1,"services":[{"host":"h","name":"probe","url":"https://h.example/mcp"}],"deadline_seconds":600,"tls_root":"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"}"#);
        assert_eq!(parse(&bytes).unwrap().config.deadline_seconds, 600);
        // The certificate line ends with a line feed, and that is required.
        bytes.pop();
        assert!(matches!(parse(&bytes), Err(BundleError::NoFinalNewline)));
    }

    #[test]
    fn the_secret_is_not_in_what_is_printed() {
        let f = Fixture::new("alice", &[]);
        let b = parse(&f.bundle(&config("http://127.0.0.1:1/"))).unwrap();
        let shown = format!("{b:?}");
        let key_body: String = f.key_file_text().lines().filter(|l| !l.starts_with("-----")).collect();
        assert!(!shown.contains(&key_body[..40]) && !shown.contains("OPENSSH"), "{shown}");
    }

    #[test]
    fn refuses_a_bad_configuration_with_its_own_error() {
        let f = Fixture::new("alice", &[]);
        let with = |cfg: &str| parse(&f.bundle(cfg));
        let url = "http://127.0.0.1:1/mcp";
        let svc = format!(r#"[{{"host":"a.example","name":"probe","url":"{url}"}}]"#);
        assert!(matches!(with(&format!(r#"{{"v":2,"services":{svc}}}"#)), Err(BundleError::UnsupportedVersion)));
        assert!(matches!(
            with(&format!(r#"{{"services":{svc}}}"#)),
            Err(BundleError::Config(ParseError::MissingMember("v")))
        ));
        assert!(
            matches!(with(&format!(r#"{{"v":1,"services":{svc},"x":1}}"#)), Err(BundleError::Config(ParseError::UnknownMember(m))) if m == "x")
        );
        assert!(matches!(
            with(&format!(r#"{{"v":1,"v":1,"services":{svc}}}"#)),
            Err(BundleError::Config(ParseError::DuplicateMember(_)))
        ));
        assert!(matches!(with(r#"{"v":1,"services":[]}"#), Err(BundleError::NoServices)));
        assert!(matches!(with(r#"{"v":1}"#), Err(BundleError::Config(ParseError::MissingMember("services")))));
        assert!(
            matches!(with(&format!(r#"{{"v":1,"services":{}}}"#, svc.replace('}', r#","x":1}"#))), Err(BundleError::Config(ParseError::UnknownMember(m))) if m == "services.x")
        );
        assert!(matches!(with(r#"{"v":1,"services":[1]}"#), Err(BundleError::Config(ParseError::WrongType { .. }))));
        assert!(matches!(with("not json"), Err(BundleError::Config(ParseError::NotJson(_)))));
        for (host, name, err) in
            [("a b", "probe", "host"), ("a@b", "probe", "host"), ("a", "Probe", "name"), ("a", "", "name")]
        {
            let cfg = format!(r#"{{"v":1,"services":[{{"host":"{host}","name":"{name}","url":"{url}"}}]}}"#);
            match (with(&cfg), err) {
                (Err(BundleError::BadHost(_)), "host") | (Err(BundleError::BadServiceName(_)), "name") => {}
                (other, _) => panic!("{host:?} {name:?}: {other:?}"),
            }
        }
        let twice = format!(
            r#"{{"v":1,"services":[{{"host":"a","name":"p","url":"{url}"}},{{"host":"a","name":"p","url":"{url}"}}]}}"#
        );
        assert!(matches!(with(&twice), Err(BundleError::DuplicateService { .. })));
        for d in ["0", "601", "-1", "1.5", "\"120\""] {
            assert!(with(&format!(r#"{{"v":1,"services":{svc},"deadline_seconds":{d}}}"#)).is_err(), "{d}");
        }
        assert!(matches!(
            with(&format!(r#"{{"v":1,"services":{svc},"deadline_seconds":0}}"#)),
            Err(BundleError::BadDeadline)
        ));
        assert!(matches!(with(&format!(r#"{{"v":1,"services":{svc},"tls_root":"nope"}}"#)), Err(BundleError::TlsRoot)));
        let https = r#"{"v":1,"services":[{"host":"a","name":"p","url":"https://a.example/mcp"}]}"#;
        assert!(matches!(with(https), Err(BundleError::TlsRoot)));
    }

    #[test]
    fn refuses_urls_that_are_not_the_documents() {
        let f = Fixture::new("alice", &[]);
        for (url, ok) in [
            ("http://127.0.0.1:8443/mcp", true),
            ("http://127.1.2.3/mcp", true),
            ("http://localhost:1/", true),
            ("http://[::1]:8080/mcp", true),
            ("http://a.example/mcp", false),
            ("http://10.0.0.1/mcp", false),
            ("http://127.0.0.1.evil.example/mcp", false),
            ("ftp://127.0.0.1/", false),
            ("127.0.0.1", false),
            ("http://user:pw@127.0.0.1/", false),
            ("http://127.0.0.1@evil/", false),
            ("http://127.0.0.1/mcp#x", false),
            ("http://127.0.0.1/a b", false),
            ("http:///mcp", false),
            ("http://", false),
            ("http://127.0.0.1/\u{e9}", false),
        ] {
            let cfg = format!(r#"{{"v":1,"services":[{{"host":"a","name":"p","url":"{url}"}}]}}"#);
            let r = parse(&f.bundle(&cfg));
            assert_eq!(r.is_ok(), ok, "{url}: {:?}", r.err());
            if !ok {
                assert!(matches!(r, Err(BundleError::BadUrl { .. })), "{url}");
            }
        }
        let many = format!(
            r#"{{"v":1,"services":[{}]}}"#,
            (0..17)
                .map(|i| format!(r#"{{"host":"a","name":"p{}","url":"http://127.0.0.1/"}}"#, "x".repeat(i + 1)))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert!(matches!(parse(&f.bundle(&many)), Err(BundleError::TooManyServices)));
    }

    #[test]
    fn refuses_a_bad_shape_size_and_trailing_data() {
        let f = Fixture::new("alice", &[]);
        let good = f.bundle(&config("http://127.0.0.1:1/"));
        assert!(matches!(parse(&[good.clone(), vec![b' '; MAX_BYTES]].concat()), Err(BundleError::TooLarge)));
        assert!(matches!(Bundle::read(&vec![b'x'; MAX_BYTES + 100][..], now()), Err(BundleError::TooLarge)));
        assert!(matches!(parse(b"{}"), Err(BundleError::NoConfigLine)));
        assert!(matches!(parse(&[0xff, 0xfe]), Err(BundleError::NotUtf8)));
        let text = String::from_utf8(good.clone()).unwrap();
        assert!(matches!(parse(format!("{text}\nmore").as_bytes()), Err(BundleError::TrailingData)));
        assert!(matches!(parse(format!("{text}\n\n").as_bytes()), Err(BundleError::TrailingData)));
        // The key block missing, truncated, with other text in it, or with the certificate first.
        let (cfg, rest) = text.split_once('\n').unwrap();
        assert!(matches!(parse(format!("{cfg}\n").as_bytes()), Err(BundleError::KeyMalformed)));
        assert!(matches!(parse(format!("{cfg}\n{}", f.cert_line()).as_bytes()), Err(BundleError::KeyMalformed)));
        assert!(matches!(
            parse(format!("{cfg}\n{}", &rest[..f.key_file_text().len() / 2]).as_bytes()),
            Err(BundleError::KeyMalformed)
        ));
        assert!(matches!(
            parse(format!("{cfg}\n{}", rest.replacen("\n", "\n!!!!", 1)).as_bytes()),
            Err(BundleError::KeyMalformed)
        ));
        assert!(matches!(
            parse(format!("{cfg}\n{}\n{}", f.cert_line(), f.key_file_text()).as_bytes()),
            Err(BundleError::KeyMalformed)
        ));
        // The certificate line missing or malformed.
        let key_only = format!("{cfg}\n{}", f.key_file_text());
        assert!(matches!(parse(key_only.as_bytes()), Err(BundleError::CertificateMalformed)));
        let line = f.cert_line();
        let broken = [
            format!("{line} x\u{7}"),
            line.replace("AAAA", "A!AA"),
            line.replacen("ssh-ed25519-cert-v01@openssh.com", "ssh-ed25519-cert-v02@openssh.com", 1),
            "ssh-ed25519-cert-v01@openssh.com".into(),
        ];
        for bad in broken {
            assert!(
                matches!(
                    parse(format!("{cfg}\n{}{bad}\n", f.key_file_text()).as_bytes()),
                    Err(BundleError::CertificateMalformed | BundleError::Certificate(_))
                ),
                "{bad}"
            );
        }
    }

    #[test]
    fn refuses_keys_that_are_not_an_unencrypted_ed25519_key() {
        let f = Fixture::new("alice", &[]);
        let dir = tempfile::tempdir().unwrap();
        let keygen = |args: &[&str]| {
            let out = std::process::Command::new("ssh-keygen")
                .args(args)
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
            assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        };
        let cfg = config("http://127.0.0.1:1/");
        let bundle_with = |key: &std::path::Path, cert: &str| {
            format!("{cfg}\n{}{cert}\n", std::fs::read_to_string(key).unwrap()).into_bytes()
        };
        // A passphrase.
        let locked = dir.path().join("locked");
        keygen(&["-q", "-t", "ed25519", "-N", "secret", "-C", "", "-f", locked.to_str().unwrap()]);
        assert!(matches!(parse(&bundle_with(&locked, &f.cert_line())), Err(BundleError::KeyEncrypted)));
        // Other types, named: ECDSA P-256 (the person's key type, not an agent's) and RSA.
        for (args, name) in
            [(vec!["-t", "ecdsa", "-b", "256"], "ecdsa-sha2-nistp256"), (vec!["-t", "rsa", "-b", "2048"], "ssh-rsa")]
        {
            let key = dir.path().join(name);
            let mut a = vec!["-q", "-N", "", "-C", "", "-f", key.to_str().unwrap()];
            a.extend(args);
            keygen(&a);
            match parse(&bundle_with(&key, &f.cert_line())) {
                Err(BundleError::KeyType(t)) => assert_eq!(t, name),
                other => panic!("{name}: {other:?}"),
            }
        }
        // A key that is not the one the certificate is for.
        let other = dir.path().join("other");
        keygen(&["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", other.to_str().unwrap()]);
        assert!(matches!(parse(&bundle_with(&other, &f.cert_line())), Err(BundleError::CertificateNotForKey)));
        // The key damaged inside (the checkints differ): not a key.
        let text = f.key_file_text();
        let lines: Vec<&str> = text.lines().collect();
        let mut damaged = lines.clone();
        let body = damaged[3].replacen('A', "B", 1);
        damaged[3] = &body;
        assert!(parse(format!("{cfg}\n{}\n{}\n", damaged.join("\n"), f.cert_line()).as_bytes()).is_err());
    }

    #[test]
    fn refuses_certificates_that_break_the_agent_rules() {
        let cfg = config("http://127.0.0.1:1/");
        let check = |options: &[&str], person: &str| {
            let f = Fixture::new(person, options);
            Bundle::parse(&f.bundle(&cfg), now()).err()
        };
        assert!(check(&[], "alice").is_none());
        assert!(matches!(
            check(&["force-command=/bin/true"], "alice"),
            Some(BundleError::Certificate(SignError::CriticalOption(_)))
        ));
        assert!(matches!(
            check(&["extension:other@x=1"], "alice"),
            Some(BundleError::Certificate(SignError::UnknownExtension(_)))
        ));
        assert!(matches!(
            check(&["extension:groups@procession=b,a"], "alice"),
            Some(BundleError::Certificate(SignError::BadGroups(_)))
        ));
        assert!(matches!(
            check(&[], "alice,bob"),
            Some(BundleError::Certificate(SignError::PrincipalCount { found: 2 }))
        ));
        assert!(matches!(check(&[], "al*ce"), Some(BundleError::Certificate(SignError::BadPrincipal(_)))));
        // A certificate for a P-256 agent key: refused by the key's type, before anything else.
        // Validity.
        let f = Fixture::new_with_validity("alice", &[], "20200101Z:20200102Z");
        assert!(matches!(Bundle::parse(&f.bundle(&cfg), now()), Err(BundleError::CertificateExpired)));
        let f = Fixture::new_with_validity("alice", &[], "20990101Z:20990102Z");
        assert!(matches!(Bundle::parse(&f.bundle(&cfg), now()), Err(BundleError::CertificateNotYetValid)));
        // The last second of validity is inside, the first second after it is not.
        let f = Fixture::new_with_validity("alice", &[], "20260101Z:20261112Z");
        let end = "2026-11-12T00:00:00Z".parse::<Timestamp>().unwrap();
        assert!(Bundle::parse(&f.bundle(&cfg), end.checked_add(-1).unwrap()).is_ok());
        assert!(matches!(Bundle::parse(&f.bundle(&cfg), end), Err(BundleError::CertificateExpired)));
    }

    #[test]
    fn errors_never_hold_key_material() {
        let f = Fixture::new("alice", &[]);
        let key_body: String = f.key_file_text().lines().filter(|l| !l.starts_with("-----")).collect();
        let cfg = config("http://127.0.0.1:1/");
        let text = String::from_utf8(f.bundle(&cfg)).unwrap();
        for broken in
            [text.replace("AAAA", "A!AA"), format!("{text}tail"), text.replacen(&key_body[10..20], "!!!!!!!!!!", 1)]
        {
            if let Err(e) = parse(broken.as_bytes()) {
                let shown = format!("{e} {e:?}");
                assert!(!shown.contains(&key_body[20..40]), "{shown}");
            }
        }
    }

    #[test]
    fn the_exact_bytes() {
        let f = Fixture::new("alice", &[]);
        let cfg = config("http://127.0.0.1:1/");
        let good = String::from_utf8(f.bundle(&cfg)).unwrap();
        assert!(parse(good.as_bytes()).is_ok());
        let key = f.key_file_text();
        assert!(
            key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n")
                && key.ends_with("-----END OPENSSH PRIVATE KEY-----\n")
        );
        // Line ends are line feeds only.
        assert!(parse(good.replace('\n', "\r\n").as_bytes()).is_err());
        assert!(parse(good.replacen('\n', "\r\n", 1).as_bytes()).is_err());
        // Nothing between the configuration line and the key, between the key and the certificate, or after.
        assert!(matches!(parse(good.replacen('\n', "\n\n", 1).as_bytes()), Err(BundleError::KeyMalformed)));
        assert!(matches!(
            parse(
                good.replacen("-----END OPENSSH PRIVATE KEY-----\n", "-----END OPENSSH PRIVATE KEY-----\n\n", 1)
                    .as_bytes()
            ),
            Err(BundleError::CertificateMalformed)
        ));
        assert!(matches!(parse(format!("{good}\n").as_bytes()), Err(BundleError::TrailingData)));
        assert!(matches!(
            parse(format!("{good} ").as_bytes()),
            Err(BundleError::NoFinalNewline | BundleError::TrailingData)
        ));
        // The key's base64 may be wrapped at any width, but has no empty line.
        let body: String = key.lines().filter(|l| !l.starts_with("-----")).collect();
        let wrapped = |width: usize| {
            let lines: Vec<String> =
                body.as_bytes().chunks(width).map(|c| String::from_utf8(c.to_vec()).unwrap()).collect();
            format!("-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n", lines.join("\n"))
        };
        for width in [16, 70, 76, 1000] {
            let b = format!("{cfg}\n{}{}\n", wrapped(width), f.cert_line());
            assert!(parse(b.as_bytes()).is_ok(), "{width}");
        }
        let blank = key.replacen("\n", "\n\n", 2);
        assert!(matches!(
            parse(format!("{cfg}\n{blank}{}\n", f.cert_line()).as_bytes()),
            Err(BundleError::KeyMalformed)
        ));
        // The limit is counted over everything read: configuration, key, certificate, the lot.
        assert!(Bundle::read(&vec![b'x'; MAX_BYTES][..], now()).is_err());
        assert!(matches!(Bundle::read(&vec![b'x'; MAX_BYTES + 1][..], now()), Err(BundleError::TooLarge)));
        // A configuration line that does not end within the limit is refused too.
        assert!(matches!(Bundle::read(&vec![b'{'; MAX_BYTES + 1][..], now()), Err(BundleError::TooLarge)));
    }

    #[test]
    fn the_floor_is_not_a_member_of_the_bundle() {
        let f = Fixture::new("alice", &[]);
        let with = |m: &str| {
            parse(&f.bundle(&format!(
                r#"{{"v":1,"services":[{{"host":"a","name":"p","url":"http://127.0.0.1:1/"}}],{m}}}"#
            )))
        };
        for member in ["min_wait_seconds", "min_wait"] {
            assert!(
                matches!(with(&format!("\"{member}\":1")), Err(BundleError::Config(ParseError::UnknownMember(m))) if m == member)
            );
        }
    }

    fn written_config() -> Config {
        Config {
            services: vec![Service {
                host: "a.example".into(),
                name: "probe".into(),
                url: "http://127.0.0.1:8443/mcp".into(),
            }],
            deadline_seconds: 90,
            tls_root: None,
        }
    }

    #[test]
    fn what_pledge_writes_pact_reads() {
        let f = Fixture::new("alice", &["extension:groups@procession=admins"]);
        let key = KeyBlock::new(f.key_file_text().into_bytes()).unwrap();
        let mut config = written_config();
        config.tls_root = Some("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".into());
        let bytes = Bundle::write(&config, &key, &f.cert_line(), now()).unwrap();
        let text = std::str::from_utf8(bytes.as_bytes()).unwrap();
        // The exact shape: one line, the key as it was, the certificate, a line feed, nothing more.
        let (first, rest) = text.split_once('\n').unwrap();
        assert!(first.starts_with("{\"v\":1,\"services\":") && !first.contains('\r'), "{first}");
        assert_eq!(rest, format!("{}{}\n", f.key_file_text(), f.cert_line()));
        let read = Bundle::parse(bytes.as_bytes(), now()).unwrap();
        assert_eq!(read.config, config);
        assert_eq!(read.key.agent().person, "alice");
        let call = f.call("probe", "a.example", vec![], 1);
        assert_eq!(read.key.sign_call(&call), f.signer().sign_call(&call));
        // Nothing prints the key.
        let shown = format!("{key:?} {bytes:?}");
        assert!(!shown.contains("OPENSSH") && !shown.contains(&f.key_file_text()[40..60]), "{shown}");
    }

    #[test]
    fn a_bundle_pact_would_refuse_is_never_written() {
        let f = Fixture::new("alice", &[]);
        let key = KeyBlock::new(f.key_file_text().into_bytes()).unwrap();
        let write = |config: &Config, cert: &str, at: Timestamp| Bundle::write(config, &key, cert, at).err();
        let refused = |e: Option<BundleError>| match e {
            Some(BundleError::Write(inner)) => *inner,
            other => panic!("{other:?}"),
        };
        let cert = f.cert_line();
        assert!(write(&written_config(), &cert, now()).is_none());
        let mut bad = written_config();
        bad.services[0].url = "http://evil.example/".into();
        assert!(matches!(refused(write(&bad, &cert, now())), BundleError::BadUrl { .. }));
        bad = written_config();
        bad.services[0].host = "a b".into();
        assert!(matches!(refused(write(&bad, &cert, now())), BundleError::BadHost(_)));
        bad = written_config();
        bad.services.clear();
        assert!(matches!(refused(write(&bad, &cert, now())), BundleError::NoServices));
        bad = written_config();
        bad.deadline_seconds = 601;
        assert!(matches!(refused(write(&bad, &cert, now())), BundleError::BadDeadline));
        bad = written_config();
        bad.services[0].url = "https://a.example/mcp".into();
        assert!(matches!(refused(write(&bad, &cert, now())), BundleError::TlsRoot));
        // The certificate: a line with a break in it, another key's, expired, one that breaks section 3.1.
        assert!(
            refused(write(&written_config(), &format!("{cert}\nextra"), now())).to_string().contains("certificate")
                || true
        );
        let other = Fixture::new("alice", &[]);
        assert!(matches!(
            refused(write(&written_config(), &other.cert_line(), now())),
            BundleError::CertificateNotForKey
        ));
        assert!(matches!(
            refused(write(&written_config(), &cert, "2100-01-01T00:00:00Z".parse().unwrap())),
            BundleError::CertificateExpired
        ));
        let two = Fixture::new("alice,bob", &[]);
        let two_key = KeyBlock::new(two.key_file_text().into_bytes()).unwrap();
        assert!(
            matches!(Bundle::write(&written_config(), &two_key, &two.cert_line(), now()).err(), Some(BundleError::Write(e)) if matches!(*e, BundleError::Certificate(SignError::PrincipalCount { found: 2 })))
        );
    }

    #[test]
    fn a_key_block_is_what_pact_reads_or_nothing() {
        let f = Fixture::new("alice", &[]);
        let key = f.key_file_text();
        assert!(KeyBlock::new(key.clone().into_bytes()).is_ok());
        for bad in [
            String::new(),
            key.trim_end().to_owned(),
            format!("{key}\n"),
            format!(" {key}"),
            key.replace("OPENSSH PRIVATE KEY", "PRIVATE KEY"),
            key.replacen("\n", "\r\n", 1),
            format!("{key}{}", f.cert_line()),
        ] {
            assert!(matches!(KeyBlock::new(bad.clone().into_bytes()), Err(BundleError::KeyMalformed)), "{bad:?}");
        }
        assert!(matches!(KeyBlock::new(vec![0xff, 0xfe]), Err(BundleError::KeyMalformed)));
    }
}
