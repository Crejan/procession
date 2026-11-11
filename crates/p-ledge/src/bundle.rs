//! The bundle `pledge agents start` writes for the agent-side signer `pact`
//! (`proposals/review-pact-bundle.md`, option B): one JSON line of
//! configuration, then the agent's key as an unmodified OpenSSH private key
//! block, then the certificate line.
//!
//! ```text
//! {"v":1,"services":[{"host":..,"name":..,"url":..}],"deadline_seconds":120,"tls_root":"-----BEGIN CERTIFICATE-----\n..."}\n
//! -----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----\n
//! ssh-ed25519-cert-v01@openssh.com AAAA...\n
//! ```
//!
//! Nothing else is written; at most [`MAX_BYTES`]. The key is not a member of
//! the JSON, so line 1 can be logged and checked without it.

use serde::Serialize;

use crate::config::{Config, DEFAULT_DEADLINE_SECONDS, ServiceEntry};

/// The most a bundle may be.
pub const MAX_BYTES: usize = 64 * 1024;

#[derive(Serialize)]
struct Line<'a> {
    v: u32,
    services: &'a [ServiceEntry],
    deadline_seconds: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_root: Option<&'a str>,
}

/// Why a bundle cannot be written.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BundleError {
    /// There is no service for the agent to talk to.
    #[error("config.json lists no services: an agent would have nowhere to send its calls")]
    NoServices,
    /// `http` is only for a loopback address; anything else needs `https` and a root.
    #[error("the service {0} uses http away from loopback, or https without tls_root")]
    Insecure(String),
    /// The result would be larger than a bundle may be.
    #[error("the bundle would be larger than {MAX_BYTES} bytes")]
    TooLarge,
    /// The key block or the certificate is not what it should be.
    #[error("the key block or the certificate is malformed")]
    Malformed,
}

fn is_loopback(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("http://") else { return false };
    let authority = rest.split('/').next().unwrap_or("");
    let host = if let Some(v6) = authority.strip_prefix('[') {
        v6.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    matches!(host, "localhost" | "127.0.0.1" | "::1")
}

/// Checks the configuration for what a bundle needs, before a delegation is
/// started for it.
///
/// # Errors
///
/// [`BundleError`] for what a bundle would be refused for.
pub fn check_config(config: &Config) -> Result<(), BundleError> {
    if config.services.is_empty() {
        return Err(BundleError::NoServices);
    }
    for service in &config.services {
        let secure = service.url.starts_with("https://") && config.tls_root.is_some();
        if !secure && !is_loopback(&service.url) {
            return Err(BundleError::Insecure(format!("{}/{}", service.host, service.name)));
        }
    }
    Ok(())
}

/// The bundle, as one buffer, to be written once.
///
/// # Errors
///
/// [`BundleError`] if the configuration, the key block or the certificate will
/// not do, or the result is too large.
pub fn write(config: &Config, key_block: &[u8], certificate: &str) -> Result<Vec<u8>, BundleError> {
    check_config(config)?;
    let block = std::str::from_utf8(key_block).map_err(|_| BundleError::Malformed)?;
    if !block.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        || !block.ends_with("-----END OPENSSH PRIVATE KEY-----\n")
    {
        return Err(BundleError::Malformed);
    }
    if !certificate.starts_with("ssh-ed25519-cert-v01@openssh.com ") || certificate.contains(['\n', '\r']) {
        return Err(BundleError::Malformed);
    }
    let line = Line {
        v: 1,
        services: &config.services,
        deadline_seconds: config.deadline_seconds.unwrap_or(DEFAULT_DEADLINE_SECONDS),
        tls_root: config.tls_root.as_deref(),
    };
    let mut out = serde_json::to_vec(&line).map_err(|_| BundleError::Malformed)?;
    out.push(b'\n');
    out.extend_from_slice(key_block);
    out.extend_from_slice(certificate.as_bytes());
    out.push(b'\n');
    if out.len() > MAX_BYTES { Err(BundleError::TooLarge) } else { Ok(out) }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCK: &str = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
    const CERT: &str = "ssh-ed25519-cert-v01@openssh.com AAAA";

    fn config(url: &str, root: Option<&str>) -> Config {
        Config {
            services: vec![ServiceEntry { host: "a.example".into(), name: "probe".into(), url: url.into() }],
            tls_root: root.map(str::to_owned),
            ..Config::default()
        }
    }

    #[test]
    fn the_bundle_is_the_configuration_line_then_the_key_block_then_the_certificate() {
        let bundle = write(&config("http://127.0.0.1:8443/mcp", None), BLOCK.as_bytes(), CERT).expect("bundle");
        let text = String::from_utf8(bundle).expect("text");
        let (first, rest) = text.split_once('\n').expect("a first line");
        assert_eq!(
            first,
            r#"{"v":1,"services":[{"host":"a.example","name":"probe","url":"http://127.0.0.1:8443/mcp"}],"deadline_seconds":120}"#
        );
        assert_eq!(rest, format!("{BLOCK}{CERT}\n"));
        assert!(!first.contains("PRIVATE"), "line 1 can be logged without the key");
    }

    #[test]
    fn https_needs_a_root_and_http_only_loopback() {
        assert!(
            write(&config("https://a.example/mcp", Some("-----BEGIN CERTIFICATE-----\nAA\n")), BLOCK.as_bytes(), CERT)
                .is_ok()
        );
        let text = String::from_utf8(
            write(&config("https://a.example/mcp", Some("PEM\nline")), BLOCK.as_bytes(), CERT).expect("ok"),
        )
        .expect("text");
        assert!(
            text.lines().next().is_some_and(|l| l.contains(r#""tls_root":"PEM\nline""#)),
            "no raw line break in line 1"
        );
        assert_eq!(
            write(&config("https://a.example/mcp", None), BLOCK.as_bytes(), CERT),
            Err(BundleError::Insecure("a.example/probe".into()))
        );
        assert!(matches!(
            write(&config("http://a.example:8443/mcp", None), BLOCK.as_bytes(), CERT),
            Err(BundleError::Insecure(_))
        ));
        for url in ["http://localhost/mcp", "http://127.0.0.1:1/x", "http://[::1]:8080/m"] {
            assert!(write(&config(url, None), BLOCK.as_bytes(), CERT).is_ok(), "{url}");
        }
        assert!(matches!(
            write(&config("http://127.0.0.1.evil.example/m", None), BLOCK.as_bytes(), CERT),
            Err(BundleError::Insecure(_))
        ));
    }

    #[test]
    fn nothing_without_services_and_nothing_malformed_or_too_large() {
        assert_eq!(write(&Config::default(), BLOCK.as_bytes(), CERT), Err(BundleError::NoServices));
        let good = config("http://127.0.0.1/m", None);
        assert_eq!(write(&good, b"not a key", CERT), Err(BundleError::Malformed));
        assert_eq!(write(&good, BLOCK.as_bytes(), "ssh-ed25519 AAAA"), Err(BundleError::Malformed));
        assert_eq!(
            write(&good, BLOCK.as_bytes(), "ssh-ed25519-cert-v01@openssh.com AA\nBB"),
            Err(BundleError::Malformed)
        );
        let big = config("http://127.0.0.1/m", Some(&"x".repeat(MAX_BYTES)));
        assert_eq!(write(&big, BLOCK.as_bytes(), CERT), Err(BundleError::TooLarge));
    }
}
