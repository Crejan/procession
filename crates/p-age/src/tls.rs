//! TLS around the connections: TLS 1.3 only, the `ring` provider, the broker's
//! certificate from the site's TLS root (or a pinned one). Nothing signed
//! depends on it (`approval-connections.md` section 1); it keeps strangers from
//! standing in the broker's place and from reading requests.

use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use thiserror::Error;

/// The label that ties a sign-in to one TLS connection (RFC 5705).
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-procession-connection-v1";

/// Why the TLS set-up failed.
#[derive(Debug, Error)]
pub enum TlsError {
    #[error("certificate or key file: {0}")]
    Pem(String),
    #[error("tls: {0}")]
    Rustls(#[from] rustls::Error),
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn pem_err(e: impl std::fmt::Display) -> TlsError {
    TlsError::Pem(e.to_string())
}

/// The broker's server configuration from a certificate chain and a private key, both PEM.
pub fn server_config(cert_pem: &[u8], key_pem: &[u8]) -> Result<Arc<ServerConfig>, TlsError> {
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem).collect::<Result<_, _>>().map_err(pem_err)?;
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(pem_err)?;
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    Ok(Arc::new(config))
}

/// A client configuration that trusts the roots in `root_pem` (the site's TLS root, or the broker's
/// pinned certificate). For pledge and services, and for tests.
pub fn client_config(root_pem: &[u8]) -> Result<Arc<ClientConfig>, TlsError> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(root_pem) {
        roots.add(cert.map_err(pem_err)?)?;
    }
    let config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// The 32 bytes both ends export from one TLS connection: what the sign-in's `tls` member carries.
pub fn exporter(conn: &ServerConnection) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    conn.export_keying_material(&mut out, EXPORTER_LABEL, None).ok()?;
    Some(out)
}
