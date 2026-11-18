//! The signature operations the broker needs, behind one trait so that the
//! state machine can be tested without `ssh-keygen` and the real thing can be
//! tested with it. Everything goes through `p-act` except what
//! [`crate::keygen`] stands in for.

use std::path::PathBuf;

use p_act::broker::{ConnectionDocument, Standing};

use crate::certs::{BrokerCertificate, BrokerCertificateFailure};
use p_act::sign::{self, Agent, PublicKey, SignError, Signer};
use p_act::{Call, Clearance, Request};
use thiserror::Error;

/// Why a signature operation failed. The broker never looks inside: a check that
/// fails is a refusal with a code.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error(transparent)]
    Sign(#[from] SignError),
}

/// Signing and verifying for the broker. All methods block (they run `ssh-keygen`).
pub trait Crypto: Send + Sync {
    /// The service's signature over a request, against its host's key.
    fn verify_request(&self, request: &Request, sig: &str, host_key: &PublicKey) -> Result<(), CryptoError>;
    /// The agent's signature over a call, against the person's delegation key; the agent's certificate read.
    fn verify_call(&self, call: &Call, sig: &str, delegation_key: &PublicKey) -> Result<Agent, CryptoError>;
    /// pledge's sign-in: the connection document, against the person's connection key.
    fn verify_connection(&self, doc: &ConnectionDocument, sig: &str, key: &PublicKey) -> Result<(), CryptoError>;
    /// An agent's certificate, read under formats section 3.1 and checked to be issued by `delegation_key`.
    fn check_agent_certificate(&self, line: &str, delegation_key: &PublicKey) -> Result<Agent, CryptoError>;
    /// A certificate of an approval key, checked against the site CA's key by `p_act::sign::check_approval_certificate`
    /// (shape, name, no critical option, signature and issuer); validity is the caller's to judge.
    fn check_approval_certificate(
        &self,
        line: &str,
        site_ca: &PublicKey,
    ) -> Result<sign::ApprovalCertificate, CryptoError>;
    /// The broker's own certificate, as it is presented in every signature: it must be for the name `broker`, issued by
    /// the site CA, valid at `now`, with no critical option and no extension, and certify the key the broker holds.
    fn check_broker_certificate(
        &self,
        site_ca: &PublicKey,
        now: std::time::SystemTime,
    ) -> Result<BrokerCertificate, BrokerCertificateFailure>;
    /// Where the broker's certificate is: `<broker_key>-cert.pub`, beside the key (named in `page status`).
    fn broker_certificate_file(&self) -> PathBuf;
    /// The broker's signature over a clearance.
    fn sign_clearance(&self, clearance: &Clearance) -> Result<String, CryptoError>;
    /// The broker's signature over a standing (namespace `broker-v1@procession`).
    fn sign_standing(&self, standing: &Standing) -> Result<String, CryptoError>;
}

/// The real thing: `ssh-keygen`, and the broker's key.
#[derive(Debug, Clone)]
pub struct SshCrypto {
    /// The broker's private key; its certificate is `<key>-cert.pub` beside it.
    broker_key: PathBuf,
}

impl SshCrypto {
    /// The broker's certificate: `<key>-cert.pub` beside the key (where `ssh-keygen` finds it).
    #[must_use]
    pub fn certificate_file(&self) -> PathBuf {
        let mut name = self.broker_key.clone().into_os_string();
        name.push("-cert.pub");
        PathBuf::from(name)
    }

    #[must_use]
    pub fn new(broker_key: impl Into<PathBuf>) -> SshCrypto {
        SshCrypto { broker_key: broker_key.into() }
    }
}

impl Crypto for SshCrypto {
    fn verify_request(&self, request: &Request, sig: &str, host_key: &PublicKey) -> Result<(), CryptoError> {
        Ok(sign::verify_request(request, sig, host_key)?)
    }

    fn verify_call(&self, call: &Call, sig: &str, delegation_key: &PublicKey) -> Result<Agent, CryptoError> {
        Ok(sign::verify_call_agent(call, sig, delegation_key)?)
    }

    fn verify_connection(&self, doc: &ConnectionDocument, sig: &str, key: &PublicKey) -> Result<(), CryptoError> {
        Ok(doc.verify(key, sig)?)
    }

    fn check_agent_certificate(&self, line: &str, delegation_key: &PublicKey) -> Result<Agent, CryptoError> {
        Ok(sign::verify_agent_certificate(line, delegation_key)?)
    }

    fn check_approval_certificate(
        &self,
        line: &str,
        site_ca: &PublicKey,
    ) -> Result<sign::ApprovalCertificate, CryptoError> {
        Ok(sign::check_approval_certificate(line, site_ca)?)
    }

    fn check_broker_certificate(
        &self,
        site_ca: &PublicKey,
        now: std::time::SystemTime,
    ) -> Result<BrokerCertificate, BrokerCertificateFailure> {
        let refused = |e: &dyn std::fmt::Display| BrokerCertificateFailure::Refused(e.to_string());
        if !self.certificate_file().is_file() {
            return Err(BrokerCertificateFailure::Missing);
        }
        // What is checked is what is presented: the certificate inside a signature the broker makes. `ssh-keygen`
        // signs with the key and the certificate beside it; the signature proves the key is the certified one.
        let probe = b"page: the broker's certificate check";
        let sig = sign::sign_broker(&Signer::certified(&self.broker_key).map_err(|e| refused(&e))?, probe)
            .map_err(|e| refused(&e))?;
        let cert = sign::signature_certificate(&sig).map_err(|e| refused(&e))?;
        if cert.principals != ["broker"] {
            return Err(BrokerCertificateFailure::Refused("its principals are not exactly `broker`".to_owned()));
        }
        if let Some((name, _)) = cert.critical_options.first() {
            return Err(BrokerCertificateFailure::Refused(format!("it has the critical option `{name}`")));
        }
        if let Some((name, _)) = cert.extensions.first() {
            return Err(BrokerCertificateFailure::Refused(format!("it has the extension `{name}`")));
        }
        let secs = now.duration_since(std::time::SystemTime::UNIX_EPOCH).map_or(0, |d| d.as_secs());
        if secs < cert.valid_after {
            return Err(BrokerCertificateFailure::NotYetValid);
        }
        if secs >= cert.valid_before {
            return Err(BrokerCertificateFailure::Expired);
        }
        // The issuer and the signature, the way a service and a pledge verify it.
        sign::verify_broker(site_ca, &sig, probe).map_err(|e| refused(&e))?;
        Ok(BrokerCertificate { valid_after: cert.valid_after, valid_before: cert.valid_before })
    }

    fn broker_certificate_file(&self) -> PathBuf {
        self.certificate_file()
    }

    fn sign_clearance(&self, clearance: &Clearance) -> Result<String, CryptoError> {
        let signer = Signer::certified(&self.broker_key)?;
        Ok(sign::sign_clearance(&signer, clearance)?)
    }

    fn sign_standing(&self, standing: &Standing) -> Result<String, CryptoError> {
        Ok(standing.sign(&Signer::certified(&self.broker_key)?)?)
    }
}
