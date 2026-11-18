//! The signature operations the broker needs, behind one trait so that the
//! state machine can be tested without `ssh-keygen` and the real thing can be
//! tested with it. Everything goes through `p-act` except what
//! [`crate::keygen`] stands in for.

use std::path::PathBuf;

use p_act::broker::{ConnectionDocument, Standing};
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

    fn sign_clearance(&self, clearance: &Clearance) -> Result<String, CryptoError> {
        let signer = Signer::certified(&self.broker_key)?;
        Ok(sign::sign_clearance(&signer, clearance)?)
    }

    fn sign_standing(&self, standing: &Standing) -> Result<String, CryptoError> {
        Ok(standing.sign(&Signer::certified(&self.broker_key)?)?)
    }
}
