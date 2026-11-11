//! How a request reaches a service: one trait, so that the HTTP client is a
//! module added to it later and everything else is tested without a network.

use super::Service;
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Set when the model cancels a call: the transport then closes its connection to the service,
/// which is the service's cancel (agent-to-service.md section 7).
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Why no JSON-RPC response came back. The detail is for the log; the model hears only the outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Nothing was sent: no connection, a refused connection, a failed TLS check.
    NotSent(String),
    /// Sent and refused at the transport: a redirect, a `5xx` without `Retry-After`. Nothing ran.
    Unavailable(String),
    /// `503` with `Retry-After`: wait, then ask again.
    TryLater,
    /// The request was sent and no answer came: the connection was lost, the stream went idle, or
    /// the answer broke a limit. **A verb may have run.**
    Lost(String),
}

/// Sends one JSON-RPC request to a service and returns its one JSON-RPC response.
///
/// An implementation applies the rules of `proposals/pact.md` section 7: only the service's URL,
/// no redirect, no proxy, the headers named there, an idle timeout of 45 seconds on the stream and
/// none counted from the deadline, a 4 MiB limit on the response message; and it stops and returns
/// when `cancel` is set.
pub trait Transport: Send + Sync {
    fn post(&self, service: &Service, request: &Value, cancel: &CancelToken) -> Result<Value, TransportError>;
}

/// The transport of a build that has no HTTP client yet: nothing can be sent.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHttp;

impl Transport for NoHttp {
    fn post(&self, _: &Service, _: &Value, _: &CancelToken) -> Result<Value, TransportError> {
        Err(TransportError::NotSent("this pact was built without an HTTP client".into()))
    }
}

type Handler = dyn Fn(&Service, &Value, &CancelToken) -> Result<Value, TransportError> + Send + Sync;

/// A transport that calls a function instead of a network, and keeps what it was given. For tests.
pub struct Memory {
    handler: Box<Handler>,
    sent: Mutex<Vec<(Service, Value)>>,
}

impl Memory {
    pub fn new(
        handler: impl Fn(&Service, &Value, &CancelToken) -> Result<Value, TransportError> + Send + Sync + 'static,
    ) -> Memory {
        Memory { handler: Box::new(handler), sent: Mutex::new(Vec::new()) }
    }

    /// Everything that was posted, in order.
    #[must_use]
    pub fn sent(&self) -> Vec<(Service, Value)> {
        self.sent.lock().map(|s| s.clone()).unwrap_or_default()
    }
}

impl Transport for Memory {
    fn post(&self, service: &Service, request: &Value, cancel: &CancelToken) -> Result<Value, TransportError> {
        if let Ok(mut sent) = self.sent.lock() {
            sent.push((service.clone(), request.clone()));
        }
        (self.handler)(service, request, cancel)
    }
}

impl<T: Transport + ?Sized> Transport for Arc<T> {
    fn post(&self, service: &Service, request: &Value, cancel: &CancelToken) -> Result<Value, TransportError> {
        (**self).post(service, request, cancel)
    }
}
