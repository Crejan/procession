//! The HTTP transport of `probe serve`: `hyper` (HTTP/1, one request per connection) around the MCP
//! layer ([`crate::mcp::Mcp`]).
//!
//! What it adds to the layer, and nothing else:
//! - a request is read with a limit (the MCP layer's 64 KiB) and a time limit for its header;
//! - the layer runs on a blocking thread and writes its response a piece at a time into a channel, which
//!   is the response body: the head of a stream goes out when the layer writes it (at acceptance of the
//!   call), and every piece (a keepalive comment) is sent at once, so that a client that reads silence as
//!   a dead connection does not;
//! - **a client that goes away cancels the call**: when `hyper` drops the response body before it ended,
//!   the call's cancel flag is set, and the layer cancels the request at pledge; a failed send does the
//!   same at the next piece.
//!
//! The connection handler is generic over the stream, so it is tested over memory and over a Unix socket;
//! a TCP listener is one more [`Incoming`].

use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::body::{Body, Frame, Incoming as RequestBody};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Semaphore, mpsc, oneshot};

use crate::mcp::{BODY_MAX, HttpRequest, KEEPALIVE, Mcp, ResponseWriter};
use crate::service::Service;

/// How long a client has to send a request's head.
pub const HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// Connections served at once; the next waits to be accepted.
pub const MAX_CONNECTIONS: usize = 64;
/// How many pieces of a response may wait for a slow reader.
const CHANNEL: usize = 16;

/// The settings of a connection.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The interval of the keepalive comments on a stream.
    pub keepalive: Duration,
    pub header_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self { keepalive: KEEPALIVE, header_timeout: HEADER_TIMEOUT }
    }
}

/// The body of a response: what the blocking thread sends. Dropped before its end, it says the client is gone.
pub struct ChannelBody {
    receiver: mpsc::Receiver<Bytes>,
    cancel: Arc<AtomicBool>,
    ended: bool,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(bytes)) => Poll::Ready(Some(Ok(Frame::data(bytes)))),
            Poll::Ready(None) => {
                self.ended = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for ChannelBody {
    fn drop(&mut self) {
        if !self.ended {
            self.cancel.store(true, Ordering::SeqCst);
        }
    }
}

type Head = (u16, Vec<(String, String)>);

/// What the MCP layer writes to, on the blocking thread.
struct ChannelWriter {
    head: Option<oneshot::Sender<Head>>,
    body: mpsc::Sender<Bytes>,
}

fn gone() -> std::io::Error {
    std::io::ErrorKind::BrokenPipe.into()
}

impl ResponseWriter for ChannelWriter {
    fn head(&mut self, status: u16, headers: &[(String, String)]) -> std::io::Result<()> {
        self.head.take().ok_or_else(gone)?.send((status, headers.to_vec())).map_err(|_| gone())
    }

    fn body(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        // Sent at once: a keepalive that waits in a buffer is no keepalive.
        self.body.blocking_send(Bytes::copy_from_slice(bytes)).map_err(|_| gone())
    }
}

fn status_only(status: StatusCode) -> Response<ChannelBody> {
    let (_, receiver) = mpsc::channel(1);
    let mut response = Response::new(ChannelBody { receiver, cancel: Arc::new(AtomicBool::new(false)), ended: true });
    *response.status_mut() = status;
    response
}

async fn handle(
    service: Arc<Service>,
    limits: Limits,
    request: Request<RequestBody>,
) -> Result<Response<ChannelBody>, Infallible> {
    let (parts, body) = request.into_parts();
    // One byte more than the layer allows, so that it can say 413 itself.
    let Ok(collected) = Limited::new(body, BODY_MAX + 1).collect().await else {
        return Ok(status_only(StatusCode::PAYLOAD_TOO_LARGE));
    };
    let http = HttpRequest {
        method: parts.method.as_str().to_string(),
        path: parts.uri.path().to_string(),
        headers: parts
            .headers
            .iter()
            .filter_map(|(name, value)| value.to_str().ok().map(|v| (name.as_str().to_string(), v.to_string())))
            .collect(),
        body: collected.to_bytes().to_vec(),
    };
    let (head_tx, head_rx) = oneshot::channel();
    let (body_tx, body_rx) = mpsc::channel(CHANNEL);
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    tokio::task::spawn_blocking(move || {
        let mut mcp = Mcp::new(&service);
        mcp.keepalive = limits.keepalive;
        let mut writer = ChannelWriter { head: Some(head_tx), body: body_tx };
        mcp.serve(&http, &worker_cancel, &mut writer);
        // `writer` is dropped here: the body ends.
    });
    let Ok((status, headers)) = head_rx.await else {
        // The layer wrote nothing: the call was cancelled, or the client is gone.
        return Ok(status_only(StatusCode::INTERNAL_SERVER_ERROR));
    };
    let mut response = Response::new(ChannelBody { receiver: body_rx, cancel, ended: false });
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) =
            (hyper::header::HeaderName::from_bytes(name.as_bytes()), hyper::header::HeaderValue::from_str(&value))
        {
            response.headers_mut().append(name, value);
        }
    }
    Ok(response)
}

/// Serves one connection: one request, one response, then it closes.
///
/// # Errors
/// What `hyper` says when the connection breaks or the client sends what is not HTTP.
pub async fn serve_connection<Io>(io: Io, service: Arc<Service>, limits: Limits) -> Result<(), hyper::Error>
where
    Io: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header_timeout)
        .keep_alive(false)
        .serve_connection(TokioIo::new(io), service_fn(move |request| handle(service.clone(), limits, request)))
        .await
}

/// Where connections come from: a listener of any kind.
pub trait Incoming: Send + Sync + 'static {
    type Io: AsyncRead + AsyncWrite + Unpin + Send + 'static;

    fn accept(&self) -> impl Future<Output = std::io::Result<Self::Io>> + Send;
}

impl Incoming for tokio::net::TcpListener {
    type Io = tokio::net::TcpStream;

    async fn accept(&self) -> std::io::Result<Self::Io> {
        tokio::net::TcpListener::accept(self).await.map(|(stream, _)| stream)
    }
}

impl Incoming for tokio::net::UnixListener {
    type Io = tokio::net::UnixStream;

    async fn accept(&self) -> std::io::Result<Self::Io> {
        tokio::net::UnixListener::accept(self).await.map(|(stream, _)| stream)
    }
}

/// Accepts connections until `shutdown` fires (or its sender is dropped), each on its own task, at most
/// [`MAX_CONNECTIONS`] at once.
pub async fn accept_loop<L: Incoming>(
    listener: L,
    service: Arc<Service>,
    limits: Limits,
    shutdown: oneshot::Receiver<()>,
) {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut shutdown = shutdown;
    loop {
        let Ok(permit) = slots.clone().acquire_owned().await else { return };
        tokio::select! {
            _ = &mut shutdown => return,
            accepted = listener.accept() => match accepted {
                Ok(io) => {
                    let service = service.clone();
                    tokio::spawn(async move {
                        let _ = serve_connection(io, service, limits).await;
                        drop(permit);
                    });
                }
                // A failed accept (too many open files, a reset connection) is not the end of the service.
                Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
            },
        }
    }
}
