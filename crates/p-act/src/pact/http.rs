//! The HTTP transport of `pact` (`proposals/pact.md` section 7), on `ureq` 3, blocking: one agent and one
//! connection per call, a thread per waiting call.
//!
//! What it does, and what `ureq`'s defaults would otherwise do and are switched off: only the configured
//! URL; **no redirect** is followed (a redirect is `unavailable`); **no proxy** from the environment; **no
//! `User-Agent`** and **no `Accept-Encoding`**; the headers `Content-Type: application/json`, `Accept:
//! application/json, text/event-stream` and `MCP-Protocol-Version: 2025-06-18`, and no `Origin`. The
//! deadline is not a timeout here: a verb is waited for as long as the service keeps the stream alive. What
//! ends a call is **45 seconds without a byte** (`ureq`'s `timeout_per_read`, which restarts at each read),
//! a connection that ends, a response over the limits, or the model's cancel (`Agent::shutdown`, which
//! closes the connection: the service's cancel).
//!
//! The reading of a response (`read_answer`, `read_sse`, `interpret`) is separate from the sockets and is
//! tested without them.

use super::Service;
use super::transport::{CancelToken, Transport, TransportError};
use serde_json::Value;
use std::io::{BufRead, BufReader, Read};
use std::time::Duration;

/// No byte for this long ends the call: the service sends a comment line at least every 15 seconds.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(45);
/// Making the connection takes at most this long.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// The final JSON-RPC message is at most this long: a verb's answer is capped at 1 MiB of lines, and
/// wrapped in JSON-RPC every `"` is doubled.
pub const MAX_ANSWER_MESSAGE: usize = 4 * 1024 * 1024;
/// The notifications and events of a stream that are not the answer are at most this long together.
pub const MAX_STREAM_EXTRAS: usize = 64 * 1024;
/// The body of an error response is read up to this much.
pub const MAX_ERROR_BODY: usize = 64 * 1024;
/// The head of a response is at most this long.
pub const MAX_RESPONSE_HEAD: usize = 16 * 1024;
/// The protocol revision `pact` speaks to services.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

fn lost(why: impl Into<String>) -> TransportError {
    TransportError::Lost(why.into())
}

/// Read at most `limit` bytes of `r`; `None` if there is more.
fn read_capped(r: impl Read, limit: usize) -> Result<Option<Vec<u8>>, std::io::Error> {
    let mut out = Vec::new();
    r.take(limit as u64 + 1).read_to_end(&mut out)?;
    Ok((out.len() <= limit).then_some(out))
}

/// Whether `value` is the JSON-RPC response (a `result` or an `error`) to the request `id`.
fn is_response_to(value: &Value, id: &Value) -> bool {
    value.is_object() && value.get("id") == Some(id) && (value.get("result").is_some() || value.get("error").is_some())
}

/// A body of `application/json`: the one JSON-RPC response.
fn read_json_answer(body: impl Read, id: &Value) -> Result<Value, TransportError> {
    let bytes = read_capped(body, MAX_ANSWER_MESSAGE)
        .map_err(|e| lost(format!("the body broke off: {e}")))?
        .ok_or_else(|| lost("the answer is over the limit"))?;
    let value: Value = p_ermit::json::parse_slice(&bytes)
        .map_err(|e| lost(format!("the body is not JSON without a repeated key: {e}")))?;
    if is_response_to(&value, id) { Ok(value) } else { Err(lost("the body is not the answer to this request")) }
}

/// A body of `text/event-stream`: comment lines and notifications are ignored, and the first event that
/// is the JSON-RPC response to `id` is the answer. The stream ends with it or without it.
pub(crate) fn read_sse(mut stream: impl BufRead, id: &Value) -> Result<Value, TransportError> {
    let mut data = String::new();
    let mut extras = 0usize;
    let dispatch = |data: &mut String, extras: &mut usize| -> Result<Option<Value>, TransportError> {
        if data.is_empty() {
            return Ok(None);
        }
        let event = std::mem::take(data);
        match p_ermit::json::parse(&event) {
            Ok(v) if is_response_to(&v, id) => Ok(Some(v)),
            // A notification, or something else: ignored, within a budget.
            _ => {
                *extras += event.len();
                if *extras > MAX_STREAM_EXTRAS {
                    Err(lost("the stream sent more than it should besides the answer"))
                } else {
                    Ok(None)
                }
            }
        }
    };
    loop {
        // A line is at most the answer's limit plus its field name.
        let mut line = Vec::new();
        let n = (&mut stream)
            .take(MAX_ANSWER_MESSAGE as u64 + 16)
            .read_until(b'\n', &mut line)
            .map_err(|e| lost(format!("the stream broke off: {e}")))?;
        if n == 0 {
            return match dispatch(&mut data, &mut extras)? {
                Some(v) => Ok(v),
                None => Err(lost("the stream ended without an answer")),
            };
        }
        if !line.ends_with(b"\n") && line.len() > MAX_ANSWER_MESSAGE {
            return Err(lost("a line of the stream is over the limit"));
        }
        let text = String::from_utf8_lossy(line.strip_suffix(b"\n").unwrap_or(&line));
        let text = text.strip_suffix('\r').unwrap_or(&text);
        if text.is_empty() {
            if let Some(v) = dispatch(&mut data, &mut extras)? {
                return Ok(v);
            }
        } else if let Some(field) = text.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(field.strip_prefix(' ').unwrap_or(field));
            if data.len() > MAX_ANSWER_MESSAGE {
                return Err(lost("an event of the stream is over the limit"));
            }
        }
        // A comment (`:`) or another field (`event:`, `id:`, `retry:`) is ignored; the read itself kept the connection alive.
    }
}

/// What a response means. `retry_after`: it has that header.
pub(crate) fn interpret(
    status: u16,
    content_type: &str,
    retry_after: bool,
    body: impl Read,
    id: &Value,
) -> Result<Value, TransportError> {
    match status {
        200..=299 => {
            let media = content_type.split(';').next().unwrap_or("").trim().to_ascii_lowercase();
            match media.as_str() {
                "application/json" => read_json_answer(body, id),
                "text/event-stream" => read_sse(BufReader::new(body), id),
                _ => {
                    Err(TransportError::Unavailable(format!("the answer is {status} with an unexpected content type")))
                }
            }
        }
        300..=399 => Err(TransportError::Unavailable("the service redirected; redirects are not followed".into())),
        503 if retry_after => Err(TransportError::TryLater),
        _ => {
            // A JSON-RPC error in the body (the service refuses a call it will not take with `400` and one) is passed on to be
            // mapped; anything else is the transport's.
            let parsed =
                read_capped(body, MAX_ERROR_BODY).ok().flatten().and_then(|b| p_ermit::json::parse_slice(&b).ok());
            match parsed {
                Some(v) if v.get("error").is_some() => Ok(v),
                _ => Err(TransportError::Unavailable(format!("the service answered {status}"))),
            }
        }
    }
}

/// The HTTP transport.
#[derive(Debug, Clone)]
pub struct HttpTransport {
    tls_root: Option<String>,
    idle: Duration,
    connect: Duration,
}

impl HttpTransport {
    /// `tls_root`: the PEM certificate that `https` services are verified against.
    #[must_use]
    pub fn new(tls_root: Option<String>) -> HttpTransport {
        HttpTransport { tls_root, idle: IDLE_TIMEOUT, connect: CONNECT_TIMEOUT }
    }

    /// Other timeouts, for tests.
    #[must_use]
    pub fn with_timeouts(mut self, idle: Duration, connect: Duration) -> HttpTransport {
        self.idle = idle;
        self.connect = connect;
        self
    }

    fn agent(&self, https: bool) -> Result<ureq::Agent, TransportError> {
        #[allow(unused_mut)]
        let mut config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .proxy(None)
            .user_agent("")
            .accept_encoding("")
            .max_response_header_size(MAX_RESPONSE_HEAD)
            .timeout_connect(Some(self.connect))
            .timeout_per_read(Some(self.idle))
            .https_only(https);
        if https {
            #[cfg(feature = "pact-tls")]
            {
                config = config.tls_config(self.tls_config()?);
            }
            #[cfg(not(feature = "pact-tls"))]
            {
                let _ = &self.tls_root;
                return Err(TransportError::NotSent("this pact was built without TLS (feature pact-tls)".into()));
            }
        }
        Ok(ureq::Agent::new_with_config(config.build()))
    }

    #[cfg(feature = "pact-tls")]
    fn tls_config(&self) -> Result<ureq::tls::TlsConfig, TransportError> {
        let root = self
            .tls_root
            .as_deref()
            .ok_or_else(|| TransportError::NotSent("an https service needs a TLS root".into()))?;
        let cert = ureq::tls::Certificate::from_pem(root.as_bytes())
            .map_err(|_| TransportError::NotSent("the TLS root is not a certificate in PEM".into()))?;
        Ok(ureq::tls::TlsConfig::builder().root_certs(ureq::tls::RootCerts::new_with_certs(&[cert])).build())
    }
}

/// Which errors mean nothing was sent. Anything else after a connection may have reached the service.
fn not_sent(e: &ureq::Error) -> bool {
    use ureq::Error as E;
    use ureq::Timeout as T;
    match e {
        E::HostNotFound
        | E::ConnectionFailed
        | E::BadUri(_)
        | E::InvalidProxyUrl
        | E::Tls(_)
        | E::RequireHttpsOnly(_)
        | E::TlsRequired
        | E::ConnectProxyFailed(_)
        | E::Http(_) => true,
        E::Timeout(t) => matches!(t, T::Resolve | T::Connect),
        // `ureq` reports a failed connect as a plain I/O error. These kinds can only come from making the connection
        // (a refused or unreachable address, or an environment that does not allow it); a reset, a broken pipe or a
        // timeout can come from a request that was sent, and are a lost answer.
        E::Io(io) if is_handshake_refusal(io) => true,
        E::Io(io) => matches!(
            io.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::HostUnreachable
                | std::io::ErrorKind::NetworkUnreachable
                | std::io::ErrorKind::NetworkDown
                | std::io::ErrorKind::AddrNotAvailable
                | std::io::ErrorKind::PermissionDenied
        ),
        _ => false,
    }
}

/// A TLS handshake that failed because the service's certificate was refused (unknown issuer, not valid for
/// the name, expired) or the peer cannot speak what we do: the request was not sent.
#[cfg(feature = "pact-tls")]
fn is_handshake_refusal(io: &std::io::Error) -> bool {
    io.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()).is_some_and(|e| {
        matches!(
            e,
            rustls::Error::InvalidCertificate(_)
                | rustls::Error::NoCertificatesPresented
                | rustls::Error::PeerIncompatible(_)
                | rustls::Error::UnsupportedNameType
        )
    })
}

#[cfg(not(feature = "pact-tls"))]
fn is_handshake_refusal(_: &std::io::Error) -> bool {
    false
}

impl Transport for HttpTransport {
    fn post(&self, service: &Service, request: &Value, cancel: &CancelToken) -> Result<Value, TransportError> {
        let https = service.url.starts_with("https://");
        if !https && !service.url.starts_with("http://") {
            return Err(TransportError::NotSent("the url is not http or https".into()));
        }
        let agent = self.agent(https)?;
        // The model's cancel closes the connection, which is the service's cancel; this thread is in a read.
        let closer = agent.clone();
        cancel.on_cancel(move || closer.shutdown());
        if cancel.is_cancelled() {
            return Err(lost("cancelled"));
        }
        let body = super::canon::bytes(request);
        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let mut response = agent
            .post(&service.url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .header("MCP-Protocol-Version", PROTOCOL_VERSION)
            .send(&body[..])
            .map_err(|e| {
                let text = e.to_string();
                if cancel.is_cancelled() {
                    lost("cancelled")
                } else if not_sent(&e) {
                    TransportError::NotSent(text)
                } else {
                    lost(text)
                }
            })?;
        let status = response.status().as_u16();
        let header = |name: &str| response.headers().get(name).and_then(|v| v.to_str().ok()).map(str::to_owned);
        let (content_type, retry_after) = (header("content-type").unwrap_or_default(), header("retry-after").is_some());
        let reader = response.body_mut().with_config().limit(u64::MAX).reader();
        interpret(status, &content_type, retry_after, reader, &id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Cursor, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;

    fn id() -> Value {
        json!(7)
    }

    fn answer() -> String {
        json!({"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "x"}]}}).to_string()
    }

    // --- reading, without sockets -------------------------------------------------------------

    #[test]
    fn a_json_body_is_the_answer_if_it_is_for_this_request() {
        let r = interpret(200, "application/json", false, Cursor::new(answer()), &id()).unwrap();
        assert_eq!(r["id"], 7);
        for (content_type, ok) in [
            ("application/json; charset=utf-8", true),
            ("APPLICATION/JSON", true),
            ("text/plain", false),
            ("", false),
            ("application/jsonx", false),
        ] {
            let r = interpret(200, content_type, false, Cursor::new(answer()), &id());
            assert_eq!(r.is_ok(), ok, "{content_type}");
            if !ok {
                assert!(matches!(r, Err(TransportError::Unavailable(_))), "{content_type}");
            }
        }
        // Not JSON, an answer for another request, not a response at all, over the limit: the call was sent and nothing usable came.
        let other = json!({"jsonrpc": "2.0", "id": 8, "result": {}}).to_string();
        let notification = json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}}).to_string();
        for body in ["not json".to_owned(), other, notification, "[]".to_owned(), String::new()] {
            assert!(
                matches!(
                    interpret(200, "application/json", false, Cursor::new(body.clone()), &id()),
                    Err(TransportError::Lost(_))
                ),
                "{body}"
            );
        }
        let at_limit = format!(r#"{{"jsonrpc":"2.0","id":7,"result":"{}"}}"#, "a".repeat(MAX_ANSWER_MESSAGE - 36));
        assert_eq!(at_limit.len(), MAX_ANSWER_MESSAGE);
        assert!(interpret(200, "application/json", false, Cursor::new(at_limit.clone()), &id()).is_ok());
        assert!(matches!(
            interpret(200, "application/json", false, Cursor::new(format!("{at_limit} ")), &id()),
            Err(TransportError::Lost(_))
        ));
        assert!(matches!(
            interpret(200, "application/json", false, Cursor::new(vec![b'x'; 5 * 1024 * 1024]), &id()),
            Err(TransportError::Lost(_))
        ));
    }

    #[test]
    fn a_stream_is_read_until_the_answer() {
        let a = answer();
        let stream = format!(
            ": keepalive\n\n: keepalive\n\nevent: message\ndata: {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/progress\",\"params\":{{}}}}\n\n: keepalive\n\nid: 1\nretry: 100\ndata: {a}\n\n"
        );
        assert_eq!(read_sse(Cursor::new(stream), &id()).unwrap()["id"], 7);
        // CRLF, no space after the colon, an event split over several data lines, the last event without its blank line.
        assert!(read_sse(Cursor::new(format!("data:{a}\r\n\r\n")), &id()).is_ok());
        // Split inside the string `"2.0"`, wherever the members of the object are: a newline there is not JSON.
        let (first, second) = a.split_at(a.find("2.0").unwrap() + 1);
        assert!(
            read_sse(Cursor::new(format!("data: {first}\ndata: {second}\n\n")), &id()).is_err(),
            "joined with a newline, which JSON does not allow inside a token"
        );
        let split = json!({"jsonrpc": "2.0", "id": 7, "result": {"a": 1}});
        let pretty = serde_json::to_string_pretty(&split).unwrap();
        let multi: String = pretty.lines().map(|l| format!("data: {l}\n")).collect();
        assert!(read_sse(Cursor::new(format!("{multi}\n")), &id()).is_ok(), "an event over several data lines");
        assert!(read_sse(Cursor::new(format!("data: {a}")), &id()).is_ok(), "the last event without its blank line");
        // An answer for another request is a notification as far as this call goes; the stream ending is a lost answer.
        let other = json!({"jsonrpc": "2.0", "id": 99, "result": {}});
        assert!(matches!(read_sse(Cursor::new(format!("data: {other}\n\n")), &id()), Err(TransportError::Lost(_))));
        assert!(matches!(read_sse(Cursor::new(""), &id()), Err(TransportError::Lost(_))));
        assert!(matches!(read_sse(Cursor::new(": keepalive\n\n"), &id()), Err(TransportError::Lost(_))));
        assert!(matches!(read_sse(Cursor::new("data: {\"jsonrpc\":"), &id()), Err(TransportError::Lost(_))));
    }

    #[test]
    fn a_stream_has_limits() {
        // More than 64 KiB of things that are not the answer.
        let note = json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"m": "x".repeat(1000)}});
        let flood: String = (0..80).map(|_| format!("data: {note}\n\n")).collect();
        assert!(matches!(
            read_sse(Cursor::new(format!("{flood}data: {}\n\n", answer())), &id()),
            Err(TransportError::Lost(_))
        ));
        let few: String = (0..20).map(|_| format!("data: {note}\n\n")).collect();
        assert!(read_sse(Cursor::new(format!("{few}data: {}\n\n", answer())), &id()).is_ok());
        // Keepalive comments are not counted: they are what keeps the stream alive, however many.
        let alive: String = (0..100_000).map(|_| ": keepalive\n\n").collect();
        assert!(read_sse(Cursor::new(format!("{alive}data: {}\n\n", answer())), &id()).is_ok());
        // One event over the answer's limit, a line over it, and an answer just under it.
        assert!(matches!(
            read_sse(Cursor::new(format!("data: {}\n\n", "a".repeat(MAX_ANSWER_MESSAGE + 100))), &id()),
            Err(TransportError::Lost(_))
        ));
        let big = format!(r#"{{"jsonrpc":"2.0","id":7,"result":"{}"}}"#, "a".repeat(MAX_ANSWER_MESSAGE - 100));
        assert!(read_sse(Cursor::new(format!("data: {big}\n\n")), &id()).is_ok());
        // Several events whose data adds up over the limit are one event.
        let lines: String = (0..60).map(|_| format!("data: {}\n", "a".repeat(100_000))).collect();
        assert!(matches!(read_sse(Cursor::new(format!("{lines}\n")), &id()), Err(TransportError::Lost(_))));
    }

    #[test]
    fn a_stream_that_breaks_off_is_a_lost_answer() {
        struct Breaks(Cursor<Vec<u8>>);
        impl Read for Breaks {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                let n = self.0.read(out)?;
                if n == 0 { Err(std::io::ErrorKind::TimedOut.into()) } else { Ok(n) }
            }
        }
        let r = interpret(200, "text/event-stream", false, Breaks(Cursor::new(b": keepalive\n\n".to_vec())), &id());
        assert!(matches!(r, Err(TransportError::Lost(_))));
        let r = interpret(200, "application/json", false, Breaks(Cursor::new(b"{\"jsonrpc\":".to_vec())), &id());
        assert!(matches!(r, Err(TransportError::Lost(_))));
    }

    #[test]
    fn statuses_map_to_the_transport_errors_of_the_document() {
        let rpc_error = json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32602, "message": "x"}}).to_string();
        // 3xx: not followed.
        for status in [301, 302, 307, 308] {
            assert!(
                matches!(interpret(status, "", false, Cursor::new(""), &id()), Err(TransportError::Unavailable(_))),
                "{status}"
            );
        }
        // 503 with Retry-After is "try later"; without it, and the other 5xx and 4xx, unavailable.
        assert_eq!(interpret(503, "", true, Cursor::new(""), &id()), Err(TransportError::TryLater));
        for (status, retry) in
            [(503, false), (500, true), (502, false), (404, false), (405, false), (403, false), (429, true)]
        {
            assert!(
                matches!(
                    interpret(status, "text/html", retry, Cursor::new("<html>"), &id()),
                    Err(TransportError::Unavailable(_))
                ),
                "{status}"
            );
        }
        // A JSON-RPC error in the body of a refusal is handed on to be mapped.
        for status in [400, 500] {
            assert_eq!(
                interpret(status, "application/json", false, Cursor::new(rpc_error.clone()), &id()).unwrap()["error"]["code"],
                -32602
            );
        }
        // But not a body that is not an error, nor a huge one.
        assert!(interpret(400, "application/json", false, Cursor::new(answer()), &id()).is_err());
        assert!(
            interpret(
                400,
                "application/json",
                false,
                Cursor::new(format!("{rpc_error}{}", " ".repeat(MAX_ERROR_BODY))),
                &id()
            )
            .is_err()
        );
        // The text of an error is not in what is returned.
        let e = interpret(500, "text/plain", false, Cursor::new("secret internal text"), &id()).unwrap_err();
        assert!(!format!("{e:?}").contains("secret"));
    }

    // --- real sockets (skipped where a port cannot be bound) -----------------------------------

    /// Under `PACT_REQUIRE_TCP=1` not being able to bind a port fails the test; otherwise the test says
    /// `SKIPPED` on standard error and passes, which proves nothing about the socket code.
    fn cannot_bind(e: &std::io::Error) {
        assert!(
            std::env::var_os("PACT_REQUIRE_TCP").is_none_or(|v| v.is_empty() || v == "0"),
            "PACT_REQUIRE_TCP is set and this environment does not allow binding a TCP port: {e}"
        );
        eprintln!("SKIPPED: this environment does not allow binding a TCP port: {e}");
    }

    trait Stream: Read + Write + Send {}
    impl<T: Read + Write + Send> Stream for T {}

    #[cfg(feature = "pact-tls")]
    type TlsServer = Option<std::sync::Arc<rustls::ServerConfig>>;
    #[cfg(not(feature = "pact-tls"))]
    type TlsServer = Option<()>;

    #[cfg(feature = "pact-tls")]
    fn wrap(tcp: TcpStream, tls: &TlsServer) -> Box<dyn Stream> {
        match tls {
            None => Box::new(tcp),
            Some(config) => Box::new(rustls::StreamOwned::new(
                rustls::ServerConnection::new(std::sync::Arc::clone(config)).unwrap(),
                tcp,
            )),
        }
    }

    #[cfg(not(feature = "pact-tls"))]
    fn wrap(tcp: TcpStream, _: &TlsServer) -> Box<dyn Stream> {
        Box::new(tcp)
    }

    struct Fake {
        url: String,
        requests: mpsc::Receiver<String>,
        _listener: thread::JoinHandle<()>,
    }

    /// A server that accepts connections, reads one request each, sends the head of it to the test, and
    /// then runs `respond` on the connection. `None` where this environment does not let a port be bound.
    fn fake(respond: impl Fn(&mut dyn Stream) + Send + Sync + 'static) -> Option<Fake> {
        fake_with(None, respond)
    }

    fn fake_with(tls: TlsServer, respond: impl Fn(&mut dyn Stream) + Send + Sync + 'static) -> Option<Fake> {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(e) => {
                cannot_bind(&e);
                return None;
            }
        };
        let scheme = if tls.is_some() { "https" } else { "http" };
        let url = format!("{scheme}://{}/mcp", listener.local_addr().unwrap());
        let tls = std::sync::Arc::new(tls);
        let (tx, requests) = mpsc::channel();
        let respond = std::sync::Arc::new(respond);
        let handle = thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(tcp) = stream else { break };
                let (tx, respond, tls) = (tx.clone(), std::sync::Arc::clone(&respond), std::sync::Arc::clone(&tls));
                thread::spawn(move || {
                    let mut stream = wrap(tcp, &tls);
                    let mut head = Vec::new();
                    let mut byte = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if stream.read(&mut byte).unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let text = String::from_utf8_lossy(&head).into_owned();
                    let length = text
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap_or(0))
                        })
                        .unwrap_or(0);
                    let mut body = vec![0u8; length];
                    let _ = stream.read_exact(&mut body);
                    let _ = tx.send(format!("{text}{}", String::from_utf8_lossy(&body)));
                    respond(&mut *stream);
                });
            }
        });
        Some(Fake { url, requests, _listener: handle })
    }

    fn service(url: &str) -> Service {
        Service { host: "a.example".into(), name: "probe".into(), url: url.into() }
    }

    fn request() -> Value {
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "rt_procs"}})
    }

    fn send(s: &mut dyn Stream, text: &str) {
        let _ = s.write_all(text.as_bytes());
        let _ = s.flush();
    }

    fn quick() -> HttpTransport {
        HttpTransport::new(None).with_timeouts(Duration::from_millis(600), Duration::from_secs(5))
    }

    #[test]
    fn a_service_answer_with_a_repeated_key_is_a_lost_answer_never_the_first_or_the_last() {
        let id = json!(7);
        for body in [
            r#"{"jsonrpc":"2.0","id":7,"result":{"content":[]},"result":{"content":[1]}}"#,
            r#"{"jsonrpc":"2.0","id":7,"id":8,"result":{}}"#,
            r#"{"jsonrpc":"2.0","id":7,"result":{"structuredContent":{"outcome":"done","outcome":"declined"}}}"#,
            r#"{"jsonrpc":"2.0","id":7,"result":{"tools":[{"name":"a","name":"b"}]}}"#,
        ] {
            let r = read_json_answer(std::io::Cursor::new(body.as_bytes().to_vec()), &id);
            assert!(
                matches!(&r, Err(TransportError::Lost(m)) if m.contains("not JSON") || m.contains("twice")),
                "{body}: {r:?}"
            );
            let sse = format!("data: {body}\n\n");
            let r = read_sse(std::io::Cursor::new(sse.into_bytes()), &id);
            assert!(r.is_err(), "{body}");
        }
        let ok = r#"{"jsonrpc":"2.0","id":7,"result":{"a":{"a":1}}}"#;
        assert!(read_json_answer(std::io::Cursor::new(ok.as_bytes().to_vec()), &id).is_ok());
    }

    #[test]
    fn a_json_answer_over_a_socket_and_what_is_sent() {
        let a = answer();
        let Some(f) = fake(move |s| {
            send(
                s,
                &format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{a}",
                    a.len()
                ),
            )
        }) else {
            return;
        };
        let r = quick().post(&service(&f.url), &request(), &CancelToken::default()).unwrap();
        assert_eq!(r["id"], 7);
        let head = f.requests.recv_timeout(Duration::from_secs(5)).unwrap();
        let lower = head.to_ascii_lowercase();
        assert!(head.starts_with("POST /mcp HTTP/1.1\r\n"), "{head}");
        for expected in [
            "content-type: application/json\r\n",
            "accept: application/json, text/event-stream\r\n",
            "mcp-protocol-version: 2025-06-18\r\n",
            "host: 127.0.0.1:",
        ] {
            assert!(lower.contains(expected), "{expected} not in {head}");
        }
        // None of what `ureq` adds by itself.
        for absent in ["user-agent", "accept-encoding", "origin:", "cookie", "proxy-"] {
            assert!(!lower.contains(absent), "{absent} in {head}");
        }
        assert!(head.ends_with(&request().to_string()), "{head}");
    }

    #[test]
    fn a_stream_with_keepalives_longer_than_the_idle_timeout_is_not_a_lost_answer() {
        let a = answer();
        let Some(f) = fake(move |s| {
            send(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            );
            let chunk = |t: &str| format!("{:x}\r\n{t}\r\n", t.len());
            // The head at once, then silence broken every 200 ms for 2 seconds: more than three idle timeouts.
            for _ in 0..10 {
                send(s, &chunk(": keepalive\n\n"));
                thread::sleep(Duration::from_millis(200));
            }
            send(s, &chunk(&format!("data: {a}\n\n")));
            send(s, "0\r\n\r\n");
        }) else {
            return;
        };
        let started = std::time::Instant::now();
        let r = quick().post(&service(&f.url), &request(), &CancelToken::default()).unwrap();
        assert_eq!(r["id"], 7);
        assert!(started.elapsed() > Duration::from_millis(1500), "it waited for the verb");
    }

    #[test]
    fn silence_for_the_idle_timeout_is_a_lost_answer() {
        let Some(f) = fake(|s| {
            send(s, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n: keepalive\n\n");
            thread::sleep(Duration::from_secs(5));
        }) else {
            return;
        };
        let started = std::time::Instant::now();
        let r = quick().post(&service(&f.url), &request(), &CancelToken::default());
        assert!(matches!(r, Err(TransportError::Lost(_))), "{r:?}");
        assert!(started.elapsed() < Duration::from_secs(4), "{:?}", started.elapsed());
    }

    #[test]
    fn a_redirect_is_not_followed_and_statuses_map() {
        let Some(f) = fake(|s| {
            send(
                s,
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
        }) else {
            return;
        };
        let r = quick().post(&service(&f.url), &request(), &CancelToken::default());
        assert!(matches!(r, Err(TransportError::Unavailable(_))), "{r:?}");
        assert!(f.requests.recv_timeout(Duration::from_secs(5)).is_ok());
        assert!(f.requests.recv_timeout(Duration::from_millis(300)).is_err(), "no second request");

        let Some(f) = fake(|s| {
            send(
                s,
                "HTTP/1.1 503 Service Unavailable\r\nRetry-After: 5\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            )
        }) else {
            return;
        };
        assert_eq!(quick().post(&service(&f.url), &request(), &CancelToken::default()), Err(TransportError::TryLater));
        let Some(f) =
            fake(|s| send(s, "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
        else {
            return;
        };
        assert!(matches!(
            quick().post(&service(&f.url), &request(), &CancelToken::default()),
            Err(TransportError::Unavailable(_))
        ));
        let body = json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32602, "message": "x"}}).to_string();
        let Some(f) = fake(move |s| {
            send(
                s,
                &format!(
                    "HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ),
            )
        }) else {
            return;
        };
        assert_eq!(
            quick().post(&service(&f.url), &request(), &CancelToken::default()).unwrap()["error"]["code"],
            -32602
        );
    }

    #[test]
    fn a_connection_that_ends_early_is_a_lost_answer() {
        let Some(f) = fake(|s| {
            send(
                s,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 500\r\nConnection: close\r\n\r\n{\"jsonrpc\"",
            )
        }) else {
            return;
        };
        assert!(matches!(
            quick().post(&service(&f.url), &request(), &CancelToken::default()),
            Err(TransportError::Lost(_))
        ));
        let Some(f) = fake(|s| {
            send(s, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n: keepalive\n\n")
        }) else {
            return;
        };
        assert!(matches!(
            quick().post(&service(&f.url), &request(), &CancelToken::default()),
            Err(TransportError::Lost(_))
        ));
        // Accepted and closed without a word: sent, and nothing came back.
        let Some(f) = fake(|_| ()) else { return };
        assert!(matches!(
            quick().post(&service(&f.url), &request(), &CancelToken::default()),
            Err(TransportError::Lost(_))
        ));
    }

    #[test]
    fn nothing_listening_means_nothing_was_sent() {
        let listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(l) => l,
            Err(e) => {
                cannot_bind(&e);
                return;
            }
        };
        let url = format!("http://{}/mcp", listener.local_addr().unwrap());
        drop(listener);
        assert!(matches!(
            quick().post(&service(&url), &request(), &CancelToken::default()),
            Err(TransportError::NotSent(_))
        ));
        assert!(matches!(
            quick().post(&service("ftp://127.0.0.1/"), &request(), &CancelToken::default()),
            Err(TransportError::NotSent(_))
        ));
    }

    #[test]
    fn a_refused_connection_is_not_sent_even_without_a_server_of_ours() {
        // Port 1 has nobody on it; where the environment forbids even connecting the same words are said.
        let r = quick().post(&service("http://127.0.0.1:1/mcp"), &request(), &CancelToken::default());
        assert!(matches!(r, Err(TransportError::NotSent(_))), "{r:?}");
    }

    #[test]
    fn a_cancel_closes_the_connection_which_is_the_services_cancel() {
        let (closed_tx, closed_rx) = mpsc::channel::<()>();
        let closed_tx = std::sync::Mutex::new(closed_tx);
        let (held_tx, held_rx) = mpsc::channel::<()>();
        let held_tx = std::sync::Mutex::new(held_tx);
        let Some(f) = fake(move |s| {
            send(s, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n: keepalive\n\n");
            let _ = held_tx.lock().unwrap().send(()); // the call is in progress: now it may be cancelled
            // Hold the call; the client closing is how this service learns of a cancel.
            let mut buf = [0u8; 16];
            while s.read(&mut buf).unwrap_or(0) > 0 {}
            let _ = closed_tx.lock().unwrap().send(());
        }) else {
            return;
        };
        let transport = HttpTransport::new(None).with_timeouts(Duration::from_secs(30), Duration::from_secs(5));
        let cancel = CancelToken::default();
        let c2 = cancel.clone();
        let canceller = thread::spawn(move || {
            // Cancel when the service says it has the call, not after a fixed time.
            let _ = held_rx.recv_timeout(Duration::from_secs(10));
            c2.cancel();
        });
        let started = std::time::Instant::now();
        let r = transport.post(&service(&f.url), &request(), &cancel);
        assert!(matches!(r, Err(TransportError::Lost(_))), "{r:?}");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "it did not wait for the idle timeout: {:?}",
            started.elapsed()
        );
        assert!(closed_rx.recv_timeout(Duration::from_secs(5)).is_ok(), "the service saw the connection close");
        canceller.join().unwrap();
        // Already cancelled: nothing is sent.
        assert!(matches!(transport.post(&service(&f.url), &request(), &cancel), Err(TransportError::Lost(_))));
    }

    #[cfg(not(feature = "pact-tls"))]
    #[test]
    fn https_without_tls_is_not_sent() {
        let r = quick().post(&service("https://a.example/mcp"), &request(), &CancelToken::default());
        assert!(matches!(r, Err(TransportError::NotSent(m)) if m.contains("pact-tls")));
    }

    // --- https, over a fake server with a test CA (feature pact-tls) -------------------------------

    #[cfg(feature = "pact-tls")]
    mod tls {
        use super::*;
        use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, SanType};
        use rustls_pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
        use std::net::{IpAddr, Ipv4Addr};
        use std::sync::Arc;

        struct Pki {
            root_pem: String,
            cert_pem: String,
            key_pem: String,
        }

        /// A root and a server certificate for the IP address `san` (the server listens on 127.0.0.1).
        fn pki(san: Ipv4Addr) -> Pki {
            let ca_key = KeyPair::generate().unwrap();
            let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let ca = ca_params.self_signed(&ca_key).unwrap();
            let server_key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
            params.subject_alt_names.push(SanType::IpAddress(IpAddr::V4(san)));
            let server = params.signed_by(&server_key, &Issuer::new(ca_params, &ca_key)).unwrap();
            Pki { root_pem: ca.pem(), cert_pem: server.pem(), key_pem: server_key.serialize_pem() }
        }

        fn server_config(p: &Pki) -> Arc<rustls::ServerConfig> {
            let chain: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(p.cert_pem.as_bytes()).collect::<Result<_, _>>().unwrap();
            let key = PrivateKeyDer::from_pem_slice(p.key_pem.as_bytes()).unwrap();
            Arc::new(
                rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                    .with_protocol_versions(&[&rustls::version::TLS13])
                    .unwrap()
                    .with_no_client_auth()
                    .with_single_cert(chain, key)
                    .unwrap(),
            )
        }

        fn json_ok() -> impl Fn(&mut dyn Stream) + Send + Sync + 'static {
            let a = answer();
            move |s| {
                send(
                    s,
                    &format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{a}",
                        a.len()
                    ),
                )
            }
        }

        fn with_root(root: &str) -> HttpTransport {
            HttpTransport::new(Some(root.to_owned())).with_timeouts(Duration::from_secs(5), Duration::from_secs(5))
        }

        #[test]
        fn an_https_answer_from_a_server_the_root_vouches_for() {
            let p = pki(Ipv4Addr::LOCALHOST);
            let Some(f) = fake_with(Some(server_config(&p)), json_ok()) else { return };
            let r = with_root(&p.root_pem).post(&service(&f.url), &request(), &CancelToken::default()).unwrap();
            assert_eq!(r["id"], 7);
            let head = f.requests.recv_timeout(Duration::from_secs(5)).unwrap().to_ascii_lowercase();
            assert!(
                head.contains("accept: application/json, text/event-stream") && !head.contains("user-agent"),
                "{head}"
            );
        }

        #[test]
        fn a_stream_over_https_with_keepalives() {
            let a = answer();
            let p = pki(Ipv4Addr::LOCALHOST);
            let Some(f) = fake_with(Some(server_config(&p)), move |s| {
                send(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                );
                let chunk = |t: &str| format!("{:x}\r\n{t}\r\n", t.len());
                for _ in 0..3 {
                    send(s, &chunk(": keepalive\n\n"));
                    thread::sleep(Duration::from_millis(100));
                }
                send(s, &chunk(&format!("data: {a}\n\n")));
                send(s, "0\r\n\r\n");
            }) else {
                return;
            };
            assert_eq!(
                with_root(&p.root_pem).post(&service(&f.url), &request(), &CancelToken::default()).unwrap()["id"],
                7
            );
        }

        #[test]
        fn a_certificate_the_root_does_not_vouch_for_is_refused_and_nothing_is_sent() {
            let (server, other) = (pki(Ipv4Addr::LOCALHOST), pki(Ipv4Addr::LOCALHOST));
            let Some(f) = fake_with(Some(server_config(&server)), json_ok()) else { return };
            let r = with_root(&other.root_pem).post(&service(&f.url), &request(), &CancelToken::default());
            assert!(matches!(r, Err(TransportError::NotSent(_))), "{r:?}");
            assert!(f.requests.recv_timeout(Duration::from_millis(500)).is_err(), "no request reached the server");
        }

        #[test]
        fn a_certificate_for_another_address_is_refused_and_nothing_is_sent() {
            let p = pki(Ipv4Addr::new(127, 0, 0, 2));
            let Some(f) = fake_with(Some(server_config(&p)), json_ok()) else { return };
            let r = with_root(&p.root_pem).post(&service(&f.url), &request(), &CancelToken::default());
            assert!(matches!(r, Err(TransportError::NotSent(_))), "{r:?}");
            assert!(f.requests.recv_timeout(Duration::from_millis(500)).is_err());
        }

        #[test]
        fn https_needs_a_root_and_a_root_must_be_a_certificate() {
            let p = pki(Ipv4Addr::LOCALHOST);
            let Some(f) = fake_with(Some(server_config(&p)), json_ok()) else { return };
            let none = HttpTransport::new(None).post(&service(&f.url), &request(), &CancelToken::default());
            assert!(matches!(none, Err(TransportError::NotSent(m)) if m.contains("TLS root")));
            let junk = with_root("not a certificate").post(&service(&f.url), &request(), &CancelToken::default());
            assert!(matches!(junk, Err(TransportError::NotSent(_))), "{junk:?}");
        }
    }
}
