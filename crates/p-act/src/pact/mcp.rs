//! The MCP server toward the model's client, newline-delimited JSON-RPC on a
//! byte stream (`proposals/pact.md` section 4): `initialize`, `ping`,
//! `tools/list`, `tools/call` and `notifications/cancelled`. Anything else is
//! `method not found`. What it does with a call is `compose` and `outcome`; how
//! the request reaches a service is the [`Transport`].

use super::bundle::AgentKey;
use super::catalogue::Catalogue;
use super::compose::prepare;
use super::outcome::{Class, ModelResult, Outcome, from_response, from_transport_error, outcome_line};
use super::rt::{Clock, Random};
use super::transport::{CancelToken, Transport};
use super::{MAX_WAITING, PROGRESS_TEXT, Service, Settings};
use crate::exchange::LineReader;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

/// A message from the model's client is at most this long.
pub const MAX_MESSAGE: usize = 1024 * 1024;
/// The protocol revisions `pact` speaks.
pub const PROTOCOL_VERSIONS: [&str; 3] = ["2025-06-18", "2025-03-26", "2024-11-05"];

/// What the model reads once, in plain words.
pub const INSTRUCTIONS: &str = "These tools call services on other machines. A call may need your person's approval and then waits for it, up to its deadline. The first text of every result is one line of JSON with an outcome. done: it ran; the answer follows. declined: your person said no; do not repeat it unless they ask. refused: someone said no without asking your person; not-allowed means change your plan, invalid means fix the call, try-later means wait and ask again. expired: nothing was done; you may ask again as a new call after telling your person. unavailable: nothing was done. unknown: the call was sent and whether it ran is not known; before you repeat anything that changes something, find out by a query.";

/// Everything a session needs; shared by the sessions of one `pact serve`.
pub struct Context {
    pub services: Vec<Service>,
    pub catalogue: RwLock<Catalogue>,
    pub key: AgentKey,
    pub settings: Settings,
    pub transport: Box<dyn Transport>,
    pub clock: Box<dyn Clock>,
    pub random: Box<dyn Random>,
    /// Where `pact` says what it did: the call's identifier and hash, what was dropped, what went wrong. Never key material.
    pub log: Box<dyn Fn(&str) + Send + Sync>,
    /// How often a progress notification goes to the model's client while a call waits.
    pub progress_interval: Duration,
    waiting: AtomicUsize,
    rpc_id: AtomicU64,
}

impl Context {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        services: Vec<Service>,
        catalogue: Catalogue,
        key: AgentKey,
        settings: Settings,
        transport: Box<dyn Transport>,
        clock: Box<dyn Clock>,
        random: Box<dyn Random>,
        log: Box<dyn Fn(&str) + Send + Sync>,
    ) -> Context {
        Context {
            services,
            catalogue: RwLock::new(catalogue),
            key,
            settings,
            transport,
            clock,
            random,
            log,
            progress_interval: super::PROGRESS_INTERVAL,
            waiting: AtomicUsize::new(0),
            rpc_id: AtomicU64::new(1),
        }
    }

    /// Ask the services for their tools again.
    pub fn refresh(&self) {
        match Catalogue::build(&self.services, &self.settings, &*self.transport) {
            Ok((catalogue, dropped)) => {
                dropped.iter().for_each(|d| (self.log)(d));
                if let Ok(mut c) = self.catalogue.write() {
                    *c = catalogue;
                }
            }
            Err(e) => (self.log)(&format!("not refreshed: {e}")),
        }
    }
}

/// The output stream, written one whole message at a time.
struct Out(Mutex<Box<dyn Write + Send>>);

impl Out {
    fn send(&self, message: &Value) {
        let mut line = super::canon::bytes(message);
        line.push(b'\n');
        if let Ok(mut w) = self.0.lock() {
            // A client that has gone is noticed by the reader; there is nobody to tell here.
            let _ = w.write_all(&line).and_then(|()| w.flush());
        }
    }

    fn result(&self, id: &Value, result: Value) {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "result": result}));
    }

    fn error(&self, id: &Value, code: i64, message: &str) {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}));
    }
}

/// Serve one client on `input` and `output` until it ends its input. Calls still waiting then are cancelled.
pub fn serve(ctx: &Arc<Context>, input: impl Read, output: impl Write + Send + 'static) -> io::Result<()> {
    let out = Arc::new(Out(Mutex::new(Box::new(output))));
    let inflight: Arc<Mutex<HashMap<String, CancelToken>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut workers = Vec::new();
    let mut lines = LineReader::with_limit(input, MAX_MESSAGE);
    loop {
        let line = match lines.read_line() {
            Ok(Some(l)) => l,
            Ok(None) => break,
            Err(e) => {
                (ctx.log)(&format!("the client's input ended badly: {e}"));
                break;
            }
        };
        let Ok(message) = serde_json::from_slice::<Value>(&line) else {
            out.error(&Value::Null, -32700, "parse error");
            continue;
        };
        let Some(object) = message.as_object() else {
            out.error(&Value::Null, -32600, "a message is one JSON object");
            continue;
        };
        let id = object.get("id").cloned();
        let params = object.get("params").cloned().unwrap_or(Value::Null);
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            // A response from the client to something `pact` never asked, or garbage.
            if id.is_some() && !object.contains_key("result") && !object.contains_key("error") {
                out.error(id.as_ref().unwrap_or(&Value::Null), -32600, "no method");
            }
            continue;
        };
        match (method, id) {
            ("initialize", Some(id)) => out.result(&id, initialize(&params)),
            ("ping", Some(id)) => out.result(&id, json!({})),
            ("tools/list", Some(id)) => {
                let tools = ctx.catalogue.read().map(|c| c.to_mcp()).unwrap_or_else(|_| json!([]));
                out.result(&id, json!({"tools": tools}));
            }
            ("tools/call", Some(id)) => {
                let Some(name) = params.get("name").and_then(Value::as_str).map(str::to_owned) else {
                    out.error(&id, -32602, "tools/call needs a name");
                    continue;
                };
                let token = CancelToken::default();
                if let Ok(mut m) = inflight.lock() {
                    m.insert(super::canon::line(&id), token.clone());
                }
                let (ctx, out, inflight) = (Arc::clone(ctx), Arc::clone(&out), Arc::clone(&inflight));
                workers.push(std::thread::spawn(move || {
                    let result = call(&ctx, &out, &name, &params, &token);
                    if let Ok(mut m) = inflight.lock() {
                        m.remove(&super::canon::line(&id));
                    }
                    // A cancelled request gets no response (MCP, cancellation).
                    if !token.is_cancelled() {
                        out.result(&id, result);
                    }
                }));
            }
            ("notifications/cancelled", None) => {
                if let (Some(rid), Ok(m)) = (params.get("requestId"), inflight.lock())
                    && let Some(t) = m.get(&super::canon::line(rid))
                {
                    t.cancel();
                }
            }
            (_, None) => {} // `notifications/initialized` and every other notification
            (_, Some(id)) => out.error(&id, -32601, "method not found"),
        }
    }
    // The client has gone: nobody will read an answer, so nothing is waited for.
    if let Ok(m) = inflight.lock() {
        m.values().for_each(CancelToken::cancel);
    }
    workers.into_iter().for_each(|w| {
        let _ = w.join();
    });
    Ok(())
}

fn initialize(params: &Value) -> Value {
    let asked = params.get("protocolVersion").and_then(Value::as_str);
    let version = asked.filter(|v| PROTOCOL_VERSIONS.contains(v)).unwrap_or(PROTOCOL_VERSIONS[0]);
    json!({
        "protocolVersion": version,
        "capabilities": {"tools": {"listChanged": false}},
        "serverInfo": {"name": "pact", "version": env!("CARGO_PKG_VERSION")},
        "instructions": INSTRUCTIONS
    })
}

/// A progress token of the model's client is a string or a number, which `pact` gives back as it came.
fn client_progress_token(params: &Value) -> Option<Value> {
    params.get("_meta")?.get("progressToken").filter(|t| t.is_string() || t.is_number()).cloned()
}

/// One tool call without a client: the same code path as `tools/call`, for `pact call`.
#[must_use]
pub fn call_once(ctx: &Context, name: &str, arguments: &Value) -> Value {
    let out = Out(Mutex::new(Box::new(io::sink())));
    call(ctx, &out, name, &json!({"name": name, "arguments": arguments}), &CancelToken::default())
}

fn call(ctx: &Context, out: &Out, name: &str, params: &Value, cancel: &CancelToken) -> Value {
    // At most 16 calls wait at once; the 17th is told to try later, and nothing is signed for it.
    if ctx.waiting.fetch_add(1, Ordering::SeqCst) >= MAX_WAITING {
        ctx.waiting.fetch_sub(1, Ordering::SeqCst);
        let line = outcome_line(Outcome::Refused(Class::TryLater), None);
        return json!({"content": [{"type": "text", "text": line}], "isError": true});
    }
    let result = call_waiting(ctx, out, name, params, cancel);
    ctx.waiting.fetch_sub(1, Ordering::SeqCst);
    result
}

fn call_waiting(ctx: &Context, out: &Out, name: &str, params: &Value, cancel: &CancelToken) -> Value {
    let found = ctx.catalogue.read().ok().and_then(|c| c.find(name).cloned());
    let Some(tool) = found else {
        let shown: String = name.chars().take(60).collect();
        return ModelResult::model_error(&format!("there is no tool `{shown}`"));
    };
    let Some(service) = ctx.services.get(tool.service) else {
        return ModelResult::model_error("there is no such tool");
    };
    let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);
    let prepared = match prepare(&ctx.key, &ctx.settings, &*ctx.clock, &*ctx.random, service, &tool, &arguments) {
        Ok(p) => p,
        Err(e) => return ModelResult::model_error(&e.0),
    };
    (ctx.log)(&format!(
        "call {} {} to {}@{} until {}",
        prepared.id, prepared.call_hash, service.name, service.host, prepared.deadline
    ));
    let request = prepared.request(ctx.rpc_id.fetch_add(1, Ordering::SeqCst));

    // While it waits, the model's client hears every 15 seconds that it does; one fixed text, never a service's.
    let (stop, ticks) = mpsc::channel::<()>();
    let posted = std::thread::scope(|scope| {
        if let Some(token) = client_progress_token(params) {
            let interval = ctx.progress_interval;
            scope.spawn(move || {
                let mut n = 0u64;
                while let Err(RecvTimeoutError::Timeout) = ticks.recv_timeout(interval) {
                    n += 1;
                    out.send(&json!({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": token, "progress": n, "message": PROGRESS_TEXT}}));
                }
            });
        }
        let r = ctx.transport.post(service, &request, cancel);
        drop(stop); // wakes the ticker, which ends
        r
    });
    let (result, log) = match posted {
        Ok(response) => from_response(&response, &prepared.id),
        Err(e) => {
            let (r, l) = from_transport_error(&e, &prepared.id);
            (r, Some(l))
        }
    };
    if let Some(l) = log {
        (ctx.log)(&format!("call {}: {l}", prepared.id));
    }
    result.to_mcp()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::call::Call;
    use crate::pact::bundle::Bundle;
    use crate::pact::fixture::Fixture;
    use crate::pact::outcome::UNKNOWN_TEXT;
    use crate::pact::rt::{SystemClock, SystemRandomSource};
    use crate::pact::transport::{Memory, TransportError};
    use crate::sign::{PublicKey, signature_from_base64, verify_call};
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixStream;
    use std::sync::Condvar;
    use std::sync::atomic::AtomicBool;
    use std::thread::JoinHandle;

    type Handler = dyn Fn(&Service, &Value, &CancelToken) -> Result<Value, TransportError> + Send + Sync;

    fn schema() -> Value {
        json!({"type": "object", "properties": {"params": {"type": "array", "maxItems": 3, "items": {"type": "string", "maxLength": 64}}, "claim": {"type": "string", "maxLength": 200}, "wait_seconds": {"type": "integer"}}, "additionalProperties": false})
    }

    fn listing() -> Value {
        json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": [{"name": "rt_procs", "description": "Rated: internal, none, none. Lists processes.", "inputSchema": schema()}]}})
    }

    fn done(request: &Value, rc: i64, text: &str) -> Value {
        // The service answers for the call it was given.
        let call =
            Call::parse(STANDARD.decode(request["params"]["_meta"]["procession/call"].as_str().unwrap()).unwrap())
                .unwrap();
        let first = json!({"type": "outcome", "outcome": "done", "id": call.id().as_str(), "rc": rc}).to_string();
        json!({"jsonrpc": "2.0", "id": request["id"], "result": {"content": [{"type": "text", "text": first}, {"type": "text", "text": text}], "isError": rc != 0}})
    }

    struct Env {
        f: Fixture,
        transport: Arc<Memory>,
        ctx: Arc<Context>,
    }

    fn env_with(
        handler: impl Fn(&Service, &Value, &CancelToken) -> Result<Value, TransportError> + Send + Sync + 'static,
        interval: Duration,
        hosts: &[&str],
    ) -> Env {
        let f = Fixture::new("alice", &["extension:groups@procession=admins"]);
        let now = "2026-11-11T15:00:00Z".parse().unwrap();
        let key = Bundle::parse(&f.bundle(&Fixture::default_config("http://127.0.0.1:1/")), now).unwrap().key;
        let services: Vec<Service> = hosts
            .iter()
            .map(|h| Service { host: (*h).into(), name: "probe".into(), url: format!("http://127.0.0.1:1/{h}") })
            .collect();
        let handler: Box<Handler> = Box::new(handler);
        let transport =
            Arc::new(Memory::new(
                move |s, r, c| if r["method"] == "tools/list" { Ok(listing()) } else { handler(s, r, c) },
            ));
        let settings = Settings::new(120, Some(1));
        let (catalogue, _) = Catalogue::build(&services, &settings, &*transport).unwrap();
        let mut ctx = Context::new(
            services,
            catalogue,
            key,
            settings,
            Box::new(Arc::clone(&transport)),
            Box::new(SystemClock),
            Box::new(SystemRandomSource::default()),
            Box::new(|_| ()),
        );
        ctx.progress_interval = interval;
        Env { f, transport, ctx: Arc::new(ctx) }
    }

    fn env(
        handler: impl Fn(&Service, &Value, &CancelToken) -> Result<Value, TransportError> + Send + Sync + 'static,
    ) -> Env {
        env_with(handler, Duration::from_secs(3600), &["a.example"])
    }

    struct Client {
        w: UnixStream,
        r: BufReader<UnixStream>,
        server: Option<JoinHandle<io::Result<()>>>,
    }

    fn connect(ctx: &Arc<Context>) -> Client {
        let (a, b) = UnixStream::pair().unwrap();
        a.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        let ctx = Arc::clone(ctx);
        let reader = b.try_clone().unwrap();
        let server = std::thread::spawn(move || serve(&ctx, reader, b));
        Client { r: BufReader::new(a.try_clone().unwrap()), w: a, server: Some(server) }
    }

    impl Client {
        fn send(&mut self, v: &Value) {
            self.w.write_all(format!("{v}\n").as_bytes()).unwrap();
        }

        fn raw(&mut self, s: &str) {
            self.w.write_all(format!("{s}\n").as_bytes()).unwrap();
        }

        fn recv(&mut self) -> Value {
            let mut line = String::new();
            self.r.read_line(&mut line).unwrap();
            assert!(!line.is_empty(), "the server closed");
            serde_json::from_str(&line).unwrap()
        }

        fn call(&mut self, id: u64, name: &str, arguments: &Value, meta: Option<Value>) {
            let mut params = json!({"name": name, "arguments": arguments});
            if let Some(m) = meta {
                params["_meta"] = m;
            }
            self.send(&json!({"jsonrpc": "2.0", "id": id, "method": "tools/call", "params": params}));
        }

        fn finish(mut self) {
            self.w.shutdown(std::net::Shutdown::Write).unwrap();
            self.server.take().unwrap().join().unwrap().unwrap();
        }
    }

    fn first_text(result: &Value) -> Value {
        serde_json::from_str(result["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
    }

    #[test]
    fn the_protocol_basics() {
        let e = env(|_, _, _| unreachable!());
        let mut c = connect(&e.ctx);
        c.send(&json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "x", "version": "1"}}}));
        let r = c.recv();
        assert_eq!(r["id"], 1);
        assert_eq!(r["result"]["protocolVersion"], "2025-03-26");
        assert_eq!(r["result"]["capabilities"], json!({"tools": {"listChanged": false}}));
        assert_eq!(r["result"]["serverInfo"]["name"], "pact");
        assert_eq!(r["result"]["instructions"], INSTRUCTIONS);
        for word in
            ["done", "declined", "refused", "expired", "unavailable", "unknown", "not-allowed", "invalid", "try-later"]
        {
            assert!(INSTRUCTIONS.contains(word), "{word}");
        }
        c.send(
            &json!({"jsonrpc": "2.0", "id": "a", "method": "initialize", "params": {"protocolVersion": "1999-01-01"}}),
        );
        let r = c.recv();
        assert_eq!((r["id"].clone(), r["result"]["protocolVersion"].clone()), (json!("a"), json!("2025-06-18")));
        c.send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        c.send(&json!({"jsonrpc": "2.0", "id": 2, "method": "ping"}));
        assert_eq!(c.recv()["result"], json!({}));
        c.send(&json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}));
        let r = c.recv();
        assert_eq!(r["result"]["tools"][0]["name"], "rt_procs");
        assert_eq!(r["result"]["tools"][0]["inputSchema"]["properties"]["params"]["maxItems"], 3);
        assert_eq!(r["result"]["tools"][0]["inputSchema"]["properties"]["wait_seconds"]["maximum"], 120);
        // Everything else is method not found, with the client's own id; notifications are ignored.
        for method in
            ["resources/list", "prompts/list", "sampling/createMessage", "completion/complete", "logging/setLevel"]
        {
            c.send(&json!({"jsonrpc": "2.0", "id": 9, "method": method}));
            let r = c.recv();
            assert_eq!((r["id"].clone(), r["error"]["code"].clone()), (json!(9), json!(-32601)), "{method}");
        }
        c.send(&json!({"jsonrpc": "2.0", "method": "resources/updated"}));
        // Garbage gets an error and the session goes on.
        c.raw("not json");
        assert_eq!(c.recv()["error"]["code"], -32700);
        c.raw("[1]");
        assert_eq!(c.recv()["error"]["code"], -32600);
        c.send(&json!({"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {}}));
        assert_eq!(c.recv()["error"]["code"], -32602);
        c.send(&json!({"jsonrpc": "2.0", "id": 5, "method": "ping"}));
        assert_eq!(c.recv()["id"], 5);
        c.finish();
    }

    #[test]
    fn a_tool_call_reaches_the_service_signed_and_the_answer_comes_back() {
        let e = env(|_, r, _| Ok(done(r, 0, r#"{"pid":1}"#)));
        let mut c = connect(&e.ctx);
        c.call(7, "rt_procs", &json!({"params": ["pid=1"], "claim": "why", "wait_seconds": 30}), None);
        let r = c.recv();
        assert_eq!(r["id"], 7);
        assert_eq!(r["result"]["isError"], false);
        assert_eq!(r["result"]["content"][1]["text"], r#"{"pid":1}"#);
        let line = first_text(&r);
        assert_eq!((line["outcome"].clone(), line["rc"].clone()), (json!("done"), json!(0)));
        c.finish();

        let sent = e.transport.sent();
        let calls: Vec<_> = sent.iter().filter(|(_, r)| r["method"] == "tools/call").collect();
        assert_eq!(calls.len(), 1);
        let (service, request) = calls[0];
        assert_eq!(service.host, "a.example");
        let params = &request["params"];
        assert_eq!(params["name"], "rt_procs");
        assert_eq!(params["arguments"], json!({"params": ["pid=1"], "claim": "why"}));
        let call = Call::parse(STANDARD.decode(params["_meta"]["procession/call"].as_str().unwrap()).unwrap()).unwrap();
        let sig = signature_from_base64(params["_meta"]["procession/call_sig"].as_str().unwrap()).unwrap();
        assert_eq!(verify_call(&call, &sig, &PublicKey::read(&e.f.delegation_pub()).unwrap()).unwrap(), "alice");
        assert_eq!(line["id"], call.id().as_str());
    }

    #[test]
    fn the_models_mistakes_and_unknown_tools_are_results_and_sign_nothing() {
        let e = env(|_, _, _| unreachable!("nothing may be sent"));
        let mut c = connect(&e.ctx);
        for (i, (name, args, expected)) in [
            ("rt_procs", json!({"params": ["a", "b", "c", "d"]}), "at most 3"),
            ("rt_procs", json!({"nope": 1}), "no argument"),
            ("rt_procs", json!({"params": [1]}), "array of strings"),
            ("no_such", json!({}), "no tool"),
        ]
        .into_iter()
        .enumerate()
        {
            c.call(i as u64 + 1, name, &args, None);
            let r = c.recv();
            assert_eq!(r["result"]["isError"], true);
            let text = r["result"]["content"][0]["text"].as_str().unwrap();
            assert!(text.contains(expected), "{text}");
            assert!(serde_json::from_str::<Value>(text).is_err(), "a model's mistake is not an outcome");
        }
        c.finish();
        assert!(e.transport.sent().iter().all(|(_, r)| r["method"] == "tools/list"));
    }

    #[test]
    fn what_the_transport_could_not_do_is_in_the_closed_list_and_nothing_is_sent_twice() {
        for (error, outcome, reason) in [
            (TransportError::NotSent("refused".into()), "unavailable", None),
            (TransportError::Unavailable("redirect".into()), "unavailable", None),
            (TransportError::TryLater, "refused", Some("try-later")),
            (TransportError::Lost("idle for 45 s".into()), "unknown", None),
        ] {
            let e2 = error.clone();
            let e = env(move |_, _, _| Err(e2.clone()));
            let mut c = connect(&e.ctx);
            c.call(1, "rt_procs", &json!({}), None);
            let r = c.recv();
            let line = first_text(&r);
            assert_eq!(line["outcome"], outcome, "{error:?}");
            assert_eq!(line.get("reason").and_then(Value::as_str), reason);
            assert_eq!(r["result"]["isError"], true);
            let all = r["result"]["content"].to_string();
            assert!(!all.contains("redirect") && !all.contains("idle for") && !all.contains("refused by"), "{all}");
            if outcome == "unknown" {
                assert_eq!(r["result"]["content"][1]["text"], UNKNOWN_TEXT);
            }
            c.finish();
            let posts = e.transport.sent().iter().filter(|(_, r)| r["method"] == "tools/call").count();
            assert_eq!(posts, 1, "a call is never sent twice: {error:?}");
        }
    }

    #[test]
    fn a_cancelled_call_stops_the_transport_and_gets_no_response() {
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let started_tx = Mutex::new(started_tx);
        let saw_cancel = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&saw_cancel);
        let e = env(move |_, _, cancel| {
            started_tx.lock().unwrap().send(()).unwrap();
            for _ in 0..2000 {
                if cancel.is_cancelled() {
                    seen.store(true, Ordering::SeqCst);
                    return Err(TransportError::Lost("cancelled".into()));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(TransportError::Lost("never cancelled".into()))
        });
        let mut c = connect(&e.ctx);
        c.call(11, "rt_procs", &json!({}), None);
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        c.send(&json!({"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 11, "reason": "changed my mind"}}));
        // The next thing the client hears is the answer to its next request, not to the cancelled one.
        c.send(&json!({"jsonrpc": "2.0", "id": 12, "method": "ping"}));
        assert_eq!(c.recv()["id"], 12);
        c.finish();
        assert!(saw_cancel.load(Ordering::SeqCst));
    }

    #[test]
    fn a_client_that_goes_cancels_what_waits() {
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        let started_tx = Mutex::new(started_tx);
        let saw_cancel = Arc::new(AtomicBool::new(false));
        let seen = Arc::clone(&saw_cancel);
        let e = env(move |_, _, cancel| {
            started_tx.lock().unwrap().send(()).unwrap();
            for _ in 0..2000 {
                if cancel.is_cancelled() {
                    seen.store(true, Ordering::SeqCst);
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(TransportError::Lost("gone".into()))
        });
        let mut c = connect(&e.ctx);
        c.call(1, "rt_procs", &json!({}), None);
        started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        c.finish(); // closes its input: the server returns, having cancelled the call
        assert!(saw_cancel.load(Ordering::SeqCst));
    }

    #[test]
    fn progress_is_pacts_own_fixed_text_and_only_for_a_client_that_asked() {
        let e = env_with(
            |_, r, _| {
                std::thread::sleep(Duration::from_millis(400));
                Ok(done(r, 0, "x"))
            },
            Duration::from_millis(40),
            &["a.example"],
        );
        let mut c = connect(&e.ctx);
        c.call(1, "rt_procs", &json!({}), Some(json!({"progressToken": "tok-1"})));
        let mut progress = vec![];
        let result = loop {
            let m = c.recv();
            if m["method"] == "notifications/progress" {
                progress.push(m);
            } else {
                break m;
            }
        };
        assert_eq!(result["id"], 1);
        assert!(progress.len() >= 3, "{} notifications", progress.len());
        for (i, p) in progress.iter().enumerate() {
            assert_eq!(p["params"]["progressToken"], "tok-1");
            assert_eq!(p["params"]["message"], "waiting for an answer");
            assert_eq!(p["params"]["progress"], i as u64 + 1);
            assert_eq!(p["jsonrpc"], "2.0");
            assert!(p.get("id").is_none());
        }
        // A numeric token comes back as a number; with no token there is nothing.
        c.call(2, "rt_procs", &json!({}), Some(json!({"progressToken": 5})));
        assert_eq!(
            loop {
                let m = c.recv();
                if m["method"] == "notifications/progress" {
                    break m["params"]["progressToken"].clone();
                }
            },
            json!(5)
        );
        c.finish();
        let e = env_with(
            |_, r, _| {
                std::thread::sleep(Duration::from_millis(200));
                Ok(done(r, 0, "x"))
            },
            Duration::from_millis(20),
            &["a.example"],
        );
        let mut c = connect(&e.ctx);
        c.call(1, "rt_procs", &json!({}), None);
        assert_eq!(c.recv()["id"], 1, "no notification came first");
        c.finish();
    }

    #[test]
    fn what_a_service_sends_as_progress_is_never_relayed() {
        // The service's own words are not in anything the model reads, and the transport is not asked for progress.
        let e = env(|_, r, _| {
            let mut v = done(r, 0, "x");
            v["method"] = json!("notifications/progress");
            v["params"] = json!({"message": "the service says hello"});
            Ok(v)
        });
        let mut c = connect(&e.ctx);
        c.call(1, "rt_procs", &json!({}), Some(json!({"progressToken": "t"})));
        let r = c.recv();
        assert!(!r.to_string().contains("the service says hello"));
        c.finish();
    }

    #[test]
    fn the_seventeenth_call_waits_for_nobody_and_signs_nothing() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let g = Arc::clone(&gate);
        let e = env(move |_, r, _| {
            let (lock, cv) = &*g;
            let mut open = lock.lock().unwrap();
            while !*open {
                open = cv.wait(open).unwrap();
            }
            Ok(done(r, 0, "x"))
        });
        let mut c = connect(&e.ctx);
        for i in 0..16 {
            c.call(100 + i, "rt_procs", &json!({}), None);
        }
        // Wait until all sixteen are in the transport.
        for _ in 0..2000 {
            if e.transport.sent().iter().filter(|(_, r)| r["method"] == "tools/call").count() == 16 {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        c.call(200, "rt_procs", &json!({}), None);
        let r = c.recv();
        assert_eq!(r["id"], 200);
        let line = first_text(&r);
        assert_eq!((line["outcome"].clone(), line["reason"].clone()), (json!("refused"), json!("try-later")));
        assert_eq!(
            e.transport.sent().iter().filter(|(_, r)| r["method"] == "tools/call").count(),
            16,
            "nothing was signed for the 17th"
        );
        {
            let (lock, cv) = &*gate;
            *lock.lock().unwrap() = true;
            cv.notify_all();
        }
        let mut ids: Vec<u64> = (0..16).map(|_| c.recv()["id"].as_u64().unwrap()).collect();
        ids.sort_unstable();
        assert_eq!(ids, (100..116).collect::<Vec<_>>());
        // And once they are done there is room again.
        c.call(300, "rt_procs", &json!({}), None);
        assert_eq!(first_text(&c.recv())["outcome"], "done");
        c.finish();
    }

    #[test]
    fn with_several_services_each_tool_goes_to_its_own() {
        let e = env_with(
            |s, r, _| {
                let mut v = done(r, 0, &s.host);
                v["result"]["isError"] = json!(false);
                Ok(v)
            },
            Duration::from_secs(3600),
            &["a.example", "b.example"],
        );
        let mut c = connect(&e.ctx);
        c.send(&json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}));
        let names: Vec<String> = c.recv()["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(names, ["probe__a-example__rt_procs", "probe__b-example__rt_procs"]);
        c.call(2, "probe__b-example__rt_procs", &json!({}), None);
        let r = c.recv();
        assert_eq!(r["result"]["content"][1]["text"], "b.example");
        c.call(3, "rt_procs", &json!({}), None);
        assert_eq!(c.recv()["result"]["isError"], true, "the unprefixed name is not a tool here");
        c.finish();
        let sent = e.transport.sent();
        let call = sent.iter().find(|(_, r)| r["method"] == "tools/call").unwrap();
        assert_eq!(call.0.host, "b.example");
        assert_eq!(call.1["params"]["name"], "rt_procs", "the service gets its own name");
        let signed =
            Call::parse(STANDARD.decode(call.1["params"]["_meta"]["procession/call"].as_str().unwrap()).unwrap())
                .unwrap();
        assert_eq!(signed.service().principal(), "probe@b.example");
    }

    #[test]
    fn a_line_over_the_limit_ends_the_session_without_a_crash() {
        let e = env(|_, _, _| unreachable!());
        let mut c = connect(&e.ctx);
        c.w.write_all(&vec![b'x'; MAX_MESSAGE + 10]).unwrap();
        c.w.write_all(b"\n").unwrap();
        c.w.shutdown(std::net::Shutdown::Write).unwrap();
        assert!(c.server.take().unwrap().join().unwrap().is_ok());
    }

    #[test]
    fn call_once_is_the_same_path() {
        let e = env(|_, r, _| Ok(done(r, 3, "x")));
        let result = call_once(&e.ctx, "rt_procs", &json!({"params": ["a"]}));
        assert_eq!(result["isError"], true);
        assert_eq!(serde_json::from_str::<Value>(result["content"][0]["text"].as_str().unwrap()).unwrap()["rc"], 3);
        assert_eq!(e.transport.sent().iter().filter(|(_, r)| r["method"] == "tools/call").count(), 1);
    }
}
