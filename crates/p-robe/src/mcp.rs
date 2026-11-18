//! The MCP layer: JSON-RPC over HTTP, as a function from a request to a
//! response. It knows nothing of sockets, so it is tested in-process, and the
//! transport that carries it (an HTTP server) is a separate piece
//! (`proposals/agent-to-service.md`).
//!
//! Stateless: no session id, no `initialize` needed first. `tools/call`
//! carries the signed call in `params._meta` (`procession/call`,
//! `procession/call_sig`, each base64), and its arguments must equal the call.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::json::Record;
use crate::outcome::Outcome;
use crate::service::{Event, Handled, Service, ToolCall};
use crate::table::{self, Availability, Verb};

/// The only protocol revision this layer speaks.
pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// A request body is at most this.
pub const BODY_MAX: usize = 64 * 1024;
const CALL_KEY: &str = "procession/call";
const SIG_KEY: &str = "procession/call_sig";
const PREFIX: &str = "procession/";

/// One HTTP request, as the transport hands it over.
#[derive(Debug, Default, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key.eq_ignore_ascii_case(name)).map(|(_, value)| value.as_str())
    }
}

/// One HTTP response to send.
#[derive(Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    fn status(status: u16) -> Self {
        Self { status, headers: Vec::new(), body: Vec::new() }
    }

    fn json(value: &Value) -> Self {
        Self {
            status: 200,
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: value.to_string().into_bytes(),
        }
    }

    fn with(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// Where a response is written, a piece at a time: what a transport provides.
/// A failing write means the client is gone.
pub trait ResponseWriter {
    /// The status line and headers. Called once, before any `body`.
    ///
    /// # Errors
    /// The client is gone.
    fn head(&mut self, status: u16, headers: &[(String, String)]) -> std::io::Result<()>;

    /// A piece of the body, sent at once (not held back): a keepalive that is
    /// buffered is no keepalive.
    ///
    /// # Errors
    /// The client is gone.
    fn body(&mut self, bytes: &[u8]) -> std::io::Result<()>;
}

/// Collects a response whole, for callers that want an [`HttpResponse`].
#[derive(Debug, Default)]
pub struct Collect {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ResponseWriter for Collect {
    fn head(&mut self, status: u16, headers: &[(String, String)]) -> std::io::Result<()> {
        self.status = status;
        self.headers = headers.to_vec();
        Ok(())
    }

    fn body(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.body.extend_from_slice(bytes);
        Ok(())
    }
}

fn send(out: &mut dyn ResponseWriter, response: &HttpResponse) {
    if out.head(response.status, &response.headers).is_ok() {
        let _ = out.body(&response.body);
    }
}

/// What `initialize` says in words to an agent.
const INSTRUCTIONS: &str = "Each tool is one action of this host's diagnostics service. A call may need your person's approval and then waits for it until its deadline. \
The first text content of a result is an outcome: declined and refused are decisions, do not repeat the call unchanged; refused with try-later may be asked again later; expired and unavailable mean nothing happened.";

/// How often something is written while a call waits or runs: well inside the
/// 45 seconds of idle time `pact` allows.
pub const KEEPALIVE: Duration = Duration::from_secs(15);
/// How often the wait looks at the clock and the cancel flag.
const TICK: Duration = Duration::from_millis(50);
/// What `pact` reads as one message at most (`pact.md`, section 7). A verb's
/// answer is capped at the dispatcher's 1 MiB; wrapped in JSON every byte
/// is at most doubled.
pub const MESSAGE_MAX: usize = 4 << 20;
const _: () = assert!(2 * crate::answer::ANSWER_CAP + 4096 < MESSAGE_MAX);

/// The MCP server of one service.
pub struct Mcp<'a> {
    pub service: &'a Service,
    /// The interval of the comment lines on a stream.
    pub keepalive: Duration,
}

impl<'a> Mcp<'a> {
    #[must_use]
    pub fn new(service: &'a Service) -> Self {
        Self { service, keepalive: KEEPALIVE }
    }
}

fn rpc_error(id: &Value, code: i64, message: &str) -> HttpResponse {
    HttpResponse::json(&json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}))
}

fn rpc_result(id: &Value, result: &Value) -> HttpResponse {
    HttpResponse::json(&json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

impl Mcp<'_> {
    /// Handles one HTTP request and returns the response whole. A call that
    /// streams is collected: its body is the event stream.
    pub fn handle(&self, request: &HttpRequest, cancel: &AtomicBool) -> HttpResponse {
        let mut collected = Collect::default();
        self.serve(request, cancel, &mut collected);
        HttpResponse { status: collected.status, headers: collected.headers, body: collected.body }
    }

    /// Handles one HTTP request, writing the response to `out` as it comes.
    /// `cancel` is set by the transport when the client's connection goes away
    /// while a call waits; a write that fails has the same effect.
    pub fn serve(&self, request: &HttpRequest, cancel: &AtomicBool, out: &mut dyn ResponseWriter) {
        if request.path != "/mcp" {
            return send(out, &HttpResponse::status(404));
        }
        if request.method != "POST" {
            return send(out, &HttpResponse::status(405).with("Allow", "POST"));
        }
        if request.header("Origin").is_some() {
            return send(out, &HttpResponse::status(403));
        }
        if request.header("MCP-Protocol-Version").is_some_and(|v| v != PROTOCOL_VERSION) {
            return send(out, &HttpResponse::status(400));
        }
        let accepts = request.header("Accept").unwrap_or("");
        if !(accepts.contains("application/json") && accepts.contains("text/event-stream")) {
            return send(out, &HttpResponse::status(406));
        }
        if !request.header("Content-Type").is_some_and(|t| t.starts_with("application/json")) {
            return send(out, &HttpResponse::status(415));
        }
        if request.body.len() > BODY_MAX {
            return send(out, &HttpResponse::status(413));
        }
        let Ok(Value::Object(message)) = serde_json::from_slice::<Value>(&request.body) else {
            return send(out, &rpc_error(&Value::Null, -32700, "not a JSON object"));
        };
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            // A response from the client, or nonsense: nothing to answer.
            return send(out, &HttpResponse::status(202));
        };
        let Some(id) = message.get("id").cloned() else {
            // A notification (`initialized`, `cancelled`): accepted, no body.
            return send(out, &HttpResponse::status(202));
        };
        if !matches!(id, Value::String(_) | Value::Number(_)) {
            return send(out, &rpc_error(&Value::Null, -32600, "bad id"));
        }
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        let plain = match method {
            "initialize" => rpc_result(
                &id,
                &json!({
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {"listChanged": false}},
                    "serverInfo": {"name": "probe", "version": env!("CARGO_PKG_VERSION")},
                    "instructions": INSTRUCTIONS,
                }),
            ),
            "ping" => rpc_result(&id, &json!({})),
            "tools/list" => rpc_result(&id, &json!({"tools": tools()})),
            "tools/call" => return self.call(&id, &params, cancel, out),
            _ => rpc_error(&id, -32601, "method not found"),
        };
        send(out, &plain);
    }

    fn call(&self, id: &Value, params: &Value, cancel: &AtomicBool, out: &mut dyn ResponseWriter) {
        let bad = |out: &mut dyn ResponseWriter, why: &str| send(out, &rpc_error(id, -32602, why));
        let Some(params) = params.as_object() else { return bad(out, "params must be an object") };
        let Some(name) = params.get("name").and_then(Value::as_str) else { return bad(out, "name is needed") };
        if !tools().iter().any(|tool| tool["name"] == name) {
            return bad(out, "unknown tool");
        }
        let empty = Map::new();
        let arguments = match params.get("arguments") {
            None => &empty,
            Some(Value::Object(arguments)) => arguments,
            Some(_) => return bad(out, "arguments must be an object"),
        };
        // `additionalProperties: false`: `wait_seconds` is not ours (`pact` adds it to the schema it shows the model
        // and strips it before it composes the call), so a call that carries it is refused like any unknown argument.
        if arguments.keys().any(|key| !matches!(key.as_str(), "params" | "claim")) {
            return bad(out, "an argument that the tool does not have");
        }
        let Some(Value::Array(list)) = arguments.get("params") else {
            return bad(out, "params is needed, an array of strings");
        };
        let Some(call_params) = list.iter().map(|v| v.as_str().map(String::from)).collect::<Option<Vec<_>>>() else {
            return bad(out, "params must be strings");
        };
        let claim = match arguments.get("claim") {
            None => None,
            Some(Value::String(text)) => Some(text.as_str()),
            Some(_) => return bad(out, "claim must be a string"),
        };
        let Some(Value::Object(meta)) = params.get("_meta") else { return bad(out, "_meta with the call is needed") };
        if meta.keys().any(|key| key.starts_with(PREFIX) && key != CALL_KEY && key != SIG_KEY) {
            return bad(out, "a procession/ key that does not exist");
        }
        let (Some(Value::String(call)), Some(Value::String(call_sig))) = (meta.get(CALL_KEY), meta.get(SIG_KEY)) else {
            return bad(out, "procession/call and procession/call_sig are needed, as strings");
        };
        let token = match meta.get("progressToken") {
            Some(token @ (Value::String(_) | Value::Number(_))) => Some(token.clone()),
            _ => None,
        };
        let tool = ToolCall { name, params: &call_params, claim, call, call_sig };
        self.run(id, &tool, token, cancel, out);
    }

    /// Runs the call on a worker and streams from here. The response head is
    /// sent **as soon as the service has accepted the call** (it passed its
    /// first checks and has a place to wait), when the client sent a
    /// `progressToken`; from then a comment line goes out at least every
    /// `keepalive`, while the person is asked and while the verb runs, so that
    /// a client that treats silence as a dead connection does not. A call
    /// refused before that is answered as plain JSON. A write that fails, or
    /// `cancel`, cancels the call.
    fn run(
        &self,
        id: &Value,
        tool: &ToolCall<'_>,
        token: Option<Value>,
        cancel: &AtomicBool,
        out: &mut dyn ResponseWriter,
    ) {
        enum Msg {
            Event(Event),
            Done(Handled),
        }
        let gone = AtomicBool::new(false);
        let (tx, rx) = mpsc::channel();
        let done = std::thread::scope(|scope| {
            let (tx_events, gone_ref) = (tx.clone(), &gone);
            scope.spawn(move || {
                let handled = self.service.handle_with(tool, gone_ref, &|event| {
                    let _ = tx_events.send(Msg::Event(event));
                });
                let _ = tx.send(Msg::Done(handled));
            });
            let (mut streaming, mut last) = (false, Instant::now());
            loop {
                let write = |out: &mut dyn ResponseWriter, bytes: &[u8]| {
                    if out.body(bytes).is_err() {
                        gone.store(true, Ordering::SeqCst);
                    }
                };
                match rx.recv_timeout(TICK) {
                    Ok(Msg::Event(event)) => {
                        if token.is_none() {
                            continue;
                        }
                        if !streaming {
                            if event != Event::Accepted {
                                continue;
                            }
                            let headers = [
                                ("Content-Type".to_string(), "text/event-stream".to_string()),
                                ("Cache-Control".to_string(), "no-cache".to_string()),
                            ];
                            if out.head(200, &headers).is_err() {
                                gone.store(true, Ordering::SeqCst);
                            }
                            streaming = true;
                            last = Instant::now();
                        }
                    }
                    Ok(Msg::Done(handled)) => break (handled, streaming),
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if cancel.load(Ordering::SeqCst) {
                            gone.store(true, Ordering::SeqCst);
                        }
                        if streaming && last.elapsed() >= self.keepalive {
                            write(out, b": keepalive\n\n");
                            last = Instant::now();
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        break (Handled::BadParams("the call could not be handled"), streaming);
                    }
                }
            }
        });
        let (handled, streaming) = done;
        let response = match handled {
            Handled::Cancelled => return,
            Handled::BadParams(why) => rpc_error(id, -32602, why),
            Handled::Busy => HttpResponse::status(503).with("Retry-After", "5"),
            Handled::Outcome { outcome, id: call_id } => rpc_result(id, &tool_result(&outcome, &call_id)),
        };
        if streaming {
            let _ =
                out.body(format!("event: message\ndata: {}\n\n", String::from_utf8_lossy(&response.body)).as_bytes());
        } else {
            send(out, &response);
        }
    }
}

/// The result of a tool call: the outcome object first, then the verb's answer.
pub fn tool_result(outcome: &Outcome, call_id: &str) -> Value {
    // The records, as objects: what the structured result carries, and what the counts are made of.
    let records: Vec<Value> = match outcome {
        Outcome::Done { answer, .. } => answer.lines().filter_map(|l| serde_json::from_str(l).ok()).collect(),
        _ => Vec::new(),
    };
    let counted = |member: &str| records.iter().filter(|r| r.get(member).is_some()).count() as u64;
    let mut line = Record::new("outcome").str("outcome", outcome.word());
    let mut structured = serde_json::Map::new();
    structured.insert("outcome".into(), json!(outcome.word()));
    if let Some(reason) = outcome.reason() {
        line = line.str("reason", reason);
        structured.insert("reason".into(), json!(reason));
    }
    if let Outcome::Done { rc, .. } = outcome {
        line = line.num("rc", u64::from(*rc));
        structured.insert("rc".into(), json!(rc));
    }
    line = line.str("id", call_id);
    structured.insert("id".into(), json!(call_id));
    if matches!(outcome, Outcome::Done { .. }) {
        // The counts of the answer, in the text line as well as in the structured result.
        let (n, escaped, clipped) = (records.len() as u64, counted("escaped"), counted("clipped"));
        line = line.num("records", n).num("escaped_records", escaped).num("clipped_records", clipped);
        structured.insert("records".into(), Value::Array(records));
        structured.insert("escaped_records".into(), json!(escaped));
        structured.insert("clipped_records".into(), json!(clipped));
    }
    let mut content = vec![json!({"type": "text", "text": line.line()})];
    if RECORDS_IN_TEXT
        && let Outcome::Done { answer, .. } = outcome
        && !answer.is_empty()
    {
        content.push(json!({"type": "text", "text": answer.trim_end()}));
    }
    json!({
        "content": content,
        "structuredContent": Value::Object(structured),
        "isError": !matches!(outcome, Outcome::Done { rc: 0, .. })
    })
}

/// Whether the records are also in the text blocks of a result (one block, the lines). The design: structured
/// content carries them and the text block only the outcome line with the counts. `pact` (p-act) reads text blocks
/// only until its change lands, so they stay until then; **set this to `false` when `pact` reads
/// `structuredContent`**.
pub const RECORDS_IN_TEXT: bool = true;

/// One line of text, no control character, the worst-case rating first.
fn description(row: &Verb) -> String {
    let r = row.rating;
    let text = format!(
        "Rated (worst case): exposure {}, damage {}, disruption {}. {}. Your person may be asked; the call waits until its deadline.",
        table::exposure(r.exposure),
        table::damage(r.damage),
        table::disruption(r.disruption),
        row.summary
    );
    // Nothing about text from the host here: the mark is `procession/host_text` in `_meta` (required for every tool),
    // and `pact` words the warning itself, the same for every service.
    debug_assert!(text.len() <= DESCRIPTION_MAX && !text.contains('\n'));
    text
}

/// A description is one line of at most this many characters, the service's alone.
pub const DESCRIPTION_MAX: usize = 600;

fn schema(row: &Verb) -> Value {
    let max_items = if row.args.takes_any() { 64 } else { 0 };
    json!({
        "type": "object",
        "properties": {
            "params": {"type": "array", "maxItems": max_items, "items": {"type": "string", "maxLength": 512, "pattern": crate::rules::argument_pattern()}},
            "claim": {"type": "string", "maxLength": 200},
        },
        "required": ["params"],
        "additionalProperties": false,
    })
}

/// The tool list, from the verb table: a tool for every row that is ready.
#[must_use]
pub fn tools() -> Vec<Value> {
    table::verbs()
        .filter(|row| matches!(row.availability, Availability::Ready(_)))
        .map(|row| {
            let r = row.rating;
            json!({
                "name": format!("{}_{}", row.noun, row.verb),
                "title": row.label(),
                "description": description(row),
                "inputSchema": schema(row),
                "annotations": {"readOnlyHint": r.damage == p_act::rating::Damage::None, "destructiveHint": r.damage == p_act::rating::Damage::Lasting, "openWorldHint": false},
                "_meta": {"procession/host_text": row.host_text, "procession/rating": {"exposure": table::exposure(r.exposure), "damage": table::damage(r.damage), "disruption": table::disruption(r.disruption)}},
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_ready_row_has_one_tool_with_a_unique_short_name() {
        let tools = tools();
        let ready = table::verbs().filter(|row| matches!(row.availability, Availability::Ready(_))).count();
        assert_eq!(tools.len(), ready);
        let mut names: Vec<_> = tools.iter().map(|t| t["name"].as_str().unwrap().to_string()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), ready);
        assert!(names.iter().all(|n| n.len() <= 64 && !n.contains(' ')));
        assert!(
            !names.iter().any(|n| n == "rt_jitter" || n == "run_command"),
            "unavailable and service-only rows are not offered"
        );
    }

    #[test]
    fn a_description_is_one_printable_line_of_at_most_600_characters_with_the_rating_first() {
        for row in table::verbs().filter(|row| matches!(row.availability, Availability::Ready(_))) {
            let text = description(row);
            assert!(text.starts_with("Rated (worst case): exposure "), "{text}");
            assert!(text.len() <= 600 && !text.chars().any(char::is_control), "{text}");
        }
    }

    #[test]
    fn a_verb_without_arguments_offers_none() {
        let kit = tools().into_iter().find(|t| t["name"] == "sys_kit").unwrap();
        assert_eq!(kit["inputSchema"]["properties"]["params"]["maxItems"], 0);
        assert_eq!(kit["inputSchema"]["additionalProperties"], false);
    }

    #[test]
    fn every_tool_has_the_host_text_mark_in_its_meta_and_a_description_of_one_line_that_is_the_services_alone() {
        for tool in tools() {
            let description = tool["description"].as_str().unwrap();
            assert!(tool["_meta"]["procession/host_text"].is_boolean(), "required for every tool: {}", tool["name"]);
            assert!(description.len() <= DESCRIPTION_MAX && !description.contains('\n'), "{}", tool["name"]);
            // The warning about text from the host is `pact`'s, in its own words; none of ours is in a description.
            assert!(!description.to_lowercase().contains("host"), "{description}");
            assert!(tool["inputSchema"]["properties"].get("wait_seconds").is_none(), "wait_seconds is not ours");
        }
        let names: Vec<_> = tools()
            .iter()
            .filter(|t| t["_meta"]["procession/host_text"] == true)
            .map(|t| t["name"].to_string())
            .collect();
        assert!(
            names.iter().any(|n| n.contains("sys_kit")) && names.iter().any(|n| n.contains("rt_procs")),
            "{names:?}"
        );
    }

    #[test]
    fn the_result_of_a_tool_call_starts_with_the_outcome_object() {
        let done = tool_result(&Outcome::Done { rc: 0, answer: "{\"type\":\"header\"}\n".into() }, "i");
        assert_eq!(done["isError"], false);
        assert_eq!(
            done["content"][0]["text"],
            "{\"type\":\"outcome\",\"outcome\":\"done\",\"rc\":0,\"id\":\"i\",\"records\":1,\"escaped_records\":0,\"clipped_records\":0}"
        );
        // The structured result: named fields, the records as objects.
        assert_eq!(
            done["structuredContent"],
            json!({"outcome": "done", "rc": 0, "id": "i", "records": [{"type": "header"}], "escaped_records": 0, "clipped_records": 0})
        );
        assert_eq!(done["content"][1]["text"], "{\"type\":\"header\"}");
        let refused = tool_result(&Outcome::Refused(crate::outcome::Why::TryLater), "i");
        assert_eq!(refused["isError"], true);
        assert_eq!(
            refused["content"][0]["text"],
            "{\"type\":\"outcome\",\"outcome\":\"refused\",\"reason\":\"try-later\",\"id\":\"i\"}"
        );
        assert_eq!(refused["content"].as_array().unwrap().len(), 1);
        // A call that was carried out and did not complete: an error, no code, no result.
        let failed = tool_result(&Outcome::Failed, "i");
        assert_eq!(failed["isError"], true);
        assert_eq!(failed["content"][0]["text"], "{\"type\":\"outcome\",\"outcome\":\"failed\",\"id\":\"i\"}");
        assert_eq!(failed["content"].as_array().unwrap().len(), 1);
        assert_eq!(failed["structuredContent"], json!({"outcome": "failed", "id": "i"}), "no records, no code");
        assert_eq!(
            tool_result(&Outcome::Declined, "i")["content"][0]["text"],
            "{\"type\":\"outcome\",\"outcome\":\"declined\",\"id\":\"i\"}"
        );
    }
}
