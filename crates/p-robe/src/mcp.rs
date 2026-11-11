//! The MCP layer: JSON-RPC over HTTP, as a function from a request to a
//! response. It knows nothing of sockets, so it is tested in-process, and the
//! transport that carries it (an HTTP server) is a separate piece
//! (`proposals/agent-to-service.md`).
//!
//! Stateless: no session id, no `initialize` needed first. `tools/call`
//! carries the signed call in `params._meta` (`procession/call`,
//! `procession/call_sig`, each base64), and its arguments must equal the call.

use std::sync::atomic::AtomicBool;

use serde_json::{Map, Value, json};

use crate::json::Record;
use crate::outcome::Outcome;
use crate::service::{Handled, Service, ToolCall};
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

/// What `initialize` says in words to an agent.
const INSTRUCTIONS: &str = "Each tool is one action of this host's diagnostics service. A call may need your person's approval and then waits for it until its deadline. \
The first text content of a result is an outcome: declined and refused are decisions, do not repeat the call unchanged; refused with try-later may be asked again later; expired and unavailable mean nothing happened.";

/// The MCP server of one service.
pub struct Mcp<'a> {
    pub service: &'a Service,
}

fn rpc_error(id: &Value, code: i64, message: &str) -> HttpResponse {
    HttpResponse::json(&json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}))
}

fn rpc_result(id: &Value, result: &Value) -> HttpResponse {
    HttpResponse::json(&json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

impl Mcp<'_> {
    /// Handles one HTTP request. `cancel` is set by the transport when the
    /// client's connection goes away while the call waits.
    pub fn handle(&self, request: &HttpRequest, cancel: &AtomicBool) -> HttpResponse {
        if request.path != "/mcp" {
            return HttpResponse::status(404);
        }
        if request.method != "POST" {
            return HttpResponse::status(405).with("Allow", "POST");
        }
        if request.header("Origin").is_some() {
            return HttpResponse::status(403);
        }
        if request.header("MCP-Protocol-Version").is_some_and(|v| v != PROTOCOL_VERSION) {
            return HttpResponse::status(400);
        }
        let accepts = request.header("Accept").unwrap_or("");
        if !(accepts.contains("application/json") && accepts.contains("text/event-stream")) {
            return HttpResponse::status(406);
        }
        if !request.header("Content-Type").is_some_and(|t| t.starts_with("application/json")) {
            return HttpResponse::status(415);
        }
        if request.body.len() > BODY_MAX {
            return HttpResponse::status(413);
        }
        let Ok(Value::Object(message)) = serde_json::from_slice::<Value>(&request.body) else {
            return rpc_error(&Value::Null, -32700, "not a JSON object");
        };
        let id = message.get("id").cloned();
        let Some(method) = message.get("method").and_then(Value::as_str) else {
            // A response from the client, or nonsense: nothing to answer.
            return HttpResponse::status(202);
        };
        let Some(id) = id else {
            // A notification (`initialized`, `cancelled`): accepted, no body.
            return HttpResponse::status(202);
        };
        if !matches!(id, Value::String(_) | Value::Number(_)) {
            return rpc_error(&Value::Null, -32600, "bad id");
        }
        let params = message.get("params").cloned().unwrap_or(Value::Null);
        match method {
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
            "tools/call" => self.call(&id, &params, cancel),
            _ => rpc_error(&id, -32601, "method not found"),
        }
    }

    fn call(&self, id: &Value, params: &Value, cancel: &AtomicBool) -> HttpResponse {
        let bad = |why: &str| rpc_error(id, -32602, why);
        let Some(params) = params.as_object() else { return bad("params must be an object") };
        let Some(name) = params.get("name").and_then(Value::as_str) else { return bad("name is needed") };
        if !tools().iter().any(|tool| tool["name"] == name) {
            return bad("unknown tool");
        }
        let empty = Map::new();
        let arguments = match params.get("arguments") {
            None => &empty,
            Some(Value::Object(arguments)) => arguments,
            Some(_) => return bad("arguments must be an object"),
        };
        // `additionalProperties: false`; `wait_seconds` is the signer's and is ignored here.
        if arguments.keys().any(|key| !matches!(key.as_str(), "params" | "claim" | "wait_seconds")) {
            return bad("an argument that the tool does not have");
        }
        let Some(Value::Array(list)) = arguments.get("params") else {
            return bad("params is needed, an array of strings");
        };
        let Some(call_params) = list.iter().map(|v| v.as_str().map(String::from)).collect::<Option<Vec<_>>>() else {
            return bad("params must be strings");
        };
        let claim = match arguments.get("claim") {
            None => None,
            Some(Value::String(text)) => Some(text.as_str()),
            Some(_) => return bad("claim must be a string"),
        };
        let Some(Value::Object(meta)) = params.get("_meta") else { return bad("_meta with the call is needed") };
        if meta.keys().any(|key| key.starts_with(PREFIX) && key != CALL_KEY && key != SIG_KEY) {
            return bad("a procession/ key that does not exist");
        }
        let (Some(Value::String(call)), Some(Value::String(call_sig))) = (meta.get(CALL_KEY), meta.get(SIG_KEY)) else {
            return bad("procession/call and procession/call_sig are needed, as strings");
        };
        let tool = ToolCall { name, params: &call_params, claim, call, call_sig };
        match self.service.handle(&tool, cancel) {
            Handled::BadParams(why) => bad(why),
            Handled::Busy => HttpResponse::status(503).with("Retry-After", "5"),
            Handled::Cancelled => HttpResponse::status(499),
            Handled::Outcome { outcome, id: call_id } => rpc_result(id, &tool_result(&outcome, &call_id)),
        }
    }
}

/// The result of a tool call: the outcome object first, then the verb's answer.
fn tool_result(outcome: &Outcome, call_id: &str) -> Value {
    let mut line = Record::new("outcome").str("outcome", outcome.word());
    if let Some(reason) = outcome.reason() {
        line = line.str("reason", reason);
    }
    if let Outcome::Done { rc, .. } = outcome {
        line = line.num("rc", u64::from(*rc));
    }
    line = line.str("id", call_id);
    let mut content = vec![json!({"type": "text", "text": line.line()})];
    if let Outcome::Done { answer, .. } = outcome {
        if !answer.is_empty() {
            content.push(json!({"type": "text", "text": answer.trim_end()}));
        }
    }
    json!({"content": content, "isError": !matches!(outcome, Outcome::Done { rc: 0, .. })})
}

/// One line of text, no control character, the worst-case rating first.
fn description(row: &Verb) -> String {
    let r = row.rating;
    format!(
        "Rated (worst case): exposure {}, damage {}, disruption {}. {}. Your person may be asked; the call waits until its deadline.",
        table::exposure(r.exposure),
        table::damage(r.damage),
        table::disruption(r.disruption),
        row.summary
    )
}

fn schema(row: &Verb) -> Value {
    let max_items = if row.args.takes_any() { 64 } else { 0 };
    json!({
        "type": "object",
        "properties": {
            "params": {"type": "array", "maxItems": max_items, "items": {"type": "string", "maxLength": 512, "pattern": crate::rules::argument_pattern()}},
            "claim": {"type": "string", "maxLength": 200},
            "wait_seconds": {"type": "integer", "minimum": 1, "maximum": 600},
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
                "_meta": {"procession/rating": {"exposure": table::exposure(r.exposure), "damage": table::damage(r.damage), "disruption": table::disruption(r.disruption)}},
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
            !names.iter().any(|n| n == "rt_irq" || n == "run_command"),
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
    fn the_result_of_a_tool_call_starts_with_the_outcome_object() {
        let done = tool_result(&Outcome::Done { rc: 0, answer: "{\"type\":\"header\"}\n".into() }, "i");
        assert_eq!(done["isError"], false);
        assert_eq!(done["content"][0]["text"], "{\"type\":\"outcome\",\"outcome\":\"done\",\"rc\":0,\"id\":\"i\"}");
        assert_eq!(done["content"][1]["text"], "{\"type\":\"header\"}");
        let refused = tool_result(&Outcome::Refused(crate::outcome::Why::TryLater), "i");
        assert_eq!(refused["isError"], true);
        assert_eq!(
            refused["content"][0]["text"],
            "{\"type\":\"outcome\",\"outcome\":\"refused\",\"reason\":\"try-later\",\"id\":\"i\"}"
        );
        assert_eq!(refused["content"].as_array().unwrap().len(), 1);
        assert_eq!(
            tool_result(&Outcome::Declined, "i")["content"][0]["text"],
            "{\"type\":\"outcome\",\"outcome\":\"declined\",\"id\":\"i\"}"
        );
    }
}
