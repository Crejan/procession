//! A tool call becomes a call (`proposals/pact.md` section 6): identifier,
//! deadline from the setting (the model may only shorten), signature, and the
//! `tools/call` request with `_meta`.

use super::bundle::AgentKey;
use super::catalogue::Tool;
use super::rt::{Clock, Random, token, uuid_v4};
use super::{Service, Settings};
use crate::call::{Call, CallContent, CallId, ServiceId};
use crate::hash::{Document, DocumentHash};
use crate::sign::signature_to_base64;
use crate::time::Timestamp;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

/// The model's mistake, said plainly. Nothing was signed. Not an outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolError(pub String);

/// A call, signed, with the request that carries it.
#[derive(Debug, Clone)]
pub struct Prepared {
    pub id: CallId,
    pub call_hash: DocumentHash,
    pub deadline: Timestamp,
    /// The `params` of the `tools/call` request.
    pub params: Value,
}

impl Prepared {
    /// The JSON-RPC request to send, with the request's own identifier `rpc_id`.
    #[must_use]
    pub fn request(&self, rpc_id: u64) -> Value {
        json!({"jsonrpc": "2.0", "id": rpc_id, "method": "tools/call", "params": self.params})
    }
}

fn err(message: impl Into<String>) -> ToolError {
    ToolError(message.into())
}

/// What the model gave, checked against the tool's bounds. `params` and `claim` as given: no trimming.
struct Arguments {
    params: Vec<String>,
    claim: Option<String>,
    wait_seconds: Option<u64>,
}

fn read_arguments(tool: &Tool, arguments: &Value) -> Result<Arguments, ToolError> {
    let empty = serde_json::Map::new();
    let members = match arguments {
        Value::Null => &empty,
        Value::Object(m) => m,
        _ => return Err(err("arguments must be an object")),
    };
    if let Some(unknown) = members.keys().find(|k| !["params", "claim", "wait_seconds"].contains(&k.as_str())) {
        let shown: String = unknown.chars().take(40).collect();
        return Err(err(format!("there is no argument `{shown}`; the arguments are params, claim and wait_seconds")));
    }
    let params = match members.get("params") {
        None => vec![],
        Some(Value::Array(items)) => items
            .iter()
            .map(|i| i.as_str().map(str::to_owned).ok_or_else(|| err("params must be an array of strings")))
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(err("params must be an array of strings")),
    };
    if params.len() > tool.bounds.max_items {
        return Err(err(format!("params has {} items, at most {} are allowed", params.len(), tool.bounds.max_items)));
    }
    if let Some(i) = params.iter().position(|p| p.len() > tool.bounds.item_max_len) {
        return Err(err(format!("params item {i} is longer than {} bytes", tool.bounds.item_max_len)));
    }
    let claim = match members.get("claim") {
        None => None,
        Some(Value::String(c)) => Some(c.clone()),
        Some(_) => return Err(err("claim must be a string")),
    };
    if claim.as_ref().is_some_and(|c| c.chars().count() > tool.bounds.claim_max_len) {
        return Err(err(format!("claim is longer than {} characters", tool.bounds.claim_max_len)));
    }
    let wait_seconds = match members.get("wait_seconds") {
        None => None,
        Some(v) => Some(
            v.as_u64()
                .filter(|w| *w >= 1)
                .ok_or_else(|| err("wait_seconds must be a whole number of seconds, 1 or more"))?,
        ),
    };
    Ok(Arguments { params, claim, wait_seconds })
}

/// The seconds to wait: the setting, or what the model asked for if that is shorter, and never below the floor.
#[must_use]
pub fn wait_seconds(settings: &Settings, asked: Option<u64>) -> u32 {
    match asked {
        None => settings.deadline_seconds,
        Some(w) => {
            let shorter = u32::try_from(w).unwrap_or(u32::MAX).min(settings.deadline_seconds);
            shorter.max(settings.min_wait_seconds)
        }
    }
}

/// Compose, sign and wrap one tool call for `tool` of `service`.
pub fn prepare(
    key: &AgentKey,
    settings: &Settings,
    clock: &dyn Clock,
    random: &dyn Random,
    service: &Service,
    tool: &Tool,
    arguments: &Value,
) -> Result<Prepared, ToolError> {
    let args = read_arguments(tool, arguments)?;
    let id = CallId::parse(&uuid_v4(random)).map_err(|e| err(format!("internal error: {e}")))?;
    let deadline = clock
        .now()
        .checked_add(i64::from(wait_seconds(settings, args.wait_seconds)))
        .ok_or_else(|| err("internal error: the clock is out of range"))?;
    let content = CallContent {
        id: id.clone(),
        deadline,
        service: ServiceId { host: service.host.clone(), name: service.name.clone() },
        action: tool.action.clone(),
        params: args.params,
        claim: args.claim,
    };
    // Every other rule of the formats (the string rule, the sizes) is the parser's, and its text says which.
    let call = Call::compose(&content).map_err(|e| err(format!("the call is not valid: {e}")))?;
    let signature = key.sign_call(&call);
    // `arguments` is built from the signed call, so it cannot differ from it; `wait_seconds` was pact's and is not sent.
    let mut arguments = json!({"params": call.params()});
    if let Some(claim) = call.claim() {
        arguments["claim"] = json!(claim);
    }
    let params = json!({
        "name": tool.wire_name,
        "arguments": arguments,
        "_meta": {
            "procession/call": STANDARD.encode(call.as_bytes()),
            "procession/call_sig": signature_to_base64(&signature),
            "progressToken": token(random),
        }
    });
    Ok(Prepared { id, call_hash: call.hash(), deadline, params })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pact::bundle::Bundle;
    use crate::pact::catalogue::Bounds;
    use crate::pact::fixture::Fixture;
    use crate::pact::rt::SystemRandomSource;
    use crate::sign::{PublicKey, signature_from_base64, verify_call_agent};

    struct Fixed(Timestamp);
    impl Clock for Fixed {
        fn now(&self) -> Timestamp {
            self.0
        }
    }

    pub(crate) fn tool() -> Tool {
        Tool {
            name: "rt_procs".into(),
            service: 0,
            wire_name: "rt_procs".into(),
            action: "rt procs".into(),
            title: None,
            description: "d".into(),
            schema: json!({}),
            annotations: None,
            bounds: Bounds { max_items: 3, item_max_len: 20, claim_max_len: 200 },
        }
    }

    fn service() -> Service {
        Service { host: "a.example".into(), name: "probe".into(), url: "http://127.0.0.1:1/mcp".into() }
    }

    fn now() -> Timestamp {
        "2026-11-11T15:00:00Z".parse().unwrap()
    }

    struct Env {
        f: Fixture,
        key: AgentKey,
    }

    fn env() -> Env {
        let f = Fixture::new("alice", &["extension:groups@procession=admins"]);
        let key = Bundle::parse(&f.bundle(&Fixture::default_config("http://127.0.0.1:1/")), now()).unwrap().key;
        Env { f, key }
    }

    fn prep(e: &Env, settings: &Settings, args: Value) -> Result<Prepared, ToolError> {
        prepare(&e.key, settings, &Fixed(now()), &SystemRandomSource::default(), &service(), &tool(), &args)
    }

    fn s() -> Settings {
        Settings::new(120, None)
    }

    #[test]
    fn composes_a_call_the_service_and_the_broker_would_verify() {
        let e = env();
        let p = prep(&e, &s(), json!({"params": ["pid=4711"], "claim": "why"})).unwrap();
        let meta = &p.params["_meta"];
        let call = Call::parse(STANDARD.decode(meta["procession/call"].as_str().unwrap()).unwrap()).unwrap();
        let sig = signature_from_base64(meta["procession/call_sig"].as_str().unwrap()).unwrap();
        let delegation = PublicKey::read(&e.f.delegation_pub()).unwrap();
        let agent = verify_call_agent(&call, &sig, &delegation).unwrap();
        assert_eq!((agent.person.as_str(), agent.groups.as_slice()), ("alice", ["admins".to_owned()].as_slice()));
        assert_eq!(call.id(), &p.id);
        assert_eq!(call.service().principal(), "probe@a.example");
        assert_eq!(
            (call.action(), call.params(), call.claim()),
            ("rt procs", ["pid=4711".to_owned()].as_slice(), Some("why"))
        );
        assert_eq!(call.deadline().to_string(), "2026-11-11T15:02:00Z");
        assert_eq!(p.call_hash, call.hash());
        // The body says what the call says, with the unprefixed name, and nothing else.
        assert_eq!(p.params["name"], "rt_procs");
        assert_eq!(p.params["arguments"], json!({"params": ["pid=4711"], "claim": "why"}));
        let mut keys: Vec<&String> = meta.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            ["procession/call", "procession/call_sig", "progressToken"],
            "exactly two procession/ keys and the token"
        );
        assert_eq!(p.request(7)["id"], 7);
        assert_eq!(p.request(7)["method"], "tools/call");
    }

    #[test]
    fn params_is_always_present_and_claim_only_when_given() {
        let e = env();
        for args in [json!({}), Value::Null, json!({"params": []})] {
            let p = prep(&e, &s(), args).unwrap();
            assert_eq!(p.params["arguments"], json!({"params": []}));
        }
    }

    #[test]
    fn the_model_may_only_shorten_the_wait() {
        let e = env();
        let deadline = |args: Value, st: &Settings| prep(&e, st, args).unwrap().deadline.to_string();
        assert_eq!(deadline(json!({}), &s()), "2026-11-11T15:02:00Z");
        assert_eq!(deadline(json!({"wait_seconds": 30}), &s()), "2026-11-11T15:00:30Z");
        assert_eq!(deadline(json!({"wait_seconds": 120}), &s()), "2026-11-11T15:02:00Z");
        assert_eq!(
            deadline(json!({"wait_seconds": 121}), &s()),
            "2026-11-11T15:02:00Z",
            "longer is clamped, not an error"
        );
        assert_eq!(deadline(json!({"wait_seconds": 100_000_000_000u64}), &s()), "2026-11-11T15:02:00Z");
        // The floor: 10 by default, so rounding by the model cannot put the deadline in the service's past.
        assert_eq!(deadline(json!({"wait_seconds": 1}), &s()), "2026-11-11T15:00:10Z");
        assert_eq!(deadline(json!({"wait_seconds": 1}), &Settings::new(120, Some(1))), "2026-11-11T15:00:01Z");
        // A setting below the default floor: the floor is the setting.
        assert_eq!(Settings::new(5, None).min_wait_seconds, 5);
        assert_eq!(deadline(json!({"wait_seconds": 2}), &Settings::new(5, None)), "2026-11-11T15:00:05Z");
        assert_eq!(deadline(json!({}), &Settings::new(600, None)), "2026-11-11T15:10:00Z");
        assert_eq!(wait_seconds(&s(), Some(u64::MAX)), 120);
        // `wait_seconds` is pact's and is not sent.
        assert!(prep(&e, &s(), json!({"wait_seconds": 30})).unwrap().params["arguments"].get("wait_seconds").is_none());
    }

    #[test]
    fn the_models_mistakes_are_said_plainly_and_sign_nothing() {
        let e = env();
        for (args, expected) in [
            (json!({"extra": 1}), "there is no argument `extra`"),
            (json!("x"), "arguments must be an object"),
            (json!([]), "arguments must be an object"),
            (json!({"params": "pid=1"}), "params must be an array of strings"),
            (json!({"params": [1]}), "params must be an array of strings"),
            (json!({"params": ["a", "b", "c", "d"]}), "params has 4 items, at most 3"),
            (json!({"params": ["x".repeat(21)]}), "params item 0 is longer than 20 bytes"),
            (json!({"claim": 5}), "claim must be a string"),
            (json!({"claim": "c".repeat(201)}), "claim is longer than 200 characters"),
            (json!({"wait_seconds": 0}), "wait_seconds must be a whole number"),
            (json!({"wait_seconds": -5}), "wait_seconds must be a whole number"),
            (json!({"wait_seconds": 1.5}), "wait_seconds must be a whole number"),
            (json!({"wait_seconds": "30"}), "wait_seconds must be a whole number"),
            (json!({"params": ["a\u{0}b"]}), "the call is not valid"),
            (json!({"params": ["a\u{202e}b"]}), "bidirectional"),
            (json!({"claim": "line\nbreak"}), "control character"),
        ] {
            let r = prep(&e, &s(), args.clone());
            let message = r.unwrap_err().0;
            assert!(message.contains(expected), "{args}: {message}");
        }
    }

    #[test]
    fn every_call_has_a_fresh_identifier() {
        let e = env();
        let ids: Vec<String> = (0..20).map(|_| prep(&e, &s(), json!({})).unwrap().id.to_string()).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), 20);
        let tokens: Vec<String> = (0..5)
            .map(|_| prep(&e, &s(), json!({})).unwrap().params["_meta"]["progressToken"].as_str().unwrap().to_owned())
            .collect();
        assert!(tokens.windows(2).all(|w| w[0] != w[1]));
    }
}
