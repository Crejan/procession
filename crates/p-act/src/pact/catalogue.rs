//! The tools the model is offered: what the services list, checked
//! (`proposals/pact.md` section 5). The service's schema passes through; what
//! `pact` adds is only that no bound is ever widened and that `wait_seconds` is
//! its own.

use super::transport::{CancelToken, Transport};
use super::{Service, Settings};
use crate::call::{MAX_CLAIM_CHARS, MAX_PARAM_BYTES, MAX_PARAMS};
use crate::text;
use serde_json::{Value, json};
use thiserror::Error;

/// Names and titles of tools are at most this long (a client wants 64).
const MAX_NAME: usize = 64;
const MAX_TITLE: usize = 100;
/// A description is one line of at most 600 characters, the rating first; `pact` never cuts it.
const MAX_DESCRIPTION: usize = 600;
const MAX_PATTERN: usize = 512;
/// Keywords whose presence makes the tool dropped: they point outside the schema or choose for the model.
const FORBIDDEN: [&str; 9] = ["$ref", "$defs", "default", "examples", "oneOf", "anyOf", "allOf", "not", "if"];

/// What the bundle makes impossible to start with.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CatalogueError {
    #[error("two services map to the tool prefix `{0}`")]
    PrefixCollision(String),
}

/// The numbers `pact` enforces before it signs: from the service's schema, never above the format's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub max_items: usize,
    pub item_max_len: usize,
    pub claim_max_len: usize,
}

/// One tool as the model sees it.
#[derive(Debug, Clone, PartialEq)]
pub struct Tool {
    /// The name the model uses.
    pub name: String,
    /// Index into the bundle's services.
    pub service: usize,
    /// The name the service uses: the action with `_` for the spaces.
    pub wire_name: String,
    /// The action of the call.
    pub action: String,
    pub title: Option<String>,
    pub description: String,
    pub schema: Value,
    pub annotations: Option<Value>,
    pub bounds: Bounds,
}

impl Tool {
    fn to_mcp(&self) -> Value {
        let mut t = json!({"name": self.name, "description": self.description, "inputSchema": self.schema});
        if let Some(title) = &self.title {
            t["title"] = json!(title);
        }
        if let Some(a) = &self.annotations {
            t["annotations"] = a.clone();
        }
        t
    }
}

/// The tools of all services.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Catalogue {
    pub tools: Vec<Tool>,
}

impl Catalogue {
    /// The `tools` of a `tools/list` result.
    #[must_use]
    pub fn to_mcp(&self) -> Value {
        Value::Array(self.tools.iter().map(Tool::to_mcp).collect())
    }

    #[must_use]
    pub fn find(&self, name: &str) -> Option<&Tool> {
        self.tools.iter().find(|t| t.name == name)
    }

    /// Ask each service for its tools and build the list. Returns what was dropped, and why, for the log.
    /// A service that cannot be reached offers nothing and is named in the log.
    pub fn build(
        services: &[Service],
        settings: &Settings,
        transport: &dyn Transport,
    ) -> Result<(Catalogue, Vec<String>), CatalogueError> {
        let prefixes: Vec<String> = services.iter().map(prefix).collect();
        for (i, p) in prefixes.iter().enumerate() {
            if prefixes[..i].contains(p) {
                return Err(CatalogueError::PrefixCollision(p.clone()));
            }
        }
        let (mut tools, mut log) = (Vec::new(), Vec::new());
        for (index, service) in services.iter().enumerate() {
            let request = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/list"});
            let listed = match transport.post(service, &request, &CancelToken::default()) {
                Ok(response) => response.get("result").and_then(|r| r.get("tools")).and_then(Value::as_array).cloned(),
                Err(e) => {
                    log.push(format!("{}@{}: no tool list: {e:?}", service.name, service.host));
                    continue;
                }
            };
            let Some(listed) = listed else {
                log.push(format!("{}@{}: no tool list in the answer", service.name, service.host));
                continue;
            };
            for raw in &listed {
                match tool_from(raw, index, &prefixes[index], services.len() > 1, settings) {
                    Ok(tool) => tools.push(tool),
                    Err(why) => log.push(format!("{}@{}: tool dropped: {why}", service.name, service.host)),
                }
            }
        }
        // A name that is not unique is dropped, all of its holders.
        let names: Vec<String> = tools.iter().map(|t| t.name.clone()).collect();
        let (unique, dropped): (Vec<Tool>, Vec<Tool>) =
            tools.into_iter().partition(|t| names.iter().filter(|n| **n == t.name).count() == 1);
        log.extend(dropped.iter().map(|t| format!("tool `{}` dropped: the name is not unique", t.name)));
        Ok((Catalogue { tools: unique }, log))
    }
}

/// `<name>__<host>__`, the host with `.` as `-`.
fn prefix(service: &Service) -> String {
    format!("{}__{}__", service.name, service.host.replace('.', "-"))
}

fn tool_from(raw: &Value, service: usize, prefix: &str, several: bool, settings: &Settings) -> Result<Tool, String> {
    let wire_name = raw.get("name").and_then(Value::as_str).ok_or("no name")?.to_owned();
    let action = wire_name.replace('_', " ");
    if !text::is_action(&action) || action.replace(' ', "_") != wire_name {
        return Err(format!("`{}` is not an action", short(&wire_name)));
    }
    let name = if several { format!("{prefix}{wire_name}") } else { wire_name.clone() };
    if name.len() > MAX_NAME {
        return Err(format!("`{}` is longer than {MAX_NAME} characters", short(&name)));
    }
    let description = one_line(
        raw.get("description").and_then(Value::as_str).ok_or("no description")?,
        MAX_DESCRIPTION,
        "description",
    )?;
    let title = raw.get("title").and_then(Value::as_str).map(|t| one_line(t, MAX_TITLE, "title")).transpose()?;
    let (schema, bounds) = check_schema(raw.get("inputSchema").ok_or("no schema")?, settings)?;
    Ok(Tool {
        name,
        service,
        wire_name,
        action,
        title,
        description,
        schema,
        annotations: annotations(raw.get("annotations")),
        bounds,
    })
}

fn short(s: &str) -> String {
    s.chars().take(40).collect()
}

/// One line without control or bidirectional characters, within `max` characters, never cut.
fn one_line(s: &str, max: usize, what: &str) -> Result<String, String> {
    if s.chars().count() > max {
        return Err(format!("the {what} is longer than {max} characters"));
    }
    text::check(what, s).map_err(|_| format!("the {what} has a control or bidirectional character"))?;
    Ok(s.to_owned())
}

/// Only the four boolean hints of MCP pass.
fn annotations(a: Option<&Value>) -> Option<Value> {
    let a = a?.as_object()?;
    let kept: serde_json::Map<String, Value> = ["readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"]
        .iter()
        .filter_map(|k| a.get(*k).filter(|v| v.is_boolean()).map(|v| ((*k).to_owned(), v.clone())))
        .collect();
    (!kept.is_empty()).then_some(Value::Object(kept))
}

fn number(v: Option<&Value>, default: usize, ceiling: usize, what: &str) -> Result<usize, String> {
    match v {
        None => Ok(default),
        Some(n) => {
            let n = n
                .as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .ok_or_else(|| format!("{what} is not a non-negative integer"))?;
            // Never widened: above the format's own limit it is the format's.
            Ok(n.min(ceiling))
        }
    }
}

fn type_is(v: &Value, t: &str) -> bool {
    v.get("type").and_then(Value::as_str) == Some(t)
}

fn check_forbidden(v: &Value, where_: &str) -> Result<(), String> {
    for k in FORBIDDEN {
        if v.get(k).is_some() {
            return Err(format!("the schema has `{k}` in {where_}"));
        }
    }
    Ok(())
}

fn description_of(v: &Value, out: &mut Value) -> Result<(), String> {
    if let Some(d) = v.get("description") {
        out["description"] = json!(one_line(
            d.as_str().ok_or("a schema description is not a string")?,
            MAX_DESCRIPTION,
            "schema description"
        )?);
    }
    Ok(())
}

/// The service's `inputSchema`, checked and cleaned, and the bounds `pact` enforces.
fn check_schema(schema: &Value, settings: &Settings) -> Result<(Value, Bounds), String> {
    check_forbidden(schema, "the top")?;
    if !type_is(schema, "object") {
        return Err("the schema is not an object".into());
    }
    if schema.get("additionalProperties").is_some_and(|a| *a != json!(false)) {
        return Err("the schema allows other properties".into());
    }
    let props = schema.get("properties").and_then(Value::as_object).ok_or("the schema has no properties")?;
    if let Some(other) = props.keys().find(|k| !["params", "claim", "wait_seconds"].contains(&k.as_str())) {
        return Err(format!("the schema has a property `{}` that pact cannot send", short(other)));
    }

    let params = props.get("params").ok_or("the schema has no params")?;
    check_forbidden(params, "params")?;
    if !type_is(params, "array") {
        return Err("params is not an array".into());
    }
    let items = params.get("items").ok_or("params has no items")?;
    check_forbidden(items, "params.items")?;
    if !type_is(items, "string") {
        return Err("params.items is not a string".into());
    }
    let (max_items, item_max_len) = (
        number(params.get("maxItems"), MAX_PARAMS, MAX_PARAMS, "maxItems")?,
        number(items.get("maxLength"), MAX_PARAM_BYTES, MAX_PARAM_BYTES, "maxLength")?,
    );
    let mut item_schema = json!({"type": "string", "maxLength": item_max_len});
    if let Some(p) = items.get("pattern") {
        let p = p
            .as_str()
            .filter(|p| p.len() <= MAX_PATTERN && p.bytes().all(|b| (b' '..0x7f).contains(&b)))
            .ok_or("the pattern is not printable ASCII of at most 512 characters")?;
        // Passed on as data and never evaluated here: the service enforces the class.
        item_schema["pattern"] = json!(p);
    }
    let mut params_schema = json!({"type": "array", "items": item_schema, "maxItems": max_items});
    description_of(params, &mut params_schema)?;

    let claim = props.get("claim");
    if let Some(c) = claim {
        check_forbidden(c, "claim")?;
        if !type_is(c, "string") {
            return Err("claim is not a string".into());
        }
    }
    let claim_max_len = number(claim.and_then(|c| c.get("maxLength")), MAX_CLAIM_CHARS, MAX_CLAIM_CHARS, "maxLength")?;
    let mut claim_schema = json!({"type": "string", "maxLength": claim_max_len});
    if let Some(c) = claim {
        description_of(c, &mut claim_schema)?;
    }

    // Whatever the service said about wait_seconds, this one is pact's: it alone knows the setting and the floor.
    let wait = json!({
        "type": "integer",
        "minimum": settings.min_wait_seconds,
        "maximum": settings.deadline_seconds,
        "description": "How many seconds to wait at most for your person's answer. A shorter wait than the default may be asked for; a longer one cannot."
    });
    let schema = json!({
        "type": "object",
        "properties": {"params": params_schema, "claim": claim_schema, "wait_seconds": wait},
        "additionalProperties": false
    });
    Ok((schema, Bounds { max_items, item_max_len, claim_max_len }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pact::transport::{Memory, TransportError};

    pub(crate) fn svc(name: &str, host: &str) -> Service {
        Service { host: host.into(), name: name.into(), url: "http://127.0.0.1:1/mcp".into() }
    }

    fn schema(extra_params: Value) -> Value {
        let mut params = json!({"type": "array", "maxItems": 64, "items": {"type": "string", "maxLength": 512}});
        for (k, v) in extra_params.as_object().cloned().unwrap_or_default() {
            params[&k] = v;
        }
        json!({"type": "object", "properties": {"params": params, "claim": {"type": "string", "maxLength": 200}, "wait_seconds": {"type": "integer", "minimum": 1, "maximum": 600}}, "additionalProperties": false})
    }

    pub(crate) fn tool(name: &str, description: &str, schema: Value) -> Value {
        json!({"name": name, "description": description, "inputSchema": schema, "title": "t", "annotations": {"readOnlyHint": true, "evil": true}})
    }

    fn list(tools: Vec<Value>) -> Value {
        json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tools}})
    }

    fn build(services: &[Service], per_service: Vec<Value>) -> (Catalogue, Vec<String>) {
        let by_host: std::collections::HashMap<String, Value> =
            services.iter().map(|s| s.host.clone()).zip(per_service).collect();
        let t = Memory::new(move |s, _, _| Ok(by_host[&s.host].clone()));
        Catalogue::build(services, &Settings::new(120, None), &t).unwrap()
    }

    #[test]
    fn one_service_is_offered_without_a_prefix_and_with_its_own_schema() {
        let pattern = "^[a-z0-9=]+$";
        let (c, log) = build(
            &[svc("probe", "a.example")],
            vec![list(vec![
                tool(
                    "rt_procs",
                    "Rated: internal, none, none. Lists processes.",
                    schema(json!({"items": {"type": "string", "maxLength": 64, "pattern": pattern}, "maxItems": 3})),
                ),
                tool("sys_kit", "Rated: open, none, none. No arguments.", schema(json!({"maxItems": 0}))),
            ])],
        );
        assert!(log.is_empty(), "{log:?}");
        assert_eq!(c.tools.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(), ["rt_procs", "sys_kit"]);
        let t = c.find("rt_procs").unwrap();
        assert_eq!((t.wire_name.as_str(), t.action.as_str(), t.service), ("rt_procs", "rt procs", 0));
        assert_eq!(t.bounds, Bounds { max_items: 3, item_max_len: 64, claim_max_len: 200 });
        let p = &t.schema["properties"]["params"];
        assert_eq!(
            (p["maxItems"].clone(), p["items"]["maxLength"].clone(), p["items"]["pattern"].clone()),
            (json!(3), json!(64), json!(pattern))
        );
        assert_eq!(
            c.find("sys_kit").unwrap().schema["properties"]["params"]["maxItems"],
            0,
            "the maxItems: 0 of a verb without arguments survives"
        );
        assert_eq!(c.find("sys_kit").unwrap().bounds.max_items, 0);
        assert_eq!(t.annotations, Some(json!({"readOnlyHint": true})), "only the boolean hints pass");
        assert_eq!(t.title.as_deref(), Some("t"));
        assert_eq!(t.description, "Rated: internal, none, none. Lists processes.");
        assert_eq!(t.schema["additionalProperties"], false);
        let listed = c.to_mcp();
        assert_eq!(listed[0]["inputSchema"], t.schema);
    }

    #[test]
    fn several_services_are_prefixed_and_a_collision_refuses() {
        let a = svc("probe", "a.example");
        let b = svc("probe", "b.example");
        let (c, _) = build(
            &[a.clone(), b.clone()],
            vec![
                list(vec![tool("rt_procs", "d", schema(json!({})))]),
                list(vec![tool("rt_procs", "d", schema(json!({})))]),
            ],
        );
        assert_eq!(
            c.tools.iter().map(|t| (t.name.as_str(), t.service, t.wire_name.as_str())).collect::<Vec<_>>(),
            [("probe__a-example__rt_procs", 0, "rt_procs"), ("probe__b-example__rt_procs", 1, "rt_procs")]
        );
        // `a.b` and `a-b` map to one prefix.
        let t = Memory::new(|_, _, _| Ok(list(vec![])));
        let clash = [svc("probe", "a.b"), svc("probe", "a-b")];
        assert_eq!(
            Catalogue::build(&clash, &Settings::new(120, None), &t).unwrap_err(),
            CatalogueError::PrefixCollision("probe__a-b__".into())
        );
    }

    #[test]
    fn tools_that_break_a_rule_are_dropped_with_a_reason() {
        let ok_schema = schema(json!({}));
        let long_name = format!("rt_{}", "x".repeat(70));
        let tools = vec![
            tool("rt_procs", "fine", ok_schema.clone()),
            tool("Rt_Procs", "upper case", ok_schema.clone()),
            tool("rt__procs", "double underscore", ok_schema.clone()),
            tool("_rt", "leading underscore", ok_schema.clone()),
            tool(&long_name, "too long", ok_schema.clone()),
            tool("a_one", &"d".repeat(601), ok_schema.clone()),
            tool("a_two", "two\nlines", ok_schema.clone()),
            tool("a_three", "bidi \u{202e} mark", ok_schema.clone()),
            json!({"name": "a_four", "inputSchema": ok_schema.clone()}),
            json!({"name": "a_five", "description": "x"}),
            json!({"description": "x", "inputSchema": ok_schema.clone()}),
        ];
        let (c, log) = build(&[svc("probe", "a.example")], vec![list(tools)]);
        assert_eq!(c.tools.len(), 1, "{log:?}");
        assert_eq!(log.len(), 10, "{log:?}");
        let ok = tool("a_ok", &"d".repeat(600), ok_schema);
        assert_eq!(
            build(&[svc("probe", "a.example")], vec![list(vec![ok])]).0.tools[0].description.len(),
            600,
            "a description of exactly 600 is never cut"
        );
        // With several services the prefix counts toward 64.
        let near = format!("rt_{}", "x".repeat(50));
        let (c, log) = build(
            &[svc("probe", "a.example"), svc("other", "b.example")],
            vec![list(vec![tool(&near, "d", schema(json!({})))]), list(vec![])],
        );
        assert!(c.tools.is_empty() && log.iter().any(|l| l.contains("longer than 64")), "{log:?}");
        // A name that is not unique is dropped with all its holders.
        let (c, log) = build(
            &[svc("probe", "a.example")],
            vec![list(vec![tool("rt_procs", "d", schema(json!({}))), tool("rt_procs", "e", schema(json!({})))])],
        );
        assert!(c.tools.is_empty() && log.iter().any(|l| l.contains("not unique")), "{log:?}");
    }

    #[test]
    fn the_schema_is_checked_cleaned_and_never_widened() {
        let one = |s: Value| build(&[svc("probe", "a.example")], vec![list(vec![tool("rt_procs", "d", s)])]);
        // Widened bounds are the format's.
        let (c, _) = one(schema(json!({"maxItems": 1000, "items": {"type": "string", "maxLength": 100_000}})));
        assert_eq!(c.tools[0].bounds, Bounds { max_items: 64, item_max_len: 512, claim_max_len: 200 });
        let mut wide = schema(json!({}));
        wide["properties"]["claim"]["maxLength"] = json!(5000);
        assert_eq!(one(wide).0.tools[0].bounds.claim_max_len, 200);
        // Missing bounds are the format's.
        let (c, _) = one(
            json!({"type": "object", "properties": {"params": {"type": "array", "items": {"type": "string"}}}, "additionalProperties": false}),
        );
        assert_eq!(c.tools[0].bounds, Bounds { max_items: 64, item_max_len: 512, claim_max_len: 200 });
        assert_eq!(c.tools[0].schema["properties"]["claim"]["maxLength"], 200);
        // wait_seconds is pact's, whatever the service said.
        let (c, _) = one(schema(json!({})));
        let w = &c.tools[0].schema["properties"]["wait_seconds"];
        assert_eq!(
            (w["minimum"].clone(), w["maximum"].clone(), w["type"].clone()),
            (json!(10), json!(120), json!("integer"))
        );
        // Unknown benign keywords are removed.
        let mut extra = schema(json!({}));
        extra["$schema"] = json!("http://json-schema.org/draft-07/schema#");
        extra["required"] = json!(["params"]);
        extra["properties"]["params"]["minItems"] = json!(1);
        let (c, _) = one(extra);
        assert!(c.tools[0].schema.get("required").is_none() && c.tools[0].schema.get("$schema").is_none());
        assert!(c.tools[0].schema["properties"]["params"].get("minItems").is_none());
        // These make the tool dropped.
        let mut bad = vec![];
        for key in ["$ref", "default", "examples", "oneOf", "anyOf", "allOf"] {
            let mut s = schema(json!({}));
            s["properties"]["params"][key] = json!(["x"]);
            bad.push(s);
        }
        let mut s = schema(json!({}));
        s["properties"]["extra"] = json!({"type": "string"});
        bad.push(s);
        let mut s = schema(json!({}));
        s["additionalProperties"] = json!(true);
        bad.push(s);
        let mut s = schema(json!({}));
        s["type"] = json!("array");
        bad.push(s);
        let mut s = schema(json!({}));
        s["properties"]["params"]["items"]["type"] = json!("integer");
        bad.push(s);
        let mut s = schema(json!({}));
        s["properties"]["params"]["items"]["pattern"] = json!("é");
        bad.push(s);
        let mut s = schema(json!({}));
        s["properties"]["params"]["items"]["pattern"] = json!("a".repeat(513));
        bad.push(s);
        let mut s = schema(json!({}));
        s["properties"]["params"]["maxItems"] = json!(-1);
        bad.push(s);
        let mut s = schema(json!({}));
        s["properties"]["params"]["description"] = json!("line\nbreak");
        bad.push(s);
        let mut s = schema(json!({}));
        s["properties"]["claim"]["type"] = json!("integer");
        bad.push(s);
        bad.push(json!({"type": "object"}));
        bad.push(json!("nope"));
        for s in bad {
            let (c, log) = one(s.clone());
            assert!(c.tools.is_empty(), "{s}");
            assert_eq!(log.len(), 1);
        }
    }

    #[test]
    fn a_service_that_cannot_be_reached_offers_nothing_and_is_named() {
        let t = Memory::new(|s, _, _| {
            if s.host == "down.example" {
                Err(TransportError::NotSent("refused".into()))
            } else {
                Ok(list(vec![tool("rt_procs", "d", schema(json!({})))]))
            }
        });
        let services = [svc("probe", "a.example"), svc("probe", "down.example")];
        let (c, log) = Catalogue::build(&services, &Settings::new(120, None), &t).unwrap();
        assert_eq!(c.tools.len(), 1);
        assert!(log.iter().any(|l| l.contains("down.example")), "{log:?}");
        let t = Memory::new(|_, _, _| Ok(json!({"result": {}})));
        let (c, log) = Catalogue::build(&services, &Settings::new(120, None), &t).unwrap();
        assert!(c.tools.is_empty() && log.len() == 2, "{log:?}");
    }
}
