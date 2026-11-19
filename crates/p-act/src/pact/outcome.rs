//! What the model is told: the closed list `done`, `declined`, `expired`,
//! `refused` (with its class), `unavailable`, `failed`, `unknown`. Only words from this
//! list ever reach the model; nothing a service or a transport said is copied.

use super::transport::TransportError;
use crate::call::CallId;
use serde_json::{Value, json};

/// A verb's answer is passed on up to this many bytes of text.
pub const MAX_ANSWER_TEXT: usize = 1024 * 1024;

/// The longest message of an error of the model's own, in characters of the escaped text.
pub const MAX_MODEL_ERROR_CHARS: usize = 1000;

/// The deepest a record may nest; deeper is not an answer.
pub const MAX_RECORD_DEPTH: usize = 32;

/// What the text of an `unknown` outcome adds.
pub const UNKNOWN_TEXT: &str = "The call was sent, and whether it ran is not known. Before you repeat anything that changes something, find out whether it happened, by a query. Ask your person if you cannot tell.";

/// What the text of a `failed` outcome adds: the action was started and did not complete.
pub const FAILED_TEXT: &str = "The call was approved and the action was started, and it did not complete. There is no result, and something may have happened on the host. Do not repeat it blindly if it changes anything: find out what happened first, by a query, and ask your person if you cannot tell. The cause is in the service's log and the host's audit lines, under this call's identifier.";

/// Why a service or `pact` refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// The delegation, the site's rules or the person's ceilings do not allow it.
    NotAllowed,
    /// The call itself is wrong.
    Invalid,
    /// Wait, then ask again.
    TryLater,
}

impl Class {
    fn word(self) -> &'static str {
        match self {
            Class::NotAllowed => "not-allowed",
            Class::Invalid => "invalid",
            Class::TryLater => "try-later",
        }
    }

    fn from_word(w: &str) -> Option<Class> {
        [Class::NotAllowed, Class::Invalid, Class::TryLater].into_iter().find(|c| c.word() == w)
    }
}

/// The outcome of one call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The verb ran, and exited with `rc`.
    Done {
        rc: i64,
    },
    Declined,
    Expired,
    Refused(Class),
    /// Nobody could be asked, or nothing was done for a reason on the service's side. Trying again is safe.
    Unavailable,
    /// The call was approved and the action was started, and it did not complete: no result, something may have
    /// happened on the host. Distinct from `Unavailable` (nothing was done) and `Unknown` (only `pact` can say
    /// it was sent without knowing whether it ran). Only a service says this one.
    Failed,
    /// The call was sent; whether it ran is not known. Only `pact` makes this.
    Unknown,
}

/// The tool result for the model: `structuredContent` when the service gave its answer as data, text contents, and
/// `isError`. **Everything in it is built by `pact` from validated fields**: the outcome words are its own, and every
/// string of an answer has been through `p_ermit::text::escape`, so nothing raw reaches the model's client.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelResult {
    pub outcome: Outcome,
    /// The text blocks. For a structured answer: the outcome line with the count of records, and for `unknown` and
    /// `failed` `pact`'s fixed sentence; **never a record** (host text must not reach a model by the route that is not
    /// framed). For an answer in the older text shape: the outcome line and the answer's texts, escaped.
    pub texts: Vec<String>,
    /// `{outcome, id, rc, records}` for a structured answer, built here; `None` for any other result.
    pub structured: Option<Value>,
    pub is_error: bool,
}

impl ModelResult {
    /// The MCP `tools/call` result.
    #[must_use]
    pub fn to_mcp(&self) -> Value {
        let content: Vec<Value> = self.texts.iter().map(|t| json!({"type": "text", "text": t})).collect();
        let mut result = json!({"content": content, "isError": self.is_error});
        if let Some(structured) = &self.structured {
            result["structuredContent"] = structured.clone();
        }
        result
    }

    /// A result that is an error of the model's, said plainly. Not an outcome.
    #[must_use]
    pub fn model_error(message: &str) -> Value {
        // `pact`'s own words, and sometimes a name the model gave: escaped and bounded all the same.
        let message = p_ermit::text::escape_clipped(message, MAX_MODEL_ERROR_CHARS).text;
        json!({"content": [{"type": "text", "text": message}], "isError": true})
    }
}

/// The members of an outcome, from the closed words: `outcome`, `id`, `reason` of a refusal, `rc` of a `done`.
fn outcome_fields(outcome: Outcome, id: Option<&CallId>) -> serde_json::Map<String, Value> {
    let mut o = serde_json::Map::new();
    let (word, reason, rc) = match outcome {
        Outcome::Done { rc } => ("done", None, Some(rc)),
        Outcome::Declined => ("declined", None, None),
        Outcome::Expired => ("expired", None, None),
        Outcome::Refused(c) => ("refused", Some(c.word()), None),
        Outcome::Unavailable => ("unavailable", None, None),
        Outcome::Failed => ("failed", None, None),
        Outcome::Unknown => ("unknown", None, None),
    };
    o.insert("outcome".into(), json!(word));
    if let Some(id) = id {
        o.insert("id".into(), json!(id.as_str()));
    }
    if let Some(r) = reason {
        o.insert("reason".into(), json!(r));
    }
    if let Some(rc) = rc {
        o.insert("rc".into(), json!(rc));
    }
    o
}

/// The first text of every result: one JSON object on one line, built here from the closed words.
#[must_use]
pub fn outcome_line(outcome: Outcome, id: Option<&CallId>) -> String {
    let mut o = outcome_fields(outcome, id);
    o.insert("type".into(), json!("outcome"));
    super::canon::line(&Value::Object(o))
}

/// The text block of a structured result: the outcome line and **the count of records, never the records**.
fn counted_line(outcome: Outcome, id: &CallId, records: usize) -> String {
    let mut o = outcome_fields(outcome, Some(id));
    o.insert("type".into(), json!("outcome"));
    o.insert("records".into(), json!(records));
    super::canon::line(&Value::Object(o))
}

fn result(outcome: Outcome, id: Option<&CallId>, answer: Vec<String>) -> ModelResult {
    let mut texts = vec![outcome_line(outcome, id)];
    texts.extend(answer);
    match outcome {
        Outcome::Unknown => texts.push(UNKNOWN_TEXT.to_owned()),
        Outcome::Failed => texts.push(FAILED_TEXT.to_owned()),
        _ => {}
    }
    let is_error = !matches!(outcome, Outcome::Done { rc: 0 });
    ModelResult { outcome, texts, structured: None, is_error }
}

/// The result of a call that did not get a response.
#[must_use]
pub fn from_transport_error(error: &TransportError, id: &CallId) -> (ModelResult, String) {
    let (outcome, log) = match error {
        TransportError::NotSent(d) => (Outcome::Unavailable, format!("not sent: {d}")),
        TransportError::Unavailable(d) => (Outcome::Unavailable, format!("unavailable: {d}")),
        TransportError::TryLater => (Outcome::Refused(Class::TryLater), "the service asked to try later".to_owned()),
        TransportError::Lost(d) => (Outcome::Unknown, format!("answer lost: {d}")),
    };
    (result(outcome, Some(id), vec![]), log)
}

/// The result of a call with the service's JSON-RPC response `response`. Whatever it holds is parsed into the
/// closed list; a word outside it is not passed on. Returns what to log, if anything.
#[must_use]
pub fn from_response(response: &Value, id: &CallId) -> (ModelResult, Option<String>) {
    // An error at the JSON-RPC level means the service did not take the call: `pact` builds it itself, so a signer bug.
    if let Some(error) = response.get("error") {
        let code = error.get("code").and_then(Value::as_i64).map_or_else(|| "none".to_owned(), |c| c.to_string());
        return (
            result(Outcome::Unavailable, Some(id), vec![]),
            Some(format!("the service answered a JSON-RPC error, code {code}")),
        );
    }
    let unknown =
        |why: &str| (result(Outcome::Unknown, Some(id), vec![]), Some(format!("unintelligible answer: {why}")));
    // The answer as data: `structuredContent` wins when it is there (and then it must be right: a broken one is not
    // read as text). The older shape, text blocks, is read when it is not there.
    if let Some(structured) = response.get("result").and_then(|r| r.get("structuredContent")) {
        return from_structured(structured, id);
    }
    let Some(content) = response.get("result").and_then(|r| r.get("content")).and_then(Value::as_array) else {
        return unknown("no content");
    };
    let texts: Vec<&str> = content
        .iter()
        .filter(|c| c.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|c| c.get("text").and_then(Value::as_str))
        .collect();
    let Some(first) = texts.first() else { return unknown("no text") };
    let Ok(Value::Object(line)) = p_ermit::json::parse(first) else {
        return unknown("the first text is not an object");
    };
    let word = |k: &str| line.get(k).and_then(Value::as_str);
    if word("type") != Some("outcome") || word("id") != Some(id.as_str()) {
        return unknown("not an outcome for this call");
    }
    let (outcome, mut log) = match outcome_of(&line) {
        Ok(found) => found,
        Err(why) => return unknown(why),
    };
    let answer: Vec<&str> = if matches!(outcome, Outcome::Done { .. }) { texts[1..].to_vec() } else { vec![] };
    if answer.iter().map(|t| t.len()).sum::<usize>() > MAX_ANSWER_TEXT {
        return unknown("the answer is longer than the limit");
    }
    // `pact` is the last thing before the model and trusts no service: every text of the answer is escaped.
    let mut flagged = 0;
    let answer: Vec<String> = answer
        .into_iter()
        .map(|t| {
            let escaped = p_ermit::text::escape(t);
            flagged += escaped.flagged;
            escaped.text
        })
        .collect();
    if flagged > 0 {
        log = Some(raw_log(flagged, log));
    }
    (result(outcome, Some(id), answer), log)
}

/// The outcome the members `outcome`, `rc` and `reason` of a service's answer name, in the closed list, and what to log
/// if the service gave a reason outside it; or why the answer is not intelligible.
fn outcome_of(members: &serde_json::Map<String, Value>) -> Result<(Outcome, Option<String>), &'static str> {
    let word = |k: &str| members.get(k).and_then(Value::as_str);
    Ok(match word("outcome") {
        Some("done") => match members.get("rc").and_then(Value::as_i64) {
            Some(rc) => (Outcome::Done { rc }, None),
            None => return Err("done without rc"),
        },
        Some("declined") => (Outcome::Declined, None),
        Some("expired") => (Outcome::Expired, None),
        Some("unavailable") => (Outcome::Unavailable, None),
        // Whatever else the service puts in it (a reason, a detail) is not passed on: the cause is in its own log.
        Some("failed") => (Outcome::Failed, None),
        Some("refused") => match word("reason").and_then(Class::from_word) {
            Some(c) => (Outcome::Refused(c), None),
            None => (Outcome::Refused(Class::NotAllowed), Some("refused with a reason outside the list".to_owned())),
        },
        _ => return Err("an outcome outside the list"),
    })
}

/// The log line for a service that sent what the rule refuses: how many, never what. A service at fault.
fn raw_log(flagged: usize, other: Option<String>) -> String {
    let raw = format!(
        "the service sent {flagged} raw control or bidirectional characters or invalid bytes in its answer, escaped here: it is at fault"
    );
    match other {
        Some(other) => format!("{other}; {raw}"),
        None => raw,
    }
}

/// Every string of `value`, at any depth, in an object's keys too, through `p_ermit::text::escape`; `flagged` counts
/// what was escaped that the rule refuses. `None` if it nests deeper than [`MAX_RECORD_DEPTH`].
fn escape_value(value: &Value, depth: usize, flagged: &mut usize) -> Option<Value> {
    if depth > MAX_RECORD_DEPTH {
        return None;
    }
    let mut text = |s: &str| {
        let escaped = p_ermit::text::escape(s);
        *flagged += escaped.flagged;
        escaped.text
    };
    Some(match value {
        Value::String(s) => Value::String(text(s)),
        Value::Array(items) => {
            Value::Array(items.iter().map(|v| escape_value(v, depth + 1, flagged)).collect::<Option<Vec<_>>>()?)
        }
        Value::Object(members) => {
            let mut out = serde_json::Map::new();
            for (key, member) in members {
                let escaped_key = {
                    let escaped = p_ermit::text::escape(key);
                    *flagged += escaped.flagged;
                    escaped.text
                };
                out.insert(escaped_key, escape_value(member, depth + 1, flagged)?);
            }
            Value::Object(out)
        }
        other => other.clone(),
    })
}

/// A service's answer as data: `{outcome, id, rc, records}`. The outcome and the id are judged as in the text shape;
/// `records` is an array of objects (absent is empty), at most [`MAX_ANSWER_TEXT`] bytes **as the service's JSON text of
/// the array** counted before escaping, nested at most [`MAX_RECORD_DEPTH`]; anything else in the object is ignored,
/// and a refusal's or a failure's records are not the model's business. What `pact` passes on is built from these
/// fields: the outcome line with the count in `texts`, the escaped records in `structured`.
fn from_structured(structured: &Value, id: &CallId) -> (ModelResult, Option<String>) {
    let unknown =
        |why: &str| (result(Outcome::Unknown, Some(id), vec![]), Some(format!("unintelligible answer: {why}")));
    let Some(members) = structured.as_object() else { return unknown("structuredContent is not an object") };
    if members.get("id").and_then(Value::as_str) != Some(id.as_str()) {
        return unknown("not an outcome for this call");
    }
    let (outcome, mut log) = match outcome_of(members) {
        Ok(found) => found,
        Err(why) => return unknown(why),
    };
    let mut fields = outcome_fields(outcome, Some(id));
    let mut texts = Vec::new();
    let mut count = None;
    if matches!(outcome, Outcome::Done { .. }) {
        let records = match members.get("records") {
            None => Vec::new(),
            Some(Value::Array(items)) if items.iter().all(Value::is_object) => items.clone(),
            Some(_) => return unknown("records is not an array of objects"),
        };
        let size = serde_json::to_string(&records).map_or(usize::MAX, |t| t.len());
        if size > MAX_ANSWER_TEXT {
            return unknown("the answer is longer than the limit");
        }
        let mut flagged = 0;
        let Some(escaped) = escape_value(&Value::Array(records), 0, &mut flagged) else {
            return unknown("the records nest too deep");
        };
        if flagged > 0 {
            log = Some(raw_log(flagged, log));
        }
        count = escaped.as_array().map(Vec::len);
        fields.insert("records".into(), escaped);
    }
    texts.push(counted_line_opt(outcome, id, count));
    match outcome {
        Outcome::Unknown => texts.push(UNKNOWN_TEXT.to_owned()),
        Outcome::Failed => texts.push(FAILED_TEXT.to_owned()),
        _ => {}
    }
    let is_error = !matches!(outcome, Outcome::Done { rc: 0 });
    (ModelResult { outcome, texts, structured: Some(Value::Object(fields)), is_error }, log)
}

/// The outcome line of a structured result: with the count of records when there are records to count.
fn counted_line_opt(outcome: Outcome, id: &CallId, count: Option<usize>) -> String {
    count.map_or_else(|| outcome_line(outcome, Some(id)), |n| counted_line(outcome, id, n))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id() -> CallId {
        CallId::parse("3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a11").unwrap()
    }

    fn response(first: &str, more: &[&str]) -> Value {
        let mut content = vec![json!({"type": "text", "text": first})];
        content.extend(more.iter().map(|t| json!({"type": "text", "text": t})));
        json!({"jsonrpc": "2.0", "id": 1, "result": {"content": content}})
    }

    fn line(outcome: &str, extra: &str) -> String {
        format!(r#"{{"type":"outcome","outcome":"{outcome}","id":"{}"{extra}}}"#, id())
    }

    fn map(first: &str, more: &[&str]) -> ModelResult {
        from_response(&response(first, more), &id()).0
    }

    #[test]
    fn the_closed_list_maps_to_itself() {
        for (outcome, extra, expected) in [
            ("declined", "", Outcome::Declined),
            ("expired", "", Outcome::Expired),
            ("unavailable", "", Outcome::Unavailable),
            ("failed", "", Outcome::Failed),
            ("refused", r#","reason":"not-allowed""#, Outcome::Refused(Class::NotAllowed)),
            ("refused", r#","reason":"invalid""#, Outcome::Refused(Class::Invalid)),
            ("refused", r#","reason":"try-later""#, Outcome::Refused(Class::TryLater)),
            ("done", r#","rc":0"#, Outcome::Done { rc: 0 }),
            ("done", r#","rc":3"#, Outcome::Done { rc: 3 }),
        ] {
            let r = map(&line(outcome, extra), &[]);
            assert_eq!(r.outcome, expected, "{outcome}");
            assert_eq!(r.is_error, expected != Outcome::Done { rc: 0 }, "{outcome}");
            let first: Value = serde_json::from_str(&r.texts[0]).unwrap();
            assert_eq!(first["outcome"], outcome);
            assert_eq!(first["id"], id().as_str());
        }
    }

    #[test]
    fn a_done_passes_the_answer_on_and_nothing_else_does() {
        let r = map(&line("done", r#","rc":0"#), &[r#"{"a":1}"#, r#"{"b":2}"#]);
        assert_eq!(r.texts[1..], [r#"{"a":1}"#, r#"{"b":2}"#]);
        assert!(!r.is_error);
        // A refusal's further texts are not the model's business.
        let r = map(&line("refused", r#","reason":"invalid""#), &["secret detail"]);
        assert_eq!(r.texts.len(), 1);
        // Non-text content is dropped.
        let mut v = response(&line("done", r#","rc":0"#), &["x"]);
        v["result"]["content"].as_array_mut().unwrap().push(json!({"type": "image", "data": "AAAA"}));
        assert_eq!(from_response(&v, &id()).0.texts.len(), 2);
    }

    #[test]
    fn a_word_outside_the_list_is_never_passed_on() {
        // A refused with a reason it does not know is a refusal that says do not repeat: not-allowed.
        let (r, log) = from_response(&response(&line("refused", r#","reason":"made-up""#), &[]), &id());
        assert_eq!(r.outcome, Outcome::Refused(Class::NotAllowed));
        assert!(log.is_some());
        assert!(!r.texts.concat().contains("made-up"));
        // An outcome it does not know, a mismatched id, no rc, not JSON, not an object, no content: unknown.
        for first in [
            line("vaporised", ""),
            line("done", ""),
            line("done", r#","rc":"0""#),
            format!(
                r#"{{"type":"outcome","outcome":"done","id":"{}","rc":0}}"#,
                "3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a12"
            ),
            r#"{"type":"outcome","outcome":"done","rc":0}"#.to_owned(),
            r#"{"outcome":"done","id":"x","rc":0}"#.to_owned(),
            "not json".to_owned(),
            "[]".to_owned(),
            "\"done\"".to_owned(),
        ] {
            let r = map(&first, &[]);
            assert_eq!(r.outcome, Outcome::Unknown, "{first}");
            assert!(r.is_error);
            assert!(!r.texts.concat().contains("vaporised"));
            assert_eq!(r.texts.last().map(String::as_str), Some(UNKNOWN_TEXT));
        }
        assert_eq!(from_response(&json!({"result": {}}), &id()).0.outcome, Outcome::Unknown);
        assert_eq!(from_response(&json!({"result": {"content": []}}), &id()).0.outcome, Outcome::Unknown);
        assert_eq!(
            from_response(&json!({"result": {"content": [{"type": "image"}]}}), &id()).0.outcome,
            Outcome::Unknown
        );
        assert_eq!(from_response(&json!("x"), &id()).0.outcome, Outcome::Unknown);
    }

    fn structured_response(members: Value) -> Value {
        json!({"jsonrpc": "2.0", "id": 1, "result": {"content": [{"type": "text", "text": "ignored"}], "structuredContent": members}})
    }

    fn structured(members: Value) -> (ModelResult, Option<String>) {
        from_response(&structured_response(members), &id())
    }

    #[test]
    fn a_structured_answer_is_rebuilt_from_validated_fields_with_the_records_only_in_the_structure() {
        let (r, log) = structured(json!({
            "outcome": "done", "id": id().as_str(), "rc": 0,
            "records": [{"pid": 1, "comm": "init"}, {"pid": 2, "comm": "kthreadd"}],
            "extra": "not passed on", "detail": {"x": 1}
        }));
        assert_eq!((r.outcome, r.is_error, log), (Outcome::Done { rc: 0 }, false, None));
        assert_eq!(
            r.structured,
            Some(
                json!({"outcome": "done", "id": id().as_str(), "rc": 0, "records": [{"pid": 1, "comm": "init"}, {"pid": 2, "comm": "kthreadd"}]})
            )
        );
        // One text block: the outcome line and the count; no record is in any text.
        assert_eq!(r.texts.len(), 1);
        let line: Value = serde_json::from_str(&r.texts[0]).unwrap();
        assert_eq!(
            (line["type"].clone(), line["outcome"].clone(), line["records"].clone()),
            (json!("outcome"), json!("done"), json!(2))
        );
        assert!(!r.texts.concat().contains("init") && !r.texts.concat().contains("not passed on"));
        let mcp = r.to_mcp();
        assert_eq!(mcp["structuredContent"], r.structured.clone().unwrap());
        assert_eq!(mcp["content"].as_array().unwrap().len(), 1);
        // No records is an empty array; a nonzero rc is an error.
        let (r, _) = structured(json!({"outcome": "done", "id": id().as_str(), "rc": 3}));
        assert_eq!((r.is_error, r.structured.unwrap()["records"].clone()), (true, json!([])));
    }

    #[test]
    fn every_non_done_outcome_of_a_structured_answer_passes_no_records_and_its_words_are_the_closed_list() {
        for (members, expected) in [
            (json!({"outcome": "declined"}), Outcome::Declined),
            (json!({"outcome": "expired"}), Outcome::Expired),
            (json!({"outcome": "unavailable"}), Outcome::Unavailable),
            (json!({"outcome": "failed"}), Outcome::Failed),
            (json!({"outcome": "refused", "reason": "invalid"}), Outcome::Refused(Class::Invalid)),
            (json!({"outcome": "refused", "reason": "made-up"}), Outcome::Refused(Class::NotAllowed)),
        ] {
            let mut members = members;
            members["id"] = json!(id().as_str());
            members["records"] = json!([{"secret": "x"}]);
            let (r, _) = structured(members);
            assert_eq!(r.outcome, expected);
            assert!(r.is_error);
            let s = r.structured.unwrap();
            assert!(s.get("records").is_none(), "{s}");
            assert!(!r.texts.concat().contains("secret"));
            assert!(!s.to_string().contains("made-up"));
        }
        let (r, _) = structured(json!({"outcome": "failed", "id": id().as_str()}));
        assert_eq!(r.texts.last().map(String::as_str), Some(FAILED_TEXT));
    }

    #[test]
    fn a_structured_answer_that_is_not_right_is_unknown_and_never_read_as_text() {
        let good = || json!({"outcome": "done", "id": id().as_str(), "rc": 0, "records": []});
        let mut cases = vec![json!("x"), json!([]), json!(null)];
        for edit in [
            |m: &mut Value| m["id"] = json!("3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a12"),
            |m: &mut Value| {
                m.as_object_mut().unwrap().remove("id");
            },
            |m: &mut Value| m["outcome"] = json!("vaporised"),
            |m: &mut Value| {
                m.as_object_mut().unwrap().remove("rc");
            },
            |m: &mut Value| m["rc"] = json!("0"),
            |m: &mut Value| m["records"] = json!({"a": 1}),
            |m: &mut Value| m["records"] = json!(["text"]),
            |m: &mut Value| m["records"] = json!([[1]]),
            |m: &mut Value| m["records"] = json!([null]),
        ] {
            let mut m = good();
            edit(&mut m);
            cases.push(m);
        }
        for members in cases {
            // The text shape beside it is right, and is not used.
            let mut v = response(&line("done", r#","rc":0"#), &["fine"]);
            v["result"]["structuredContent"] = members.clone();
            let (r, log) = from_response(&v, &id());
            assert_eq!(r.outcome, Outcome::Unknown, "{members}");
            assert!(r.structured.is_none() && log.is_some());
            assert_eq!(r.texts.last().map(String::as_str), Some(UNKNOWN_TEXT));
        }
        assert_eq!(structured(good()).0.outcome, Outcome::Done { rc: 0 });
    }

    #[test]
    fn the_structured_answer_wins_when_both_shapes_are_there_and_the_text_shape_is_read_when_it_is_alone() {
        let mut v = response(&line("done", r#","rc":0"#), &["from the text"]);
        v["result"]["structuredContent"] =
            json!({"outcome": "done", "id": id().as_str(), "rc": 0, "records": [{"a": "from the data"}]});
        let (r, _) = from_response(&v, &id());
        assert!(r.structured.is_some() && !r.texts.concat().contains("from the text"));
        let (r, _) = from_response(&response(&line("done", r#","rc":0"#), &["from the text"]), &id());
        assert!(r.structured.is_none());
        assert_eq!(r.texts[1], "from the text");
        assert!(r.to_mcp().get("structuredContent").is_none());
    }

    #[test]
    fn the_size_bound_counts_the_json_text_of_the_records_and_the_depth_is_bounded() {
        // At the limit: one record whose text, `[{"k":"..."}]`, is exactly MAX_ANSWER_TEXT bytes.
        let overhead = r#"[{"k":""}]"#.len();
        let at = json!({"outcome": "done", "id": id().as_str(), "rc": 0, "records": [{"k": "x".repeat(MAX_ANSWER_TEXT - overhead)}]});
        assert_eq!(structured(at).0.outcome, Outcome::Done { rc: 0 });
        let over = json!({"outcome": "done", "id": id().as_str(), "rc": 0, "records": [{"k": "x".repeat(MAX_ANSWER_TEXT - overhead + 1)}]});
        assert_eq!(structured(over).0.outcome, Outcome::Unknown);
        // Depth.
        let mut deep = json!("leaf");
        for _ in 0..MAX_RECORD_DEPTH {
            deep = json!({"n": deep});
        }
        let ok = json!({"outcome": "done", "id": id().as_str(), "rc": 0, "records": [{"n": deep.clone()}]});
        let too = json!({"outcome": "done", "id": id().as_str(), "rc": 0, "records": [{"n": {"n": deep}}]});
        assert_eq!(structured(ok).0.outcome, Outcome::Unknown, "33 deep is over");
        assert_eq!(structured(too).0.outcome, Outcome::Unknown);
        let shallow =
            json!({"outcome": "done", "id": id().as_str(), "rc": 0, "records": [{"a": {"b": [1, {"c": "d"}]}}]});
        assert_eq!(structured(shallow).0.outcome, Outcome::Done { rc: 0 });
    }

    #[test]
    fn nothing_raw_reaches_the_model_from_a_service_that_did_not_clean_its_output() {
        use p_ermit::probe::{PROBE_ALL, PROBES, assert_clean_in};
        for probe in PROBES.iter().copied().chain([PROBE_ALL]) {
            // Structured: values, keys, at any depth, in arrays.
            let records = json!([{format!("key{probe}"): format!("value{probe}"), "nested": {"list": [format!("a{probe}b"), 3, true, null]}}]);
            let (r, log) = structured(json!({"outcome": "done", "id": id().as_str(), "rc": 0, "records": records}));
            let mcp = r.to_mcp();
            assert_clean_in("structured result", &serde_json::to_string(&mcp).unwrap());
            assert_clean_in("structured log", &log.clone().unwrap());
            assert!(log.unwrap().contains("it is at fault"));
            // The text shape: every text after the first.
            let (r, log) =
                from_response(&response(&line("done", r#","rc":0"#), &[&format!("text {probe}"), "clean"]), &id());
            assert_clean_in("text result", &serde_json::to_string(&r.to_mcp()).unwrap());
            assert!(log.is_some());
            assert!(r.texts[1].contains("\\u{") && r.texts[1].starts_with("text "), "{}", r.texts[1]);
            assert_eq!(r.texts[2], "clean");
            // A clean answer is not logged, and is the same text.
            let (r, log) = from_response(&response(&line("done", r#","rc":0"#), &["plain text"]), &id());
            assert_eq!((r.texts[1].as_str(), log), ("plain text", None));
        }
        // The count is of what was escaped, not what is in the answer.
        let (_, log) = structured(
            json!({"outcome": "done", "id": id().as_str(), "rc": 0, "records": [{"a\u{85}": "b\u{202e}", "c": "d"}]}),
        );
        assert!(log.unwrap().contains("sent 2 raw"));
        // A model error of `pact`'s own is escaped and bounded too.
        let e = ModelResult::model_error(&format!("there is no tool `{PROBE_ALL}{}`", "x".repeat(2000)));
        assert_clean_in("model error", &e.to_string());
        assert!(e["content"][0]["text"].as_str().unwrap().chars().count() <= MAX_MODEL_ERROR_CHARS);
    }

    #[test]
    fn an_outcome_line_with_a_repeated_key_is_unknown_never_the_first_or_the_last() {
        let line = format!(r#"{{"type":"outcome","outcome":"done","outcome":"declined","id":"{}","rc":0}}"#, id());
        let r = map(&line, &["data"]);
        assert_eq!(r.outcome, Outcome::Unknown);
        let line = format!(r#"{{"type":"outcome","outcome":"done","id":"{0}","id":"{0}","rc":0,"rc":1}}"#, id());
        assert_eq!(map(&line, &[]).outcome, Outcome::Unknown);
    }

    #[test]
    fn an_answer_over_the_limit_is_unknown() {
        let big = "x".repeat(MAX_ANSWER_TEXT + 1);
        assert_eq!(map(&line("done", r#","rc":0"#), &[&big]).outcome, Outcome::Unknown);
        let at = "x".repeat(MAX_ANSWER_TEXT);
        assert_eq!(map(&line("done", r#","rc":0"#), &[&at]).outcome, Outcome::Done { rc: 0 });
    }

    #[test]
    fn a_json_rpc_error_is_unavailable_and_says_nothing_of_itself() {
        let v = json!({"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "secret internal text"}});
        let (r, log) = from_response(&v, &id());
        assert_eq!(r.outcome, Outcome::Unavailable);
        assert!(log.unwrap().contains("-32602"));
        assert!(!r.texts.concat().contains("secret"));
    }

    #[test]
    fn transport_errors_map_to_the_list() {
        for (e, expected) in [
            (TransportError::NotSent("connection refused".into()), Outcome::Unavailable),
            (TransportError::Unavailable("redirect".into()), Outcome::Unavailable),
            (TransportError::TryLater, Outcome::Refused(Class::TryLater)),
            (TransportError::Lost("idle".into()), Outcome::Unknown),
        ] {
            let (r, log) = from_transport_error(&e, &id());
            assert_eq!(r.outcome, expected, "{e:?}");
            assert!(r.is_error);
            assert!(!log.is_empty());
            let shown = r.texts.concat();
            assert!(!shown.contains("refused by") && !shown.contains("redirect") && !shown.contains("idle"), "{shown}");
        }
        let (r, _) = from_transport_error(&TransportError::Lost("x".into()), &id());
        assert_eq!(r.texts.len(), 2);
        assert!(r.texts[1].contains("find out"));
    }

    #[test]
    fn the_outcome_line_is_one_json_object_built_from_the_words() {
        assert_eq!(
            outcome_line(Outcome::Declined, Some(&id())),
            format!(r#"{{"id":"{}","outcome":"declined","type":"outcome"}}"#, id())
        );
        assert_eq!(
            outcome_line(Outcome::Refused(Class::TryLater), None),
            r#"{"outcome":"refused","reason":"try-later","type":"outcome"}"#
        );
        assert!(outcome_line(Outcome::Done { rc: 2 }, None).contains(r#""rc":2"#));
        assert_eq!(ModelResult::model_error("no")["isError"], true);
    }

    #[test]
    fn failed_is_its_own_word_with_its_own_text_and_nothing_of_the_services() {
        let r = map(&line("failed", ""), &[]);
        assert_eq!(r.outcome, Outcome::Failed);
        assert!(r.is_error);
        assert_eq!(r.texts.len(), 2);
        let first: Value = serde_json::from_str(&r.texts[0]).unwrap();
        assert_eq!((first["outcome"].clone(), first["id"].clone()), (json!("failed"), json!(id().as_str())));
        assert!(first.get("reason").is_none() && first.get("rc").is_none());
        assert_eq!(r.texts[1], FAILED_TEXT);
        // The text says what the model must do, and what it must not.
        for needed in [
            "did not complete",
            "no result",
            "something may have happened",
            "Do not repeat it blindly",
            "find out what happened first",
            "audit lines",
            "identifier",
        ] {
            assert!(FAILED_TEXT.contains(needed), "{needed}");
        }
        // Not `unavailable` (nothing was done) and not `unknown` (only `pact` says that).
        assert_ne!(r.outcome, Outcome::Unavailable);
        assert!(!FAILED_TEXT.contains("trying again is safe") && !FAILED_TEXT.contains("not known"));
        // What a service adds to it (a reason, a code, a cause, further texts) never reaches the model.
        let r =
            map(&line("failed", r#","reason":"disk-on-fire","rc":9,"cause":"secret""#), &["detail from the service"]);
        assert_eq!(r.outcome, Outcome::Failed);
        let shown = r.texts.concat();
        assert!(
            !shown.contains("disk-on-fire")
                && !shown.contains("secret")
                && !shown.contains("detail from the service")
                && !shown.contains("\"rc\""),
            "{shown}"
        );
        assert_eq!(
            outcome_line(Outcome::Failed, Some(&id())),
            format!(r#"{{"id":"{}","outcome":"failed","type":"outcome"}}"#, id())
        );
        // The outcome word of another call is not this call's failure.
        let other =
            format!(r#"{{"type":"outcome","outcome":"failed","id":"{}"}}"#, "3f2b6c1e-8a57-4d0e-9b1a-5c2e7d9f0a12");
        assert_eq!(map(&other, &[]).outcome, Outcome::Unknown);
    }
}
