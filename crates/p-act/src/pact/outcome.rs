//! What the model is told: the closed list `done`, `declined`, `expired`,
//! `refused` (with its class), `unavailable`, `failed`, `unknown`. Only words from this
//! list ever reach the model; nothing a service or a transport said is copied.

use super::transport::TransportError;
use crate::call::CallId;
use serde_json::{Value, json};

/// A verb's answer is passed on up to this many bytes of text.
pub const MAX_ANSWER_TEXT: usize = 1024 * 1024;

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

/// The tool result for the model: text contents, and `isError`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelResult {
    pub outcome: Outcome,
    pub texts: Vec<String>,
    pub is_error: bool,
}

impl ModelResult {
    /// The MCP `tools/call` result.
    #[must_use]
    pub fn to_mcp(&self) -> Value {
        let content: Vec<Value> = self.texts.iter().map(|t| json!({"type": "text", "text": t})).collect();
        json!({"content": content, "isError": self.is_error})
    }

    /// A result that is an error of the model's, said plainly. Not an outcome.
    #[must_use]
    pub fn model_error(message: &str) -> Value {
        json!({"content": [{"type": "text", "text": message}], "isError": true})
    }
}

/// The first text of every result: one JSON object on one line, built here from the closed words.
#[must_use]
pub fn outcome_line(outcome: Outcome, id: Option<&CallId>) -> String {
    let mut o = serde_json::Map::new();
    o.insert("type".into(), json!("outcome"));
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
    ModelResult { outcome, texts, is_error }
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
    let Some(content) = response.get("result").and_then(|r| r.get("content")).and_then(Value::as_array) else {
        return unknown("no content");
    };
    let texts: Vec<&str> = content
        .iter()
        .filter(|c| c.get("type").and_then(Value::as_str) == Some("text"))
        .filter_map(|c| c.get("text").and_then(Value::as_str))
        .collect();
    let Some(first) = texts.first() else { return unknown("no text") };
    let Ok(Value::Object(line)) = serde_json::from_str::<Value>(first) else {
        return unknown("the first text is not an object");
    };
    let word = |k: &str| line.get(k).and_then(Value::as_str);
    if word("type") != Some("outcome") || word("id") != Some(id.as_str()) {
        return unknown("not an outcome for this call");
    }
    let mut log = None;
    let outcome = match word("outcome") {
        Some("done") => match line.get("rc").and_then(Value::as_i64) {
            Some(rc) => Outcome::Done { rc },
            None => return unknown("done without rc"),
        },
        Some("declined") => Outcome::Declined,
        Some("expired") => Outcome::Expired,
        Some("unavailable") => Outcome::Unavailable,
        // Whatever else the service puts in it (a reason, a detail) is not passed on: the cause is in its own log.
        Some("failed") => Outcome::Failed,
        Some("refused") => match word("reason").and_then(Class::from_word) {
            Some(c) => Outcome::Refused(c),
            None => {
                log = Some("refused with a reason outside the list".to_owned());
                Outcome::Refused(Class::NotAllowed)
            }
        },
        _ => return unknown("an outcome outside the list"),
    };
    let answer: Vec<String> = if matches!(outcome, Outcome::Done { .. }) {
        texts[1..].iter().map(|t| (*t).to_owned()).collect()
    } else {
        vec![]
    };
    if answer.iter().map(String::len).sum::<usize>() > MAX_ANSWER_TEXT {
        return unknown("the answer is longer than the limit");
    }
    (result(outcome, Some(id), answer), log)
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
