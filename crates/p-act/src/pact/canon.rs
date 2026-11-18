//! JSON that `pact` writes from a `serde_json::Value`, with its members in one order whatever `serde_json`'s
//! features are: sorted by key, at every depth. `serde_json::Map` is sorted only without its `preserve_order`
//! feature, which any crate of a build can switch on for everyone; text that comes out of a `Value` must not
//! depend on that. (The signed documents and the exchange's messages are written from structs, whose field order
//! is fixed by the code: see the report on member order.)

use serde_json::{Map, Value};

/// `value` with every object's members sorted by key. Arrays keep their order.
#[must_use]
pub fn sorted(value: &Value) -> Value {
    match value {
        Value::Object(members) => {
            let mut entries: Vec<(&String, &Value)> = members.iter().collect();
            entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
            // Inserting in sorted order gives a sorted map with or without `preserve_order`.
            let mut out = Map::new();
            for (key, member) in entries {
                out.insert(key.clone(), sorted(member));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// The compact text of `value`, members sorted.
#[must_use]
pub fn line(value: &Value) -> String {
    sorted(value).to_string()
}

/// The compact bytes of `value`, members sorted.
#[must_use]
pub fn bytes(value: &Value) -> Vec<u8> {
    line(value).into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn members_are_sorted_at_every_depth_and_arrays_keep_their_order() {
        let v = json!({"b": 1, "a": {"z": [3, 1, {"y": 1, "x": 2}], "c": null}, "A": true});
        assert_eq!(line(&v), r#"{"A":true,"a":{"c":null,"z":[3,1,{"x":2,"y":1}]},"b":1}"#);
        assert_eq!(bytes(&v), line(&v).into_bytes());
        assert_eq!(line(&json!([])), "[]");
        assert_eq!(line(&json!("x")), "\"x\"");
        // The same value built in another order gives the same text.
        let mut m = Map::new();
        m.insert("z".into(), json!(1));
        m.insert("a".into(), json!(2));
        assert_eq!(line(&Value::Object(m)), r#"{"a":2,"z":1}"#);
    }

    #[cfg(feature = "guard-preserve-order")]
    #[test]
    fn the_guard_really_has_preserve_order_on() {
        // With `serde_json`'s `preserve_order` a map keeps insertion order; this is what the guard feature is for.
        assert_eq!(json!({"b": 1, "a": 2}).to_string(), r#"{"b":1,"a":2}"#);
        // And the text this module writes does not care.
        assert_eq!(line(&json!({"b": 1, "a": 2})), r#"{"a":2,"b":1}"#);
    }
}
