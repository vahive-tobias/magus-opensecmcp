// src/schema_check.rs
//
// A deliberately NARROW structural conformance check against a tool's
// declared `outputSchema` — not a general-purpose JSON Schema validator.
//
// A real JSON Schema validator (the `jsonschema` crate, most notably) pulls
// in URL/IDNA parsing and numeric-precision handling to support `$ref`
// resolution against remote URIs and the full `format`/numeric-constraint
// vocabulary — real machinery, but built for a much bigger problem than
// "does this response roughly have the shape this tool promised," and it
// does not compile under the same edition2024-constrained toolchain
// documented in the README for exactly the reason blake3 and friends are
// pinned. More importantly: MCP tool output schemas are self-contained
// structural descriptions in practice, not multi-document schemas with
// external references, so the machinery a full validator exists for is
// mostly unused weight here anyway.
//
// What this DOES check, recursively:
//   - `type` (including an array of allowed types, e.g. `["string","null"]`)
//   - `required` (object key presence)
//   - `properties` (recurses into each property present in the data)
//   - `items` (recurses into each array element against one shared schema)
//   - `enum` (literal value membership)
//   - `additionalProperties: false` (rejects object keys not in `properties`)
//
// What this explicitly does NOT check — a violation here does not mean
// full JSON Schema conformance, only that nothing in the above list failed:
//   `$ref`, `oneOf`/`anyOf`/`allOf`/`not`, `format`, `pattern`,
//   `minimum`/`maximum` and other numeric constraints, `minLength`/
//   `maxLength`, `minItems`/`maxItems`, `uniqueItems`, `const`,
//   `if`/`then`/`else`, `dependentRequired`. `pattern` support would be a
//   natural, cheap follow-up given `regex` is already a dependency with the
//   size-bounded compilation this module would want to reuse — not done
//   here, to keep this change reviewable as one thing at a time.
//
// The schema argument is not fully trusted input: it comes from a tool
// definition that may not be hash-pinned yet (see hasher.rs — a
// first-seen tool has no pin to check against). A malicious or careless
// downstream server could hand this module a pathologically deep schema
// hoping to blow the stack; recursion is depth-bounded the same way
// hasher.rs already bounds its own canonicalization recursion, for the same
// reason.

use serde_json::Value;

const MAX_SCHEMA_CHECK_DEPTH: u32 = 64;

/// Checks whether `data` structurally conforms to `schema`, per the subset
/// of JSON Schema described in this module's header comment. Fails CLOSED
/// (returns `false`) on a schema deep enough to hit `MAX_SCHEMA_CHECK_DEPTH`
/// — if conformance can't be fully verified, it isn't treated as verified.
pub fn conforms(schema: &Value, data: &Value) -> bool {
    check_rec(schema, data, 0)
}

fn check_rec(schema: &Value, data: &Value, depth: u32) -> bool {
    if depth > MAX_SCHEMA_CHECK_DEPTH {
        return false;
    }

    let schema_obj = match schema {
        Value::Object(o) => o,
        // JSON Schema permits a bare boolean as a whole schema: `true`
        // accepts anything, `false` accepts nothing.
        Value::Bool(b) => return *b,
        _ => return false,
    };

    if let Some(type_val) = schema_obj.get("type") {
        if !check_type(type_val, data) {
            return false;
        }
    }

    if let Some(Value::Array(allowed)) = schema_obj.get("enum") {
        if !allowed.contains(data) {
            return false;
        }
    }

    match data {
        Value::Object(data_obj) => {
            if let Some(Value::Array(required)) = schema_obj.get("required") {
                for req in required {
                    if let Value::String(key) = req {
                        if !data_obj.contains_key(key) {
                            return false;
                        }
                    }
                }
            }

            let properties = schema_obj.get("properties").and_then(|p| p.as_object());
            if let Some(props) = properties {
                for (key, sub_schema) in props {
                    if let Some(sub_data) = data_obj.get(key) {
                        if !check_rec(sub_schema, sub_data, depth + 1) {
                            return false;
                        }
                    }
                }
            }

            if schema_obj.get("additionalProperties") == Some(&Value::Bool(false)) {
                let allowed_keys: std::collections::HashSet<&str> = properties
                    .map(|p| p.keys().map(String::as_str).collect())
                    .unwrap_or_default();
                for key in data_obj.keys() {
                    if !allowed_keys.contains(key.as_str()) {
                        return false;
                    }
                }
            }
        }
        Value::Array(data_arr) => {
            if let Some(items_schema) = schema_obj.get("items") {
                for item in data_arr {
                    if !check_rec(items_schema, item, depth + 1) {
                        return false;
                    }
                }
            }
        }
        _ => {}
    }

    true
}

fn check_type(type_val: &Value, data: &Value) -> bool {
    match type_val {
        Value::String(t) => type_matches(t, data),
        Value::Array(types) => types
            .iter()
            .any(|t| matches!(t, Value::String(s) if type_matches(s, data))),
        // A malformed `type` keyword is a problem with the SCHEMA, not
        // grounds to fail the data — we're checking conformance, not
        // validating that the schema is itself well-formed JSON Schema.
        _ => true,
    }
}

fn type_matches(type_name: &str, data: &Value) -> bool {
    match type_name {
        "object" => data.is_object(),
        "array" => data.is_array(),
        "string" => data.is_string(),
        "number" => data.is_number(),
        "integer" => data.is_i64() || data.is_u64() || data.as_f64().is_some_and(|f| f.fract() == 0.0),
        "boolean" => data.is_boolean(),
        "null" => data.is_null(),
        // Unknown type keyword: not our call to make, don't fail on it.
        _ => true,
    }
}

/// Discovery-time sanity check, not enforcement: per the MCP 2025-06-18
/// spec, a tool's `outputSchema` root must be `type: "object"`. A tool that
/// gets this wrong isn't necessarily malicious — it's just non-compliant —
/// so this is surfaced as a warning at startup (see main.rs) rather than
/// treated as a signature hit or a reason to withhold the tool.
pub fn root_is_object_type(schema: &Value) -> bool {
    schema.get("type").and_then(|t| t.as_str()) == Some("object")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn simple_object_conforms() {
        let schema = json!({
            "type": "object",
            "properties": { "balance": { "type": "number" } },
            "required": ["balance"]
        });
        assert!(conforms(&schema, &json!({ "balance": 42.5 })));
    }

    #[test]
    fn missing_required_field_violates() {
        let schema = json!({
            "type": "object",
            "properties": { "balance": { "type": "number" } },
            "required": ["balance"]
        });
        assert!(!conforms(&schema, &json!({ "not_balance": 1 })));
    }

    #[test]
    fn wrong_property_type_violates() {
        let schema = json!({
            "type": "object",
            "properties": { "balance": { "type": "number" } }
        });
        assert!(!conforms(&schema, &json!({ "balance": "not a number" })));
    }

    #[test]
    fn array_items_checked_recursively() {
        let schema = json!({ "type": "array", "items": { "type": "string" } });
        assert!(conforms(&schema, &json!(["a", "b", "c"])));
        assert!(!conforms(&schema, &json!(["a", 2, "c"])));
    }

    #[test]
    fn additional_properties_false_rejects_extras() {
        let schema = json!({
            "type": "object",
            "properties": { "a": { "type": "string" } },
            "additionalProperties": false
        });
        assert!(conforms(&schema, &json!({ "a": "x" })));
        assert!(!conforms(&schema, &json!({ "a": "x", "b": "unexpected" })));
    }

    #[test]
    fn enum_constraint_enforced() {
        let schema = json!({ "enum": ["low", "medium", "high"] });
        assert!(conforms(&schema, &json!("medium")));
        assert!(!conforms(&schema, &json!("extreme")));
    }

    #[test]
    fn nullable_via_type_array() {
        let schema = json!({ "type": ["string", "null"] });
        assert!(conforms(&schema, &json!("hello")));
        assert!(conforms(&schema, &json!(null)));
        assert!(!conforms(&schema, &json!(42)));
    }

    #[test]
    fn pathologically_deep_schema_fails_closed() {
        // Build nesting well past MAX_SCHEMA_CHECK_DEPTH.
        let mut schema = json!({ "type": "string" });
        for _ in 0..(MAX_SCHEMA_CHECK_DEPTH + 10) {
            schema = json!({ "type": "object", "properties": { "x": schema } });
        }
        let mut data = json!("leaf");
        for _ in 0..(MAX_SCHEMA_CHECK_DEPTH + 10) {
            data = json!({ "x": data });
        }
        assert!(!conforms(&schema, &data), "depth beyond the bound must fail closed, not stack overflow");
    }

    #[test]
    fn boolean_schema_true_accepts_anything() {
        assert!(conforms(&json!(true), &json!({ "whatever": [1, 2, 3] })));
    }

    #[test]
    fn root_type_object_check() {
        assert!(root_is_object_type(&json!({ "type": "object" })));
        assert!(!root_is_object_type(&json!({ "type": "string" })));
        assert!(!root_is_object_type(&json!({})));
    }
}
