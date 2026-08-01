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
//   - `pattern` (string values only — see below for dialect and bounds)
//
// What this explicitly does NOT check — a violation here does not mean
// full JSON Schema conformance, only that nothing in the above list failed:
//   `$ref`, `oneOf`/`anyOf`/`allOf`/`not`, `format`,
//   `minimum`/`maximum` and other numeric constraints, `minLength`/
//   `maxLength`, `minItems`/`maxItems`, `uniqueItems`, `const`,
//   `if`/`then`/`else`, `dependentRequired`.
//
// `pattern` dialect: JSON Schema specifies `pattern` against ECMA 262 regex
// syntax. Rust's `regex` crate is not ECMA 262 — no backreferences, no
// lookaround. This is the identical tradeoff `rules_engine.rs` already made
// and documented for `locked-rules.yaml`/`user-rules.yaml` patterns,
// specifically because the crate's non-backtracking guarantee (finite
// automata, not backtracking) is what makes it safe to compile
// attacker-influenceable patterns at all. A `pattern` using backreferences
// or lookaround fails to compile, and per the fail-closed rule below, the
// node it's on is treated as non-conforming, not silently passed.
//
// `pattern` bounded compilation: a schema's `pattern` value is untrusted
// input for the same reason the rest of this module's argument is (see the
// paragraph below) — `rules_engine.rs` already built the mitigation for
// CVE-2022-24713 (pathological pattern compilation as a real
// resource-exhaustion vector, not hypothetical) for exactly this class of
// problem. This module reuses those same bound *values* (read directly
// from `rules_engine.rs` at the time of this change: `REGEX_SIZE_LIMIT`
// and `REGEX_DFA_SIZE_LIMIT` both `1 << 20`, `MAX_PATTERN_SOURCE_LEN` `500`
// bytes) as its own local constants below — duplicated, not shared, since
// `rules_engine.rs`'s constants are private to that module and this spec's
// scope explicitly excludes modifying `rules_engine.rs` to export them; the
// two modules staying decoupled is a legitimate shape here, not a shortcut.
//
// `pattern` failure handling: a `pattern` that fails to compile — bad
// syntax, or a pattern whose source exceeds `MAX_PATTERN_SOURCE_LEN` or
// whose compiled form exceeds `REGEX_SIZE_LIMIT`/`REGEX_DFA_SIZE_LIMIT` —
// makes `check_rec` return `false` for that node, the same as exceeding
// `MAX_SCHEMA_CHECK_DEPTH` does below. This module's stated philosophy is
// explicit: if conformance can't be fully verified, it isn't treated as
// verified. An uncompilable pattern can't be verified, so it isn't silently
// skipped and treated as passing.
//
// `pattern` compiled-pattern caching: deliberately NOT done. `conforms()`
// is a pure function called fresh per response with no load-once lifecycle
// to hook a cache into (unlike `rules_engine.rs`, where patterns compile
// once at `RuleEngine::load` time because the rules files load once at
// startup). Recompiling a `pattern` regex on every `check_rec` call that
// reaches one is real, repeated work, but this is a local, single-operator
// tool with no profiling or reported slowness suggesting it matters yet —
// noted here as a known, deliberate tradeoff and a real future
// optimization if it ever does, not a gap being silently ignored now.
//
// The schema argument is not fully trusted input: it comes from a tool
// definition that may not be hash-pinned yet (see hasher.rs — a
// first-seen tool has no pin to check against). A malicious or careless
// downstream server could hand this module a pathologically deep schema
// hoping to blow the stack; recursion is depth-bounded the same way
// hasher.rs already bounds its own canonicalization recursion, for the same
// reason.

use regex::RegexBuilder;
use serde_json::Value;

const MAX_SCHEMA_CHECK_DEPTH: u32 = 64;

// Duplicated from rules_engine.rs (REGEX_SIZE_LIMIT, REGEX_DFA_SIZE_LIMIT,
// MAX_PATTERN_SOURCE_LEN), read directly from that file at the time of this
// change, not from memory — see the module header above for why these are
// duplicated locally rather than shared, and CVE-2022-24713 for why the
// bound exists at all. If rules_engine.rs's values ever change, these must
// be re-read and updated to match, not assumed to still agree.
const SCHEMA_PATTERN_SIZE_LIMIT: usize = 1 << 20; // ~1MB compiled-form cap per pattern
const SCHEMA_PATTERN_DFA_SIZE_LIMIT: usize = 1 << 20;
const MAX_SCHEMA_PATTERN_SOURCE_LEN: usize = 500;

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
        Value::String(s) => {
            if let Some(Value::String(pattern)) = schema_obj.get("pattern") {
                if !pattern_matches(pattern, s) {
                    return false;
                }
            }
        }
        _ => {}
    }

    true
}

/// Compiles `pattern` (untrusted — see module header) with the same
/// CVE-2022-24713 mitigation `rules_engine.rs` uses for its own untrusted
/// patterns, then checks whether `value` matches. Fails CLOSED (`false`) on
/// any compilation failure — oversized source, a compiled form exceeding
/// the size/DFA bounds, or plain invalid regex syntax — per this module's
/// stated philosophy: an uncompilable pattern can't be verified, so it
/// isn't treated as passing.
fn pattern_matches(pattern: &str, value: &str) -> bool {
    if pattern.len() > MAX_SCHEMA_PATTERN_SOURCE_LEN {
        return false;
    }
    match RegexBuilder::new(pattern)
        .size_limit(SCHEMA_PATTERN_SIZE_LIMIT)
        .dfa_size_limit(SCHEMA_PATTERN_DFA_SIZE_LIMIT)
        .build()
    {
        Ok(re) => re.is_match(value),
        Err(_) => false,
    }
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
    fn pattern_constraint_enforced() {
        let schema = json!({ "pattern": "^[A-Z]{3}$" });
        assert!(conforms(&schema, &json!("ABC")));
        assert!(!conforms(&schema, &json!("abc")));
        assert!(!conforms(&schema, &json!("AB")));
    }

    #[test]
    fn pattern_ignored_when_data_is_not_a_string() {
        // pattern is string-scoped per JSON Schema — a non-string value
        // doesn't violate it, the same way `items` doesn't apply to an
        // object and `required` doesn't apply to an array.
        let schema = json!({ "pattern": "^[A-Z]{3}$" });
        assert!(conforms(&schema, &json!(42)));
        assert!(conforms(&schema, &json!(null)));
        assert!(conforms(&schema, &json!(["AB", "not checked either"])));
    }

    #[test]
    fn pattern_with_invalid_regex_syntax_fails_closed() {
        // Backreferences aren't valid in the regex crate's (non-ECMA-262)
        // dialect — an uncompilable pattern must fail closed, not be
        // silently skipped and treated as passing.
        let schema = json!({ "pattern": "^(a)\\1$" });
        assert!(!conforms(&schema, &json!("aa")));
    }

    #[test]
    fn pattern_exceeding_compiled_size_limit_fails_closed() {
        // The exact pathological pattern this module's own header (and
        // rules_engine.rs's CVE-2022-24713 mitigation comment) names:
        // nested bounded quantifiers blow up the compiled automaton's size
        // without needing a long source string. Verified directly against
        // this module's actual reused bound (RegexBuilder::size_limit(1 <<
        // 20)) before writing this assertion — this pattern's compiled
        // form measures well over that limit, not assumed to.
        let schema = json!({ "pattern": "a{100}{100}{100}" });
        assert!(!conforms(&schema, &json!("aaa")));
    }

    #[test]
    fn pattern_composes_with_type_string_both_must_pass() {
        let schema = json!({ "type": "string", "pattern": "^[A-Z]{3}$" });
        assert!(conforms(&schema, &json!("ABC")));
        // Wrong type fails on `type` before `pattern` is even relevant.
        assert!(!conforms(&schema, &json!(123)));
        // Right type, wrong pattern — `type` alone isn't enough.
        assert!(!conforms(&schema, &json!("abc")));
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
