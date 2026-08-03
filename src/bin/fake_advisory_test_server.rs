// src/bin/fake_advisory_test_server.rs
//
// Minimal fake MCP stdio server for tests/sec01_advisory.rs (SEC-01).
// Exposes two fixed-response tools so the test can exercise both tiers of
// the advisory-injection fallback ordering against the real compiled
// magus-gateway binary, without any external interpreter dependency —
// same rationale as fake_pin_test_server.rs (SEC-03).
//
// "tier1_tool" returns a response with BOTH content[] and a string
// structuredContent.content (matching the real filesystem server's actual
// shape, verified byte-for-byte during the OP-1 experiments) — exercises
// tier 1. "tier2_tool" returns content[] text only, no structuredContent
// at all — exercises tier 2. Both use identical, deliberately benign but
// long text (LONG_BENIGN_TEXT); with a "Known" source grade, a long string
// is what escalates a fresh session from Clean to Elevated via
// classify_response's structural signal (see provenance::compute_new_state)
// — no rules.yaml pattern hit is needed to exercise the injection path,
// which keeps the fixture simple and isolates "did an escalation happen"
// from "did a rule fire." A third tool, "tiny_tool", returns a short benign
// reply (SHORT_BENIGN_TEXT) specifically to exercise the opposite case: a
// short response from a Known server must NOT escalate post-C1-fix (see
// docs/specs/spec-c1-provenance-trap-fix.md) — this fixture's original
// short-text premise was only true because of that bug.

use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

const LONG_BENIGN_TEXT: &str = "Standard reply text with nothing unusual in it. This response is deliberately verbose so the structural response-shape classifier treats it as substantial content rather than a short, trivial reply, which is exactly the condition this fixture exists to exercise.";
const SHORT_BENIGN_TEXT: &str = "Standard reply text with nothing unusual in it.";

fn tier1_tool_definition() -> Value {
    json!({
        "name": "tier1_tool",
        "description": "Returns a response with a string structuredContent.content.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
    })
}

fn tier2_tool_definition() -> Value {
    json!({
        "name": "tier2_tool",
        "description": "Returns a response with content[] text only, no structuredContent.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
    })
}

fn tiny_tool_definition() -> Value {
    json!({
        "name": "tiny_tool",
        "description": "Returns a short content[] text reply, well under the long-string threshold.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
    })
}

fn main() {
    let stdin = io::stdin();
    let mut stdout = io::stdout();

    for line in stdin.lock().lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }

        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let method = msg.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = msg.get("id").cloned();
        let params = msg.get("params").cloned().unwrap_or_else(|| json!({}));

        let response: Option<Value> = match method {
            "initialize" => id.map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "fake-advisory-test-server", "version": "0.0.0" }
                    }
                })
            }),
            "notifications/initialized" => None,
            "tools/list" => id.map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "tools": [tier1_tool_definition(), tier2_tool_definition(), tiny_tool_definition()] }
                })
            }),
            "tools/call" => id.map(|id| {
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let result = match name {
                    "tier1_tool" => json!({
                        "content": [{"type": "text", "text": LONG_BENIGN_TEXT}],
                        "structuredContent": {"content": LONG_BENIGN_TEXT}
                    }),
                    "tier2_tool" => json!({
                        "content": [{"type": "text", "text": LONG_BENIGN_TEXT}]
                    }),
                    "tiny_tool" => json!({
                        "content": [{"type": "text", "text": SHORT_BENIGN_TEXT}]
                    }),
                    _ => json!({"content": [{"type": "text", "text": "unknown tool"}]}),
                };
                json!({"jsonrpc": "2.0", "id": id, "result": result})
            }),
            _ => None,
        };

        if let Some(resp) = response {
            let out = serde_json::to_string(&resp).unwrap() + "\n";
            let _ = stdout.write_all(out.as_bytes());
            let _ = stdout.flush();
        }
    }
}
