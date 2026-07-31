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
// at all — exercises tier 2. Both use identical, deliberately benign text;
// with a "Known" source grade this is enough on its own to escalate a
// fresh session from Clean to Elevated via classify_response's structural
// signal (see provenance::compute_new_state) — no rules.yaml pattern hit
// is needed to exercise the injection path, which keeps the fixture simple
// and isolates "did an escalation happen" from "did a rule fire."

use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

const BENIGN_TEXT: &str = "Standard reply text with nothing unusual in it.";

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
                    "result": { "tools": [tier1_tool_definition(), tier2_tool_definition()] }
                })
            }),
            "tools/call" => id.map(|id| {
                let name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let result = match name {
                    "tier1_tool" => json!({
                        "content": [{"type": "text", "text": BENIGN_TEXT}],
                        "structuredContent": {"content": BENIGN_TEXT}
                    }),
                    "tier2_tool" => json!({
                        "content": [{"type": "text", "text": BENIGN_TEXT}]
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
