// src/bin/fake_pin_test_server.rs
//
// Minimal fake MCP stdio server, used only by tests/pin_enforcement.rs
// (SEC-03/OP-2). For a fake downstream server to test hash-pin enforcement
// against, the spec explicitly steers away from a Python fixture script
// (that would add an external interpreter dependency to CI that doesn't
// otherwise exist) — this is a second [[bin]] target in this same crate
// instead, staying entirely within the Rust toolchain the project already
// requires to build at all. See
// docs/specs/spec-sec03-hash-pin-enforcement.md's Testing section.
//
// Advertises exactly one tool, "ping", with a fixed definition. The test
// computes that definition's hash directly via magus_opensecmcp::hasher
// (using the identical name/description/inputSchema below) to derive a
// correct pin and a deliberately-wrong one, rather than hardcoding a hash
// literal here that would silently go stale the moment this file's tool
// definition changes.

use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

fn tool_definition() -> Value {
    json!({
        "name": "ping",
        "description": "Replies pong for connectivity testing.",
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

        let response: Option<Value> = match method {
            "initialize" => id.map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "fake-pin-test-server", "version": "0.0.0" }
                    }
                })
            }),
            "notifications/initialized" => None,
            "tools/list" => id.map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "tools": [tool_definition()] }
                })
            }),
            "tools/call" => id.map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "content": [{ "type": "text", "text": "pong" }] }
                })
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
