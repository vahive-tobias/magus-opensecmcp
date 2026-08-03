// src/bin/fake_hang_test_server.rs
//
// Fake MCP stdio server for F5 (downstream timeout enforcement — see
// docs/specs/Adversarial Review magus-opensecmcp.md). The only fake server
// in this crate built to genuinely never respond to certain requests,
// rather than respond with a wrong/malformed answer — none of the
// existing fixtures (fake_pin_test_server.rs, fake_desc_test_server.rs)
// can be made to hang on command. Mirrors their shape: a real compiled
// [[bin]] target, spawned as a real child process and genuinely blocked,
// not a simulated delay.
//
// Normal mode (no arguments) responds to initialize/tools/list
// immediately and advertises two tools:
//   - "quick_tool": responds immediately, for confirming an ordinary call
//     is completely unaffected by this fix.
//   - "hang_tool": receives the request and then genuinely never
//     responds — no reply is ever written. This is a real hang, not a
//     simulated one: this process blocks reading its own stdin for the
//     next line, which the gateway (one request in flight at a time)
//     never sends while it's still waiting on this response, so both
//     sides are genuinely stuck until the gateway's timeout fires and it
//     gives up (dropping the connection, which kills this process via
//     kill_on_drop).
//
// --hang-on-initialize mode never responds to the FIRST request at all
// (initialize itself), simulating a server wedged before the MCP
// handshake even completes — for the discovery-time timeout scenarios.

use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

fn quick_tool_definition() -> Value {
    json!({
        "name": "quick_tool",
        "description": "Responds immediately.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
    })
}

fn hang_tool_definition() -> Value {
    json!({
        "name": "hang_tool",
        "description": "Never responds, on purpose.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
    })
}

fn main() {
    let hang_on_initialize = std::env::args().any(|a| a == "--hang-on-initialize");

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
            "initialize" if hang_on_initialize => None, // never respond — see module doc comment
            "initialize" => id.map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": { "tools": {} },
                        "serverInfo": { "name": "fake-hang-test-server", "version": "0.0.0" }
                    }
                })
            }),
            "notifications/initialized" => None,
            "tools/list" => id.map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "tools": [quick_tool_definition(), hang_tool_definition()] }
                })
            }),
            "tools/call" => {
                let name = msg.get("params").and_then(|p| p.get("name")).and_then(|n| n.as_str()).unwrap_or("");
                if name == "hang_tool" {
                    None // never respond — see module doc comment
                } else {
                    id.map(|id| json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": { "content": [{ "type": "text", "text": "quick" }] }
                    }))
                }
            }
            _ => None,
        };

        if let Some(resp) = response {
            let out = serde_json::to_string(&resp).unwrap() + "\n";
            let _ = stdout.write_all(out.as_bytes());
            let _ = stdout.flush();
        }
    }
}
