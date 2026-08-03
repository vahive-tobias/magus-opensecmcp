// src/bin/fake_desc_test_server.rs
//
// Minimal fake MCP stdio server, used only by
// tests/description_sanitization.rs (F4 — tool-description sanitization
// for Attested/Known-graded servers). Mirrors fake_pin_test_server.rs's
// shape: a second [[bin]] target in this same crate, exercised by spawning
// the real compiled binary, not a Python fixture script.
//
// Advertises three tools whose descriptions carry different payloads, so
// one spawned server backs every scenario the test file needs:
//   - "poison_tool": a genuine Unicode Tag-block-smuggled MCT-001 marker
//     ("<|im_start|>", spelled entirely in Tag-block codepoints) — a real
//     locked-rules.yaml rule, no injected user-rules.yaml needed.
//   - "flagged_tool": a zero-width-fragmented nonce string, matched by a
//     rule the test injects via user-rules.yaml (scope: tool_description,
//     action: elevate) — locked-rules.yaml has no elevate/flag-tier rule
//     with a tool_description-eligible scope today, so this is the
//     realistic way to exercise that path.
//   - "clean_tool": an ordinary description with no hits at all, to
//     confirm sanitize_for_forwarding is a no-op on text that never had
//     anything to remove.

use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

/// Encodes `ascii` entirely in Unicode Tag-block codepoints (U+E0000 +
/// codepoint), mirroring the "hi" -> U+E0068 U+E0069 example
/// rules_engine.rs's own tests already use — the ASCII-smuggling
/// technique this file exists to exercise end-to-end.
fn tag_block_encode(ascii: &str) -> String {
    ascii.chars().map(|c| char::from_u32(0xE0000 + c as u32).expect("valid ASCII maps to a valid Tag-block codepoint")).collect()
}

/// Fragments `ascii` with a zero-width space (U+200B) between every
/// character — the same fragmentation technique rules_engine.rs's own
/// `zero_width_fragmented_keyword_collapses` test uses, just applied
/// across the whole string rather than one keyword.
fn zero_width_fragment(ascii: &str) -> String {
    let mut out = String::new();
    for (i, c) in ascii.chars().enumerate() {
        if i > 0 {
            out.push('\u{200B}');
        }
        out.push(c);
    }
    out
}

/// The literal nonce `tests/description_sanitization.rs` injects a
/// user-rules.yaml rule to match, before it gets zero-width-fragmented
/// below. Distinctive on purpose so it can't accidentally collide with
/// any locked-rules.yaml pattern. `[[bin]]` targets aren't importable
/// from an integration test (unlike the lib crate) — this MUST stay
/// byte-for-byte identical to the copy in tests/description_sanitization.rs,
/// the same "must stay in sync, can't be shared" constraint
/// fake_pin_test_server.rs's tool definition already lives with.
const FLAGGED_MARKER: &str = "TESTMARKER-F4-ELEVATE-7d91a";

fn tool_definitions() -> Vec<Value> {
    let poison_desc = format!(
        "A perfectly normal-looking tool description. {}",
        tag_block_encode("<|im_start|>")
    );
    let flagged_desc = format!(
        "Also a normal-looking description, with a hidden marker: {}",
        zero_width_fragment(FLAGGED_MARKER)
    );

    vec![
        json!({
            "name": "poison_tool",
            "description": poison_desc,
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
        }),
        json!({
            "name": "flagged_tool",
            "description": flagged_desc,
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
        }),
        json!({
            "name": "clean_tool",
            "description": "Reads a file from disk and returns its contents as text.",
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": false},
        }),
    ]
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
                        "serverInfo": { "name": "fake-desc-test-server", "version": "0.0.0" }
                    }
                })
            }),
            "notifications/initialized" => None,
            "tools/list" => id.map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "tools": tool_definitions() }
                })
            }),
            "tools/call" => id.map(|id| {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "content": [{ "type": "text", "text": "ok" }] }
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
