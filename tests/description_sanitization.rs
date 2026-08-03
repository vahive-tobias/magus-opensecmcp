// tests/description_sanitization.rs
//
// End-to-end tests for F4 (tool-description sanitization for Attested/Known
// source grades). Spawns the real compiled magus-gateway binary against a
// real spawned downstream process (fake_desc_test_server, a second [[bin]]
// target in this crate — see src/bin/fake_desc_test_server.rs), matching
// the pattern tests/pin_enforcement.rs already established: exercise the
// compiled artifact and the ACTUAL tools/list response text, not an
// internal function call.
//
// The finding: sanitize_description previously called strip_formatting (a
// bespoke angle-bracket stripper) for Attested/Known descriptions, entirely
// bypassing rules_engine's real anti-smuggling machinery
// (normalize_for_matching's decode_unicode_tags/strip_zero_width) for what
// actually gets FORWARDED — the detection-time scan ran but only produced a
// console warning. A Known-graded server could smuggle an instruction into
// its own tool description via Tag-block or zero-width-fragmented text and
// have it reach the agent completely unfiltered. See F4 in
// docs/specs/Adversarial Review magus-opensecmcp.md.

use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Must stay byte-for-byte identical to the same constant in
/// src/bin/fake_desc_test_server.rs — [[bin]] targets aren't importable
/// from an integration test, the same constraint fake_pin_test_server.rs's
/// tool definition already lives with (see tests/pin_enforcement.rs).
const FLAGGED_MARKER: &str = "TESTMARKER-F4-ELEVATE-7d91a";

/// Mirrors fake_desc_test_server.rs's own encoding exactly, so this test
/// file can assert on both the smuggled form (must be ABSENT from the real
/// response) and the plain-text form (must also be absent for poison_tool,
/// present but defragmented for flagged_tool).
fn tag_block_encode(ascii: &str) -> String {
    ascii.chars().map(|c| char::from_u32(0xE0000 + c as u32).unwrap()).collect()
}

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

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("magus_desc_test_{label}_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("failed to create temp test dir");
        TempDir(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `strict_description_scanning` and an optional `user-rules.yaml` (for the
/// flagged_tool elevate-tier scenario, which has no matching locked rule —
/// see fake_desc_test_server.rs's module comment for why) are the two
/// pieces of test-specific config; everything else about the fake server
/// (three fixed tools) is constant across every test in this file.
fn write_config(dir: &Path, strict_description_scanning: bool, user_rules: Option<&str>) -> PathBuf {
    let server_cmd = env!("CARGO_BIN_EXE_fake_desc_test_server");
    let config = format!(
        "downstream_servers:\n\
         \x20\x20- server_id: \"fake\"\n\
         \x20\x20\x20\x20transport: \"stdio\"\n\
         \x20\x20\x20\x20command: '{server_cmd}'\n\
         \x20\x20\x20\x20args: []\n\
         \x20\x20\x20\x20source_grade: \"Known\"\n\
         \n\
         tools:\n\
         \x20\x20- mcp_server_id: \"fake\"\n\
         \x20\x20\x20\x20tool_name: \"poison_tool\"\n\
         \x20\x20\x20\x20risk_class: \"Low\"\n\
         \x20\x20\x20\x20authority_source: \"User\"\n\
         \x20\x20- mcp_server_id: \"fake\"\n\
         \x20\x20\x20\x20tool_name: \"flagged_tool\"\n\
         \x20\x20\x20\x20risk_class: \"Low\"\n\
         \x20\x20\x20\x20authority_source: \"User\"\n\
         \x20\x20- mcp_server_id: \"fake\"\n\
         \x20\x20\x20\x20tool_name: \"clean_tool\"\n\
         \x20\x20\x20\x20risk_class: \"Low\"\n\
         \x20\x20\x20\x20authority_source: \"User\"\n\
         \n\
         security_policy:\n\
         \x20\x20strict_description_scanning: {strict_description_scanning}\n"
    );
    let path = dir.join("config.yaml");
    std::fs::write(&path, config).expect("failed to write test config.yaml");

    if let Some(rules) = user_rules {
        std::fs::write(dir.join("user-rules.yaml"), rules).expect("failed to write test user-rules.yaml");
    }

    path
}

/// A rule with no locked-rules.yaml equivalent today: elevate-tier,
/// tool_description-scoped. Needed because every current locked
/// description-eligible rule (MCT-*, scope: any) is poison-tier — see
/// fake_desc_test_server.rs's module comment.
fn elevate_tier_description_rule() -> String {
    format!(
        "rules:\n\
         \x20\x20- id: TEST-DESC-ELEVATE-001\n\
         \x20\x20\x20\x20category: test\n\
         \x20\x20\x20\x20severity: high\n\
         \x20\x20\x20\x20match: {{ type: literal, pattern: \"{FLAGGED_MARKER}\" }}\n\
         \x20\x20\x20\x20scope: tool_description\n\
         \x20\x20\x20\x20action: elevate\n"
    )
}

fn jsonrpc_lines(call_tool: Option<&str>) -> Vec<String> {
    let mut lines = vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0.1"}}}).to_string(),
        json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}).to_string(),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}).to_string(),
    ];
    if let Some(name) = call_tool {
        lines.push(json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":name,"arguments":{}}}).to_string());
    }
    lines
}

fn run_gateway(config_path: &Path, stdin_lines: &[String]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_magus-gateway"))
        .arg(config_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn the compiled magus-gateway binary");

    {
        let stdin = child.stdin.as_mut().expect("child stdin");
        for line in stdin_lines {
            writeln!(stdin, "{line}").expect("failed writing to child stdin");
        }
    }

    child.wait_with_output().expect("failed to wait on magus-gateway")
}

fn parse_responses(stdout: &[u8]) -> Vec<Value> {
    String::from_utf8_lossy(stdout)
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("non-JSON line from gateway stdout: {l:?}: {e}")))
        .collect()
}

fn find_response(responses: &[Value], id: i64) -> &Value {
    responses
        .iter()
        .find(|r| r.get("id") == Some(&json!(id)))
        .unwrap_or_else(|| panic!("no response with id {id} in: {responses:?}"))
}

fn tool_description<'a>(tools_list_response: &'a Value, name: &str) -> &'a str {
    tools_list_response["result"]["tools"]
        .as_array()
        .expect("tools/list result must have a tools array")
        .iter()
        .find(|t| t["name"] == name)
        .unwrap_or_else(|| panic!("tool {name:?} not found in tools/list response: {tools_list_response:?}"))
        ["description"]
        .as_str()
        .expect("description must be a string")
}

fn tool_names(tools_list_response: &Value) -> Vec<String> {
    tools_list_response["result"]["tools"]
        .as_array()
        .expect("tools/list result must have a tools array")
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect()
}

/// THE required regression test: a Known-graded server's tool description
/// carries a genuine Tag-block-smuggled MCT-001 marker ("<|im_start|>",
/// spelled entirely in Tag-block codepoints, decoded only by
/// normalize_for_matching's detection-side pass). Asserted against the
/// ACTUAL tools/list response text — not sanitize_description called
/// directly — that the payload is absent in BOTH forms: the raw
/// Tag-block bytes (never decoded for forwarding) and the decoded plain
/// ASCII (never revealed either, since the whole description is withheld
/// on a poison-tier hit). Before this fix, sanitize_description called
/// strip_formatting alone, which has nothing to do with Tag-block
/// handling at all — the smuggled marker would have reached this exact
/// response field, in the decoded, fully readable form, because
/// strip_formatting's angle-bracket-only stripping is not tag-block-aware.
#[test]
fn poison_tier_smuggled_payload_is_absent_from_the_real_response_in_any_form() {
    let dir = TempDir::new("poison");
    let config = write_config(dir.path(), false, None);

    let output = run_gateway(&config, &jsonrpc_lines(Some("poison_tool")));
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let responses = parse_responses(&output.stdout);
    let tools_list = find_response(&responses, 2);
    let desc = tool_description(tools_list, "poison_tool");

    let raw_smuggled = tag_block_encode("<|im_start|>");
    assert!(
        !desc.contains(&raw_smuggled),
        "the raw Tag-block-encoded payload must never reach the response, got: {desc:?}"
    );
    assert!(
        !desc.contains("<|im_start|>"),
        "the DECODED payload must not reach the response either — poison withholds the whole \
         description, it does not forward a cleaned-but-revealed version, got: {desc:?}"
    );
    assert!(
        desc.contains("withheld"),
        "expected the withholding message for a poison-tier description hit, got: {desc:?}"
    );

    // Name and schema still visible, tool still fully callable — this is
    // the existing Unvalidated/Suspicious withholding shape, NOT SEC-03's
    // quarantine shape (full removal from tools/list).
    let names = tool_names(tools_list);
    assert!(names.contains(&"poison_tool".to_string()), "the tool itself must still appear in tools/list, got: {names:?}");
    let call = find_response(&responses, 3);
    assert!(call.get("error").is_none(), "a poison-tier description hit must not block the tool from being called, got: {call:?}");
}

/// Elevate/flag-tier hit, non-strict (the default): sanitized for
/// forwarding, NOT withheld. The zero-width-fragmented marker must have
/// its fragmenting characters removed (so it doesn't survive as a
/// fragmented, matcher-evading string) but the readable text itself
/// still reaches the response — this is the "sanitize and warn," not
/// "withhold," path.
#[test]
fn elevate_tier_hit_sanitizes_but_does_not_withhold_by_default() {
    let dir = TempDir::new("elevate_nonstrict");
    let config = write_config(dir.path(), false, Some(&elevate_tier_description_rule()));

    let output = run_gateway(&config, &jsonrpc_lines(None));
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let responses = parse_responses(&output.stdout);
    let desc = tool_description(find_response(&responses, 2), "flagged_tool");

    let fragmented = zero_width_fragment(FLAGGED_MARKER);
    assert!(!desc.contains(&fragmented), "the zero-width-fragmented form must not survive, got: {desc:?}");
    assert!(!desc.contains('\u{200B}'), "no zero-width characters at all should remain, got: {desc:?}");
    assert!(
        desc.contains(FLAGGED_MARKER),
        "the defragmented, readable marker text SHOULD still reach the response in non-strict mode \
         (sanitize, not withhold), got: {desc:?}"
    );
    assert!(!desc.contains("withheld"), "non-strict mode must not withhold an elevate-tier hit, got: {desc:?}");
}

/// Same hit, same tool, `strict_description_scanning: true` this time —
/// the escalation toggle. Only the strictness flag differs from the test
/// above; everything else about the scenario is identical.
#[test]
fn elevate_tier_hit_withholds_under_strict_description_scanning() {
    let dir = TempDir::new("elevate_strict");
    let config = write_config(dir.path(), true, Some(&elevate_tier_description_rule()));

    let output = run_gateway(&config, &jsonrpc_lines(None));
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let responses = parse_responses(&output.stdout);
    let desc = tool_description(find_response(&responses, 2), "flagged_tool");

    assert!(
        !desc.contains(FLAGGED_MARKER),
        "under strict_description_scanning, the marker text must not reach the response at all, got: {desc:?}"
    );
    assert!(desc.contains("withheld"), "expected the withholding message under strict mode, got: {desc:?}");
}

/// An ordinary description with nothing to remove must pass through
/// sanitize_for_forwarding unchanged — confirming the new pipeline isn't
/// over-aggressive against legitimate text.
#[test]
fn clean_description_passes_through_unaffected() {
    let dir = TempDir::new("clean");
    let config = write_config(dir.path(), false, None);

    let output = run_gateway(&config, &jsonrpc_lines(None));
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let responses = parse_responses(&output.stdout);
    let desc = tool_description(find_response(&responses, 2), "clean_tool");
    assert_eq!(desc, "Reads a file from disk and returns its contents as text.");
}
