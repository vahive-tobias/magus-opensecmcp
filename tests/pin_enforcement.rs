// tests/pin_enforcement.rs
//
// End-to-end tests for SEC-03/OP-2 (hash-pin mismatch enforcement).
// Spawns the real compiled magus-gateway binary against a real spawned
// downstream process (fake_pin_test_server, a second [[bin]] target in this
// crate — see src/bin/fake_pin_test_server.rs for why, instead of a Python
// fixture script) — extending the pattern tests/cli_flags.rs already
// established: exercise the compiled artifact itself, not internal
// functions. See docs/specs/spec-sec03-hash-pin-enforcement.md for the full
// scenario list this covers.
//
// The pure "given this pin status and these flags, quarantine or not"
// decision logic itself is unit-tested directly in src/pin_policy.rs; these
// tests confirm that logic is actually wired into main.rs's discovery loop
// and handle_tools_call for real.

use magus_opensecmcp::hasher::{compute_definition_hash, hash_to_hex, McpToolDefinition};
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

/// Must stay byte-for-byte equal (as JSON values, not text) to the tool
/// definition fake_pin_test_server.rs actually returns from tools/list —
/// the hash is computed from this, not copied from a hardcoded literal.
fn ping_definition() -> McpToolDefinition {
    McpToolDefinition {
        name: "ping".to_string(),
        description: "Replies pong for connectivity testing.".to_string(),
        input_schema: json!({"type": "object", "properties": {}, "additionalProperties": false}),
        output_schema: None,
    }
}

fn correct_pin_hex() -> String {
    hash_to_hex(&compute_definition_hash(&ping_definition()))
}

/// Deliberately wrong by construction (flip the first hex character),
/// mirroring config.yaml's own "move_file's pin is wrong by one character,
/// on purpose" convention rather than a made-up unrelated string.
fn wrong_pin_hex() -> String {
    let mut hex = correct_pin_hex();
    let first_digit = hex.chars().next().unwrap().to_digit(16).unwrap();
    let flipped = std::char::from_digit((first_digit + 1) % 16, 16).unwrap();
    hex.replace_range(0..1, &flipped.to_string());
    hex
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("magus_pin_test_{label}_{}", uuid::Uuid::new_v4()));
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

fn write_config(dir: &Path, tools_block: &str, security_policy_block: &str) -> PathBuf {
    let server_cmd = env!("CARGO_BIN_EXE_fake_pin_test_server");
    let config = format!(
        "downstream_servers:\n\
         \x20\x20- server_id: \"fake\"\n\
         \x20\x20\x20\x20transport: \"stdio\"\n\
         \x20\x20\x20\x20command: '{server_cmd}'\n\
         \x20\x20\x20\x20args: []\n\
         \x20\x20\x20\x20source_grade: \"Known\"\n\
         \n\
         {tools_block}\n\
         {security_policy_block}\n"
    );
    let path = dir.join("config.yaml");
    std::fs::write(&path, config).expect("failed to write test config.yaml");
    path
}

fn jsonrpc_lines() -> Vec<String> {
    vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0.1"}}}).to_string(),
        json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}).to_string(),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}).to_string(),
        json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"ping","arguments":{}}}).to_string(),
    ]
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
        // stdin dropped at end of this block -> EOF -> gateway's stdio loop
        // exits normally, same as the README's own printf-piped demo.
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

fn find_response<'a>(responses: &'a [Value], id: i64) -> &'a Value {
    responses
        .iter()
        .find(|r| r.get("id") == Some(&json!(id)))
        .unwrap_or_else(|| panic!("no response with id {id} in: {responses:?}"))
}

fn tool_names(tools_list_response: &Value) -> Vec<String> {
    tools_list_response["result"]["tools"]
        .as_array()
        .expect("tools/list result must have a tools array")
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect()
}

#[test]
fn first_run_no_pin_tool_is_not_quarantined_and_is_callable() {
    let dir = TempDir::new("no_pin");
    let tools_block = "tools:\n\
        \x20\x20- mcp_server_id: \"fake\"\n\
        \x20\x20\x20\x20tool_name: \"ping\"\n\
        \x20\x20\x20\x20risk_class: \"Low\"\n\
        \x20\x20\x20\x20authority_source: \"User\"\n";
    let config = write_config(dir.path(), tools_block, "");

    let output = run_gateway(&config, &jsonrpc_lines());
    assert!(
        output.status.success(),
        "gateway must exit 0 on day-one/no-pin, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let responses = parse_responses(&output.stdout);
    let names = tool_names(find_response(&responses, 2));
    assert!(names.contains(&"ping".to_string()), "unpinned tool must appear in tools/list, got: {names:?}");

    let call = find_response(&responses, 3);
    assert!(call.get("error").is_none(), "unpinned tool must be callable, got error: {call:?}");
    // starts_with, not an exact match: this is a fresh session's first call
    // against a Known-graded server, which genuinely escalates Clean ->
    // Elevated on structural signal alone (see provenance::compute_new_state)
    // and now legitimately gets a SEC-01 advisory appended as a result —
    // this test is about pin enforcement, not about asserting the response
    // is byte-for-byte untouched.
    let text = call["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("pong"), "got: {text:?}");
}

#[test]
fn strict_true_with_wrong_pin_quarantines_the_tool() {
    let dir = TempDir::new("strict_wrong_pin");
    let tools_block = format!(
        "tools:\n\
         \x20\x20- mcp_server_id: \"fake\"\n\
         \x20\x20\x20\x20tool_name: \"ping\"\n\
         \x20\x20\x20\x20risk_class: \"Low\"\n\
         \x20\x20\x20\x20authority_source: \"User\"\n\
         \x20\x20\x20\x20pinned_definition_hash_hex: \"{}\"\n",
        wrong_pin_hex()
    );
    let security_policy_block = "security_policy:\n  strict_schema_pinning: true\n";
    let config = write_config(dir.path(), &tools_block, security_policy_block);

    let output = run_gateway(&config, &jsonrpc_lines());
    assert!(
        output.status.success(),
        "strict quarantine on one tool must not take the whole gateway down, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let responses = parse_responses(&output.stdout);
    let names = tool_names(find_response(&responses, 2));
    assert!(!names.contains(&"ping".to_string()), "quarantined tool must be absent from tools/list, got: {names:?}");

    let call = find_response(&responses, 3);
    let error = call.get("error").expect("a direct call to a quarantined tool must be rejected");
    assert_eq!(
        error["data"]["magus_rejection_code"], "ToolQuarantinedPinMismatch",
        "must be the distinct quarantine code, not a generic one: {error:?}"
    );
}

#[test]
fn wrong_pin_without_strict_mode_tool_remains_callable() {
    let dir = TempDir::new("nonstrict_wrong_pin");
    let tools_block = format!(
        "tools:\n\
         \x20\x20- mcp_server_id: \"fake\"\n\
         \x20\x20\x20\x20tool_name: \"ping\"\n\
         \x20\x20\x20\x20risk_class: \"Low\"\n\
         \x20\x20\x20\x20authority_source: \"User\"\n\
         \x20\x20\x20\x20pinned_definition_hash_hex: \"{}\"\n",
        wrong_pin_hex()
    );
    let security_policy_block = "security_policy:\n  strict_schema_pinning: false\n";
    let config = write_config(dir.path(), &tools_block, security_policy_block);

    let output = run_gateway(&config, &jsonrpc_lines());
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let responses = parse_responses(&output.stdout);
    let names = tool_names(find_response(&responses, 2));
    assert!(names.contains(&"ping".to_string()), "warn-only mismatch must not remove the tool, got: {names:?}");

    let call = find_response(&responses, 3);
    assert!(call.get("error").is_none(), "warn-only mismatch must not block the call, got: {call:?}");
}

#[test]
fn refuse_startup_with_a_real_mismatch_exits_3_before_the_stdio_loop() {
    let dir = TempDir::new("refuse_with_mismatch");
    let tools_block = format!(
        "tools:\n\
         \x20\x20- mcp_server_id: \"fake\"\n\
         \x20\x20\x20\x20tool_name: \"ping\"\n\
         \x20\x20\x20\x20risk_class: \"Low\"\n\
         \x20\x20\x20\x20authority_source: \"User\"\n\
         \x20\x20\x20\x20pinned_definition_hash_hex: \"{}\"\n",
        wrong_pin_hex()
    );
    let security_policy_block = "security_policy:\n  strict_schema_pinning: true\n  refuse_startup_on_pin_mismatch: true\n";
    let config = write_config(dir.path(), &tools_block, security_policy_block);

    // No stdin needed: refusal must happen before the stdio loop ever reads.
    let output = run_gateway(&config, &[]);

    assert_eq!(output.status.code(), Some(3), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("ping"), "exit(3) summary must name the mismatched tool, stderr: {stderr}");
    assert!(
        output.stdout.is_empty(),
        "must exit before producing any stdio-loop response, stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[test]
fn refuse_startup_without_strict_mode_is_a_config_error_exit_2() {
    let dir = TempDir::new("refuse_without_strict");
    let security_policy_block = "security_policy:\n  strict_schema_pinning: false\n  refuse_startup_on_pin_mismatch: true\n";
    let config = write_config(dir.path(), "", security_policy_block);

    let output = run_gateway(&config, &[]);

    assert_eq!(output.status.code(), Some(2), "stderr: {}", String::from_utf8_lossy(&output.stderr));
}
