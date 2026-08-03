// tests/tool_name_collision.rs
//
// End-to-end tests for F3 (multi-server bare-tool-name collision). Spawns
// the real compiled magus-gateway binary against real spawned downstream
// processes — two of them, at once, which nothing in this test suite did
// before this fix. Deliberately reuses the existing fake_pin_test_server
// binary (already advertises a fixed "ping" tool) rather than building new
// fake-server infrastructure: two config.yaml entries both pointing at
// that same binary produce a genuine, real name collision for free. See
// docs/specs/Adversarial Review magus-opensecmcp.md, finding F3.
//
// tests/pin_enforcement.rs's ping_definition()/correct_pin_hex()/
// wrong_pin_hex() helpers are duplicated here rather than shared — the
// same "no cross-test-binary sharing convention in this repo yet"
// situation fake_pin_test_server.rs's own tool definition already lives
// with in that file.

use magus_opensecmcp::hasher::{compute_definition_hash, hash_to_hex, McpToolDefinition};
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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
        let dir = std::env::temp_dir().join(format!("magus_collision_test_{label}_{}", uuid::Uuid::new_v4()));
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

fn pin_server_entry(server_id: &str) -> String {
    let cmd = env!("CARGO_BIN_EXE_fake_pin_test_server");
    format!(
        "  - server_id: \"{server_id}\"\n\
         \x20\x20\x20\x20transport: \"stdio\"\n\
         \x20\x20\x20\x20command: '{cmd}'\n\
         \x20\x20\x20\x20args: []\n\
         \x20\x20\x20\x20source_grade: \"Known\"\n"
    )
}

fn desc_server_entry(server_id: &str) -> String {
    let cmd = env!("CARGO_BIN_EXE_fake_desc_test_server");
    format!(
        "  - server_id: \"{server_id}\"\n\
         \x20\x20\x20\x20transport: \"stdio\"\n\
         \x20\x20\x20\x20command: '{cmd}'\n\
         \x20\x20\x20\x20args: []\n\
         \x20\x20\x20\x20source_grade: \"Known\"\n"
    )
}

fn tool_entry(server_id: &str, tool_name: &str, pin: Option<&str>) -> String {
    let pin_line = pin
        .map(|p| format!("    pinned_definition_hash_hex: \"{p}\"\n"))
        .unwrap_or_default();
    format!(
        "  - mcp_server_id: \"{server_id}\"\n\
         \x20\x20\x20\x20tool_name: \"{tool_name}\"\n\
         \x20\x20\x20\x20risk_class: \"Low\"\n\
         \x20\x20\x20\x20authority_source: \"User\"\n\
         {pin_line}"
    )
}

fn write_config(dir: &Path, servers: &str, tools: &str, security_policy: &str) -> PathBuf {
    let config = format!(
        "downstream_servers:\n{servers}\ntools:\n{tools}\nsecurity_policy:\n{security_policy}\n"
    );
    let path = dir.join("config.yaml");
    std::fs::write(&path, config).expect("failed to write test config.yaml");
    path
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

fn run_gateway(config_path: &Path, extra_args: &[&str], stdin_lines: &[String]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_magus-gateway"))
        .arg(config_path)
        .args(extra_args)
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

fn tool_names(tools_list_response: &Value) -> Vec<String> {
    tools_list_response["result"]["tools"]
        .as_array()
        .expect("tools/list result must have a tools array")
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect()
}

/// THE core F3 regression: two servers both spawn fake_pin_test_server, so
/// both genuinely advertise "ping" — a real collision, not a simulated
/// one. Neither claimant should be promoted to the agent-facing tier; a
/// direct call to "ping" must get the new, distinct
/// ToolExcludedNameCollision code, not silently route to whichever server
/// happened to be processed last (the original bug) and not the
/// pin-mismatch code either.
#[test]
fn two_servers_same_tool_name_both_excluded_and_rejected_with_collision_code() {
    let dir = TempDir::new("collision");
    let servers = format!("{}{}", pin_server_entry("server-a"), pin_server_entry("server-b"));
    let tools = format!(
        "{}{}",
        tool_entry("server-a", "ping", None),
        tool_entry("server-b", "ping", None)
    );
    let config = write_config(dir.path(), &servers, &tools, "");

    let output = run_gateway(&config, &[], &jsonrpc_lines(Some("ping")));
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let responses = parse_responses(&output.stdout);
    let names = tool_names(find_response(&responses, 2));
    assert!(!names.contains(&"ping".to_string()), "a colliding name must be absent from tools/list entirely, got: {names:?}");

    let call = find_response(&responses, 3);
    let error = call.get("error").expect("a direct call to an excluded, colliding tool name must be rejected");
    assert_eq!(
        error["data"]["magus_rejection_code"], "ToolExcludedNameCollision",
        "must be the distinct collision code, not quarantine or a generic one: {error:?}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("EXCLUDED"), "stderr must report the exclusion, got: {stderr}");
    assert!(stderr.contains("Discovery complete"), "the end-of-discovery summary must print, got: {stderr}");
}

/// THE quarantine-first interaction: server-a's "ping" is pin-mismatched
/// (quarantined under strict_schema_pinning), server-b's "ping" is clean
/// (unpinned — NotYetPinned never quarantines). Quarantine must remove
/// server-a's tool BEFORE collision detection ever runs, so server-b's
/// "ping" ends up the SOLE survivor for that name — no collision, no
/// spurious exclusion, works exactly like an ordinary single-server "ping".
#[test]
fn quarantine_runs_before_collision_so_a_clean_survivor_is_unaffected() {
    let dir = TempDir::new("quarantine_first");
    let servers = format!("{}{}", pin_server_entry("server-a"), pin_server_entry("server-b"));
    let tools = format!(
        "{}{}",
        tool_entry("server-a", "ping", Some(&wrong_pin_hex())),
        tool_entry("server-b", "ping", None)
    );
    let security_policy = "  strict_schema_pinning: true\n";
    let config = write_config(dir.path(), &servers, &tools, security_policy);

    let output = run_gateway(&config, &[], &jsonrpc_lines(Some("ping")));
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let responses = parse_responses(&output.stdout);
    let names = tool_names(find_response(&responses, 2));
    assert!(
        names.contains(&"ping".to_string()),
        "server-b's clean 'ping' must survive once server-a's mismatched 'ping' is quarantined first, got: {names:?}"
    );

    let call = find_response(&responses, 3);
    assert!(
        call.get("error").is_none(),
        "the surviving clean tool must be callable normally, no spurious collision exclusion, got: {call:?}"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("QUARANTINED"), "server-a's tool must be reported quarantined, got: {stderr}");
    assert!(!stderr.contains("EXCLUDED (name collision)"), "no collision should ever be reported here, got: {stderr}");
}

/// Two servers, no shared tool names at all (fake_pin_test_server's
/// "ping" vs. fake_desc_test_server's three distinct tools) — proves F3
/// doesn't regress ordinary multi-server usage, the roadmap's own stated
/// future direction. "ping" must work exactly as it does in a
/// single-server config.
#[test]
fn distinct_tool_names_across_two_servers_both_work_normally() {
    let dir = TempDir::new("distinct_names");
    let servers = format!("{}{}", pin_server_entry("server-a"), desc_server_entry("server-b"));
    let tools = format!(
        "{}{}{}{}",
        tool_entry("server-a", "ping", None),
        tool_entry("server-b", "poison_tool", None),
        tool_entry("server-b", "flagged_tool", None),
        tool_entry("server-b", "clean_tool", None),
    );
    let config = write_config(dir.path(), &servers, &tools, "");

    let output = run_gateway(&config, &[], &jsonrpc_lines(Some("ping")));
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let responses = parse_responses(&output.stdout);
    let names = tool_names(find_response(&responses, 2));
    for expected in ["ping", "poison_tool", "flagged_tool", "clean_tool"] {
        assert!(names.contains(&expected.to_string()), "expected {expected:?} in tools/list, got: {names:?}");
    }
    assert_eq!(names.len(), 4, "no tool should be excluded when no names collide, got: {names:?}");

    let call = find_response(&responses, 3);
    assert!(call.get("error").is_none(), "ping must be callable normally with no collision in play, got: {call:?}");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("EXCLUDED"), "no exclusion should ever be reported here, got: {stderr}");
}

/// `--discovery-report`: runs the real discovery pipeline (real spawned
/// servers, real collision detection), prints the summary to STDOUT, and
/// exits 0 before the stdio loop ever starts — no stdin is sent at all,
/// mirroring how refuse_startup_with_a_real_mismatch_exits_3... in
/// pin_enforcement.rs already asserts an early-exit path never produces
/// stdio-loop output.
#[test]
fn discovery_report_prints_summary_to_stdout_and_exits_before_the_stdio_loop() {
    let dir = TempDir::new("discovery_report");
    let servers = format!("{}{}", pin_server_entry("server-a"), pin_server_entry("server-b"));
    let tools = format!(
        "{}{}",
        tool_entry("server-a", "ping", None),
        tool_entry("server-b", "ping", None)
    );
    let config = write_config(dir.path(), &servers, &tools, "");

    // No stdin: the flag must cause an exit before the stdio loop ever reads.
    let output = run_gateway(&config, &["--discovery-report"], &[]);

    assert!(output.status.success(), "--discovery-report must exit 0, stderr: {}", String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Discovery complete"), "stdout must contain the summary, got: {stdout:?}");
    assert!(stdout.contains("DISCOVERED WITH ISSUES"), "stdout must report the real collision found, got: {stdout:?}");
    assert!(stdout.contains("server-a/ping") || stdout.contains("server-b/ping"), "stdout must name the colliding tool, got: {stdout:?}");

    // No stdio-loop JSON-RPC response of any kind was ever produced — the
    // process exited before reading stdin at all, so parsing stdout as
    // JSON-RPC lines (the way parse_responses does elsewhere in this file)
    // must find nothing that looks like a response.
    assert!(
        !stdout.lines().any(|l| serde_json::from_str::<Value>(l).is_ok()),
        "stdout must contain the plain-text summary only, no JSON-RPC lines, got: {stdout:?}"
    );
}
