// tests/downstream_timeout.rs
//
// End-to-end tests for F5 (downstream call/discovery timeout enforcement —
// see docs/specs/Adversarial Review magus-opensecmcp.md). Spawns the real
// compiled magus-gateway binary against a real spawned downstream process
// that can genuinely hang on command (fake_hang_test_server.rs — none of
// the existing fixtures can be made to hang), extending the same
// spawn-the-real-binary pattern tests/pin_enforcement.rs and
// tests/tool_name_collision.rs already established.
//
// Configured timeouts throughout this file are short and sub-second
// (0.3-0.5s) — this is fundamentally testing timing behavior, and
// cargo test shouldn't take minutes because of it.

use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("magus_timeout_test_{label}_{}", uuid::Uuid::new_v4()));
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

/// One `downstream_servers:` entry for fake_hang_test_server.rs.
/// `hang_on_initialize` maps to that binary's `--hang-on-initialize` flag
/// (for discovery-time scenarios); `discovery_timeout` is this server's
/// own optional `discovery_timeout_seconds` override.
fn hang_server_entry(server_id: &str, hang_on_initialize: bool, discovery_timeout: Option<f64>) -> String {
    let cmd = env!("CARGO_BIN_EXE_fake_hang_test_server");
    let args_line = if hang_on_initialize { "[\"--hang-on-initialize\"]" } else { "[]" };
    let dto_line = discovery_timeout
        .map(|d| format!("    discovery_timeout_seconds: {}\n", d))
        .unwrap_or_default();
    format!(
        "  - server_id: \"{server_id}\"\n\
         \x20\x20\x20\x20transport: \"stdio\"\n\
         \x20\x20\x20\x20command: '{cmd}'\n\
         \x20\x20\x20\x20args: {args_line}\n\
         \x20\x20\x20\x20source_grade: \"Known\"\n\
         {dto_line}"
    )
}

/// One `downstream_servers:` entry for fake_pin_test_server.rs (the
/// "ping"-only fixture from SEC-03's tests) — reused here purely as an
/// ordinary, always-healthy server for the "one hung server alongside a
/// healthy one" scenarios, not to exercise pin behavior.
fn pin_server_entry(server_id: &str, discovery_timeout: Option<f64>) -> String {
    let cmd = env!("CARGO_BIN_EXE_fake_pin_test_server");
    let dto_line = discovery_timeout
        .map(|d| format!("    discovery_timeout_seconds: {}\n", d))
        .unwrap_or_default();
    format!(
        "  - server_id: \"{server_id}\"\n\
         \x20\x20\x20\x20transport: \"stdio\"\n\
         \x20\x20\x20\x20command: '{cmd}'\n\
         \x20\x20\x20\x20args: []\n\
         \x20\x20\x20\x20source_grade: \"Known\"\n\
         {dto_line}"
    )
}

fn tool_entry(server_id: &str, tool_name: &str, timeout_seconds: Option<f64>) -> String {
    let t_line = timeout_seconds
        .map(|t| format!("    timeout_seconds: {}\n", t))
        .unwrap_or_default();
    format!(
        "  - mcp_server_id: \"{server_id}\"\n\
         \x20\x20\x20\x20tool_name: \"{tool_name}\"\n\
         \x20\x20\x20\x20risk_class: \"Low\"\n\
         \x20\x20\x20\x20authority_source: \"User\"\n\
         {t_line}"
    )
}

/// Wraps one or more `servers_entries`/`tool_entries` with their `tools:`/
/// `downstream_servers:` header only when non-empty — a bare `tools:\n`
/// key with nothing indented under it parses as YAML null, not an empty
/// sequence, which `Vec<YamlToolEntry>` would reject. Omitting the key
/// line entirely when there's nothing under it is what actually triggers
/// `#[serde(default)]`, the same reason tests/pin_enforcement.rs's
/// write_config lets a caller pass "" for a whole block rather than this
/// function always emitting an empty-bodied key.
fn servers_block(entries: &[String]) -> String {
    format!("downstream_servers:\n{}", entries.concat())
}

fn tools_block(entries: &[String]) -> String {
    if entries.is_empty() {
        String::new()
    } else {
        format!("tools:\n{}", entries.concat())
    }
}

fn write_config(dir: &Path, servers_block: &str, tools_block: &str, security_policy_block: &str) -> PathBuf {
    let config = format!("{servers_block}\n{tools_block}\n{security_policy_block}\n");
    let path = dir.join("config.yaml");
    std::fs::write(&path, config).expect("failed to write test config.yaml");
    path
}

fn init_and_list_lines() -> Vec<String> {
    vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0.1"}}}).to_string(),
        json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}).to_string(),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}).to_string(),
    ]
}

fn call_line(id: i64, tool_name: &str) -> String {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool_name,"arguments":{}}}).to_string()
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

fn rejection_code(responses: &[Value], id: i64) -> String {
    find_response(responses, id)["error"]["data"]["magus_rejection_code"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

/// A call that hangs past its configured per-tool timeout is rejected with
/// the new distinct code, in roughly the configured duration — not
/// instantly (that would mean the timeout wrapper isn't actually engaging
/// the real request), and not dramatically longer either (that would mean
/// the wait isn't actually bounded).
#[test]
fn hang_past_its_timeout_is_rejected_with_the_distinct_code_in_roughly_the_configured_duration() {
    let dir = TempDir::new("call_timeout");
    let servers = servers_block(&[hang_server_entry("srv-hang", false, None)]);
    let tools = tools_block(&[tool_entry("srv-hang", "hang_tool", Some(0.4))]);
    let config = write_config(dir.path(), &servers, &tools, "");

    let mut lines = init_and_list_lines();
    lines.push(call_line(3, "hang_tool"));

    let start = Instant::now();
    let output = run_gateway(&config, &[], &lines);
    let elapsed = start.elapsed();

    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let responses = parse_responses(&output.stdout);
    assert_eq!(rejection_code(&responses, 3), "DownstreamTimeout");

    assert!(elapsed >= Duration::from_millis(350), "must actually wait roughly the configured timeout, got {:?}", elapsed);
    assert!(elapsed < Duration::from_secs(3), "must not wait dramatically longer than the configured timeout, got {:?}", elapsed);
}

/// A call that completes normally, well within its timeout, must be
/// totally unaffected by this fix — the ordinary case regresses to
/// nothing.
#[test]
fn a_call_well_within_its_timeout_is_totally_unaffected() {
    let dir = TempDir::new("no_timeout");
    let servers = servers_block(&[hang_server_entry("srv-hang", false, None)]);
    let tools = tools_block(&[tool_entry("srv-hang", "quick_tool", Some(5.0))]);
    let config = write_config(dir.path(), &servers, &tools, "");

    let mut lines = init_and_list_lines();
    lines.push(call_line(3, "quick_tool"));

    let output = run_gateway(&config, &[], &lines);
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));

    let responses = parse_responses(&output.stdout);
    let names = tool_names(find_response(&responses, 2));
    assert!(names.contains(&"quick_tool".to_string()), "got: {names:?}");

    let call = find_response(&responses, 3);
    assert!(call.get("error").is_none(), "an ordinary call must not be rejected, got: {call:?}");
    // starts_with, not an exact match: a fresh session's first call
    // against a Known-graded server legitimately escalates Clean ->
    // Elevated on structural signal alone and gets a SEC-01 advisory
    // appended — same reasoning tests/pin_enforcement.rs's own
    // first-call test already documents. This test is about timeout
    // behavior, not about asserting the response is byte-for-byte
    // untouched.
    let text = call["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.starts_with("quick"), "got: {text:?}");
}

/// Two consecutive timeouts on one server mark the connection degraded;
/// a third call to that server fails FAST with the distinct degraded
/// code — asserted both by response code and by timing. Timing is
/// measured as a DELTA between two real runs (two calls vs. three)
/// rather than an absolute bound against a fixed constant: this
/// environment's own process-spawn overhead (spawning both the gateway
/// and its downstream child) turned out to be large and variable enough
/// that an absolute upper bound on total wall-clock time was unreliable
/// in practice. Measuring the SAME machine's own two-call baseline first
/// and comparing what the third call adds on top cancels that overhead
/// out, leaving only what's actually being tested: did the third call
/// wait, or fail fast.
#[test]
fn two_consecutive_timeouts_degrade_the_connection_and_the_third_call_fails_fast() {
    let dir = TempDir::new("degrade");
    let servers = servers_block(&[hang_server_entry("srv-hang", false, None)]);
    let tools = tools_block(&[tool_entry("srv-hang", "hang_tool", Some(0.5))]);
    let config = write_config(dir.path(), &servers, &tools, "");

    // Baseline: two genuine timeouts only.
    let mut two_calls = init_and_list_lines();
    two_calls.push(call_line(3, "hang_tool"));
    two_calls.push(call_line(4, "hang_tool"));
    let start_two = Instant::now();
    let output_two = run_gateway(&config, &[], &two_calls);
    let elapsed_two = start_two.elapsed();
    assert!(output_two.status.success(), "stderr: {}", String::from_utf8_lossy(&output_two.stderr));
    let responses_two = parse_responses(&output_two.stdout);
    assert_eq!(rejection_code(&responses_two, 3), "DownstreamTimeout");
    assert_eq!(rejection_code(&responses_two, 4), "DownstreamTimeout");

    // Same two timeouts, plus a third call that should now be degraded
    // and fail fast.
    let mut three_calls = two_calls.clone();
    three_calls.push(call_line(5, "hang_tool"));
    let start_three = Instant::now();
    let output_three = run_gateway(&config, &[], &three_calls);
    let elapsed_three = start_three.elapsed();
    assert!(output_three.status.success(), "stderr: {}", String::from_utf8_lossy(&output_three.stderr));
    let responses_three = parse_responses(&output_three.stdout);
    assert_eq!(rejection_code(&responses_three, 3), "DownstreamTimeout");
    assert_eq!(rejection_code(&responses_three, 4), "DownstreamTimeout");
    assert_eq!(rejection_code(&responses_three, 5), "DownstreamConnectionDegraded");

    // The environment-independent assertion: adding the third (degraded)
    // call must cost far less than another full 0.5s timeout on top of
    // the freshly measured two-call baseline — if fail-fast silently
    // didn't engage and call 5 re-waited the full timeout too, this
    // delta would be close to 0.5s instead.
    let added = elapsed_three.saturating_sub(elapsed_two);
    assert!(
        added < Duration::from_millis(350),
        "the third, degraded call must fail fast (added ~0s), not re-wait the full 0.5s timeout — \
         added {:?} on top of the two-call baseline of {:?}",
        added, elapsed_two
    );
}

/// One timeout followed by a successful call must NOT degrade the
/// connection — and, critically, the counter must actually have reset:
/// the next timeout after that success needs its own 2 fresh consecutive
/// occurrences to degrade, not just 1 riding on the pre-reset count.
#[test]
fn a_timeout_followed_by_success_resets_the_counter_so_two_more_are_needed_to_degrade() {
    let dir = TempDir::new("reset");
    let servers = servers_block(&[hang_server_entry("srv-hang", false, None)]);
    let tools = tools_block(&[
        tool_entry("srv-hang", "hang_tool", Some(0.4)),
        tool_entry("srv-hang", "quick_tool", Some(5.0)),
    ]);
    let config = write_config(dir.path(), &servers, &tools, "");

    let mut lines = init_and_list_lines();
    lines.push(call_line(3, "hang_tool"));  // timeout #1 (streak -> 1)
    lines.push(call_line(4, "quick_tool")); // success (streak reset -> 0)
    lines.push(call_line(5, "hang_tool"));  // timeout (streak -> 1, NOT degraded)
    lines.push(call_line(6, "hang_tool"));  // 2nd consecutive since reset (streak -> 2, degrades after this)
    lines.push(call_line(7, "hang_tool"));  // now degraded -> fails fast

    let output = run_gateway(&config, &[], &lines);
    assert!(output.status.success(), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    let responses = parse_responses(&output.stdout);

    assert_eq!(rejection_code(&responses, 3), "DownstreamTimeout");
    assert!(find_response(&responses, 4).get("error").is_none(), "the successful call must not be rejected");
    // The critical assertion: call 5 must still be an ordinary timeout,
    // NOT already "DownstreamConnectionDegraded" — if call 4's success
    // had failed to reset the streak, this would incorrectly be the
    // second consecutive timeout (riding on call 3's un-reset count) and
    // would show the degraded code one call too early.
    assert_eq!(rejection_code(&responses, 5), "DownstreamTimeout", "the streak must have been reset by call 4's success");
    assert_eq!(rejection_code(&responses, 6), "DownstreamTimeout", "the second timeout since the reset still gets its own full wait");
    assert_eq!(rejection_code(&responses, 7), "DownstreamConnectionDegraded", "only now, after 2 fresh consecutive timeouts, is the connection degraded");
}

/// A discovery-time hang on one server, configured alongside a second,
/// healthy server: the gateway still starts, the healthy server's tools
/// are available in tools/list, and the hung server shows up in the
/// discovery summary's new failed-servers section.
#[test]
fn discovery_time_hang_on_one_server_excludes_just_it_and_the_healthy_server_still_starts() {
    let dir = TempDir::new("discovery_hang");
    let servers = servers_block(&[
        hang_server_entry("srv-hung", true, Some(0.3)),
        pin_server_entry("srv-healthy", None),
    ]);
    let tools = tools_block(&[tool_entry("srv-healthy", "ping", None)]);
    let config = write_config(dir.path(), &servers, &tools, "");

    let start = Instant::now();
    let output = run_gateway(&config, &[], &init_and_list_lines());
    let elapsed = start.elapsed();

    assert!(output.status.success(), "gateway must still start with one healthy server, stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(elapsed < Duration::from_secs(3), "must not wait dramatically longer than discovery_timeout_seconds, got {:?}", elapsed);

    let responses = parse_responses(&output.stdout);
    let names = tool_names(find_response(&responses, 2));
    assert!(names.contains(&"ping".to_string()), "the healthy server's tools must still be available, got: {names:?}");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("FAILED TO DISCOVER"), "the hung server must show up in the discovery summary, stderr: {stderr}");
    assert!(stderr.contains("srv-hung"), "stderr: {stderr}");
}

/// `refuse_startup_on_discovery_timeout: true` with a hanging server:
/// the gateway refuses to start entirely, exit code 5, no stdio-loop
/// output — mirroring how tests/pin_enforcement.rs already asserts an
/// early-refusal path's stdout is empty.
#[test]
fn refuse_startup_on_discovery_timeout_with_a_hanging_server_exits_5_before_the_stdio_loop() {
    let dir = TempDir::new("refuse_discovery_timeout");
    let servers = servers_block(&[hang_server_entry("srv-hung", true, Some(0.3))]);
    let security_policy = "security_policy:\n  refuse_startup_on_discovery_timeout: true\n";
    let config = write_config(dir.path(), &servers, "", security_policy);

    let output = run_gateway(&config, &[], &[]);

    assert_eq!(output.status.code(), Some(5), "stderr: {}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.stdout.is_empty(),
        "must exit before producing any stdio-loop response, stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("srv-hung"), "exit(5) summary must name the failed server, stderr: {stderr}");
}

/// Config validation rejects `timeout_seconds: 0` outright — a zero
/// timeout would mean "wait forever", exactly the bug this field exists
/// to close, so it must never be a silently-accepted value.
#[test]
fn zero_tool_timeout_seconds_is_rejected_at_config_load() {
    let dir = TempDir::new("zero_tool_timeout");
    let servers = servers_block(&[pin_server_entry("srv-a", None)]);
    let tools = tools_block(&[tool_entry("srv-a", "ping", Some(0.0))]);
    let config = write_config(dir.path(), &servers, &tools, "");

    let output = run_gateway(&config, &[], &[]);

    assert!(!output.status.success(), "a zero timeout_seconds must refuse to start");
    assert!(output.stdout.is_empty(), "must refuse before any stdio-loop output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("timeout_seconds"), "stderr must name the offending field, got: {stderr}");
}

/// Same as above, for `discovery_timeout_seconds: 0` on a
/// `downstream_servers:` entry.
#[test]
fn zero_discovery_timeout_seconds_is_rejected_at_config_load() {
    let dir = TempDir::new("zero_discovery_timeout");
    let servers = servers_block(&[pin_server_entry("srv-a", Some(0.0))]);
    let config = write_config(dir.path(), &servers, "", "");

    let output = run_gateway(&config, &[], &[]);

    assert!(!output.status.success(), "a zero discovery_timeout_seconds must refuse to start");
    assert!(output.stdout.is_empty(), "must refuse before any stdio-loop output");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("discovery_timeout_seconds"), "stderr must name the offending field, got: {stderr}");
}
