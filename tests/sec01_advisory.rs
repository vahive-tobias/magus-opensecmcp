// tests/sec01_advisory.rs
//
// End-to-end tests for SEC-01 (advisory injection on genuine provenance
// escalation). Spawns the real compiled magus-gateway binary against a
// real spawned downstream process (fake_advisory_test_server, a second
// [[bin]] target in this crate — see src/bin/fake_advisory_test_server.rs)
// — the same pattern tests/pin_enforcement.rs (SEC-03) established:
// exercise the compiled artifact against a real connection, not internal
// functions. See docs/specs/spec-sec01-poisoned-content-advisory.md for
// the full spec.
//
// The pure tier-selection/string-extension logic itself is unit-tested
// directly in src/advisory.rs; these tests confirm that logic is actually
// wired into main.rs's handle_tools_call for real, against a real
// downstream response.

use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("magus_sec01_test_{label}_{}", uuid::Uuid::new_v4()));
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

fn write_config(dir: &Path) -> PathBuf {
    let server_cmd = env!("CARGO_BIN_EXE_fake_advisory_test_server");
    let config = format!(
        "downstream_servers:\n\
         \x20\x20- server_id: \"fake\"\n\
         \x20\x20\x20\x20transport: \"stdio\"\n\
         \x20\x20\x20\x20command: '{server_cmd}'\n\
         \x20\x20\x20\x20args: []\n\
         \x20\x20\x20\x20source_grade: \"Known\"\n"
    );
    let path = dir.join("config.yaml");
    std::fs::write(&path, config).expect("failed to write test config.yaml");
    path
}

fn tools_call_line(id: i64, tool_name: &str) -> String {
    json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":tool_name,"arguments":{}}}).to_string()
}

fn handshake_lines() -> Vec<String> {
    vec![
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"probe","version":"0.1"}}}).to_string(),
        json!({"jsonrpc":"2.0","method":"notifications/initialized","params":{}}).to_string(),
    ]
}

fn run_gateway(config_path: &Path, stdin_lines: &[String]) -> Vec<Value> {
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
        // stdin dropped here -> EOF -> gateway's stdio loop exits normally.
    }

    let output = child.wait_with_output().expect("failed to wait on magus-gateway");
    assert!(
        output.status.success(),
        "gateway must exit 0, stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout)
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

// Must match src/bin/fake_advisory_test_server.rs exactly.
const LONG_BENIGN_TEXT: &str = "Standard reply text with nothing unusual in it. This response is deliberately verbose so the structural response-shape classifier treats it as substantial content rather than a short, trivial reply, which is exactly the condition this fixture exists to exercise.";
const SHORT_BENIGN_TEXT: &str = "Standard reply text with nothing unusual in it.";

#[test]
fn tier1_response_gets_advisory_appended_to_structured_content() {
    let dir = TempDir::new("tier1");
    let config = write_config(dir.path());

    let mut lines = handshake_lines();
    lines.push(tools_call_line(2, "tier1_tool"));
    let responses = run_gateway(&config, &lines);

    let call = find_response(&responses, 2);
    let result = &call["result"];

    // content[] must be untouched -- tier 1 exists precisely to avoid
    // needing to add a content block at all.
    assert_eq!(
        result["content"][0]["text"], LONG_BENIGN_TEXT,
        "content[] text must be left exactly as the downstream server returned it"
    );

    let structured = result["structuredContent"]["content"]
        .as_str()
        .expect("structuredContent.content must still be a string");
    assert!(
        structured.starts_with(LONG_BENIGN_TEXT),
        "original structuredContent.content must survive intact as a prefix, got: {structured:?}"
    );
    assert!(structured.contains("MAGUS ADVISORY"), "got: {structured:?}");
    assert!(structured.contains("Elevated"), "got: {structured:?}");
}

#[test]
fn tier2_response_gets_advisory_appended_to_content_block_when_no_structured_content() {
    let dir = TempDir::new("tier2");
    let config = write_config(dir.path());

    let mut lines = handshake_lines();
    lines.push(tools_call_line(2, "tier2_tool"));
    let responses = run_gateway(&config, &lines);

    let call = find_response(&responses, 2);
    let result = &call["result"];

    assert!(
        result.get("structuredContent").is_none(),
        "must not introduce a structuredContent key that wasn't already there"
    );

    let content_array = result["content"].as_array().expect("content must be an array");
    assert_eq!(content_array.len(), 1, "must not add a new content block");

    let text = content_array[0]["text"].as_str().expect("text must still be a string");
    assert!(
        text.starts_with(LONG_BENIGN_TEXT),
        "original content[].text must survive intact as a prefix, got: {text:?}"
    );
    assert!(text.contains("MAGUS ADVISORY"), "got: {text:?}");
    assert!(text.contains("Elevated"), "got: {text:?}");
}

#[test]
fn no_further_advisory_once_already_elevated() {
    let dir = TempDir::new("plateau");
    let config = write_config(dir.path());

    let mut lines = handshake_lines();
    lines.push(tools_call_line(2, "tier1_tool"));
    lines.push(tools_call_line(3, "tier1_tool"));
    let responses = run_gateway(&config, &lines);

    let first = find_response(&responses, 2);
    let first_structured = first["result"]["structuredContent"]["content"].as_str().unwrap();
    assert!(
        first_structured.contains("MAGUS ADVISORY"),
        "first call must escalate Clean -> Elevated and get the advisory, got: {first_structured:?}"
    );

    let second = find_response(&responses, 3);
    let second_structured = second["result"]["structuredContent"]["content"].as_str().unwrap();
    assert_eq!(
        second_structured, LONG_BENIGN_TEXT,
        "second call must not escalate further (already Elevated), so no advisory should be injected"
    );
}

/// The C1-fix counterpart to the three tests above: a short, benign
/// response from a Known server must NOT escalate Clean -> Elevated at
/// all, so no advisory is injected. Before the C1 fix, this was
/// impossible to assert -- compute_new_state forced Elevated for any
/// Known-graded BareString/PrimitiveData response regardless of content,
/// which is exactly what made the three tests above pass on a 49-char
/// reply and is the bug this fixture and its short/long text split now
/// exist to keep from silently regressing.
#[test]
fn short_benign_response_does_not_escalate_or_get_advisory() {
    let dir = TempDir::new("tiny");
    let config = write_config(dir.path());

    let mut lines = handshake_lines();
    lines.push(tools_call_line(2, "tiny_tool"));
    let responses = run_gateway(&config, &lines);

    let call = find_response(&responses, 2);
    let result = &call["result"];

    assert!(
        result.get("structuredContent").is_none(),
        "must not introduce a structuredContent key that wasn't already there"
    );

    let content_array = result["content"].as_array().expect("content must be an array");
    assert_eq!(content_array.len(), 1, "must not add a new content block");

    let text = content_array[0]["text"].as_str().expect("text must still be a string");
    assert_eq!(
        text, SHORT_BENIGN_TEXT,
        "a short benign response must be forwarded completely untouched -- no advisory, no escalation"
    );
}
