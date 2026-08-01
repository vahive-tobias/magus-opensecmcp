// tests/op3_capability_tag.rs
//
// End-to-end test for OP-3 (the `communicates_externally` capability tag).
// Spawns the real compiled magus-gateway binary against a real spawned
// downstream process (fake_op3_test_server, a second [[bin]] target in this
// crate — see src/bin/fake_op3_test_server.rs) — extending the fake-server
// pattern tests/pin_enforcement.rs (SEC-03) established, rather than a
// Python fixture script. See docs/specs/spec-op3-capability-tag.md.
//
// The pure ordering/bump logic itself is unit-tested directly in
// src/membrane.rs, alongside the relocated bump-table tests; this test
// confirms it's actually wired end-to-end AND verifies the outcome against
// the real audit.jsonl record, not just the call result — per the spec's
// explicit instruction not to stop at "the call succeeded/failed."
//
// Scenario: one session, three calls. First, a real rule hit
// (`trigger_heuristic_tool`) escalates Clean -> Contaminated. Then two
// otherwise-identical Medium-risk tools are called — one untagged, one
// tagged `communicates_externally: true` in config.yaml. At Contaminated,
// the existing (Medium, Contaminated) -> High bump already applies to both.
// Only the tagged one then gets the OP-3 bump on top (High -> Critical),
// which trips the existing Critical gate: the untagged call is approved,
// the tagged one is rejected — same risk_class, same state, only the tag
// differs. That is the demonstrable outcome difference the spec asks for.

use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct TempDir(PathBuf);

impl TempDir {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("magus_op3_test_{label}_{}", uuid::Uuid::new_v4()));
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
    let server_cmd = env!("CARGO_BIN_EXE_fake_op3_test_server");
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
         \x20\x20\x20\x20tool_name: \"trigger_heuristic_tool\"\n\
         \x20\x20\x20\x20risk_class: \"Low\"\n\
         \x20\x20\x20\x20authority_source: \"User\"\n\
         \n\
         \x20\x20- mcp_server_id: \"fake\"\n\
         \x20\x20\x20\x20tool_name: \"network_call_untagged\"\n\
         \x20\x20\x20\x20risk_class: \"Medium\"\n\
         \x20\x20\x20\x20authority_source: \"User\"\n\
         \n\
         \x20\x20- mcp_server_id: \"fake\"\n\
         \x20\x20\x20\x20tool_name: \"network_call_tagged\"\n\
         \x20\x20\x20\x20risk_class: \"Medium\"\n\
         \x20\x20\x20\x20authority_source: \"User\"\n\
         \x20\x20\x20\x20communicates_externally: true\n"
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
        // stdin dropped here -> EOF -> gateway's stdio loop exits normally.
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

/// Extracts "[MAGUS] Gateway active. Session <uuid>. Listening..." from
/// stderr, so this test can filter the real, shared ~/.magus/audit.jsonl
/// down to only the records THIS run produced — the production binary has
/// no test-only audit path override (by design, see audit.rs), so this
/// reads the actual mechanism a real operator would, not a test double.
fn extract_session_id(stderr: &[u8]) -> String {
    let text = String::from_utf8_lossy(stderr);
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("[MAGUS] Gateway active. Session ") {
            if let Some(id) = rest.strip_suffix(". Listening on stdio for MCP agent...") {
                return id.to_string();
            }
        }
    }
    panic!("could not find session id in stderr: {text}");
}

fn audit_records_for_session(session_id: &str) -> Vec<Value> {
    let audit_path = dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".magus")
        .join("audit.jsonl");
    let contents = std::fs::read_to_string(&audit_path)
        .unwrap_or_else(|e| panic!("failed to read real audit.jsonl at {audit_path:?}: {e}"));
    contents
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .filter(|r| r.get("session_id").and_then(|s| s.as_str()) == Some(session_id))
        .collect()
}

#[test]
fn tagged_and_untagged_medium_tools_diverge_at_contaminated_verified_via_audit_log() {
    let dir = TempDir::new("main");
    let config = write_config(dir.path());

    let mut lines = handshake_lines();
    lines.push(tools_call_line(2, "trigger_heuristic_tool"));
    lines.push(tools_call_line(3, "network_call_untagged"));
    lines.push(tools_call_line(4, "network_call_tagged"));
    let output = run_gateway(&config, &lines);

    let session_id = extract_session_id(&output.stderr);
    let responses = parse_responses(&output.stdout);

    // ---- Call result level ----
    let heuristic_call = find_response(&responses, 2);
    assert!(heuristic_call.get("error").is_none(), "the heuristic-triggering read itself must be approved (Low risk, Clean state)");

    let untagged_call = find_response(&responses, 3);
    assert!(
        untagged_call.get("error").is_none(),
        "untagged Medium tool at Contaminated must be approved (bumped to High, not Critical), got: {untagged_call:?}"
    );

    let tagged_call = find_response(&responses, 4);
    let tagged_error = tagged_call.get("error").expect(
        "tagged Medium tool at Contaminated must be REJECTED (bumped to High by the state \
         table, then to Critical by the tag, tripping the existing Critical gate) — same \
         risk_class and state as the untagged call above, which was approved",
    );
    assert_eq!(tagged_error["data"]["magus_rejection_code"], "CriticalBlockedByProvenance");

    // ---- Audit record level — the spec's explicit ask: verify against the
    //      audit record, not just the call result. ----
    let records = audit_records_for_session(&session_id);

    let untagged_record = records
        .iter()
        .find(|r| r["tool_name"] == "network_call_untagged")
        .expect("audit record for network_call_untagged must exist");
    assert_eq!(untagged_record["status"], "Approved");
    assert_eq!(untagged_record["rejection_code"], Value::Null);
    assert_eq!(untagged_record["effective_risk_class"], "High", "untagged Medium at Contaminated must be bumped to High by the existing table alone");
    assert_eq!(untagged_record["communicates_externally"], false);

    let tagged_record = records
        .iter()
        .find(|r| r["tool_name"] == "network_call_tagged")
        .expect("audit record for network_call_tagged must exist");
    assert_eq!(tagged_record["status"], "Rejected");
    assert_eq!(tagged_record["rejection_code"], "CriticalBlockedByProvenance");
    assert_eq!(
        tagged_record["communicates_externally"], true,
        "the audit record must show the tag contributed — without this, a tagged High tool \
         blocked at Elevated is indistinguishable from an untagged Critical one"
    );
}
