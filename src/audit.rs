// src/audit.rs

use serde::Serialize;
use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::provenance::ProvenanceState;
use crate::registry::{AuthoritySource, RiskClass};

/// ~/.magus/ on Mac/Linux, %USERPROFILE%\.magus\ on Windows.
fn get_magus_home() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".magus")
    } else {
        PathBuf::from(".magus")
    }
}

#[derive(Debug, Serialize)]
pub struct AuditRecord {
    pub timestamp_unix: u64,
    pub session_id: String,
    pub connection_id: String,
    pub proposal_id: String,
    pub mcp_server_id: String,
    pub tool_name: String,
    pub risk_class: RiskClass,
    pub authority_source: AuthoritySource,
    pub bootstrap: bool,
    /// OP-3: whether this tool is operator-tagged as communicating outside
    /// the local machine. Without this, a tagged `High` tool blocked at
    /// `Elevated` (now `Critical` after the tag bump) is indistinguishable
    /// in the log from an untagged `Critical` tool — an operator reading
    /// `audit.jsonl` needs to see that the tag contributed to the outcome.
    #[serde(default)]
    pub communicates_externally: bool,
    pub status: String,
    pub rejection_code: Option<String>,
    pub provenance_state: ProvenanceState,
    pub effective_risk_class: RiskClass,
    pub bp_consumed: u32,
    pub r_abs_bp_after: u32,
    /// ids of any rules.yaml rules that fired on the tool response ingested
    /// just before this proposal was evaluated. Empty most of the time.
    /// Populated in main.rs from RuleHitSummary — see rules_engine.rs. This
    /// is what makes a Poisoned/Elevated line in the audit log answer "which
    /// rule did this" instead of just "the state changed".
    #[serde(default)]
    pub triggered_rule_ids: Vec<String>,
}

pub struct AuditLogger {
    path: PathBuf,
}

impl AuditLogger {
    pub fn new(session_id: &str) -> Self {
        let magus_home = get_magus_home();

        if let Err(e) = DirBuilder::new().recursive(true).create(&magus_home) {
            eprintln!("[AUDIT] WARN: Failed to create directory {:?}: {}", magus_home, e);
        }

        let path = magus_home.join("audit.jsonl");

        let header = serde_json::json!({
            "event": "session_start",
            "timestamp_unix": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            "session_id": session_id
        });

        if let Ok(mut file) = OpenOptions::new().append(true).create(true).open(&path) {
            let _ = writeln!(file, "{}", header);
        }

        eprintln!("[AUDIT] Logging to {:?}", path);
        Self { path }
    }

    /// Test-only: takes an explicit path instead of computing one via
    /// `get_magus_home()`, so tests don't interleave writes into the real,
    /// shared `~/.magus/audit.jsonl` on whatever machine runs them, and can
    /// assert on audit record *content* by reading the file back. Does not
    /// change `new`'s signature or any of its callers in main.rs.
    #[cfg(test)]
    pub fn new_with_path(path: PathBuf, session_id: &str) -> Self {
        if let Some(parent) = path.parent() {
            if let Err(e) = DirBuilder::new().recursive(true).create(parent) {
                eprintln!("[AUDIT] WARN: Failed to create directory {:?}: {}", parent, e);
            }
        }

        let header = serde_json::json!({
            "event": "session_start",
            "timestamp_unix": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            "session_id": session_id
        });

        if let Ok(mut file) = OpenOptions::new().append(true).create(true).open(&path) {
            let _ = writeln!(file, "{}", header);
        }

        Self { path }
    }

    pub fn log(&self, record: AuditRecord) {
        let json_str = match serde_json::to_string(&record) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[AUDIT] ERROR: Failed to serialize audit record: {}", e);
                return;
            }
        };
        self.append_line(&json_str);
    }

    /// Appends a bare, unstructured event line — the same shape `new`/
    /// `new_with_path` already use for the `session_start` line, not
    /// `AuditRecord`'s full per-proposal structure. For registration-time
    /// events (discovery-time findings, one per server/tool, independent
    /// of any proposal ever being evaluated) that have no proposal_id,
    /// risk_class, or BP to report. `event` names the event type
    /// (`"pin_mismatch"`, `"schema_root_not_object"`,
    /// `"description_hit"`); `fields` carries whatever event-specific data
    /// is relevant, merged alongside `event` and `timestamp_unix`.
    ///
    /// Closes the same gap for all three registration-time findings that
    /// previously reached only stderr — a console line, easy to miss when
    /// the gateway runs as a silently-spawned background process, the
    /// common case for a desktop MCP client — not just the description-hit
    /// case this was added for.
    pub fn log_event(&self, event: &str, mut fields: serde_json::Map<String, serde_json::Value>) {
        fields.insert("event".to_string(), serde_json::Value::String(event.to_string()));
        fields.insert(
            "timestamp_unix".to_string(),
            serde_json::json!(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()),
        );
        self.append_line(&serde_json::Value::Object(fields).to_string());
    }

    fn append_line(&self, json_str: &str) {
        match OpenOptions::new().append(true).create(true).open(&self.path) {
            Ok(mut file) => {
                if let Err(e) = writeln!(file, "{}", json_str) {
                    eprintln!("[AUDIT] ERROR: Failed to write to audit log: {}", e);
                }
            }
            Err(e) => {
                eprintln!("[AUDIT] ERROR: Failed to open audit log at {:?}: {}", self.path, e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_audit_path() -> PathBuf {
        std::env::temp_dir()
            .join(format!("magus-audit-test-{}", uuid::Uuid::new_v4()))
            .join("audit.jsonl")
    }

    /// `log_event` must write the bare-event shape (event + timestamp_unix
    /// + whatever fields were passed), not `AuditRecord`'s full structure —
    /// confirmed by reading the actual file back, not just by not panicking.
    #[test]
    fn log_event_writes_bare_event_shape_with_custom_fields() {
        let path = temp_audit_path();
        let audit = AuditLogger::new_with_path(path.clone(), "test-session");

        let mut fields = serde_json::Map::new();
        fields.insert("server_id".to_string(), serde_json::json!("fake-server"));
        fields.insert("tool_name".to_string(), serde_json::json!("some_tool"));
        fields.insert("rule_ids".to_string(), serde_json::json!(["MCT-001"]));
        audit.log_event("description_hit", fields);

        let contents = std::fs::read_to_string(&path).expect("audit log file must exist and be readable");
        let lines: Vec<serde_json::Value> = contents
            .lines()
            .map(|l| serde_json::from_str(l).expect("each audit line must be valid JSON"))
            .collect();
        // First line is the session_start header written by new_with_path.
        let event = lines.iter().find(|r| r["event"] == "description_hit")
            .expect("description_hit event line must be present");

        assert_eq!(event["server_id"], "fake-server");
        assert_eq!(event["tool_name"], "some_tool");
        assert_eq!(event["rule_ids"], serde_json::json!(["MCT-001"]));
        assert!(event["timestamp_unix"].is_u64(), "timestamp_unix must be present and numeric");
    }

    /// Two different event types via the same helper must not clobber each
    /// other's fields — a real risk if `log_event` accidentally reused a
    /// shared mutable buffer instead of building a fresh Map per call.
    #[test]
    fn log_event_supports_multiple_distinct_event_types() {
        let path = temp_audit_path();
        let audit = AuditLogger::new_with_path(path.clone(), "test-session");

        let mut pin_fields = serde_json::Map::new();
        pin_fields.insert("expected".to_string(), serde_json::json!("aaa"));
        pin_fields.insert("actual".to_string(), serde_json::json!("bbb"));
        audit.log_event("pin_mismatch", pin_fields);

        let mut schema_fields = serde_json::Map::new();
        schema_fields.insert("tool_name".to_string(), serde_json::json!("weird_tool"));
        audit.log_event("schema_root_not_object", schema_fields);

        let contents = std::fs::read_to_string(&path).expect("audit log file must exist and be readable");
        let lines: Vec<serde_json::Value> = contents
            .lines()
            .map(|l| serde_json::from_str(l).expect("each audit line must be valid JSON"))
            .collect();

        let pin_event = lines.iter().find(|r| r["event"] == "pin_mismatch").expect("pin_mismatch event must be present");
        assert_eq!(pin_event["expected"], "aaa");
        assert!(pin_event.get("tool_name").is_none(), "pin_mismatch must not carry schema_root_not_object's fields");

        let schema_event = lines.iter().find(|r| r["event"] == "schema_root_not_object").expect("schema_root_not_object event must be present");
        assert_eq!(schema_event["tool_name"], "weird_tool");
        assert!(schema_event.get("expected").is_none(), "schema_root_not_object must not carry pin_mismatch's fields");
    }
}
