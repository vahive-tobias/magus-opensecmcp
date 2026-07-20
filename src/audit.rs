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
    pub status: String,
    pub rejection_code: Option<String>,
    pub provenance_state: ProvenanceState,
    pub effective_risk_class: RiskClass,
    pub bp_consumed: u32,
    pub r_abs_bp_after: u32,
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

    pub fn log(&self, record: AuditRecord) {
        let json_str = match serde_json::to_string(&record) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[AUDIT] ERROR: Failed to serialize audit record: {}", e);
                return;
            }
        };

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
