// src/main.rs

mod audit;
mod downstream;
mod hasher;
mod membrane;
mod provenance;
mod quota;
mod registry;

use anyhow::{Context, Result};
use registry::{SourceGrade, ToolRegistry};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::audit::AuditLogger;
use crate::downstream::DownstreamConnection;
use crate::hasher::{compute_definition_hash, hash_to_hex, McpToolDefinition};
use crate::membrane::{Membrane, Proposal};
use crate::provenance::{AgentProvenanceTracker, SchemaConformance};

const FREE_TIER_MAX_AGENTS: usize = 3;
const DEFAULT_MONTHLY_EVAL_LIMIT: u32 = 5_000;

/// Everything discovery produces for one downstream server: real tool
/// definitions, plus the hash-pinning result for each.
#[allow(dead_code)]
struct DiscoveredServer {
    server_id: String,
    source_grade: SourceGrade,
    tools: Vec<McpToolDefinition>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "config.yaml".to_string()));
    if !config_path.exists() {
        eprintln!("[MAGUS] FATAL: config file not found at {:?}", config_path);
        eprintln!("[MAGUS] Usage: magus-gateway [path/to/config.yaml]");
        std::process::exit(1);
    }

    let registry = ToolRegistry::load_from_yaml(&config_path)
        .context("Failed to load tool registry")?;
    eprintln!("[MAGUS] Loaded config. Downstream servers: {}", registry.servers.len());

    // ---- Spawn + initialize every configured downstream server, discover its
    //      real tools, and hash-pin each definition. This is the step the
    //      original draft never did — nothing was ever actually connected to.
    let mut connections: HashMap<String, Arc<Mutex<DownstreamConnection>>> = HashMap::new();
    let mut discovered: Vec<DiscoveredServer> = Vec::new();
    let mut tool_owner: HashMap<String, String> = HashMap::new(); // tool_name -> server_id

    for server_cfg in &registry.servers {
        eprintln!("[MAGUS] Spawning downstream '{}': {} {:?}", server_cfg.server_id, server_cfg.command, server_cfg.args);
        let mut conn = DownstreamConnection::spawn_and_initialize(server_cfg).await
            .with_context(|| format!("failed to bring up downstream server '{}'", server_cfg.server_id))?;

        let tools = conn.list_tools().await
            .with_context(|| format!("tools/list failed against '{}'", server_cfg.server_id))?;
        eprintln!("[MAGUS] '{}' advertises {} real tool(s).", server_cfg.server_id, tools.len());

        for t in &tools {
            let hash = compute_definition_hash(t);
            let hash_hex = hash_to_hex(&hash);
            let pin = registry.lookup(&server_cfg.server_id, &t.name).pinned_definition_hash_hex;
            match &pin {
                Some(pinned) if pinned.eq_ignore_ascii_case(&hash_hex) => {
                    eprintln!("[MAGUS] '{}'/{}: definition hash matches pin.", server_cfg.server_id, t.name);
                }
                Some(pinned) => {
                    eprintln!(
                        "[MAGUS] WARNING: '{}'/{} definition hash does NOT match the pinned value in config.yaml.\n\
                         [MAGUS]   expected: {}\n\
                         [MAGUS]   actual:   {}\n\
                         [MAGUS]   The tool's description or schema changed since this was pinned. Treat this\n\
                         [MAGUS]   the same as an unreviewed new tool until you've confirmed the change is legitimate.",
                        server_cfg.server_id, t.name, pinned, hash_hex
                    );
                }
                None => {
                    eprintln!("[MAGUS] '{}'/{}: no pin set yet. First-seen hash: {}", server_cfg.server_id, t.name, hash_hex);
                }
            }
            tool_owner.insert(t.name.clone(), server_cfg.server_id.clone());
        }

        connections.insert(server_cfg.server_id.clone(), Arc::new(Mutex::new(conn)));
        discovered.push(DiscoveredServer {
            server_id: server_cfg.server_id.clone(),
            source_grade: server_cfg.source_grade,
            tools,
        });
    }

    // ---- Core governance components ----
    let session_id = Uuid::new_v4().to_string();
    let audit_logger = Arc::new(AuditLogger::new(&session_id));
    let membrane = Arc::new(Mutex::new(Membrane::new(session_id.clone(), FREE_TIER_MAX_AGENTS, DEFAULT_MONTHLY_EVAL_LIMIT)));
    let connection_id = Uuid::new_v4();
    {
        let mut mem = membrane.lock().await;
        if let Err(e) = mem.register_agent(connection_id) {
            eprintln!("[MAGUS] FATAL: could not register agent: {:?}", e);
            std::process::exit(1);
        }
    }
    let provenance_tracker = Arc::new(Mutex::new(AgentProvenanceTracker::new()));

    eprintln!("[MAGUS] Gateway active. Session {session_id}. Listening on stdio for MCP agent...");

    // ---- Agent-facing stdio JSON-RPC loop ----
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await?;
        if bytes_read == 0 { break; }
        let trimmed = line.trim();
        if trimmed.is_empty() { continue; }

        let json_rpc: serde_json::Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(_) => continue,
        };

        let method = json_rpc.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let id = json_rpc.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let is_notification = json_rpc.get("id").is_none();

        let response = match method {
            "initialize" => Some(handle_initialize(&id)),
            "notifications/initialized" => None, // agent's own handshake notification; nothing to send back
            "tools/list" => Some(handle_tools_list(&id, &discovered)),
            "tools/call" => Some(handle_tools_call(
                &id, &json_rpc, &registry, &tool_owner, &connections,
                &membrane, &provenance_tracker, &audit_logger, connection_id,
            ).await),
            _ if is_notification => None,
            _ => Some(serde_json::json!({
                "jsonrpc": "2.0", "id": id,
                "error": { "code": -32601, "message": "Method not found" }
            })),
        };

        if let Some(resp) = response {
            let resp_str = serde_json::to_string(&resp)? + "\n";
            stdout.write_all(resp_str.as_bytes()).await?;
            stdout.flush().await?;
        }
    }

    {
        let mut mem = membrane.lock().await;
        mem.deregister_agent(connection_id);
    }
    eprintln!("[MAGUS] Agent disconnected. Shutting down.");
    Ok(())
}

fn handle_initialize(id: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": { "tools": {} },
            "serverInfo": { "name": "magus-opensecmcp", "version": env!("CARGO_PKG_VERSION") }
        }
    })
}

/// Real tool discovery output, merged across every configured downstream
/// server, with descriptions sanitized according to that server's own
/// static v1 trust grade. This used to unconditionally return `[]`.
fn handle_tools_list(id: &serde_json::Value, discovered: &[DiscoveredServer]) -> serde_json::Value {
    let mut tools = Vec::new();
    for server in discovered {
        for t in &server.tools {
            tools.push(serde_json::json!({
                "name": t.name,
                "description": sanitize_description(&t.description, server.source_grade),
                "inputSchema": t.input_schema,
            }));
        }
    }
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": { "tools": tools }
    })
}

/// Attested/Known grades pass descriptions through (stripped of tag-looking
/// content); Unvalidated/Suspicious get the name and schema but the
/// description text withheld, since an unreviewed server's prose is the
/// cheapest place to hide an instruction aimed at the agent, not the human.
fn sanitize_description(raw: &str, grade: SourceGrade) -> String {
    match grade {
        SourceGrade::Attested | SourceGrade::Known => strip_formatting(raw),
        SourceGrade::Unvalidated | SourceGrade::Suspicious => {
            format!("[Description withheld - source grade: {:?}. Name and schema only.]", grade)
        }
    }
}

fn strip_formatting(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut in_tag = false;
    for c in text.chars() {
        match c {
            '<' => in_tag = true,
            '>' => { in_tag = false; result.push(' '); }
            _ if !in_tag => result.push(c),
            _ => {}
        }
    }
    result.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[allow(clippy::too_many_arguments)]
async fn handle_tools_call(
    id: &serde_json::Value,
    json_rpc: &serde_json::Value,
    registry: &ToolRegistry,
    tool_owner: &HashMap<String, String>,
    connections: &HashMap<String, Arc<Mutex<DownstreamConnection>>>,
    membrane: &Arc<Mutex<Membrane>>,
    provenance_tracker: &Arc<Mutex<AgentProvenanceTracker>>,
    audit_logger: &AuditLogger,
    connection_id: Uuid,
) -> serde_json::Value {
    let params = match json_rpc.get("params") {
        Some(p) => p,
        None => return jsonrpc_error(id, -32602, "Missing params", None),
    };
    let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
    let arguments = params.get("arguments").cloned().unwrap_or(serde_json::json!({}));

    let mcp_server_id = match tool_owner.get(tool_name) {
        Some(s) => s.clone(),
        None => return jsonrpc_error(id, -32602, "Unknown tool", Some("UnknownTool")),
    };

    let entry = registry.lookup(&mcp_server_id, tool_name);
    let egress_bytes = serde_json::to_vec(&arguments).map(|b| b.len()).unwrap_or(0);
    let proposal = Proposal {
        id: Uuid::new_v4().to_string(),
        risk_class: entry.risk_class,
        authority_source: entry.authority_source,
        external_content_influence: false,
        mcp_server_id: mcp_server_id.clone(),
        tool_name: tool_name.to_string(),
        bootstrap: entry.bootstrap,
        egress_bytes,
    };

    let mut mem = membrane.lock().await;
    let mut tracker = provenance_tracker.lock().await;
    let eval_result = mem.evaluate(&proposal, connection_id, &mut tracker, audit_logger);
    drop(mem);

    match eval_result {
        Ok(()) => {
            // GOVERNANCE APPROVED. Forward to the REAL downstream server.
            let conn_arc = match connections.get(&mcp_server_id) {
                Some(c) => c.clone(),
                None => return jsonrpc_error(id, -32002, "Downstream connection missing", None),
            };
            let mut conn = conn_arc.lock().await;
            let call_result = conn.call_tool(tool_name, arguments).await;
            drop(conn);

            match call_result {
                Ok((real_result, ingress_bytes)) => {
                    let raw_bytes = serde_json::to_vec(&real_result).unwrap_or_default();
                    let (form, _sc, long_sc, total_bytes, hits) = provenance::classify_response(&raw_bytes);
                    // No downstream-declared output schema is fetched in v1, so
                    // conformance is NotDeclared unless the response fails to
                    // parse at all (classify_response already returns Malformed
                    // for that case, which the state machine treats as Poisoned
                    // regardless of this field).
                    let schema_conformance = SchemaConformance::NotDeclared;

                    let server_grade = registry.server_config(&mcp_server_id)
                        .map(|c| c.source_grade)
                        .unwrap_or_default();

                    let new_state = provenance::compute_new_state(
                        server_grade, form, hits, schema_conformance, total_bytes, long_sc,
                    );
                    tracker.ingest_signature(new_state, ingress_bytes, &mcp_server_id);

                    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": real_result })
                }
                Err(e) => {
                    eprintln!("[MAGUS] Downstream call failed: {}", e);
                    jsonrpc_error(id, -32002, "Tool execution failed", Some("ExecutionFailed"))
                }
            }
        }
        Err(code) => jsonrpc_error(id, -32001, "Action blocked by governance policy", Some(code.as_str())),
    }
}

fn jsonrpc_error(id: &serde_json::Value, code: i64, message: &str, magus_code: Option<&str>) -> serde_json::Value {
    let mut data = serde_json::Map::new();
    if let Some(rc) = magus_code {
        data.insert("magus_rejection_code".to_string(), serde_json::Value::String(rc.to_string()));
    }
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message, "data": data }
    })
}
