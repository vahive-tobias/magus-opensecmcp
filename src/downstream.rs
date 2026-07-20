// src/downstream.rs
//
// Transport: stdio, newline-delimited JSON-RPC, matching the framing already
// used on the agent-facing side of the gateway. One persistent child process
// per configured downstream server, spawned once at startup and kept alive
// for the life of the gateway.

use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use crate::hasher::McpToolDefinition;
use crate::registry::DownstreamServerConfig;

pub struct DownstreamConnection {
    #[allow(dead_code)] // held to keep the child alive; not read directly again
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    next_id: AtomicU64,
    pub server_id: String,
}

impl DownstreamConnection {
    /// Spawns the configured downstream command and performs the full MCP
    /// initialize handshake (initialize request -> notifications/initialized).
    /// Returns a connection ready for tools/list and tools/call.
    pub async fn spawn_and_initialize(config: &DownstreamServerConfig) -> Result<Self> {
        let mut cmd = Command::new(&config.command);
        cmd.args(&config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()); // downstream server's own logs pass through visibly

        let mut child = cmd
            .spawn()
            .with_context(|| format!("failed to spawn downstream server '{}' ({} {:?})",
                config.server_id, config.command, config.args))?;

        let stdin = child.stdin.take().ok_or_else(|| anyhow!("no stdin on child"))?;
        let stdout = child.stdout.take().ok_or_else(|| anyhow!("no stdout on child"))?;
        let reader = BufReader::new(stdout);

        let mut conn = Self {
            child,
            stdin,
            reader,
            next_id: AtomicU64::new(1),
            server_id: config.server_id.clone(),
        };

        conn.initialize().await.with_context(|| {
            format!("MCP initialize handshake failed for '{}'", config.server_id)
        })?;

        Ok(conn)
    }

    async fn initialize(&mut self) -> Result<()> {
        let init_result = self.request("initialize", json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "magus-opensecmcp", "version": env!("CARGO_PKG_VERSION") }
        })).await?;

        eprintln!(
            "[DOWNSTREAM:{}] Initialized. Server: {}",
            self.server_id,
            init_result.get("serverInfo").and_then(|s| s.get("name")).and_then(|n| n.as_str()).unwrap_or("unknown")
        );

        // Required by the MCP handshake: a notification (no id, no response expected)
        // must follow initialize before any other request is sent.
        self.notify("notifications/initialized", json!({})).await?;

        Ok(())
    }

    pub async fn list_tools(&mut self) -> Result<Vec<McpToolDefinition>> {
        let result = self.request("tools/list", json!({})).await?;
        let tools = result.get("tools").cloned().unwrap_or(Value::Array(vec![]));
        let defs: Vec<McpToolDefinition> = serde_json::from_value(tools)
            .context("failed to parse tools/list result into McpToolDefinition")?;
        Ok(defs)
    }

    /// Forwards an approved tools/call to the real server and returns the raw
    /// JSON result plus its serialized byte length (for provenance ingress
    /// accounting — the actual bytes that would enter the agent's context).
    pub async fn call_tool(&mut self, name: &str, arguments: Value) -> Result<(Value, usize)> {
        let result = self.request("tools/call", json!({
            "name": name,
            "arguments": arguments,
        })).await?;
        let bytes = serde_json::to_vec(&result).unwrap_or_default().len();
        Ok((result, bytes))
    }

    async fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let payload = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        self.write_line(&payload).await?;

        // Skip any notifications the server sends before the matching response
        // (e.g. logging notifications), and match on id in case of interleaving.
        loop {
            let line = self.read_line().await?;
            let msg: Value = serde_json::from_str(&line)
                .with_context(|| format!("downstream '{}' sent non-JSON line: {}", self.server_id, line))?;

            if msg.get("id").and_then(|v| v.as_u64()) == Some(id) {
                if let Some(err) = msg.get("error") {
                    return Err(anyhow!("downstream '{}' returned JSON-RPC error for {}: {}", self.server_id, method, err));
                }
                return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
            }
            // else: a notification or a response to a different in-flight id — ignore and keep reading.
        }
    }

    async fn notify(&mut self, method: &str, params: Value) -> Result<()> {
        let payload = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        self.write_line(&payload).await
    }

    async fn write_line(&mut self, value: &Value) -> Result<()> {
        let mut line = serde_json::to_string(value)?;
        line.push('\n');
        self.stdin.write_all(line.as_bytes()).await
            .with_context(|| format!("failed writing to downstream '{}'", self.server_id))?;
        self.stdin.flush().await?;
        Ok(())
    }

    async fn read_line(&mut self) -> Result<String> {
        let mut line = String::new();
        let bytes_read = self.reader.read_line(&mut line).await
            .with_context(|| format!("failed reading from downstream '{}'", self.server_id))?;
        if bytes_read == 0 {
            return Err(anyhow!("downstream '{}' closed its stdout (process exited)", self.server_id));
        }
        Ok(line.trim_end().to_string())
    }
}
