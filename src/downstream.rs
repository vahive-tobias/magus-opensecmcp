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
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};

use crate::hasher::McpToolDefinition;
use crate::registry::DownstreamServerConfig;

/// F5 (see docs/specs/Adversarial Review magus-opensecmcp.md): a second
/// consecutive timeout on the same server, after which every further call
/// is refused without attempting or waiting at all. A policy guess, like
/// the timeout durations themselves, not a measured value — there's no
/// dataset "2" is fit to, just the judgment that a single timeout could be
/// one slow call, but two in a row on the same connection is a genuine
/// signal something is actually wedged, not just momentarily slow.
const CONSECUTIVE_TIMEOUTS_TO_DEGRADE: u32 = 2;

/// Distinguishes a request timing out (or a connection already known to be
/// wedged) from every other downstream failure — spawn errors, malformed
/// JSON, the process exiting. main.rs needs to react to a timeout
/// differently at both discovery time (exclude just this server, keep
/// starting) and runtime (a distinct rejection code, and per-server
/// consecutive-timeout tracking), while every other error keeps behaving
/// exactly as it did before this type existed — `Other` wraps the same
/// `anyhow::Error` these methods used to return directly, so existing
/// `.context(...)` chains built inside this file are preserved unchanged.
pub enum DownstreamError {
    /// The request was sent (or, for `Degraded`'s sibling checks, would
    /// have been) but no matching response arrived within `limit`.
    Timeout { elapsed: Duration, limit: Duration },
    /// A prior consecutive-timeout streak on this connection already
    /// crossed `CONSECUTIVE_TIMEOUTS_TO_DEGRADE` — this call was refused
    /// without attempting any I/O at all, not even a fresh wait.
    Degraded,
    Other(anyhow::Error),
}

impl From<anyhow::Error> for DownstreamError {
    fn from(e: anyhow::Error) -> Self {
        DownstreamError::Other(e)
    }
}

impl std::fmt::Display for DownstreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DownstreamError::Timeout { elapsed, limit } => {
                write!(f, "timed out after {:.1}s (limit {:.1}s)", elapsed.as_secs_f64(), limit.as_secs_f64())
            }
            DownstreamError::Degraded => write!(
                f,
                "connection is degraded after {} consecutive timeout(s); refusing further calls without a gateway restart",
                CONSECUTIVE_TIMEOUTS_TO_DEGRADE
            ),
            DownstreamError::Other(e) => write!(f, "{}", e),
        }
    }
}

pub struct DownstreamConnection {
    #[allow(dead_code)] // held to keep the child alive; not read directly again
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<ChildStdout>,
    next_id: AtomicU64,
    pub server_id: String,
    /// F5: consecutive timeouts on THIS connection, reset to 0 by any
    /// successful `call_tool`. Only `call_tool` (runtime) advances this —
    /// discovery-time timeouts (`spawn_and_initialize`/`list_tools`) never
    /// touch it, since a server that never finished discovery is excluded
    /// outright and never reaches a state where "degraded" would mean
    /// anything (there's no connection left in `main.rs`'s `connections`
    /// map for it to apply to).
    consecutive_timeouts: u32,
    /// F5: once true, stays true for the rest of the process's life — no
    /// automatic recovery. See `call_tool`'s doc comment for why.
    degraded: bool,
}

impl DownstreamConnection {
    /// Spawns the configured downstream command and performs the full MCP
    /// initialize handshake (initialize request -> notifications/initialized).
    /// Returns a connection ready for tools/list and tools/call.
    ///
    /// `discovery_timeout` bounds the `initialize` request specifically
    /// (see `initialize`'s own doc comment for why `tools/list` gets its
    /// own separate, equally-sized timeout rather than sharing a combined
    /// budget).
    pub async fn spawn_and_initialize(config: &DownstreamServerConfig, discovery_timeout: Duration) -> Result<Self, DownstreamError> {
        let mut cmd = Command::new(&config.command);
        cmd.args(&config.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit()) // downstream server's own logs pass through visibly
            // F5: before timeouts existed, the only way a call ever gave up
            // on a connection was the process itself exiting (an IO/EOF
            // error) — there was no scenario where the gateway walked away
            // from a still-alive child. A discovery-time timeout changes
            // that: the server is excluded and this DownstreamConnection is
            // dropped immediately (never inserted into main.rs's
            // `connections` map), while the spawned process may still be
            // genuinely running (that's what "hung" means). Without
            // kill_on_drop, that process would be silently orphaned rather
            // than cleaned up. A runtime-degraded connection, by contrast,
            // stays in `connections` for the rest of the process's life and
            // is never dropped early, so this doesn't affect that path.
            .kill_on_drop(true);

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
            consecutive_timeouts: 0,
            degraded: false,
        };

        conn.initialize(discovery_timeout).await?;

        Ok(conn)
    }

    async fn initialize(&mut self, discovery_timeout: Duration) -> Result<(), DownstreamError> {
        let init_result = self.request_with_timeout("initialize", json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "magus-opensecmcp", "version": env!("CARGO_PKG_VERSION") }
        }), discovery_timeout).await?;

        eprintln!(
            "[DOWNSTREAM:{}] Initialized. Server: {}",
            self.server_id,
            init_result.get("serverInfo").and_then(|s| s.get("name")).and_then(|n| n.as_str()).unwrap_or("unknown")
        );

        // Required by the MCP handshake: a notification (no id, no response expected)
        // must follow initialize before any other request is sent. Not
        // timeout-wrapped: a notification never waits for a response, so
        // there's nothing for a timeout to bound.
        self.notify("notifications/initialized", json!({})).await?;

        Ok(())
    }

    /// `discovery_timeout` bounds THIS request alone, with its own fresh
    /// clock — not a remainder of whatever `initialize` used. F5's design
    /// applies the shared timeout wrapper uniformly per individual
    /// request rather than budgeting one combined allowance across the
    /// whole two-call handshake, specifically so the wrapping mechanism
    /// stays identical everywhere it's used (discovery's two calls,
    /// runtime's one) instead of `initialize`+`list_tools` needing
    /// special split-budget accounting no other call site has.
    pub async fn list_tools(&mut self, discovery_timeout: Duration) -> Result<Vec<McpToolDefinition>, DownstreamError> {
        let result = self.request_with_timeout("tools/list", json!({}), discovery_timeout).await?;
        let tools = result.get("tools").cloned().unwrap_or(Value::Array(vec![]));
        let defs: Vec<McpToolDefinition> = serde_json::from_value(tools)
            .context("failed to parse tools/list result into McpToolDefinition")?;
        Ok(defs)
    }

    /// Forwards an approved tools/call to the real server and returns the raw
    /// JSON result. Used to also return a serialized byte count alongside it
    /// for provenance ingress accounting (decay's old `egress_bytes`
    /// mechanism) — removed per docs/specs/spec-f1-clean-call-decay.md: that
    /// count was redundant with the separate serialization main.rs already
    /// performs for `classify_response`, and its only reader was the
    /// byte-threshold decay mechanism this fix replaced entirely.
    ///
    /// F5: checks `degraded` FIRST, before attempting any I/O — this is
    /// what makes a degraded connection "fail fast" rather than just
    /// "fail after another full wait." A single timeout does NOT degrade
    /// the connection (the caller gets its own fresh wait next time); a
    /// SECOND CONSECUTIVE one does, permanently for this process's life —
    /// no automatic recovery, restart required. A successful call resets
    /// the streak to zero, so one timeout followed by a success does not
    /// count toward degrading later. Deliberately does NOT retry the
    /// timed-out call itself, ever, on either the first or second
    /// timeout: most tools aren't idempotent (`write_file`, `move_file`,
    /// anything with a real side effect), and inventing an
    /// "idempotent/safe-to-retry" config property is explicitly out of
    /// scope for this fix — see the F5 finding's non-goals.
    pub async fn call_tool(&mut self, name: &str, arguments: Value, call_timeout: Duration) -> Result<Value, DownstreamError> {
        if self.degraded {
            return Err(DownstreamError::Degraded);
        }

        let result = self.request_with_timeout("tools/call", json!({
            "name": name,
            "arguments": arguments,
        }), call_timeout).await;

        match &result {
            Ok(_) => self.consecutive_timeouts = 0,
            Err(DownstreamError::Timeout { .. }) => {
                self.consecutive_timeouts += 1;
                if self.consecutive_timeouts >= CONSECUTIVE_TIMEOUTS_TO_DEGRADE {
                    self.degraded = true;
                }
            }
            // Any other error (process exited, malformed response, ...) is
            // a different failure class than "wedged" and doesn't touch
            // the timeout streak — out of scope for this fix to redefine.
            Err(_) => {}
        }

        result
    }

    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// The ONE shared timeout mechanism (F5 point 1) — `initialize`,
    /// `list_tools`, and `call_tool` all wrap their single request through
    /// this, rather than each reimplementing the same
    /// `tokio::time::timeout` composition.
    ///
    /// Known, deliberately out-of-scope limitation, traced rather than
    /// missed: tokio's `read_line` (inside `request`, below) is not fully
    /// cancellation-safe — if a timeout fires AFTER the downstream has
    /// started writing a response but BEFORE the newline is seen, the
    /// partial bytes already pulled into `read_line`'s local buffer are
    /// dropped along with the cancelled future, and the persistent
    /// `self.reader`'s stream position can end up desynced for whatever
    /// read comes next. F5's own design deliberately keeps reusing the
    /// SAME connection after a single (non-degrading) timeout — a
    /// respawn-on-any-timeout policy would eliminate this risk but was
    /// explicitly ruled out (see the non-goals: no automatic
    /// reconnection/respawn). In practice this window is narrow: a real
    /// MCP server, like this gateway's own `write_line`, almost always
    /// writes one JSON-RPC line via a single `write_all`+`flush`, so a
    /// mid-line split at the OS pipe level for a reasonably-sized response
    /// is rare. A genuinely hung server (writes nothing at all, the case
    /// these fixtures and this fix are actually built around) hits zero
    /// bytes read before cancellation and is never at risk. If desync
    /// does happen, the next read fails to parse as JSON and surfaces as
    /// an ordinary `Other` error (mapped to the pre-existing
    /// `ExecutionFailed` path) rather than a misrouted response to the
    /// wrong caller — a loud, safe failure, not a silent one — and two
    /// consecutive timeouts (which a desynced stream tends to keep
    /// producing) degrades the connection regardless, per the design
    /// above. Full desync-proofing (byte-accounting, forced respawn) is a
    /// real health-check/reconnect project, already out of scope here.
    async fn request_with_timeout(&mut self, method: &str, params: Value, limit: Duration) -> Result<Value, DownstreamError> {
        let start = Instant::now();
        match tokio::time::timeout(limit, self.request(method, params)).await {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(DownstreamError::Other(e)),
            Err(_elapsed) => Err(DownstreamError::Timeout { elapsed: start.elapsed(), limit }),
        }
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
