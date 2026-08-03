// src/registry.rs

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

/// Policy defaults for F5 (downstream timeout enforcement — see
/// docs/specs/Adversarial Review magus-opensecmcp.md). Like the
/// CLEAN_CALLS_TO_DECAY_*/BP-surcharge constants elsewhere in this
/// codebase, these are deliberate policy judgment calls, not calibrated
/// against any dataset — there is no "correct" number of seconds a tool
/// call should be allowed to run, only a reasonable starting point an
/// operator can override per-tool (`timeout_seconds`) or per-server
/// (`discovery_timeout_seconds`). Discovery (`tools/list`) should be
/// near-instant on a healthy server, hence the much shorter default there
/// than for executing an arbitrary tool, whose legitimate duration varies
/// by orders of magnitude (a `run_tests` call and a `ping` call have
/// nothing in common timing-wise).
const DEFAULT_TOOL_TIMEOUT_SECONDS: f64 = 30.0;
const DEFAULT_DISCOVERY_TIMEOUT_SECONDS: f64 = 15.0;

fn default_tool_timeout_seconds() -> f64 {
    DEFAULT_TOOL_TIMEOUT_SECONDS
}

fn default_discovery_timeout_seconds() -> f64 {
    DEFAULT_DISCOVERY_TIMEOUT_SECONDS
}

/// Shared by both the global `security_policy` defaults and every
/// per-entry `timeout_seconds`/`discovery_timeout_seconds` override:
/// zero, negative, NaN, and infinite are all rejected, not just zero.
/// Zero was the finding's explicit example (it would resurrect exactly
/// the unbounded-hang bug this field exists to close, as a *supported*
/// configuration), but `f64` opens the door to other nonsense values a
/// `u64` couldn't express (a negative number, or a value that would make
/// `Duration::from_secs_f64` panic outright on NaN/infinity) — all of
/// them mean the same thing operationally: this is not a usable timeout,
/// so all are refused the same way, at the same validation point.
fn validate_timeout_value(seconds: f64, field_desc: &str) -> Result<(), String> {
    if !seconds.is_finite() || seconds <= 0.0 {
        return Err(format!(
            "{} must be a positive, finite number of seconds ({} is not) — a zero, negative, NaN, or \
             infinite timeout would mean \"wait forever\" (or crash), exactly the unbounded-hang behavior \
             this field exists to prevent.",
            field_desc, seconds
        ));
    }
    Ok(())
}

/// Risk classification for a tool call.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Deserialize, Serialize)]
pub enum RiskClass {
    Low,
    Medium,
    High,
    Critical,
}

/// Who or what is initiating the action.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Deserialize, Serialize)]
pub enum AuthoritySource {
    User,
    System,
    External,
}

/// Static, operator-set trust grade for a downstream server.
/// V1 has no promotion/demotion lifecycle (that's a v2 feature) — this is read
/// once from config.yaml at startup and held for the life of the process.
/// Defaults to Unvalidated if omitted, which is the safe default: a server you
/// haven't explicitly graded should not get the benefit of the doubt.
#[derive(Debug, PartialEq, Eq, Clone, Copy, Deserialize, Serialize, Default)]
pub enum SourceGrade {
    Attested,
    Known,
    #[default]
    Unvalidated,
    Suspicious,
}

/// Optional, top-level policy for how a discovery-time hash-pin mismatch is
/// handled. Absent entirely from `config.yaml` (or every field omitted)
/// deserializes to all-`false`, which is today's warn-only behavior,
/// unchanged — see `pin_policy.rs` and
/// `docs/specs/spec-sec03-hash-pin-enforcement.md`.
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct SecurityPolicy {
    #[serde(default)]
    pub strict_schema_pinning: bool,
    #[serde(default)]
    pub refuse_startup_on_pin_mismatch: bool,
    /// Escalates an elevate/flag-tier tool-description rule hit (from an
    /// Attested/Known-graded server) from sanitize-and-warn to full
    /// withholding — same shape as `strict_schema_pinning`, `false` by
    /// default (today's behavior, unchanged). A poison-tier description
    /// hit withholds unconditionally regardless of this flag; see
    /// `main.rs`'s `sanitize_description`.
    #[serde(default)]
    pub strict_description_scanning: bool,
    /// Escalates a discovered bare-tool-name collision (F3 — see
    /// `docs/specs/Adversarial Review magus-opensecmcp.md`) from "exclude
    /// both/all claimants, keep running" (always-on, unconditional — there
    /// is no coherent "warn but leave them working" middle state for a
    /// name two servers both claim, unlike a hash mismatch) to refusing
    /// startup entirely. `false` by default. Unlike
    /// `refuse_startup_on_pin_mismatch`, this has NO `strict_...`
    /// prerequisite — confirmed deliberately, not assumed, in
    /// `pin_policy::validate_policy`'s doc comment: the base "exclude"
    /// behavior this escalates isn't gated behind any flag, so there's no
    /// "escalation without its base" misconfiguration to reject the way
    /// `refuse_startup_on_pin_mismatch` needs `strict_schema_pinning`.
    #[serde(default)]
    pub refuse_startup_on_tool_name_collision: bool,
    /// F5 (see `docs/specs/Adversarial Review magus-opensecmcp.md`):
    /// global fallback for `tools:` entries that don't set their own
    /// `timeout_seconds`. Lives here rather than a new top-level
    /// `config.yaml` section — deliberate, not default-by-omission: this
    /// is the same "how long to wait before giving up" decision the rest
    /// of this struct's flags already gate, and two lone numbers didn't
    /// seem worth a whole new section just to avoid putting a numeric
    /// value next to boolean ones. See `validate_timeout_value` for what
    /// makes a value here rejected.
    #[serde(default = "default_tool_timeout_seconds")]
    pub default_tool_timeout_seconds: f64,
    /// Same reasoning as `default_tool_timeout_seconds`, for
    /// `downstream_servers:` entries that don't set their own
    /// `discovery_timeout_seconds`.
    #[serde(default = "default_discovery_timeout_seconds")]
    pub default_discovery_timeout_seconds: f64,
    /// Escalates a discovery-time timeout (F5) from "exclude just the
    /// failing server, keep starting with whatever else discovered
    /// successfully" (the always-on default — same "scope the damage,
    /// keep running" shape F3/SEC-03 already established, not a new one)
    /// to refusing startup entirely. `false` by default. Mirrors
    /// `refuse_startup_on_pin_mismatch`/`refuse_startup_on_tool_name_collision`'s
    /// naming and shape, but — like `refuse_startup_on_tool_name_collision`
    /// — needs no `strict_...` prerequisite: there's no partial-strictness
    /// middle tier for "did the server respond at all" the way there is
    /// for hash-pin comparison.
    #[serde(default)]
    pub refuse_startup_on_discovery_timeout: bool,
}

impl Default for SecurityPolicy {
    /// NOT derived, deliberately: `default_tool_timeout_seconds`/
    /// `default_discovery_timeout_seconds` need to land on the same
    /// non-zero policy defaults here as their `#[serde(default = ...)]`
    /// functions produce for a `config.yaml` that omits `security_policy:`
    /// entirely — a derived `Default` would silently give both `0.0`
    /// instead (a `bool`-shaped assumption baked into `#[derive(Default)]`
    /// that stopped holding the moment this struct grew numeric fields),
    /// which `pin_policy::validate_policy`'s new zero-timeout check would
    /// then reject for every caller that builds a `SecurityPolicy` via
    /// `..Default::default()` — including this file's own pre-existing
    /// test helpers, none of which are testing timeout behavior at all.
    fn default() -> Self {
        SecurityPolicy {
            strict_schema_pinning: false,
            refuse_startup_on_pin_mismatch: false,
            strict_description_scanning: false,
            refuse_startup_on_tool_name_collision: false,
            default_tool_timeout_seconds: DEFAULT_TOOL_TIMEOUT_SECONDS,
            default_discovery_timeout_seconds: DEFAULT_DISCOVERY_TIMEOUT_SECONDS,
            refuse_startup_on_discovery_timeout: false,
        }
    }
}

/// The configuration for a downstream MCP server connection.
#[derive(Debug, Clone, Deserialize)]
pub struct DownstreamServerConfig {
    pub server_id: String,
    pub transport: String, // "stdio" for now
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Static v1 trust grade. Defaults to Unvalidated — see SourceGrade::default().
    #[serde(default)]
    pub source_grade: SourceGrade,
    /// F5: optional per-server override for how long the discovery-time
    /// `initialize`/`tools/list` handshake may take before this server is
    /// excluded from discovery, falling back to
    /// `security_policy.default_discovery_timeout_seconds` when unset. See
    /// `downstream.rs`'s timeout wrapper and main.rs's phase-1 discovery
    /// loop.
    #[serde(default)]
    pub discovery_timeout_seconds: Option<f64>,
}

/// The raw YAML structure for a tool entry.
#[derive(Debug, Clone, Deserialize)]
struct YamlToolEntry {
    mcp_server_id: String,
    tool_name: String,
    risk_class: RiskClass,
    authority_source: AuthoritySource,
    /// Optional: pin the expected definition hash (hex-encoded blake3) for
    /// THIS tool specifically — a server has many tools, each with its own
    /// hash, so the pin has to live here, not on the server config. If
    /// present, a mismatch at discovery time is logged as a warning (v1:
    /// warn-only, not a hard block — see main.rs's discovery loop).
    #[serde(default)]
    pinned_definition_hash_hex: Option<String>,
    /// F5: optional per-tool override for how long a `tools/call` to THIS
    /// tool may run before it's rejected with `DownstreamTimeout`, falling
    /// back to `security_policy.default_tool_timeout_seconds` when unset.
    /// Per-tool, not per-server, deliberately — unlike a wedged
    /// connection (which affects every tool on it equally, hence the
    /// separate per-server consecutive-timeout tracking on
    /// `DownstreamConnection`), a legitimately long-running tool
    /// (`run_tests`) and a legitimately fast one (`ping`) on the SAME
    /// server can need very different ceilings.
    #[serde(default)]
    timeout_seconds: Option<f64>,
    /// OP-3 capability tag: does this tool communicate outside the local
    /// machine (network fetch, external API call, etc.)? Operator-declared
    /// only — never auto-detected. Defaults to `false`, so an existing
    /// `config.yaml` written before this field existed parses and behaves
    /// identically. See `membrane::modulate_risk_class` for what this
    /// actually does — a one-tier risk bump applied AFTER the provenance
    /// state table, not a new gate.
    #[serde(default)]
    communicates_externally: bool,
}

/// The root YAML file structure.
#[derive(Debug, Deserialize)]
struct YamlConfig {
    downstream_servers: Vec<DownstreamServerConfig>,
    #[serde(default)]
    tools: Vec<YamlToolEntry>,
    #[serde(default)]
    security_policy: SecurityPolicy,
}

/// The runtime representation of a tool in the registry.
#[derive(Debug, Clone)]
pub struct ToolRegistryEntry {
    pub mcp_server_id: String,
    pub tool_name: String,
    pub risk_class: RiskClass,
    pub authority_source: AuthoritySource,
    /// True if this entry was auto-created because no config.yaml entry existed
    /// for a tool the downstream server actually advertises (see §3.4 of the
    /// original Outbound Gateway design: bootstrap at a Medium ceiling, never
    /// silently at Low, never silently at Critical).
    pub bootstrap: bool,
    pub pinned_definition_hash_hex: Option<String>,
    pub communicates_externally: bool,
    /// F5: this tool's own `timeout_seconds` override, if `config.yaml`
    /// set one. `None` means "use `security_policy.default_tool_timeout_seconds`",
    /// same fallback shape as an unset `pinned_definition_hash_hex`.
    pub timeout_seconds: Option<f64>,
}

/// The in-memory tool registry.
pub struct ToolRegistry {
    entries: HashMap<(String, String), ToolRegistryEntry>,
    pub servers: Vec<DownstreamServerConfig>,
    pub security_policy: SecurityPolicy,
}

impl ToolRegistry {
    /// Loads the registry from a YAML file on disk.
    pub fn load_from_yaml(path: &Path) -> Result<Self> {
        let yaml_str = std::fs::read_to_string(path)
            .context(format!("Failed to read config file at {:?}", path))?;

        let config: YamlConfig = serde_yaml::from_str(&yaml_str)
            .context("Failed to parse YAML config")?;

        // F5: reject a nonsensical per-entry timeout override before
        // building anything from it — same "fail loud at load time, not
        // deep inside a discovery/dispatch path" shape the rest of this
        // function's error handling already uses. Checked here, not in
        // pin_policy::validate_policy, because these overrides live on
        // per-entry YAML structs this function already owns parsing for,
        // not on SecurityPolicy itself (which validate_policy does own —
        // see its own new zero-timeout checks for the two global
        // defaults).
        for tool in &config.tools {
            if let Some(seconds) = tool.timeout_seconds {
                validate_timeout_value(
                    seconds,
                    &format!("tools: entry for '{}'/{} timeout_seconds", tool.mcp_server_id, tool.tool_name),
                )
                .map_err(|msg| anyhow!(msg))?;
            }
        }
        for server in &config.downstream_servers {
            if let Some(seconds) = server.discovery_timeout_seconds {
                validate_timeout_value(
                    seconds,
                    &format!("downstream_servers: entry for '{}' discovery_timeout_seconds", server.server_id),
                )
                .map_err(|msg| anyhow!(msg))?;
            }
        }

        let mut entries = HashMap::new();
        for tool in config.tools {
            let key = (tool.mcp_server_id.clone(), tool.tool_name.clone());
            entries.insert(key, ToolRegistryEntry {
                mcp_server_id: tool.mcp_server_id,
                tool_name: tool.tool_name,
                risk_class: tool.risk_class,
                authority_source: tool.authority_source,
                bootstrap: false,
                pinned_definition_hash_hex: tool.pinned_definition_hash_hex,
                communicates_externally: tool.communicates_externally,
                timeout_seconds: tool.timeout_seconds,
            });
        }

        Ok(Self {
            entries,
            servers: config.downstream_servers,
            security_policy: config.security_policy,
        })
    }

    /// Looks up a tool by server_id and tool_name.
    /// If not found, returns a bootstrap entry at Medium risk / User authority —
    /// visible to the operator via `bootstrap: true` in audit records, so an
    /// unclassified tool is never silently under- or over-trusted.
    pub fn lookup(&self, server_id: &str, tool_name: &str) -> ToolRegistryEntry {
        self.entries
            .get(&(server_id.to_string(), tool_name.to_string()))
            .cloned()
            .unwrap_or_else(|| ToolRegistryEntry {
                mcp_server_id: server_id.to_string(),
                tool_name: tool_name.to_string(),
                risk_class: RiskClass::Medium,
                authority_source: AuthoritySource::User,
                bootstrap: true,
                pinned_definition_hash_hex: None,
                // Deliberately false, not guessed: bootstrap already applies
                // a Medium risk ceiling for an unclassified tool. Inventing
                // a capability claim here would be guessing at a
                // security-relevant property rather than defaulting
                // conservatively on a known one.
                communicates_externally: false,
                // None -> falls back to security_policy.default_tool_timeout_seconds,
                // same as any other tool with no explicit override.
                timeout_seconds: None,
            })
    }

    pub fn server_config(&self, server_id: &str) -> Option<&DownstreamServerConfig> {
        self.servers.iter().find(|s| s.server_id == server_id)
    }
}
