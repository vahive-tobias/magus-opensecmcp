// src/registry.rs

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

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
}

/// The root YAML file structure.
#[derive(Debug, Deserialize)]
struct YamlConfig {
    downstream_servers: Vec<DownstreamServerConfig>,
    #[serde(default)]
    tools: Vec<YamlToolEntry>,
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
}

/// The in-memory tool registry.
pub struct ToolRegistry {
    entries: HashMap<(String, String), ToolRegistryEntry>,
    pub servers: Vec<DownstreamServerConfig>,
}

impl ToolRegistry {
    /// Loads the registry from a YAML file on disk.
    pub fn load_from_yaml(path: &Path) -> Result<Self> {
        let yaml_str = std::fs::read_to_string(path)
            .context(format!("Failed to read config file at {:?}", path))?;

        let config: YamlConfig = serde_yaml::from_str(&yaml_str)
            .context("Failed to parse YAML config")?;

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
            });
        }

        Ok(Self {
            entries,
            servers: config.downstream_servers,
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
            })
    }

    pub fn server_config(&self, server_id: &str) -> Option<&DownstreamServerConfig> {
        self.servers.iter().find(|s| s.server_id == server_id)
    }
}
