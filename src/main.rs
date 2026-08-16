// src/main.rs

use anyhow::{Context, Result};
use magus_opensecmcp::registry::{SourceGrade, ToolRegistry};
use magus_opensecmcp::rules_engine::{self, RuleEngine, Scope};
use magus_opensecmcp::schema_check;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use uuid::Uuid;

use magus_opensecmcp::advisory;
use magus_opensecmcp::audit::AuditLogger;
use magus_opensecmcp::downstream::{DownstreamConnection, DownstreamError};
use magus_opensecmcp::hasher::{compute_definition_hash, hash_to_hex, McpToolDefinition};
use magus_opensecmcp::membrane::{Membrane, Proposal};
use magus_opensecmcp::pin_policy::{self, PinStatus};
use magus_opensecmcp::provenance::{self, AgentProvenanceTracker, SchemaConformance};

const DEFAULT_MAX_AGENTS: usize = 3;
const DEFAULT_MONTHLY_EVAL_LIMIT: u32 = 5_000;

/// Everything discovery produces for one downstream server: real tool
/// definitions, plus the hash-pinning result for each.
struct DiscoveredServer {
    server_id: String,
    source_grade: SourceGrade,
    tools: Vec<McpToolDefinition>,
}

/// A confirmed hash-pin mismatch found during discovery, collected across
/// every server/tool so the `refuse_startup_on_pin_mismatch` decision (and
/// the summary printed for it) can see the complete picture, not just the
/// first one found — see spec-sec03-hash-pin-enforcement.md.
struct PinMismatch {
    server_id: String,
    tool_name: String,
    expected: String,
    actual: String,
}

/// F5 (see `docs/specs/Adversarial Review magus-opensecmcp.md`): a server
/// that never completed discovery at all — currently only reached via a
/// discovery-time timeout (`spawn_and_initialize`/`list_tools` exceeding
/// `discovery_timeout_seconds`), never via other spawn/handshake failures,
/// which keep failing the whole gateway startup exactly as before this
/// fix (see the phase-1 loop below for why that split is deliberate, not
/// partial). A fourth observability tier alongside `discovered`/
/// `discovered_with_issues`/`discovered_quarantined` — those three all
/// classify a TOOL; this classifies a SERVER that produced no tool list
/// to classify tools from at all.
struct FailedServer {
    server_id: String,
    reason: String,
}

/// Shared by both discovery-time timeout sites (`initialize`, `tools/list`)
/// in the phase-1 loop below — one place that logs, audits, and records
/// the failure, so the two call sites can't drift into slightly different
/// wording or an inconsistent audit event shape.
fn record_discovery_timeout(
    audit_logger: &AuditLogger,
    failed_servers: &mut Vec<FailedServer>,
    server_id: &str,
    phase: &str,
    elapsed: std::time::Duration,
    limit: std::time::Duration,
) {
    let reason = format!("{} timed out after {:.1}s (limit {:.1}s)", phase, elapsed.as_secs_f64(), limit.as_secs_f64());
    eprintln!(
        "[MAGUS] WARNING: downstream '{}' {} Excluding this server from discovery; other servers continue.",
        server_id, reason
    );
    audit_logger.log_event("downstream_timeout", serde_json::Map::from_iter([
        ("server_id".to_string(), serde_json::json!(server_id)),
        ("tool_name".to_string(), serde_json::Value::Null),
        ("phase".to_string(), serde_json::json!(phase)),
        ("elapsed_seconds".to_string(), serde_json::json!(elapsed.as_secs_f64())),
        ("limit_seconds".to_string(), serde_json::json!(limit.as_secs_f64())),
    ]));
    failed_servers.push(FailedServer { server_id: server_id.to_string(), reason });
}

/// Outcome of the tool-description rule scan at discovery time, cached for
/// consultation in `handle_tools_list`/`sanitize_description` — a separate
/// function, invoked on every `tools/list` request, potentially more than
/// once per session — rather than recomputed or (as before this change)
/// discarded immediately after the discovery-time `eprintln!`. Empty
/// `rule_ids` means no hit at all (the common case). Keyed by
/// `(server_id, tool_name)`, NOT tool name alone — this was already
/// correctly composite-keyed before F3 (below) fixed the SAME bug class
/// in `tool_owner`/`tool_output_schemas`; nothing here needed to change
/// for F3, only for F3 to not regress this file's one existing example of
/// getting the key right.
struct DescriptionHitOutcome {
    has_poison: bool,
    rule_ids: Vec<String>,
}

/// F3 (see `docs/specs/Adversarial Review magus-opensecmcp.md`): which
/// pipeline stage excluded a tool from the agent-facing tier, and why.
/// Quarantine (SEC-03) and name-collision exclusion (F3) are structurally
/// different reasons — a hash mismatch is about ONE server's tool being
/// untrusted; a collision is about TWO OR MORE servers' tools being
/// indistinguishable over the wire — but both need the same downstream
/// handling (excluded from `tools/list`/`tools/call`, one distinct
/// `magus_rejection_code`, one audit event, one line in the discovery
/// summary), so one shared record type carries both rather than two
/// parallel ad hoc structures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExclusionStage {
    Quarantine,
    NameCollision,
}

/// One tool excluded from the agent-facing tier, with the single
/// authoritative reason. "Single" is load-bearing: quarantine (phase 2)
/// runs strictly before collision detection (phase 3) specifically so a
/// tool that would have collided ANYWAY, but was already quarantined for
/// an unrelated reason, gets exactly one exclusion record
/// (`Quarantine`) — not a second, confusing `NameCollision` record on
/// top, and not a phantom collision against a name that's actually only
/// claimed by one surviving tool once the quarantined one is gone. See
/// the phase-3 resolution loop for the concrete case this ordering
/// prevents.
struct ToolExclusion {
    server_id: String,
    tool_name: String,
    stage: ExclusionStage,
    reason: String,
}

// `sanitize_description` reads `Option<&DescriptionHitOutcome>` and
// defaults a missing entry to "no hit" (`unwrap_or(false)` on both
// checks) — a fail-OPEN default for a security-relevant decision, worth
// being explicit about rather than leaving implicit: this is safe only
// because the discovery loop below inserts an entry, unconditionally, in
// BOTH branches (hit and no-hit) for every tool it processes, and
// `discovered`/`description_hits` are both immutable for the rest of the
// process after discovery finishes — there is no code path that adds a
// tool to `discovered` without also inserting its outcome here. If a
// future change ever adds a second way for a tool to reach
// `handle_tools_list` (e.g. dynamic re-discovery), this invariant needs
// re-checking, not assuming it still holds.

/// Parsed command line, before any of it has been acted on. `--version`/
/// `--help` used to be the only recognized flags, handled by a single-slot
/// `args().nth(1)` match — that shape can't represent
/// `magus-gateway config.yaml --discovery-report` (a flag that coexists
/// with a positional config path, in either order), so this replaces it
/// with a small manual parser over every argument. Deliberately not a CLI
/// crate dependency — the surface (three flags, one optional positional
/// argument) is far too small to justify one.
struct CliArgs {
    show_version: bool,
    show_help: bool,
    discovery_report: bool,
    config_path: String,
}

/// Splits on a leading `-`/`--` to distinguish a flag from the one
/// positional config-path argument, in either order. Fails closed on
/// anything it doesn't recognize — an unrecognized flag or a second
/// positional argument is a clear usage error, not silently ignored or
/// silently treated as the config path; a typo'd flag (`--discvery-report`)
/// silently doing nothing would be a worse failure mode than a startup
/// error naming the problem.
fn parse_args(raw_args: &[String]) -> Result<CliArgs, String> {
    let mut show_version = false;
    let mut show_help = false;
    let mut discovery_report = false;
    let mut config_path: Option<String> = None;

    for arg in raw_args {
        match arg.as_str() {
            "--version" | "-V" => show_version = true,
            "--help" | "-h" => show_help = true,
            "--discovery-report" => discovery_report = true,
            other if other.starts_with('-') => {
                return Err(format!("unrecognized flag: {}", other));
            }
            other => {
                if config_path.is_some() {
                    return Err(format!("unexpected extra argument: {} (only one config path is accepted)", other));
                }
                config_path = Some(other.to_string());
            }
        }
    }

    Ok(CliArgs {
        show_version,
        show_help,
        discovery_report,
        config_path: config_path.unwrap_or_else(|| "config.yaml".to_string()),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let raw_args: Vec<String> = std::env::args().skip(1).collect();
    let cli = match parse_args(&raw_args) {
        Ok(c) => c,
        Err(msg) => {
            eprintln!("[MAGUS] FATAL: {}", msg);
            eprintln!("[MAGUS] Usage: magus-gateway [config.yaml] [--discovery-report]");
            std::process::exit(1);
        }
    };

    if cli.show_version {
        println!("magus-gateway {}", env!("CARGO_PKG_VERSION"));
        std::process::exit(0);
    }
    if cli.show_help {
        println!("magus-gateway - a deterministic execution firewall for MCP agents.");
        println!();
        println!("Usage: magus-gateway [config.yaml] [--discovery-report]");
        println!();
        println!("  --discovery-report   Run discovery, print the tool availability");
        println!("                       summary to stdout, and exit before entering");
        println!("                       the agent-facing stdio loop.");
        std::process::exit(0);
    }

    let config_path = PathBuf::from(&cli.config_path);
    if !config_path.exists() {
        eprintln!("[MAGUS] FATAL: config file not found at {:?}", config_path);
        eprintln!("[MAGUS] Usage: magus-gateway [path/to/config.yaml]");
        std::process::exit(1);
    }

    // ---- Rule engine: loaded before anything else touches the network or
    //      spawns a child process, so a broken rules file is caught as
    //      early as possible, before any of that work happens.
    //
    //      Fail-closed by design, with no fallback path: if user-rules.yaml
    //      exists and is broken in any way, the gateway refuses to start.
    //      A silent downgrade to locked-only would leave an operator
    //      believing their custom rules were active when they weren't,
    //      which is a worse failure than not starting. A missing
    //      user-rules.yaml, by contrast, is a completely normal
    //      configuration and produces no error at all — see the three
    //      distinct outcomes logged below, which mirror the
    //      absent / present-and-matching / present-and-mismatched shape the
    //      hash-pin check already uses for tool definitions further down.
    let user_rules_path = config_path.parent().map(|dir| dir.join("user-rules.yaml"));
    let rule_engine = match RuleEngine::load(user_rules_path.as_deref()) {
        Ok(engine) => {
            if engine.had_user_rules {
                eprintln!(
                    "[MAGUS] Loaded user-rules.yaml: {} user rule(s), {} suppression(s). {} rule(s) active in total.",
                    engine.user_rule_count(),
                    engine.suppression_count(),
                    engine.total_rule_count()
                );
            } else {
                eprintln!(
                    "[MAGUS] No user-rules.yaml found at {} — running locked-rules.yaml only ({} rule(s)). \
                     This is a normal configuration, not a degraded one; see user-rules.example.yaml to add your own.",
                    user_rules_path
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "<none>".to_string()),
                    engine.total_rule_count()
                );
            }
            engine
        }
        Err(e) => {
            eprintln!("[MAGUS] FATAL: rule engine failed to load — refusing to start.");
            eprintln!("[MAGUS]   {}", e);
            for cause in e.chain().skip(1) {
                eprintln!("[MAGUS]     caused by: {}", cause);
            }
            eprintln!("[MAGUS]");
            eprintln!("[MAGUS]   There is no fallback mode. A gateway silently running with less");
            eprintln!("[MAGUS]   protection than configured is worse than one that won't start at all.");
            eprintln!("[MAGUS]   Fix the error above and restart. If the problem is in");
            eprintln!("[MAGUS]   user-rules.yaml and you want locked-rules.yaml only in the");
            eprintln!("[MAGUS]   meantime, delete or rename user-rules.yaml — that's a supported,");
            eprintln!("[MAGUS]   fully visible configuration, not a hidden degraded mode.");
            std::process::exit(1);
        }
    };

    let registry = ToolRegistry::load_from_yaml(&config_path)
        .context("Failed to load tool registry")?;
    eprintln!("[MAGUS] Loaded config. Downstream servers: {}", registry.servers.len());

    // ---- security_policy sanity check, before any discovery work happens.
    //      Checked here, not after discovery, specifically so a nonsensical
    //      config is refused without first spawning every downstream server
    //      for nothing — see pin_policy::validate_policy.
    if let Err(msg) = pin_policy::validate_policy(&registry.security_policy) {
        eprintln!("[MAGUS] FATAL: invalid security_policy configuration.");
        eprintln!("[MAGUS]   {}", msg);
        std::process::exit(2);
    }

    // ---- session_id / audit_logger, moved ahead of discovery (they used to
    //      live under "Core governance components" further down, after
    //      discovery finished). Neither depends on anything discovery
    //      produces — session_id is just a fresh UUID — and discovery now
    //      needs a working AuditLogger of its own, to close the same
    //      stderr-only gap for hash-pin mismatches, non-object outputSchema
    //      roots, and (new) tool-description rule hits, none of which
    //      persisted anywhere but the console before this change.
    let session_id = Uuid::new_v4().to_string();
    let audit_logger = Arc::new(AuditLogger::new(&session_id));

    // ==== PHASE 1: DISCOVER ====================================================
    // Spawn + initialize every configured downstream server, collect every
    // tool it advertises, compute pin status, description-hit outcome, and
    // schema info. Deliberately does NOT build tool_owner/tool_output_schemas
    // yet (that used to happen inline here, per-tool, with no collision
    // check at all — the F3 bug: whichever server was processed last in
    // config order silently won any bare-name collision). `discovered`
    // starts with EVERY tool from EVERY server, unfiltered — phases 2 and 3
    // below progressively narrow it to the agent-facing set.
    let mut connections: HashMap<String, Arc<Mutex<DownstreamConnection>>> = HashMap::new();
    let mut discovered: Vec<DiscoveredServer> = Vec::new();
    // Confirmed hash-pin mismatches, collected across every server/tool
    // during discovery. Acted on only after the full loop below completes —
    // see the refuse-startup / quarantine decision after it.
    let mut mismatches: Vec<PinMismatch> = Vec::new();
    // Tool-description rule-scan outcome, keyed (server_id, tool_name) — see
    // DescriptionHitOutcome. Consulted by handle_tools_list/
    // sanitize_description, not discarded after discovery the way it used
    // to be. Already correctly composite-keyed; F3 doesn't touch this.
    let mut description_hits: HashMap<(String, String), DescriptionHitOutcome> = HashMap::new();
    // F5: servers that never completed discovery at all — see
    // FailedServer's doc comment. Populated only by a discovery-time
    // timeout; every other spawn/handshake failure still propagates via
    // `?` and aborts the whole gateway exactly as before this fix (see
    // the two `DownstreamError::Other` arms below) — that behavior isn't
    // part of what F5 asked to change, and conflating "server timed out"
    // with "server's command doesn't exist"/"server sent garbage" would
    // blur two genuinely different failure classes into one fail-soft
    // path without that having been the actual finding.
    let mut failed_servers: Vec<FailedServer> = Vec::new();

    for server_cfg in &registry.servers {
        let discovery_timeout = Duration::from_secs_f64(
            server_cfg.discovery_timeout_seconds.unwrap_or(registry.security_policy.default_discovery_timeout_seconds),
        );
        eprintln!("[MAGUS] Spawning downstream '{}': {} {:?}", server_cfg.server_id, server_cfg.command, server_cfg.args);
        let mut conn = match DownstreamConnection::spawn_and_initialize(server_cfg, discovery_timeout).await {
            Ok(c) => c,
            Err(DownstreamError::Timeout { elapsed, limit }) => {
                record_discovery_timeout(&audit_logger, &mut failed_servers, &server_cfg.server_id, "initialize", elapsed, limit);
                continue;
            }
            Err(DownstreamError::Other(e)) => {
                return Err(e.context(format!("failed to bring up downstream server '{}'", server_cfg.server_id)));
            }
            Err(DownstreamError::Degraded) => {
                // Unreachable in practice (a freshly spawned connection is
                // never degraded), but DownstreamError is one shared type
                // across discovery and runtime — matched explicitly rather
                // than assumed away, so this stays a clean, traceable
                // error instead of a panic if that assumption is ever
                // wrong later.
                return Err(anyhow::anyhow!(
                    "unexpected: a freshly spawned connection for '{}' reported itself degraded",
                    server_cfg.server_id
                ));
            }
        };

        let tools = match conn.list_tools(discovery_timeout).await {
            Ok(t) => t,
            Err(DownstreamError::Timeout { elapsed, limit }) => {
                record_discovery_timeout(&audit_logger, &mut failed_servers, &server_cfg.server_id, "tools/list", elapsed, limit);
                continue;
            }
            Err(DownstreamError::Other(e)) => {
                return Err(e.context(format!("tools/list failed against '{}'", server_cfg.server_id)));
            }
            Err(DownstreamError::Degraded) => {
                return Err(anyhow::anyhow!(
                    "unexpected: connection for '{}' reported itself degraded during discovery",
                    server_cfg.server_id
                ));
            }
        };
        eprintln!("[MAGUS] '{}' advertises {} real tool(s).", server_cfg.server_id, tools.len());

        for t in &tools {
            let hash = compute_definition_hash(t);
            let hash_hex = hash_to_hex(&hash);
            let pin = registry.lookup(&server_cfg.server_id, &t.name).pinned_definition_hash_hex;
            let pin_status = PinStatus::from_pin(pin.as_deref(), &hash_hex);
            match &pin_status {
                PinStatus::Matched => {
                    eprintln!("[MAGUS] '{}'/{}: definition hash matches pin.", server_cfg.server_id, t.name);
                }
                PinStatus::Mismatched { expected, actual } => {
                    eprintln!(
                        "[MAGUS] WARNING: '{}'/{} definition hash does NOT match the pinned value in config.yaml.\n\
                         [MAGUS]   expected: {}\n\
                         [MAGUS]   actual:   {}\n\
                         [MAGUS]   The tool's description or schema changed since this was pinned. Treat this\n\
                         [MAGUS]   the same as an unreviewed new tool until you've confirmed the change is legitimate.",
                        server_cfg.server_id, t.name, expected, actual
                    );
                    audit_logger.log_event("pin_mismatch", serde_json::Map::from_iter([
                        ("server_id".to_string(), serde_json::json!(server_cfg.server_id)),
                        ("tool_name".to_string(), serde_json::json!(t.name)),
                        ("expected".to_string(), serde_json::json!(expected)),
                        ("actual".to_string(), serde_json::json!(actual)),
                    ]));
                    mismatches.push(PinMismatch {
                        server_id: server_cfg.server_id.clone(),
                        tool_name: t.name.clone(),
                        expected: expected.clone(),
                        actual: actual.clone(),
                    });
                }
                PinStatus::NotYetPinned => {
                    eprintln!("[MAGUS] '{}'/{}: no pin set yet. First-seen hash: {}", server_cfg.server_id, t.name, hash_hex);
                }
            }

            // Registration-time tool poisoning is a distinct threat from the
            // response-poisoning this proxy otherwise watches for: a
            // malicious or compromised downstream server can embed
            // instructions in a tool's own DESCRIPTION, aimed at the agent
            // reading tools/list, without the poisoned tool ever being
            // invoked. Same rule engine, same rules.yaml, different scope —
            // scan: tool_description rules only fire here.
            //
            // The scan outcome now has a real consequence, not just a
            // warning (see F4 in docs/specs/Adversarial Review
            // magus-opensecmcp.md and sanitize_description below): a
            // poison-tier hit withholds the description unconditionally; an
            // elevate/flag-tier hit sanitizes it for forwarding and, under
            // security_policy.strict_description_scanning, also withholds.
            // The outcome is cached here (description_hits), keyed
            // (server_id, tool_name), for handle_tools_list to consult —
            // it used to be computed and immediately discarded after the
            // eprintln! below.
            let normalized_desc = rules_engine::normalize_for_matching(&t.description);
            let desc_hits = rule_engine.scan(&normalized_desc, Scope::ToolDescription, &server_cfg.server_id);
            if !desc_hits.is_empty() {
                let has_poison = desc_hits.hits.iter().any(|h| h.action == rules_engine::Action::Poison);
                eprintln!(
                    "[MAGUS] WARNING: '{}'/{} tool DESCRIPTION matched {} rule(s), highest severity {:?}: [{}]. \
                     This is registration-time tool poisoning, not a response — the tool has not been called. \
                     {}",
                    server_cfg.server_id,
                    t.name,
                    desc_hits.hits.len(),
                    desc_hits.max_severity().expect("non-empty summary has a max severity"),
                    desc_hits.rule_ids().join(", "),
                    if has_poison {
                        "Poison-tier: description withheld from tools/list unconditionally."
                    } else {
                        "Description sanitized for forwarding; withheld too if strict_description_scanning is set."
                    }
                );
                audit_logger.log_event("description_hit", serde_json::Map::from_iter([
                    ("server_id".to_string(), serde_json::json!(server_cfg.server_id)),
                    ("tool_name".to_string(), serde_json::json!(t.name)),
                    ("rule_ids".to_string(), serde_json::json!(desc_hits.rule_ids())),
                    ("has_poison".to_string(), serde_json::json!(has_poison)),
                ]));
                description_hits.insert(
                    (server_cfg.server_id.clone(), t.name.clone()),
                    DescriptionHitOutcome { has_poison, rule_ids: desc_hits.rule_ids() },
                );
            } else {
                description_hits.insert(
                    (server_cfg.server_id.clone(), t.name.clone()),
                    DescriptionHitOutcome { has_poison: false, rule_ids: Vec::new() },
                );
            }

            // Flag at discovery time — not as a signature hit, just a
            // heads-up — if the server got the one structural rule the MCP
            // 2025-06-18 spec itself imposes wrong: outputSchema's root
            // must be `type: "object"`. Getting this wrong is far more
            // likely to be an unmaintained server than a malicious one, so
            // this stays a warning, not an elevation. The schema value
            // itself is NOT cached into a bare-name-keyed map here anymore
            // (that was the same F3 bug class as tool_owner) — it's still
            // sitting on `t.output_schema` inside `discovered`, and gets
            // promoted into `tool_output_schemas` in phase 3 below, only
            // for tools that actually survive to the clean tier.
            if let Some(schema) = &t.output_schema {
                if !schema_check::root_is_object_type(schema) {
                    eprintln!(
                        "[MAGUS] WARNING: '{}'/{} declares an outputSchema whose root is not type \"object\", \
                         which the MCP spec requires. Conformance checking for this tool may not behave as expected.",
                        server_cfg.server_id, t.name
                    );
                    audit_logger.log_event("schema_root_not_object", serde_json::Map::from_iter([
                        ("server_id".to_string(), serde_json::json!(server_cfg.server_id)),
                        ("tool_name".to_string(), serde_json::json!(t.name)),
                    ]));
                }
            }
        }

        connections.insert(server_cfg.server_id.clone(), Arc::new(Mutex::new(conn)));
        discovered.push(DiscoveredServer {
            server_id: server_cfg.server_id.clone(),
            source_grade: server_cfg.source_grade,
            tools,
        });
    }

    // ---- F5: decide what to do with the complete failed-discovery
    //      picture, now that every server has been attempted. Checked
    //      FIRST, ahead of the pin-mismatch decision below — a server
    //      that never completed discovery contributed zero mismatches to
    //      judge in the first place, so this is just the earliest point
    //      in the pipeline where "did discovery even finish for every
    //      configured server" is knowable at all.
    if registry.security_policy.refuse_startup_on_discovery_timeout && !failed_servers.is_empty() {
        eprintln!(
            "[MAGUS] FATAL: refuse_startup_on_discovery_timeout is set and {} server(s) failed to complete discovery:",
            failed_servers.len()
        );
        for f in &failed_servers {
            eprintln!("[MAGUS]   '{}': {}", f.server_id, f.reason);
        }
        std::process::exit(5);
    }

    // ---- Decide what to do with the complete pin-mismatch picture, now
    //      that discovery has finished for every server. Not done per-tool
    //      or per-server above — refuse_startup_on_pin_mismatch's summary
    //      needs to list every mismatch found anywhere in one pass, and
    //      security_policy's own validity was already checked before
    //      discovery ran at all.
    if registry.security_policy.refuse_startup_on_pin_mismatch && !mismatches.is_empty() {
        eprintln!(
            "[MAGUS] FATAL: refuse_startup_on_pin_mismatch is set and {} tool(s) failed hash-pin verification:",
            mismatches.len()
        );
        for m in &mismatches {
            eprintln!(
                "[MAGUS]   '{}'/{}: expected {}, got {}",
                m.server_id, m.tool_name, m.expected, m.actual
            );
        }
        std::process::exit(3);
    }

    // ==== PHASE 2: QUARANTINE (SEC-03, essentially unchanged) ==================
    // Runs strictly BEFORE phase 3's collision detection — load-bearing,
    // not a preference. If server A's tool is quarantined here for a pin
    // mismatch and server B has a clean tool of the same bare name,
    // removing A's tool from `discovered` FIRST means phase 3 below only
    // ever sees B's tool for that name — no collision at all, it just
    // works, with one exclusion record (Quarantine), not two overlapping
    // ones for the same underlying situation. Collision-detection-first
    // would have excluded B's tool too, for a "collision" that was never
    // real once A's was already gone for an unrelated reason.
    let mut discovered_quarantined: Vec<ToolExclusion> = Vec::new();
    if registry.security_policy.strict_schema_pinning {
        for m in &mismatches {
            let reason = format!("hash mismatch: expected {}, got {}", m.expected, m.actual);
            eprintln!("[MAGUS] QUARANTINED (hash mismatch) '{}'/{}: {}", m.server_id, m.tool_name, reason);
            if let Some(ds) = discovered.iter_mut().find(|d| d.server_id == m.server_id) {
                ds.tools.retain(|t| t.name != m.tool_name);
            }
            discovered_quarantined.push(ToolExclusion {
                server_id: m.server_id.clone(),
                tool_name: m.tool_name.clone(),
                stage: ExclusionStage::Quarantine,
                reason,
            });
        }
    }

    // ==== PHASE 3: RESOLVE (F3 — new) ===========================================
    // Walks the post-quarantine survivor set and groups by bare tool
    // name — the only field MCP's `tools/call` actually carries on the
    // wire, no `server_id`. A name still claimed by 2+ surviving tools is
    // structurally ambiguous: nothing about which server "should" win is
    // knowable from the protocol itself, so ALL claimants are excluded,
    // not just the extras. No tiebreak (first-registered-wins,
    // higher-SourceGrade-wins) — either would make config.yaml's
    // `downstream_servers:` ORDER (or grade) an implicit, easy-to-miss
    // security decision: a less-trusted server's tool could silently
    // shadow a more-trusted one just by how the file happens to be
    // written. Excluding the whole group is blunter but symmetric and
    // depends on nothing accidental.
    //
    // Two passes, deliberately: the first builds a read-only tally of
    // every surviving name's claimants; the second mutates `discovered`
    // using that tally. Interleaving them would mean a name's collision
    // status could depend on iteration order (has this claimant been
    // counted yet?) rather than the actual final count — a real
    // correctness bug this two-pass shape avoids by construction, not by
    // luck.
    let mut name_occurrences: HashMap<String, Vec<String>> = HashMap::new();
    for server in &discovered {
        for t in &server.tools {
            name_occurrences.entry(t.name.clone()).or_default().push(server.server_id.clone());
        }
    }

    let mut discovered_with_issues: Vec<ToolExclusion> = Vec::new();
    for server in &mut discovered {
        let server_id = server.server_id.clone();
        server.tools.retain(|t| {
            let claimants = &name_occurrences[&t.name];
            if claimants.len() <= 1 {
                return true; // unique among survivors — safe to keep
            }
            let others: Vec<&str> = claimants.iter().filter(|s| **s != server_id).map(|s| s.as_str()).collect();
            let reason = format!("also registered by server(s): {}", others.join(", "));
            eprintln!("[MAGUS] EXCLUDED (name collision) '{}'/{}: {}", server_id, t.name, reason);
            audit_logger.log_event("tool_name_collision", serde_json::Map::from_iter([
                ("server_id".to_string(), serde_json::json!(server_id)),
                ("tool_name".to_string(), serde_json::json!(t.name)),
                ("claimants".to_string(), serde_json::json!(claimants)),
            ]));
            discovered_with_issues.push(ToolExclusion {
                server_id: server_id.clone(),
                tool_name: t.name.clone(),
                stage: ExclusionStage::NameCollision,
                reason,
            });
            false
        });
    }

    // `refuse_startup_on_tool_name_collision` — the opt-in escalation on
    // top of the always-on "exclude, keep running" default above. No
    // `strict_...` prerequisite check needed here — see
    // pin_policy::validate_policy's doc comment for why that's confirmed,
    // not assumed. Checked here, once the complete post-resolution
    // picture is known, mirroring where refuse_startup_on_pin_mismatch is
    // checked relative to phase 1's mismatches.
    if registry.security_policy.refuse_startup_on_tool_name_collision && !discovered_with_issues.is_empty() {
        eprintln!(
            "[MAGUS] FATAL: refuse_startup_on_tool_name_collision is set and {} tool(s) were excluded for a bare-name collision:",
            discovered_with_issues.len()
        );
        for e in &discovered_with_issues {
            eprintln!("[MAGUS]   '{}'/{}: {}", e.server_id, e.tool_name, e.reason);
        }
        std::process::exit(4);
    }

    // NOW safe to build tool_owner/tool_output_schemas from bare names —
    // this is the ONE point in the pipeline where bare-name uniqueness has
    // actually been established by phase 3 above, not assumed the way it
    // was before F3. handle_tools_list and description_hits need ZERO
    // changes: they consume `discovered` directly and inherit correctness
    // for free once this phase guarantees it.
    let mut tool_owner: HashMap<String, String> = HashMap::new(); // tool_name -> server_id
    // tool_name -> declared outputSchema, for tools that have one. Consulted
    // in handle_tools_call to populate SchemaConformance instead of leaving
    // it at NotDeclared forever — see schema_check.rs for what "conformance"
    // does and doesn't mean here, and provenance.rs for how Violated feeds
    // the state machine.
    let mut tool_output_schemas: HashMap<String, serde_json::Value> = HashMap::new();
    for server in &discovered {
        for t in &server.tools {
            tool_owner.insert(t.name.clone(), server.server_id.clone());
            if let Some(schema) = &t.output_schema {
                tool_output_schemas.insert(t.name.clone(), schema.clone());
            }
        }
    }

    // Unified bare-name-keyed exclusion lookup for handle_tools_call's
    // rejection path — the ONE place a bare-name-keyed map is actually
    // safe here, PROVIDED it only holds names with no surviving owner.
    // Collision exclusions already guarantee that for free: phase 3's
    // retain() above removes every colliding entry from `discovered`
    // before tool_owner is built, so a name in discovered_with_issues can
    // never also be in tool_owner.
    //
    // Quarantine exclusions do NOT get that guarantee for free, and
    // inserting them unconditionally here was a real bug caught by this
    // module's own tests: quarantine removes one server's instance of a
    // name, not the name itself, so a second, clean server can still be
    // the name's sole surviving owner (tool_owner correctly routes to it)
    // while the quarantined instance's exclusion record for that same
    // bare name would otherwise still shadow it here and reject every
    // call before tool_owner is ever consulted. Skipping any quarantine
    // exclusion whose name already has an owner fixes that — the
    // quarantined instance itself is still fully reported in
    // discovered_quarantined for the summary/audit either way, this only
    // controls whether calling the bare name is blocked.
    let mut excluded_tools: HashMap<String, ToolExclusion> = HashMap::new();
    for exclusion in &discovered_quarantined {
        if tool_owner.contains_key(&exclusion.tool_name) {
            continue;
        }
        excluded_tools.insert(exclusion.tool_name.clone(), ToolExclusion {
            server_id: exclusion.server_id.clone(),
            tool_name: exclusion.tool_name.clone(),
            stage: exclusion.stage,
            reason: exclusion.reason.clone(),
        });
    }
    for exclusion in &discovered_with_issues {
        excluded_tools.insert(exclusion.tool_name.clone(), ToolExclusion {
            server_id: exclusion.server_id.clone(),
            tool_name: exclusion.tool_name.clone(),
            stage: exclusion.stage,
            reason: exclusion.reason.clone(),
        });
    }

    // One durable snapshot of the complete tier breakdown, rather than
    // something an operator has to reconstruct later by collecting the
    // scattered per-finding events above — cheap, since the classification
    // data already exists in memory at this point.
    let tool_count: usize = discovered.iter().map(|d| d.tools.len()).sum();
    audit_logger.log_event(
        "discovery_summary",
        discovery_summary_audit_fields(
            tool_count, discovered_quarantined.len(), discovered_with_issues.len(), failed_servers.len(),
        ),
    );

    let summary = discovery_summary(tool_count, &discovered_quarantined, &discovered_with_issues, &failed_servers);
    // The final tally, printed IN ADDITION to the per-finding warnings
    // already printed in real time above as each was discovered — this
    // doesn't replace those, it's the summary on top of them. Only the
    // headline line gets the "[MAGUS] " prefix every other line in this
    // file uses; the breakdown underneath is a clean, unprefixed block —
    // readable as a stand-alone report either here (stderr) or in
    // --discovery-report mode (stdout, see below), not something that
    // needs re-formatting to work in both places.
    eprintln!("[MAGUS] {}", summary.lines().collect::<Vec<_>>().join("\n"));

    // --discovery-report: recognized early (see parse_args) but
    // deliberately NOT an instant exit the way --version/--help are —
    // unlike those, this needs a REAL discovery pass (real spawned
    // servers, real computed hashes), so it pays the same startup cost
    // normal operation does and can only exit here, after phases 1-3
    // finish, at the exact point normal operation would otherwise print
    // "Gateway active..." and enter the stdio loop. Printed to STDOUT,
    // deliberately different from this file's stderr-only convention
    // everywhere else: the stdio loop never starts in this mode, so
    // stdout is never reserved for JSON-RPC traffic here, and stdout is
    // the more usable choice (redirectable, pipeable) once that's true.
    if cli.discovery_report {
        println!("{}", summary);
        std::process::exit(0);
    }

    // ---- Core governance components (session_id/audit_logger now
    //      constructed earlier, before discovery — see the comment there) ----
    let membrane = Arc::new(Mutex::new(Membrane::new(
        session_id.clone(),
        DEFAULT_MAX_AGENTS,
        DEFAULT_MONTHLY_EVAL_LIMIT,
        registry.security_policy.max_session_risk_bp,
    )));
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
            "tools/list" => Some(handle_tools_list(
                &id, &discovered, &description_hits, registry.security_policy.strict_description_scanning,
            )),
            "tools/call" => Some(handle_tools_call(
                &id, &json_rpc, &registry, &rule_engine, &tool_owner, &excluded_tools, &tool_output_schemas, &connections,
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

/// The end-of-discovery tally — shared between the always-on stderr
/// summary and `--discovery-report`'s stdout output, so the two modes
/// can never drift into showing different numbers. Exact wording is not
/// load-bearing (no test asserts on it byte-for-byte); the SHAPE is:
/// final tally line, then one section per non-empty exclusion tier, each
/// with a per-item line and a remediation hint.
fn discovery_summary(
    available_count: usize,
    quarantined: &[ToolExclusion],
    with_issues: &[ToolExclusion],
    failed_servers: &[FailedServer],
) -> String {
    let excluded_count = quarantined.len() + with_issues.len();
    let mut out = format!(
        "Discovery complete: {} tool(s) available to the agent, {} excluded, {} server(s) failed to complete discovery.\n",
        available_count, excluded_count, failed_servers.len()
    );

    if !with_issues.is_empty() {
        out.push_str(&format!(
            "\nDISCOVERED WITH ISSUES ({}) — name collision, not available to the agent:\n",
            with_issues.len()
        ));
        for e in with_issues {
            out.push_str(&format!("  {}/{}   ({})\n", e.server_id, e.tool_name, e.reason));
        }
        out.push_str(
            "  To fix: avoid running both servers together, or rename the conflicting\n\
             \x20\x20tool at the source. No in-band rename exists in v1 — that's a real\n\
             \x20\x20limitation, not a hidden option.\n",
        );
    }

    if !quarantined.is_empty() {
        out.push_str(&format!(
            "\nQUARANTINED ({}) — hash-pin mismatch, not available to the agent:\n",
            quarantined.len()
        ));
        for e in quarantined {
            out.push_str(&format!("  {}/{}  ({})\n", e.server_id, e.tool_name, e.reason));
        }
        out.push_str(
            "  To fix: review the change; if legitimate, update pinned_definition_hash_hex\n\
             \x20\x20in config.yaml.\n",
        );
    }

    if !failed_servers.is_empty() {
        out.push_str(&format!(
            "\nFAILED TO DISCOVER ({}) — server did not complete discovery, no tools available from it:\n",
            failed_servers.len()
        ));
        for f in failed_servers {
            out.push_str(&format!("  {}   ({})\n", f.server_id, f.reason));
        }
        out.push_str(
            "  To fix: check the server's own logs (passed through to this process's stderr);\n\
             \x20\x20increase discovery_timeout_seconds for it in config.yaml if it's just slow to\n\
             \x20\x20start, or fix/restart it if it's genuinely wedged.\n",
        );
    }

    out.trim_end().to_string()
}

/// The `discovery_summary` audit event's field set — extracted into its
/// own pure function for the same reason `discovery_summary` above is one:
/// directly unit-testable without spawning a real gateway process, which
/// an e2e test can't do for audit-log content anyway (`AuditLogger::new`
/// writes to the real `~/.magus/audit.jsonl` on whatever machine runs the
/// compiled binary, with no config-driven override — only
/// `AuditLogger::new_with_path`, `#[cfg(test)]`-only, can redirect it, and
/// only for in-process tests, not a spawned child process).
fn discovery_summary_audit_fields(
    available_count: usize,
    quarantined_count: usize,
    name_collision_count: usize,
    failed_server_count: usize,
) -> serde_json::Map<String, serde_json::Value> {
    serde_json::Map::from_iter([
        ("available_count".to_string(), serde_json::json!(available_count)),
        ("quarantined_count".to_string(), serde_json::json!(quarantined_count)),
        ("name_collision_count".to_string(), serde_json::json!(name_collision_count)),
        ("failed_server_count".to_string(), serde_json::json!(failed_server_count)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_args ----

    #[test]
    fn parse_args_defaults_to_config_yaml_with_no_args() {
        let cli = parse_args(&[]).expect("no args must parse successfully");
        assert_eq!(cli.config_path, "config.yaml");
        assert!(!cli.show_version && !cli.show_help && !cli.discovery_report);
    }

    #[test]
    fn parse_args_accepts_config_path_and_flag_in_either_order() {
        let a = parse_args(&["myconfig.yaml".to_string(), "--discovery-report".to_string()])
            .expect("config path then flag must parse");
        assert_eq!(a.config_path, "myconfig.yaml");
        assert!(a.discovery_report);

        let b = parse_args(&["--discovery-report".to_string(), "myconfig.yaml".to_string()])
            .expect("flag then config path must parse");
        assert_eq!(b.config_path, "myconfig.yaml");
        assert!(b.discovery_report);
    }

    #[test]
    fn parse_args_rejects_an_unrecognized_flag() {
        assert!(parse_args(&["--nonsense".to_string()]).is_err(), "an unrecognized flag must fail closed, not be silently ignored");
    }

    #[test]
    fn parse_args_rejects_two_positional_arguments() {
        assert!(
            parse_args(&["one.yaml".to_string(), "two.yaml".to_string()]).is_err(),
            "a second positional argument must be rejected, not silently overwrite the first"
        );
    }

    // ---- discovery_summary ----

    fn exclusion(server_id: &str, tool_name: &str, stage: ExclusionStage, reason: &str) -> ToolExclusion {
        ToolExclusion { server_id: server_id.to_string(), tool_name: tool_name.to_string(), stage, reason: reason.to_string() }
    }

    #[test]
    fn discovery_summary_with_no_exclusions_has_no_tier_sections() {
        let summary = discovery_summary(5, &[], &[], &[]);
        assert!(summary.contains("5 tool(s) available to the agent, 0 excluded"));
        assert!(!summary.contains("QUARANTINED"));
        assert!(!summary.contains("DISCOVERED WITH ISSUES"));
        assert!(!summary.contains("FAILED TO DISCOVER"));
    }

    #[test]
    fn discovery_summary_includes_both_tiers_when_both_are_present() {
        let quarantined = vec![exclusion("srv-a", "move_file", ExclusionStage::Quarantine, "hash mismatch: expected X, got Y")];
        let with_issues = vec![
            exclusion("srv-b", "search", ExclusionStage::NameCollision, "also registered by server(s): srv-c"),
            exclusion("srv-c", "search", ExclusionStage::NameCollision, "also registered by server(s): srv-b"),
        ];
        let summary = discovery_summary(3, &quarantined, &with_issues, &[]);

        assert!(summary.contains("3 tool(s) available to the agent, 3 excluded"));
        assert!(summary.contains("QUARANTINED (1)"));
        assert!(summary.contains("srv-a/move_file"));
        assert!(summary.contains("DISCOVERED WITH ISSUES (2)"));
        assert!(summary.contains("srv-b/search"));
        assert!(summary.contains("srv-c/search"));
    }

    // ---- discovery_summary: F5 failed-servers tier ----

    #[test]
    fn discovery_summary_includes_failed_servers_section() {
        let failed = vec![FailedServer {
            server_id: "srv-hung".to_string(),
            reason: "initialize timed out after 15.0s (limit 15.0s)".to_string(),
        }];
        let summary = discovery_summary(4, &[], &[], &failed);

        assert!(summary.contains("4 tool(s) available to the agent, 0 excluded, 1 server(s) failed to complete discovery"));
        assert!(summary.contains("FAILED TO DISCOVER (1)"));
        assert!(summary.contains("srv-hung"));
        assert!(summary.contains("initialize timed out"));
    }

    // ---- discovery_summary_audit_fields ----

    #[test]
    fn discovery_summary_audit_fields_has_the_expected_shape() {
        let fields = discovery_summary_audit_fields(11, 1, 2, 3);
        assert_eq!(fields.get("available_count"), Some(&serde_json::json!(11)));
        assert_eq!(fields.get("quarantined_count"), Some(&serde_json::json!(1)));
        assert_eq!(fields.get("name_collision_count"), Some(&serde_json::json!(2)));
        assert_eq!(fields.get("failed_server_count"), Some(&serde_json::json!(3)));
    }
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
/// static v1 trust grade AND, now, that specific tool's own
/// discovery-time description-scan outcome (see `DescriptionHitOutcome`,
/// `sanitize_description`). This used to unconditionally return `[]`.
fn handle_tools_list(
    id: &serde_json::Value,
    discovered: &[DiscoveredServer],
    description_hits: &HashMap<(String, String), DescriptionHitOutcome>,
    strict_description_scanning: bool,
) -> serde_json::Value {
    let mut tools = Vec::new();
    for server in discovered {
        for t in &server.tools {
            let outcome = description_hits.get(&(server.server_id.clone(), t.name.clone()));
            tools.push(serde_json::json!({
                "name": t.name,
                "description": sanitize_description(&t.description, server.source_grade, outcome, strict_description_scanning),
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

/// Attested/Known grades pass descriptions through `sanitize_for_forwarding`
/// (safe even on an ordinary description that never had any tag/zero-width
/// content — deleting nothing is a no-op). Unvalidated/Suspicious get the
/// name and schema but the description text withheld UNCONDITIONALLY,
/// regardless of scan outcome, since an unreviewed server's prose is the
/// cheapest place to hide an instruction aimed at the agent, not the
/// human — unchanged from before this change.
///
/// On top of that existing grade-based gate, a tool-description rule hit
/// now has its own consequence for Attested/Known descriptions,
/// independent of source grade (see F4 in `docs/specs/Adversarial Review
/// magus-opensecmcp.md`): a `poison`-tier hit withholds the description
/// unconditionally — the same zero-corroboration standard `poison`
/// already gets everywhere else in this codebase, applied consistently
/// here rather than as a new, harsher rule. An `elevate`/`flag`-tier hit
/// is sanitized (which already happens to every Attested/Known
/// description regardless of hits) and, only when
/// `security_policy.strict_description_scanning` is set, also withheld.
///
/// The withheld message reuses the EXACT shape the Unvalidated/Suspicious
/// case already uses (`[Description withheld - ...]`, name and schema
/// still visible, tool still fully callable) — this is NOT SEC-03's
/// quarantine shape (full removal from `tools/list`). The payload lives
/// in the prose, not the name or schema, so the response stays scoped to
/// the prose. The reason clause deliberately does not name which rule(s)
/// matched or reproduce the matched text — that detail lives in
/// `audit.jsonl` and the discovery-time `eprintln!`, not in a field
/// handed back to the same agent whose context this is trying to protect.
fn sanitize_description(
    raw: &str,
    grade: SourceGrade,
    hit_outcome: Option<&DescriptionHitOutcome>,
    strict_description_scanning: bool,
) -> String {
    if matches!(grade, SourceGrade::Unvalidated | SourceGrade::Suspicious) {
        return format!("[Description withheld - source grade: {:?}. Name and schema only.]", grade);
    }

    let has_poison = hit_outcome.map(|o| o.has_poison).unwrap_or(false);
    let has_hit = hit_outcome.map(|o| !o.rule_ids.is_empty()).unwrap_or(false);

    if has_poison {
        return "[Description withheld - matched a poison-tier detection rule. Name and schema only.]".to_string();
    }
    if has_hit && strict_description_scanning {
        return "[Description withheld - matched a detection rule under strict_description_scanning. \
                 Name and schema only.]".to_string();
    }

    sanitize_for_forwarding(raw)
}

/// Removes content with no legitimate reason to reach a model's context as
/// part of a tool description. A NEW primitive, distinct in kind from
/// `rules_engine::normalize_for_matching` — not a reuse of it, and
/// deliberately not: `normalize_for_matching`'s job is to DECODE
/// obfuscation back into visible form so a detector can see through it;
/// reusing that here would be wrong in the opposite direction. A
/// Tag-block-smuggled instruction, decoded back to plain ASCII and then
/// forwarded, goes from invisible-but-present to fully readable — worse,
/// not better. The forwarding-safe operation is DELETE, not decode —
/// there is no legitimate reason a tool description needs Tag-block
/// codepoints or zero-width characters to reach a model at all. This
/// function's job is "what's safe to hand to a model," not "what does
/// this text actually say" — the opposite of the detection pipeline's
/// job.
///
/// `delete_unicode_tags` is the one genuinely new primitive (a sibling to
/// `normalize_for_matching`'s `decode_unicode_tags` that removes the
/// codepoints instead of revealing them). `strip_zero_width` is reused
/// as-is from the same module — a zero-width character has no legitimate
/// reason to reach a model either, so the detection-side deletion is
/// already forwarding-safe. `strip_formatting` is this file's own,
/// unchanged, pre-existing angle-bracket stripper. Known, pre-existing,
/// NOT-in-scope-here limitation: `strip_formatting`'s angle-bracket
/// stripping is a blunt instrument that already mangles legitimate
/// `<`/`>` content in descriptions — carried forward unchanged, not
/// something to fix as part of this.
///
/// Ordering, traced rather than assumed (`normalize_for_matching` has an
/// explicit ordering requirement — tag-block decode before whitespace
/// collapse, since a decoded tag character can itself become a space —
/// so this composition's own ordering needed the same scrutiny, not a
/// free pass because it looks similar): `delete_unicode_tags` and
/// `strip_zero_width` commute freely here, unlike
/// `normalize_for_matching`'s decode step. Decoding can PRODUCE new
/// characters (including spaces) that a later step needs to see;
/// deletion only ever REMOVES characters, so running these two deletions
/// in either order yields the same result. `strip_formatting` runs last
/// because it performs its own whitespace normalization as a final
/// cleanup step, the same reason it's last in behavior even though
/// nothing upstream of it could reorder unsafely.
fn sanitize_for_forwarding(raw: &str) -> String {
    let no_tags = rules_engine::delete_unicode_tags(raw);
    let no_zero_width = rules_engine::strip_zero_width(&no_tags);
    strip_formatting(&no_zero_width)
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
    rule_engine: &RuleEngine,
    tool_owner: &HashMap<String, String>,
    excluded_tools: &HashMap<String, ToolExclusion>,
    tool_output_schemas: &HashMap<String, serde_json::Value>,
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

    // Checked before the tool_owner lookup, deliberately: an agent that
    // already knows this tool's name (cached from an earlier session, or
    // from documentation) and calls it directly must get a distinct,
    // specific rejection, not a generic "Unknown tool" that makes it look
    // like the tool never existed. Two distinct stages, two distinct
    // rejection codes — "ToolQuarantinedPinMismatch" must survive
    // byte-for-byte unchanged (pin_enforcement.rs asserts on it directly);
    // "ToolExcludedNameCollision" is new for F3.
    if let Some(exclusion) = excluded_tools.get(tool_name) {
        let (code, prefix) = match exclusion.stage {
            ExclusionStage::Quarantine => ("ToolQuarantinedPinMismatch", "Tool quarantined"),
            ExclusionStage::NameCollision => ("ToolExcludedNameCollision", "Tool excluded"),
        };
        return jsonrpc_error(
            id,
            -32602,
            &format!("{}: {}", prefix, exclusion.reason),
            Some(code),
        );
    }

    let mcp_server_id = match tool_owner.get(tool_name) {
        Some(s) => s.clone(),
        None => return jsonrpc_error(id, -32602, "Unknown tool", Some("UnknownTool")),
    };

    let entry = registry.lookup(&mcp_server_id, tool_name);
    // Resolved here, once, and reused below at the compute_new_state call
    // site too — not a second lookup. Also feeds Proposal.source_grade for
    // membrane.rs's Unvalidated BP surcharge (see
    // docs/specs/spec-provenance-semantics-correction.md §4).
    let server_grade = registry.server_config(&mcp_server_id)
        .map(|c| c.source_grade)
        .unwrap_or_default();
    let mut tracker = provenance_tracker.lock().await;
    let proposal = Proposal {
        id: Uuid::new_v4().to_string(),
        risk_class: entry.risk_class,
        authority_source: entry.authority_source,
        // Gate on Contaminated, not Elevated: under the corrected semantics,
        // Contaminated means heuristic evidence actually fired (a rule hit),
        // never just "external content was read" — Elevated is that normal
        // resting state, so gating on it would reject nearly every call
        // shortly after session start. See
        // docs/specs/spec-provenance-semantics-correction.md.
        external_content_influence: tracker.current_state == provenance::ProvenanceState::Contaminated,
        communicates_externally: entry.communicates_externally,
        source_grade: server_grade,
        mcp_server_id: mcp_server_id.clone(),
        tool_name: tool_name.to_string(),
        bootstrap: entry.bootstrap,
    };

    let mut mem = membrane.lock().await;
    let eval_result = mem.evaluate(&proposal, connection_id, &mut tracker, audit_logger);
    drop(mem);

    match eval_result {
        Ok(()) => {
            // GOVERNANCE APPROVED. Forward to the REAL downstream server.
            //
            // F5 (see docs/specs/Adversarial Review magus-opensecmcp.md):
            // note where this sits relative to `mem.evaluate` above —
            // governance has ALREADY run and its BP/provenance-state
            // effects have ALREADY landed by the time this call is even
            // attempted, exactly as for any other downstream outcome
            // (success, ExecutionFailed). A timeout or a degraded-refusal
            // below adds NOTHING further to provenance/Membrane — neither
            // `record_response_outcome` nor `ingest_signature` nor the
            // SEC-01 advisory injection are reachable outside the `Ok`
            // arm's success path. That's the hard boundary the finding
            // requires (a timeout is an absence, not evidence about
            // content, and has no calibration basis the way a rule hit
            // does) — satisfied structurally here, not by a special case.
            let conn_arc = match connections.get(&mcp_server_id) {
                Some(c) => c.clone(),
                None => return jsonrpc_error(id, -32002, "Downstream connection missing", None),
            };
            let call_timeout = Duration::from_secs_f64(
                entry.timeout_seconds.unwrap_or(registry.security_policy.default_tool_timeout_seconds),
            );
            let mut conn = conn_arc.lock().await;
            let call_result = conn.call_tool(tool_name, arguments, call_timeout).await;
            drop(conn);

            match call_result {
                Ok(mut real_result) => {
                    let raw_bytes = serde_json::to_vec(&real_result).unwrap_or_default();
                    let (form, _sc, long_sc, total_bytes, combined_text) = provenance::classify_response(&raw_bytes);
                    // No downstream-declared output schema means this stays
                    // NotDeclared, same as before. When a schema IS
                    // declared, the spec says the response must carry a
                    // sibling `structuredContent` field validated against
                    // it — but real-world servers are inconsistent about
                    // actually populating that even when they declare the
                    // schema (documented behavior, not a v1 guess). A
                    // present structuredContent that fails to conform is a
                    // real signal (-> Violated -> Poisoned, unchanged from
                    // before). An ABSENT structuredContent when a schema was
                    // declared deliberately stays NotDeclared rather than
                    // Violated: penalizing every server that hasn't caught
                    // up to the newer spec revision would make this feature
                    // noisy against legitimate tools, not precise against
                    // malicious ones.
                    let schema_conformance = match tool_output_schemas.get(tool_name) {
                        Some(schema) => match real_result.get("structuredContent") {
                            Some(structured) if schema_check::conforms(schema, structured) => {
                                SchemaConformance::Conformant
                            }
                            Some(_) => SchemaConformance::Violated,
                            None => SchemaConformance::NotDeclared,
                        },
                        None => SchemaConformance::NotDeclared,
                    };

                    // Structural signals (source grade, response shape, size,
                    // schema conformance) and pattern-hit signals (rules.yaml)
                    // are computed independently and combined by taking the
                    // max — see provenance.rs for why they're kept separate.
                    let structural_state = provenance::compute_new_state(
                        server_grade, form, schema_conformance, total_bytes, long_sc,
                    );

                    let normalized = rules_engine::normalize_for_matching(&combined_text);
                    let hit_summary = rule_engine.scan(&normalized, Scope::ToolOutputOnly, &mcp_server_id);
                    let hit_state = provenance::state_from_rule_hits(&hit_summary, tracker.current_state);

                    let new_state = structural_state.max(hit_state);
                    // Captured before ingest_signature so the "did THIS
                    // response actually escalate anything" check below is
                    // exact, not approximate: ingest_signature already only
                    // mutates current_state on a strict increase (see its
                    // own doc comment), so comparing before/after here is
                    // reading that existing semantics, not adding a second,
                    // separate noise-suppression mechanism on top of it.
                    let state_before = tracker.current_state;

                    // record_response_outcome BEFORE ingest_signature —
                    // verified to matter for one specific transition, not
                    // merely a readability preference (see
                    // docs/specs/spec-f1-clean-call-decay.md; the spec's own
                    // "the order is provably arbitrary" framing did not
                    // survive a direct trace and is corrected here rather
                    // than copied — see this fix's report). Both functions
                    // are projections of the same `new_state`.
                    // ingest_signature only mutates `current_state` on
                    // strict escalation (`new_state > current_state`).
                    // record_response_outcome's reset branch
                    // (`new_state > Elevated`) never reads `current_state`
                    // for its core action, so ordering doesn't matter
                    // there. Its OTHER branch (`new_state <= Elevated`)
                    // reads `current_state` to pick which tier applies —
                    // and there is exactly one transition where
                    // ingest_signature's mutation would change that read: a
                    // session at `Clean` receiving `new_state == Elevated`.
                    // `ingest_signature` escalates `Clean -> Elevated` on
                    // that response; if `record_response_outcome` ran
                    // AFTER that escalation, it would see
                    // `current_state == Elevated` and incorrectly start
                    // counting THIS SAME escalating response as the first
                    // clean call toward decaying back out of `Elevated` —
                    // the response that just left `Clean` shouldn't also
                    // earn credit for returning to it. Running
                    // `record_response_outcome` FIRST avoids this: it sees
                    // `current_state == Clean` (no tier to decay from
                    // `Clean`, correctly a no-op), and the escalation
                    // happens afterward, unaffected. Every other
                    // transition is genuinely order-independent; this one
                    // is why the order is required, not just readable.
                    tracker.record_response_outcome(new_state);
                    tracker.ingest_signature(new_state, &mcp_server_id, &hit_summary.rule_ids());

                    // SEC-01: only inject when this specific call caused a
                    // genuine escalation, not on every subsequent call while
                    // the session merely remains at an already-elevated
                    // state — see advisory.rs for the tier fallback and its
                    // honesty distinction (tier 1 proven, tiers 2/3 reasoned
                    // extensions of the same principle).
                    if tracker.current_state > state_before {
                        let advisory_text = advisory::build_advisory_text(tracker.current_state, &hit_summary.rule_ids());
                        let tier = advisory::inject_advisory(&mut real_result, &advisory_text);

                        // Logged unconditionally — this is also the only
                        // audit trail provenance escalation itself has
                        // anywhere in this codebase, not just a record of
                        // which tier delivered the advisory. eprintln! is
                        // reserved for the two outcomes where delivery is
                        // doubtful or failed, pairing warn-with-audit the
                        // same way schema_root_not_object does above.
                        audit_logger.log_event("advisory_injection", serde_json::Map::from_iter([
                            ("server_id".to_string(), serde_json::json!(mcp_server_id)),
                            ("tool_name".to_string(), serde_json::json!(tool_name)),
                            ("tier".to_string(), serde_json::json!(tier)),
                            ("new_state".to_string(), serde_json::json!(tracker.current_state)),
                            ("rule_ids".to_string(), serde_json::json!(hit_summary.rule_ids())),
                        ]));
                        if matches!(tier, advisory::InjectionTier::ContentBlockShadowed | advisory::InjectionTier::NoSafeField) {
                            eprintln!(
                                "[MAGUS] WARNING: '{}'/{} caused the session's provenance state to escalate to \
                                 {:?}, but the in-band advisory could not be reliably delivered to the model in \
                                 this response's shape ({:?}). Enforcement is unaffected -- gating still fires;\n\
                                 [MAGUS]   only this notice may not reach the model.",
                                mcp_server_id, tool_name, tracker.current_state, tier
                            );
                        }
                    }

                    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": real_result })
                }
                // F5: DownstreamTimeout/DownstreamConnectionDegraded are
                // new, distinct rejection codes — matching the existing
                // ToolQuarantinedPinMismatch/ToolExcludedNameCollision
                // pattern rather than folding either into the pre-existing
                // generic ExecutionFailed, which stays exactly as it was
                // for every OTHER downstream failure (process exited,
                // malformed response, ...).
                Err(DownstreamError::Timeout { elapsed, limit }) => {
                    eprintln!(
                        "[MAGUS] Downstream call to '{}'/{} timed out after {:.1}s (limit {:.1}s).",
                        mcp_server_id, tool_name, elapsed.as_secs_f64(), limit.as_secs_f64()
                    );
                    audit_logger.log_event("downstream_timeout", serde_json::Map::from_iter([
                        ("server_id".to_string(), serde_json::json!(mcp_server_id)),
                        ("tool_name".to_string(), serde_json::json!(tool_name)),
                        ("phase".to_string(), serde_json::json!("runtime")),
                        ("elapsed_seconds".to_string(), serde_json::json!(elapsed.as_secs_f64())),
                        ("limit_seconds".to_string(), serde_json::json!(limit.as_secs_f64())),
                    ]));
                    jsonrpc_error(id, -32002, "Downstream call timed out", Some("DownstreamTimeout"))
                }
                Err(DownstreamError::Degraded) => {
                    eprintln!(
                        "[MAGUS] Downstream call to '{}'/{} rejected: connection degraded after repeated timeouts.",
                        mcp_server_id, tool_name
                    );
                    jsonrpc_error(
                        id, -32002,
                        "Downstream connection degraded after repeated timeouts; a gateway restart is required",
                        Some("DownstreamConnectionDegraded"),
                    )
                }
                Err(DownstreamError::Other(e)) => {
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
