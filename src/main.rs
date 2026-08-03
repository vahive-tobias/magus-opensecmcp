// src/main.rs

use anyhow::{Context, Result};
use magus_opensecmcp::registry::{SourceGrade, ToolRegistry};
use magus_opensecmcp::rules_engine::{self, RuleEngine, Scope};
use magus_opensecmcp::schema_check;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use uuid::Uuid;

use magus_opensecmcp::advisory;
use magus_opensecmcp::audit::AuditLogger;
use magus_opensecmcp::downstream::DownstreamConnection;
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

/// Outcome of the tool-description rule scan at discovery time, cached for
/// consultation in `handle_tools_list`/`sanitize_description` — a separate
/// function, invoked on every `tools/list` request, potentially more than
/// once per session — rather than recomputed or (as before this change)
/// discarded immediately after the discovery-time `eprintln!`. Empty
/// `rule_ids` means no hit at all (the common case). Keyed by
/// `(server_id, tool_name)`, NOT tool name alone, unlike `tool_owner`/
/// `tool_output_schemas`/`quarantined_tools` today (the still-open `F3`
/// finding) — this must not add a fourth instance of that bug.
struct DescriptionHitOutcome {
    has_poison: bool,
    rule_ids: Vec<String>,
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

#[tokio::main]
async fn main() -> Result<()> {
    let first_arg = std::env::args().nth(1);
    match first_arg.as_deref() {
        Some("--version") | Some("-V") => {
            println!("magus-gateway {}", env!("CARGO_PKG_VERSION"));
            std::process::exit(0);
        }
        Some("--help") | Some("-h") => {
            println!("magus-gateway - a deterministic execution firewall for MCP agents.");
            println!();
            println!("Usage: magus-gateway [config.yaml]");
            std::process::exit(0);
        }
        _ => {}
    }

    let config_path = PathBuf::from(first_arg.unwrap_or_else(|| "config.yaml".to_string()));
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

    // ---- Spawn + initialize every configured downstream server, discover its
    //      real tools, and hash-pin each definition. This is the step the
    //      original draft never did — nothing was ever actually connected to.
    let mut connections: HashMap<String, Arc<Mutex<DownstreamConnection>>> = HashMap::new();
    let mut discovered: Vec<DiscoveredServer> = Vec::new();
    let mut tool_owner: HashMap<String, String> = HashMap::new(); // tool_name -> server_id
    // tool_name -> declared outputSchema, for tools that have one. Consulted
    // in handle_tools_call to populate SchemaConformance instead of leaving
    // it at NotDeclared forever — see schema_check.rs for what "conformance"
    // does and doesn't mean here, and provenance.rs for how Violated feeds
    // the state machine (it already did before this change; only the
    // population of the value was missing).
    let mut tool_output_schemas: HashMap<String, serde_json::Value> = HashMap::new();
    // Confirmed hash-pin mismatches, collected across every server/tool
    // during discovery. Acted on only after the full loop below completes —
    // see the refuse-startup / quarantine decision after it.
    let mut mismatches: Vec<PinMismatch> = Vec::new();
    // Tool-description rule-scan outcome, keyed (server_id, tool_name) — see
    // DescriptionHitOutcome. Consulted by handle_tools_list/
    // sanitize_description, not discarded after discovery the way it used
    // to be.
    let mut description_hits: HashMap<(String, String), DescriptionHitOutcome> = HashMap::new();

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

            // Cache the declared outputSchema (if any) for response-time
            // conformance checking, and flag at discovery time — not as a
            // signature hit, just a heads-up — if the server got the one
            // structural rule the MCP 2025-06-18 spec itself imposes wrong:
            // outputSchema's root must be `type: "object"`. Getting this
            // wrong is far more likely to be an unmaintained server than a
            // malicious one, so this stays a warning, not an elevation.
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
                tool_output_schemas.insert(t.name.clone(), schema.clone());
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

    // Tool name -> human-readable reason. Checked in handle_tools_call
    // before the tool_owner lookup, so a quarantined tool gets a distinct,
    // specific rejection instead of looking like it never existed.
    let mut quarantined_tools: HashMap<String, String> = HashMap::new();
    if registry.security_policy.strict_schema_pinning {
        for m in &mismatches {
            let reason = format!("hash mismatch: expected {}, got {}", m.expected, m.actual);
            eprintln!("[MAGUS] QUARANTINED '{}'/{}: {}", m.server_id, m.tool_name, reason);
            tool_owner.remove(&m.tool_name);
            if let Some(ds) = discovered.iter_mut().find(|d| d.server_id == m.server_id) {
                ds.tools.retain(|t| t.name != m.tool_name);
            }
            quarantined_tools.insert(m.tool_name.clone(), reason);
        }
    }

    // ---- Core governance components (session_id/audit_logger now
    //      constructed earlier, before discovery — see the comment there) ----
    let membrane = Arc::new(Mutex::new(Membrane::new(session_id.clone(), DEFAULT_MAX_AGENTS, DEFAULT_MONTHLY_EVAL_LIMIT)));
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
                &id, &json_rpc, &registry, &rule_engine, &tool_owner, &quarantined_tools, &tool_output_schemas, &connections,
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
    quarantined_tools: &HashMap<String, String>,
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
    // like the tool never existed.
    if let Some(reason) = quarantined_tools.get(tool_name) {
        return jsonrpc_error(
            id,
            -32602,
            &format!("Tool quarantined: {}", reason),
            Some("ToolQuarantinedPinMismatch"),
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
            let conn_arc = match connections.get(&mcp_server_id) {
                Some(c) => c.clone(),
                None => return jsonrpc_error(id, -32002, "Downstream connection missing", None),
            };
            let mut conn = conn_arc.lock().await;
            let call_result = conn.call_tool(tool_name, arguments).await;
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
                        advisory::inject_advisory(&mut real_result, &advisory_text);
                    }

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
