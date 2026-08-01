// src/rules_engine.rs
//
// Loads and compiles the detection rule set from two YAML sources:
//
//   - `locked-rules.yaml`, embedded into the binary at compile time via
//     `include_str!`. This is the maintainer-shipped default set. It cannot
//     be edited without rebuilding and redistributing the binary — that is
//     the point. Local file-write access to the deployment directory is not
//     enough to touch it, which is what makes it a meaningful floor rather
//     than just "the other config file".
//
//   - `user-rules.yaml`, an OPTIONAL file read from disk next to config.yaml.
//     Its grammar is strictly additive: `Action` below has no `allow` /
//     `bypass` / `pass` variant, so a rule that tries to weaken enforcement
//     fails to deserialize rather than needing to be specially detected and
//     rejected. That is a property of the type, not of extra validation
//     code someone could forget to call.
//
// Loading is fail-closed: if EITHER file fails to parse, or any pattern in
// it fails to compile, `RuleEngine::load` returns `Err` and the caller
// (main.rs) must refuse to start. There is no fallback path anywhere in
// this module. A gateway silently protecting less than it was configured to
// is a worse failure mode than a gateway that will not start — see the
// design discussion this module came out of.

use anyhow::{bail, Context, Result};
use regex::RegexBuilder;
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Compiled-pattern size bounds. These exist because pattern STRINGS in
/// user-rules.yaml are, by definition, untrusted input: anyone who can write
/// that file controls them. Two separate things are true about this crate
/// and worth being precise about:
///
///   1. Matching is immune to classic ReDoS by construction. `regex` compiles
///      to finite automata rather than backtracking, so it guarantees
///      worst-case linear time in the HAYSTACK regardless of pattern shape —
///      a pattern like `(a+)+$` run against attacker-controlled tool output
///      just matches in linear time here. It does not hang.
///   2. Compiling a pathological PATTERN can still be expensive in time or
///      memory even though matching never is — e.g. `a{100}{100}{100}` or
///      very large repeated Unicode-aware character classes blow up the
///      compiled automaton's size, not the search time. This was a real,
///      published advisory against this exact crate (CVE-2022-24713, in the
///      "compiling untrusted patterns" scenario, which is exactly what
///      loading user-rules.yaml is). `size_limit` / `dfa_size_limit` below
///      are the documented mitigation, plus a raw source-length cap so a
///      pattern that would blow the limit fails fast instead of spending
///      real compile time getting there.
const REGEX_SIZE_LIMIT: usize = 1 << 20; // ~1MB compiled-form cap per pattern
const REGEX_DFA_SIZE_LIMIT: usize = 1 << 20;
const MAX_PATTERN_SOURCE_LEN: usize = 500;

/// Synthesis threshold: this many medium-or-above hits, spanning this many
/// distinct categories, in one response, is treated as a single high-severity
/// hit by provenance::state_from_rule_hits. Keeps a pile of individually
/// weak signals from being ignorable just because none of them alone reached
/// `high`.
pub const SYNTHESIS_MIN_CATEGORIES: usize = 2;
pub const SYNTHESIS_MIN_HITS: usize = 3;

const LOCKED_RULES_YAML: &str = include_str!("../locked-rules.yaml");

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn as_lowercase_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum MatchType {
    Literal,
    Regex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    ToolOutputOnly,
    ToolDescription,
    Any,
}

/// Deliberately has NO `Allow` / `Bypass` / `Pass` variant. This is the
/// structural fix for "exception injection": neither locked-rules.yaml nor
/// user-rules.yaml can express a rule that WEAKENS enforcement, because the
/// grammar has no word for it. Anyone who tries — local attacker, compromised
/// agent with filesystem write access, or an honest typo — gets a
/// deserialize error on that line, which fails closed like any other broken
/// rule, rather than opening a live bypass. See provenance::state_from_rule_hits
/// for how `Action` maps onto FSM transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Flag,
    Elevate,
    Poison,
}

impl Action {
    fn rank(self) -> u8 {
        match self {
            Action::Flag => 0,
            Action::Elevate => 1,
            Action::Poison => 2,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct MatchSpec {
    #[serde(rename = "type")]
    match_type: MatchType,
    pattern: String,
}

/// Second-pass escalation for a hit that isn't exempted: if the matched
/// span's Shannon entropy exceeds `entropy_gt` (bits/char), the hit's action
/// becomes `escalated_action` instead of the rule's base `action`. See
/// `shannon_entropy` and `SECRET-AWS-001` in locked-rules.yaml, the one rule
/// that currently uses this.
#[derive(Debug, Clone, Deserialize)]
struct EscalateIf {
    entropy_gt: f64,
    escalated_action: Action,
}

#[derive(Debug, Clone, Deserialize)]
struct RuleDef {
    id: String,
    category: String,
    severity: Severity,
    #[serde(rename = "match")]
    match_spec: MatchSpec,
    #[serde(default = "default_scope")]
    scope: Scope,
    action: Action,
    #[serde(default)]
    case_sensitive: bool,
    #[serde(default)]
    escalate_if: Option<EscalateIf>,
    /// Case-insensitive substrings that, if found anywhere in the matched
    /// span, cause the hit to be dropped entirely (not logged, not even at
    /// `flag`) — for known-inert placeholders like AWS's own
    /// `AKIAIOSFODNN7EXAMPLE`. This is the load-bearing check for that case;
    /// see the module-level notes on why entropy math alone isn't trusted
    /// to separate a placeholder from a real secret.
    #[serde(default)]
    exempt_if_contains: Vec<String>,
    #[allow(dead_code)] // documentation only, never read at runtime
    #[serde(default)]
    notes: String,
}

fn default_scope() -> Scope {
    Scope::ToolOutputOnly
}

/// Narrows enforcement of ONE already-reviewed rule for ONE downstream
/// server. It references an existing `rule_id` rather than defining a new
/// pattern, so it cannot itself become a fresh bypass. It cannot fully
/// silence a hit either — `min_action_after_suppress` is a floor, not an
/// off switch, so the audit trail survives even when the enforcement action
/// is downgraded. `critical`-severity rules cannot be targeted at all
/// (enforced in `RuleEngine::load`): the categories at that tier have
/// near-zero legitimate false-positive rate and do not need an escape hatch.
#[derive(Debug, Clone, Deserialize)]
struct SuppressionDef {
    rule_id: String,
    #[serde(default)]
    server_id: Option<String>,
    #[serde(default = "default_min_action")]
    min_action_after_suppress: Action,
}

fn default_min_action() -> Action {
    Action::Flag
}

#[derive(Debug, Deserialize, Default)]
struct RulesFile {
    #[serde(default)]
    rules: Vec<RuleDef>,
    #[serde(default)]
    suppressions: Vec<SuppressionDef>,
}

#[derive(Debug, Clone, Copy)]
enum SourceFile {
    Locked,
    User,
}

impl SourceFile {
    fn label(self) -> &'static str {
        match self {
            SourceFile::Locked => "locked-rules.yaml",
            SourceFile::User => "user-rules.yaml",
        }
    }
}

struct CompiledRule {
    id: String,
    category: String,
    severity: Severity,
    scope: Scope,
    action: Action,
    escalate_if: Option<EscalateIf>,
    exempt_if_contains: Vec<String>,
}

/// One rule hit, post-suppression.
#[derive(Debug, Clone)]
pub struct HitDetail {
    pub rule_id: String,
    pub category: String,
    pub severity: Severity,
    pub action: Action,
    pub suppressed_from: Option<Severity>,
}

#[derive(Debug, Default)]
pub struct RuleHitSummary {
    pub hits: Vec<HitDetail>,
}

impl RuleHitSummary {
    pub fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }

    pub fn max_severity(&self) -> Option<Severity> {
        self.hits.iter().map(|h| h.severity).max()
    }

    pub fn medium_or_above_count(&self) -> usize {
        self.hits.iter().filter(|h| h.severity >= Severity::Medium).count()
    }

    /// Number of DISTINCT categories with at least one medium-or-above hit —
    /// feeds the "N medium hits across M categories synthesize into one high"
    /// rule in provenance::state_from_rule_hits.
    pub fn medium_or_above_category_count(&self) -> usize {
        self.hits
            .iter()
            .filter(|h| h.severity >= Severity::Medium)
            .map(|h| h.category.as_str())
            .collect::<HashSet<_>>()
            .len()
    }

    /// Rule ids for the audit log's `triggered_rule_ids`. A suppressed hit
    /// is annotated inline (`RULE-ID(suppressed from high)`) rather than
    /// looking identical to an unsuppressed one — the audit trail should be
    /// able to answer "did this fire at full strength or was it dialed
    /// down" without cross-referencing user-rules.yaml separately.
    pub fn rule_ids(&self) -> Vec<String> {
        self.hits
            .iter()
            .map(|h| match h.suppressed_from {
                Some(original) => format!("{}(suppressed from {})", h.rule_id, original.as_lowercase_str()),
                None => h.rule_id.clone(),
            })
            .collect()
    }
}

pub struct RuleEngine {
    literal_automaton: aho_corasick::AhoCorasick,
    /// Parallel to `literal_automaton`'s pattern indices.
    literal_rules: Vec<CompiledRule>,
    regex_rules: Vec<(regex::Regex, CompiledRule)>,
    suppressions: Vec<SuppressionDef>,
    /// True iff a user-rules.yaml was found AND successfully loaded. This is
    /// the third state alongside "load() returned Err" (found but broken)
    /// and the absence of any signal at all being impossible — `load()`
    /// always resolves one of the three explicitly, on purpose. See
    /// main.rs's startup logging, which mirrors the same
    /// absent / present-and-good / present-and-bad shape the hash-pin check
    /// already uses for tool definitions (SEC-03), rather than collapsing
    /// "no file" and "file loaded fine" into identical silence.
    pub had_user_rules: bool,
    user_rule_count: usize,
    suppression_count: usize,
}

impl RuleEngine {
    /// `user_rules_path`: checked for existence; if absent, that is a normal,
    /// fully-supported configuration (locked-only), not a degraded one. If
    /// PRESENT but invalid in any way — bad YAML, an unknown action like
    /// `allow`, a pattern that will not compile, a duplicate id, a
    /// suppression targeting a critical rule or an unknown id — this returns
    /// `Err` and the caller must refuse to start. Nothing downstream of this
    /// function falls back to anything.
    pub fn load(user_rules_path: Option<&Path>) -> Result<Self> {
        let locked_raw = LOCKED_RULES_YAML;
        let locked: RulesFile = parse_rules_file(locked_raw).context(
            "BUG: built-in locked-rules.yaml failed to parse. This ships inside the binary \
             and is covered by `cargo test`; if this fires, the release itself is broken.",
        )?;

        let user_raw: Option<String> = match user_rules_path {
            Some(path) if path.exists() => Some(
                std::fs::read_to_string(path)
                    .with_context(|| format!("failed to read {}", path.display()))?,
            ),
            _ => None,
        };
        let user: Option<RulesFile> = match (&user_raw, user_rules_path) {
            (Some(raw), Some(path)) => Some(
                parse_rules_file(raw)
                    .with_context(|| format!("{} failed to parse as YAML", path.display()))?,
            ),
            _ => None,
        };

        let mut all_rule_defs: Vec<(SourceFile, RuleDef)> = Vec::new();
        for r in locked.rules {
            all_rule_defs.push((SourceFile::Locked, r));
        }
        let mut suppressions = locked.suppressions;
        let had_user_rules = user.is_some();
        let mut user_rule_count = 0usize;
        if let Some(u) = user {
            user_rule_count = u.rules.len();
            for r in u.rules {
                all_rule_defs.push((SourceFile::User, r));
            }
            suppressions.extend(u.suppressions);
        }

        // Ids must be unique across BOTH files combined. A user rule id that
        // collides with a locked one is almost certainly a mistake, and
        // "which one silently wins" is exactly the kind of ambiguity this
        // whole redesign exists to remove.
        let mut seen_ids: HashSet<&str> = HashSet::new();
        for (_, r) in &all_rule_defs {
            if !seen_ids.insert(r.id.as_str()) {
                bail!(
                    "duplicate rule id '{}' — ids must be unique across locked-rules.yaml \
                     and user-rules.yaml combined",
                    r.id
                );
            }
        }

        let severity_by_id: HashMap<&str, Severity> =
            all_rule_defs.iter().map(|(_, r)| (r.id.as_str(), r.severity)).collect();
        for s in &suppressions {
            match severity_by_id.get(s.rule_id.as_str()) {
                Some(Severity::Critical) => bail!(
                    "suppression targets rule '{}', which is critical severity — \
                     critical-tier rules cannot be suppressed",
                    s.rule_id
                ),
                None => bail!("suppression references unknown rule id '{}'", s.rule_id),
                _ => {}
            }
        }

        let mut literal_patterns: Vec<String> = Vec::new();
        let mut literal_rules: Vec<CompiledRule> = Vec::new();
        let mut regex_rules: Vec<(regex::Regex, CompiledRule)> = Vec::new();

        for (source, def) in &all_rule_defs {
            let compiled_meta = CompiledRule {
                id: def.id.clone(),
                category: def.category.clone(),
                severity: def.severity,
                scope: def.scope,
                action: def.action,
                escalate_if: def.escalate_if.clone(),
                exempt_if_contains: def.exempt_if_contains.clone(),
            };

            match def.match_spec.match_type {
                // Literal matching is always case-insensitive: every literal
                // pattern is lowercased at load time and scanned against a
                // fully-lowercased buffer in `scan()`. `case_sensitive` on a
                // literal rule is a no-op — deliberately, because mixing
                // case-sensitive and case-insensitive patterns in one shared
                // automaton scanned against one buffer would silently make
                // the case-sensitive ones unmatchable (whichever buffer case
                // you pick loses the other kind). Rules that genuinely need
                // case sensitivity (secret-shaped patterns like AKIA...,
                // PEM headers) should use `type: regex`, where
                // `case_sensitive` is honored exactly, per-pattern, via
                // RegexBuilder.
                MatchType::Literal => {
                    literal_patterns.push(def.match_spec.pattern.to_lowercase());
                    literal_rules.push(compiled_meta);
                }
                MatchType::Regex => {
                    if def.match_spec.pattern.len() > MAX_PATTERN_SOURCE_LEN {
                        bail!(
                            "{}: rule '{}' pattern is {} bytes, over the {}-byte limit for \
                             regex patterns (untrusted-pattern compile-cost bound)",
                            source.label(),
                            def.id,
                            def.match_spec.pattern.len(),
                            MAX_PATTERN_SOURCE_LEN
                        );
                    }
                    let raw_for_lookup: &str = match source {
                        SourceFile::Locked => locked_raw,
                        SourceFile::User => user_raw.as_deref().unwrap_or(""),
                    };
                    let line_suffix = find_line(raw_for_lookup, &def.id)
                        .map(|n| format!(", line {}", n))
                        .unwrap_or_default();

                    let compiled_re = RegexBuilder::new(&def.match_spec.pattern)
                        .case_insensitive(!def.case_sensitive)
                        .size_limit(REGEX_SIZE_LIMIT)
                        .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
                        .build()
                        .with_context(|| {
                            format!(
                                "{}{}: rule '{}' pattern failed to compile: '{}'",
                                source.label(),
                                line_suffix,
                                def.id,
                                def.match_spec.pattern
                            )
                        })?;
                    regex_rules.push((compiled_re, compiled_meta));
                }
            }
        }

        let literal_automaton = aho_corasick::AhoCorasickBuilder::new()
            .build(&literal_patterns)
            .context("failed to build the literal-pattern automaton")?;

        let suppression_count = suppressions.len();

        Ok(Self {
            literal_automaton,
            literal_rules,
            regex_rules,
            suppressions,
            had_user_rules,
            user_rule_count,
            suppression_count,
        })
    }

    pub fn total_rule_count(&self) -> usize {
        self.literal_rules.len() + self.regex_rules.len()
    }

    pub fn user_rule_count(&self) -> usize {
        self.user_rule_count
    }

    pub fn suppression_count(&self) -> usize {
        self.suppression_count
    }

    /// Scans already-normalized text (see `normalize_for_matching`) for the
    /// given scope. `mcp_server_id` is only used to resolve suppressions
    /// scoped to a specific server.
    pub fn scan(&self, normalized_text: &str, scope: Scope, mcp_server_id: &str) -> RuleHitSummary {
        let lower = normalized_text.to_lowercase();
        let mut hits = Vec::new();

        for m in self.literal_automaton.find_iter(&lower) {
            let rule = &self.literal_rules[m.pattern().as_usize()];
            if rule_applies(rule.scope, scope) {
                // Literal matching is always case-insensitive (see the note
                // on MatchType::Literal above), so the matched span's own
                // "true" text IS its lowercased form here — there's no
                // separate original-case text to recover for this match
                // kind, unlike regex matches below.
                let matched_text = &lower[m.start()..m.end()];
                push_hit(&mut hits, rule, matched_text, &self.suppressions, mcp_server_id);
            }
        }
        for (re, rule) in &self.regex_rules {
            if rule_applies(rule.scope, scope) {
                if let Some(m) = re.find(normalized_text) {
                    push_hit(&mut hits, rule, m.as_str(), &self.suppressions, mcp_server_id);
                }
            }
        }

        RuleHitSummary { hits }
    }
}

fn rule_applies(rule_scope: Scope, requested_scope: Scope) -> bool {
    matches!(rule_scope, Scope::Any) || rule_scope == requested_scope
}

/// Applies, in order: `exempt_if_contains` (drop the hit entirely if the
/// matched span contains any listed substring, case-insensitively — a
/// known-inert placeholder is not a signal worth logging even at `flag`),
/// then `escalate_if` (bump the action for the hits that remain if the
/// matched span's Shannon entropy clears the configured bar), then
/// suppression exactly as before. This order matters: suppression must see
/// the already-exempted/escalated action, not the raw rule default, and
/// exemption must run before entropy is even computed since an exempted hit
/// never becomes a `HitDetail` at all.
fn push_hit(
    hits: &mut Vec<HitDetail>,
    rule: &CompiledRule,
    matched_text: &str,
    suppressions: &[SuppressionDef],
    mcp_server_id: &str,
) {
    let matched_lower = matched_text.to_lowercase();
    if rule
        .exempt_if_contains
        .iter()
        .any(|needle| matched_lower.contains(&needle.to_lowercase()))
    {
        return;
    }

    let effective_action = match &rule.escalate_if {
        Some(esc) if shannon_entropy(matched_text) > esc.entropy_gt => esc.escalated_action,
        _ => rule.action,
    };

    let applicable = suppressions.iter().find(|s| {
        s.rule_id == rule.id
            && s.server_id.as_deref().map_or(true, |sid| sid == mcp_server_id)
    });

    let (severity, action, suppressed_from) = match applicable {
        Some(s) => (
            downgrade_severity(rule.severity),
            weaker_action(effective_action, s.min_action_after_suppress),
            Some(rule.severity),
        ),
        None => (rule.severity, effective_action, None),
    };

    hits.push(HitDetail {
        rule_id: rule.id.clone(),
        category: rule.category.clone(),
        severity,
        action,
        suppressed_from,
    });
}

/// Shannon entropy in bits per character over `s`'s character distribution:
/// `H(s) = -Σ p(c) * log2(p(c))` for each distinct character `c`, where
/// `p(c) = count(c) / len(s)`. Used by `escalate_if.entropy_gt` to tell a
/// genuinely random-looking match (a real leaked secret) apart from a
/// low-entropy, hand-typed one (a placeholder or test value) — see
/// `EscalateIf` and `SECRET-AWS-001` in locked-rules.yaml.
fn shannon_entropy(s: &str) -> f64 {
    let len = s.chars().count();
    if len == 0 {
        return 0.0;
    }
    let mut counts: HashMap<char, usize> = HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    counts
        .values()
        .map(|&count| {
            let p = count as f64 / len as f64;
            -p * p.log2()
        })
        .sum()
}

/// Suppression can only move a hit TOWARD `Flag`, never past it — there is
/// no way to reach a fully-silent outcome through this path.
fn weaker_action(original: Action, floor: Action) -> Action {
    if original.rank() < floor.rank() {
        original
    } else {
        floor
    }
}

fn downgrade_severity(s: Severity) -> Severity {
    match s {
        // Unreachable in practice: RuleEngine::load refuses to load any
        // suppression that targets a Critical rule, so this arm never runs
        // against a real Critical hit. Kept exhaustive rather than panicking.
        Severity::Critical => Severity::High,
        Severity::High => Severity::Medium,
        Severity::Medium => Severity::Low,
        Severity::Low => Severity::Low,
    }
}

fn parse_rules_file(raw: &str) -> Result<RulesFile> {
    serde_yaml::from_str(raw).context("YAML parse error")
}

/// Best-effort line lookup for error messages: after successful YAML
/// deserialization we no longer have source positions, so this just
/// searches the raw text for the rule's id string and counts newlines up to
/// it. Good enough to point a human at roughly the right spot; not a
/// guarantee if an id string happens to also appear earlier in a comment or
/// another rule's notes.
fn find_line(raw: &str, needle: &str) -> Option<usize> {
    raw.find(needle).map(|byte_pos| raw[..byte_pos].matches('\n').count() + 1)
}

/// Cheap normalization pass before matching. Deliberately a subset of the
/// full pipeline discussed alongside this engine (NFKC, confusables/TR39
/// skeletonization, and a base64/hex decode-and-rescan peel are the notable
/// omissions) — this covers the cheapest, highest-leverage steps so v1
/// isn't trivially bypassed by casing or whitespace tricks, without pulling
/// in unicode-normalization / unicode-security yet. Order matters: tag-block
/// decode has to happen before whitespace collapse, since a decoded tag
/// character can itself be a space.
pub fn normalize_for_matching(raw: &str) -> String {
    let tag_decoded = decode_unicode_tags(raw);
    let stripped = strip_zero_width(&tag_decoded);
    collapse_whitespace(&stripped)
}

/// Unicode Tag block (U+E0001, U+E0020..=U+E007E, U+E007F) mirrors the ASCII
/// printable range shifted by 0xE0000 and is invisible in ordinary text
/// rendering while still being tokenized and read by an LLM — the
/// "ASCII smuggling" technique. There is no legitimate use of this block in
/// the tool-output contexts this proxy handles, so decoding it back to
/// plain ASCII for matching (rather than just stripping it) is what lets a
/// fully tag-smuggled "ignore previous instructions" still hit the literal
/// automaton.
fn decode_unicode_tags(s: &str) -> String {
    s.chars()
        .map(|c| {
            let cp = c as u32;
            if (0xE0020..=0xE007E).contains(&cp) {
                char::from_u32(cp - 0xE0000).unwrap_or(c)
            } else {
                c
            }
        })
        .collect()
}

/// Strips the zero-width characters most commonly used to fragment a
/// keyword across matcher boundaries (e.g. "i<ZWSP>g<ZWSP>nore"). Complex
/// script and emoji text legitimately uses ZWJ too, but this proxy is
/// matching against tool output for known-bad phrasing, not rendering text,
/// so stripping unconditionally (rather than density-gating, which the
/// fuller pipeline discussion called for) is an acceptable v1 trade-off.
fn strip_zero_width(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(*c, '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}'))
        .collect()
}

fn collapse_whitespace(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_space = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !last_was_space {
                out.push(' ');
            }
            last_was_space = true;
        } else {
            out.push(c);
            last_was_space = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one test that matters most for a fail-closed loader: the exact
    /// file that ships inside every release must load cleanly with no user
    /// layer at all. If this fails, the release is broken — see the context
    /// message on the corresponding `.context()` call in `load`.
    #[test]
    fn locked_rules_yaml_loads_and_compiles() {
        let engine = RuleEngine::load(None).expect("locked-rules.yaml must load standalone");
        assert!(!engine.literal_rules.is_empty() || !engine.regex_rules.is_empty());
    }

    #[test]
    fn user_rules_cannot_express_allow() {
        let dir = std::env::temp_dir().join(format!("magus-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("user-rules.yaml");
        std::fs::write(
            &path,
            "rules:\n  - id: ATTACKER-001\n    category: test\n    severity: high\n    match: { type: literal, pattern: \"x\" }\n    action: allow\n",
        )
        .unwrap();

        let result = RuleEngine::load(Some(&path));
        assert!(result.is_err(), "an 'allow' action must fail to deserialize, not load");
    }

    #[test]
    fn suppression_cannot_target_critical() {
        let dir = std::env::temp_dir().join(format!("magus-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("user-rules.yaml");
        // MCT-001 in locked-rules.yaml is critical severity.
        std::fs::write(
            &path,
            "suppressions:\n  - rule_id: MCT-001\n    min_action_after_suppress: flag\n",
        )
        .unwrap();

        let result = RuleEngine::load(Some(&path));
        assert!(result.is_err(), "a suppression targeting a critical rule must fail to load");
    }

    #[test]
    fn tag_block_smuggled_phrase_is_decoded_for_matching() {
        // "hi" spelled entirely in Unicode Tag characters (U+E0068 U+E0069).
        let smuggled = "\u{E0068}\u{E0069}";
        assert_eq!(normalize_for_matching(smuggled), "hi");
    }

    #[test]
    fn zero_width_fragmented_keyword_collapses() {
        let fragmented = "ig\u{200B}no\u{200B}re";
        assert_eq!(strip_zero_width(fragmented), "ignore");
    }

    #[test]
    fn missing_user_rules_file_is_not_an_error() {
        // A path that has never been created — not "configured but empty",
        // genuinely absent. This must succeed and report had_user_rules =
        // false, the same signal shape as SEC-03's "no pin set yet": absence
        // is informational, not a failure, and must not be confused with a
        // present-but-broken file below.
        let dir = std::env::temp_dir().join(format!("magus-test-{}", uuid::Uuid::new_v4()));
        let never_created = dir.join("user-rules.yaml");
        assert!(!never_created.exists());

        let engine = RuleEngine::load(Some(&never_created))
            .expect("a missing user-rules.yaml must load successfully, locked-only");
        assert!(!engine.had_user_rules);
        assert_eq!(engine.user_rule_count(), 0);
    }

    #[test]
    fn present_but_broken_user_rules_file_fails_closed() {
        // Same missing-directory setup as above, EXCEPT the file is actually
        // written this time — this is the "present but broken" case, which
        // must behave oppositely to the test above: Err, not a silent
        // locked-only fallback.
        let dir = std::env::temp_dir().join(format!("magus-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("user-rules.yaml");
        std::fs::write(&path, "rules:\n  - id: BROKEN-001\n    category: test\n    severity: high\n    match: { type: regex, pattern: \"(\" }\n    action: elevate\n").unwrap();

        let result = RuleEngine::load(Some(&path));
        assert!(result.is_err(), "a present-but-unparseable pattern must fail closed, not fall back silently");
    }

    /// Mechanism test, not a policy test: a rule with `exempt_if_contains`
    /// must drop a hit entirely when the matched span contains a listed
    /// substring, and must still fire normally when it doesn't. This is
    /// independent of any specific rule (SECRET-AWS-001's use of it is
    /// covered by the corpus test's fixtures, not here).
    #[test]
    fn exempt_if_contains_drops_matching_hit_entirely() {
        let dir = std::env::temp_dir().join(format!("magus-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("user-rules.yaml");
        std::fs::write(
            &path,
            "rules:\n  - id: TEST-EXEMPT-001\n    category: test\n    severity: medium\n    match: { type: regex, pattern: \"TESTKEY[0-9A-Z]{8}\" }\n    action: flag\n    case_sensitive: true\n    exempt_if_contains: [\"EXAMPLE\"]\n",
        )
        .unwrap();
        let engine = RuleEngine::load(Some(&path)).expect("valid user-rules.yaml must load");

        // Matched span is "TESTKEYEXAMPLE1" (7 + 8 chars) — contains the
        // exempt substring, so this must produce no hit at all.
        let exempted = engine.scan("prefix TESTKEYEXAMPLE1 suffix", Scope::ToolOutputOnly, "srv");
        assert!(
            exempted.is_empty(),
            "a match containing an exempt_if_contains substring must be dropped entirely, got: {:?}",
            exempted.rule_ids()
        );

        // Matched span is "TESTKEYQWERTYUI" — same rule, no exempt
        // substring present, must fire normally at the base action.
        let not_exempted = engine.scan("prefix TESTKEYQWERTYUI suffix", Scope::ToolOutputOnly, "srv");
        assert!(
            !not_exempted.is_empty(),
            "the same rule without the exempt substring in the matched span must still fire"
        );
        assert_eq!(not_exempted.hits[0].action, Action::Flag);
    }

    /// Mechanism test: a rule with `escalate_if.entropy_gt` must escalate a
    /// high-entropy match to `escalated_action` and leave a low-entropy
    /// match at the rule's base `action`. Threshold and both fixture
    /// strings were checked ahead of time (bits/char, over the full matched
    /// span): "ENTKEYQz7XpL9mWk" ≈ 3.875, "ENTKEYAAAAAAAAAA" ≈ 1.799, so
    /// entropy_gt: 3.5 cleanly separates them.
    #[test]
    fn escalate_if_entropy_gt_escalates_high_entropy_and_spares_low_entropy() {
        let dir = std::env::temp_dir().join(format!("magus-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("user-rules.yaml");
        std::fs::write(
            &path,
            "rules:\n  - id: TEST-ENTROPY-001\n    category: test\n    severity: medium\n    match: { type: regex, pattern: \"ENTKEY[0-9A-Za-z]{10}\" }\n    action: flag\n    case_sensitive: true\n    escalate_if: { entropy_gt: 3.5, escalated_action: elevate }\n",
        )
        .unwrap();
        let engine = RuleEngine::load(Some(&path)).expect("valid user-rules.yaml must load");

        let high_entropy = engine.scan("token: ENTKEYQz7XpL9mWk end", Scope::ToolOutputOnly, "srv");
        assert_eq!(high_entropy.hits.len(), 1, "expected exactly one hit for the high-entropy match");
        assert_eq!(
            high_entropy.hits[0].action,
            Action::Elevate,
            "a match whose entropy exceeds entropy_gt must use escalated_action"
        );

        let low_entropy = engine.scan("token: ENTKEYAAAAAAAAAA end", Scope::ToolOutputOnly, "srv");
        assert_eq!(low_entropy.hits.len(), 1, "expected exactly one hit for the low-entropy match");
        assert_eq!(
            low_entropy.hits[0].action,
            Action::Flag,
            "a match whose entropy does not exceed entropy_gt must stay at the rule's base action"
        );
    }

    /// Applies the exempt_if_contains + escalate_if pattern (already proven
    /// generic by the two tests above) to SECRET-GH-001's *actual*
    /// locked-rules.yaml configuration, not a synthetic copy — loads the
    /// real locked rules deliberately, per
    /// docs/specs/spec-secret-gh-001.md's instruction not to assume
    /// SECRET-AWS-001's pattern, threshold, or exemption shape transfer to
    /// GH-001's wider (62-char) alphabet without re-verifying against real
    /// measurements.
    ///
    /// Entropy values measured ahead of time with the real `shannon_entropy`
    /// function, over ten random 36-62-char samples plus the researched
    /// placeholder (full record in this fix's report / commit history):
    /// genuinely random tokens measured ~4.61-5.11 bits/char; GitHub's own
    /// REST API docs placeholder (docs.github.com/en/rest/credentials/revoke,
    /// "Revoke a personal access token") measured ~4.23 bits/char — close
    /// enough to real that, exactly like SECRET-AWS-001's own placeholder,
    /// entropy_gt: 4.4 alone would not be a trustworthy margin for it;
    /// exempt_if_contains on its distinctive repeated substring is the
    /// load-bearing check for that specific documented case, same
    /// division of labor as SECRET-AWS-001's "EXAMPLE" substring.
    #[test]
    fn secret_gh_001_exempts_documented_placeholder_and_escalates_real_shaped_token() {
        let engine = RuleEngine::load(None).expect("locked-rules.yaml must load standalone");

        // GitHub's own documented placeholder — must be dropped entirely.
        let placeholder = "ghp_1234567890abcdef1234567890abcdef12345678";
        let exempted = engine.scan(&format!("token: {placeholder} end"), Scope::ToolOutputOnly, "srv");
        assert!(
            exempted.is_empty(),
            "GitHub's own documented placeholder token must be exempted entirely, got: {:?}",
            exempted.rule_ids()
        );

        // A genuinely real-shaped, high-entropy token (measured ~4.803
        // bits/char ahead of time) — not the documented placeholder
        // substring — must escalate.
        let real = "ghp_zBxs7hHGEUb5Gn1GBqgrqRbuO10lKt2F0OSD";
        let escalated = engine.scan(&format!("token: {real} end"), Scope::ToolOutputOnly, "srv");
        assert_eq!(escalated.hits.len(), 1, "expected exactly one SECRET-GH-001 hit on the real-shaped token");
        assert_eq!(
            escalated.hits[0].action,
            Action::Elevate,
            "a real-shaped, high-entropy GitHub-token-shaped match must escalate via entropy_gt"
        );

        // A low-effort placeholder that is NOT the specific exempted
        // substring (a plain digit-cycle, measured ~3.641 bits/char) must
        // stay at the rule's base action — proving exempt_if_contains isn't
        // doing this work by accident, and that entropy_gt: 4.4 is a real
        // floor, not a no-op.
        let digit_cycle = "ghp_0123456789012345678901234567890123456789";
        let not_escalated = engine.scan(&format!("token: {digit_cycle} end"), Scope::ToolOutputOnly, "srv");
        assert_eq!(not_escalated.hits.len(), 1, "expected exactly one SECRET-GH-001 hit on the digit-cycle placeholder");
        assert_eq!(
            not_escalated.hits[0].action,
            Action::Flag,
            "a low-entropy, non-exempted placeholder must stay at the rule's base action, not escalate"
        );
    }

    #[test]
    fn valid_user_rules_file_is_reflected_in_counts() {
        let dir = std::env::temp_dir().join(format!("magus-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("user-rules.yaml");
        std::fs::write(
            &path,
            "rules:\n  - id: CUSTOM-001\n    category: internal\n    severity: high\n    match: { type: literal, pattern: \"our-internal-secret-prefix\" }\n    action: elevate\n",
        )
        .unwrap();

        let engine = RuleEngine::load(Some(&path)).expect("valid user-rules.yaml must load");
        assert!(engine.had_user_rules);
        assert_eq!(engine.user_rule_count(), 1);
    }
}
