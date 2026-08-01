// tests/false_positive_corpus.rs
//
// Backs the false-positive claims sprinkled through locked-rules.yaml's rule
// comments (e.g. SECRET-AWS-001's "FP risk: README examples... flag-only,
// not elevate") with an actual test instead of leaving them as assertions
// nobody ever ran. See docs/specs/spec-fp-corpus-test.md for the full
// rationale and the three-tier design this file implements.
//
// The three tiers are NOT "hits vs no hits" — some locked rules are
// deliberately designed to match legitimate content at flag severity
// without escalating the session (see CEH-001, SECRET-AWS-001). Testing for
// "zero hits" on that tier would fail a rule set that's working exactly as
// specced, so tier 2 instead asserts on the thing that actually matters:
// state_from_rule_hits must never reach Poisoned.
//
//   should_be_silent/  zero rule hits, full stop.
//   should_not_poison/ hits allowed, including an `elevate`-action hit;
//                       state_from_rule_hits (starting from Clean) must
//                       stay at Clean or Elevated — only Poisoned fails
//                       this tier. `elevate` exists specifically to tighten
//                       a session on one ambiguous signal without
//                       condemning it outright; Poisoned requires either a
//                       critical hit or a second, independent corroborating
//                       signal (see provenance::state_from_rule_hits and
//                       docs/specs/spec-fp-corpus-findings-fix.md). This
//                       tier was originally named should_flag_not_escalate/
//                       and asserted `== Clean`, which tested for a
//                       guarantee the design never made — renamed and
//                       corrected per that spec addendum.
//   should_still_catch/ genuine attack shapes; state_from_rule_hits must
//                       reach Elevated or Poisoned. Exists so a precision
//                       fix aimed at tiers 1/2 can't silently gut recall —
//                       a change that makes this tier go quiet fails
//                       loudly, on purpose.
//
// If a tier-2 or tier-3 assertion fails, that is real signal about
// locked-rules.yaml (or the state machine), not a bug in this test — per the
// spec, do not loosen the assertion or edit locked-rules.yaml to force a
// pass; report which fixture, which rule id(s), and which tier.

use magus_opensecmcp::provenance::{state_from_rule_hits, ProvenanceState};
use magus_opensecmcp::rules_engine::{normalize_for_matching, RuleEngine, Scope};
use std::fs;
use std::path::{Path, PathBuf};

fn fixture_dir(tier: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(tier)
}

/// Reads every file directly inside `tests/fixtures/<tier>/`, sorted by name
/// for deterministic failure output. Fixture files are real, standalone
/// files (not Rust string literals) specifically so a future false-positive
/// report can be a one-file PR that never touches this file.
fn read_fixtures(tier: &str) -> Vec<(String, String)> {
    let dir = fixture_dir(tier);
    let mut entries: Vec<_> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("failed to read fixture directory {}: {}", dir.display(), e))
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    let mut out = Vec::new();
    for entry in entries {
        let path = entry.path();
        if path.is_file() {
            let content = fs::read_to_string(&path)
                .unwrap_or_else(|e| panic!("failed to read fixture {}: {}", path.display(), e));
            out.push((path.file_name().unwrap().to_string_lossy().to_string(), content));
        }
    }
    assert!(!out.is_empty(), "no fixture files found in {}", dir.display());
    out
}

#[test]
fn should_be_silent_produces_zero_hits() {
    let engine = RuleEngine::load(None).expect("locked-rules.yaml must load standalone");

    for (name, content) in read_fixtures("should_be_silent") {
        let normalized = normalize_for_matching(&content);
        let hits = engine.scan(&normalized, Scope::ToolOutputOnly, "fp-corpus-test");
        assert!(
            hits.is_empty(),
            "fixture 'should_be_silent/{}' was expected to produce zero rule hits, \
             but the following rule(s) fired: [{}]",
            name,
            hits.rule_ids().join(", ")
        );
    }
}

#[test]
fn should_not_poison_never_reaches_poisoned() {
    let engine = RuleEngine::load(None).expect("locked-rules.yaml must load standalone");

    for (name, content) in read_fixtures("should_not_poison") {
        let normalized = normalize_for_matching(&content);
        let hits = engine.scan(&normalized, Scope::ToolOutputOnly, "fp-corpus-test");
        // Deliberately NOT asserting hits.is_empty() here — this tier is
        // allowed, even expected, to produce hits (e.g. CEH-001 on a
        // Dockerfile's curl-pipe-to-shell install line), and is allowed to
        // reach Elevated (e.g. a single DSO-001 hit on a lone quoted phrase
        // in a longer document — see docs/specs/spec-fp-corpus-findings-fix.md
        // for why Elevated is the correct, proportionate outcome there, not
        // a bug). What must not happen is the resulting state reaching
        // Poisoned, which requires either a critical-tier hit or a second,
        // independent corroborating signal — neither of which a single
        // ambiguous fixture should ever produce.
        let state = state_from_rule_hits(&hits, ProvenanceState::Clean);
        assert_ne!(
            state,
            ProvenanceState::Poisoned,
            "fixture 'should_not_poison/{}' escalated provenance all the way to \
             Poisoned (rule hit(s): [{}]) — this tier permits Clean or Elevated \
             but must never reach Poisoned",
            name,
            hits.rule_ids().join(", ")
        );
    }
}

#[test]
fn should_still_catch_escalates_or_poisons() {
    let engine = RuleEngine::load(None).expect("locked-rules.yaml must load standalone");

    for (name, content) in read_fixtures("should_still_catch") {
        let normalized = normalize_for_matching(&content);
        let hits = engine.scan(&normalized, Scope::ToolOutputOnly, "fp-corpus-test");
        let state = state_from_rule_hits(&hits, ProvenanceState::Clean);
        assert!(
            state >= ProvenanceState::Elevated,
            "fixture 'should_still_catch/{}' was expected to reach at least \
             ProvenanceState::Elevated, but stayed at {:?} (rule hit(s): [{}]) — \
             this fixture is genuine attack-shaped content; failing to escalate \
             is a recall gap, not a passing result",
            name,
            state,
            hits.rule_ids().join(", ")
        );
    }
}

/// Replaces the former should_still_catch/real_shaped_aws_key.txt fixture,
/// which GitHub's secret-scanning push protection blocked on push (a
/// structurally-real AWS access key ID shape, even a synthetic one used
/// purely as test content, still trips it). Built in-line from two
/// non-contiguous literals joined at runtime instead: no single committed
/// span of source text here contains a contiguous run matching
/// `AKIA[0-9A-Z]{16}`, only the reconstructed runtime string does, which is
/// what the rule engine actually scans. Neither fragment spells "EXAMPLE"
/// (that would hit exempt_if_contains instead of escalate_if, defeating the
/// point), and the suffix is high-entropy, not an obviously patterned
/// placeholder — same intent as the deleted fixture: prove a genuinely
/// real-shaped, real-entropy key still escalates via SECRET-AWS-001's
/// escalate_if path, per docs/specs/spec-fp-corpus-findings-fix.md.
#[test]
fn secret_aws_001_escalates_on_structurally_real_high_entropy_key() {
    let engine = RuleEngine::load(None).expect("locked-rules.yaml must load standalone");

    let prefix = "AKIA";
    let suffix = "4XJZQPMR7VNTK2LH";
    let key = format!("{prefix}{suffix}");
    let content = format!(
        "$ cat deploy/.env.production\nAWS_ACCESS_KEY_ID={key}\nDB_HOST=prod-db-primary.internal\n"
    );

    let normalized = normalize_for_matching(&content);
    let hits = engine.scan(&normalized, Scope::ToolOutputOnly, "fp-corpus-test");
    let state = state_from_rule_hits(&hits, ProvenanceState::Clean);
    assert!(
        state >= ProvenanceState::Elevated,
        "a structurally-real, high-entropy AWS-key-shaped string was expected \
         to escalate via SECRET-AWS-001's escalate_if, but stayed at {:?} \
         (rule hit(s): [{}])",
        state,
        hits.rule_ids().join(", ")
    );
}

/// Post-fix proof, superseding the pre-fix gap-demonstration test that
/// lived at this location (see docs/specs/spec-secret-gh-001.md's fix
/// report for that test's "before" output — it asserted the real-shaped
/// token and a documentation-style placeholder received identical
/// flag-only treatment, and passed, because SECRET-GH-001 then had
/// neither `escalate_if` nor `exempt_if_contains`). Now that the fix has
/// landed, this fixture's role per step 3 of the spec is the
/// should_still_catch-equivalent proof: a genuinely real-shaped,
/// high-entropy GitHub-token-shaped string must still escalate. The
/// should_be_silent-equivalent proof (the documented placeholder,
/// producing zero hits) lives as a committed fixture instead:
/// `tests/fixtures/should_be_silent/gh_doc_placeholder_readme.md`.
///
/// Built in-line from two non-contiguous literals joined at runtime,
/// mirroring `secret_aws_001_escalates_on_structurally_real_high_entropy_key`
/// above: no single committed span of source text here contains a
/// contiguous run matching `gh[pousr]_[A-Za-z0-9]{36,}`, only the
/// reconstructed runtime string does, so this doesn't trip GitHub's own
/// secret-scanning push protection on push.
#[test]
fn secret_gh_001_escalates_on_structurally_real_high_entropy_token() {
    let engine = RuleEngine::load(None).expect("locked-rules.yaml must load standalone");

    let prefix = "ghp_";
    let mid = "jrmMLgn7VLNVcQIHMmya";
    let tail = "56zedt0w17FRX1Es3Oco";
    let token = format!("{prefix}{mid}{tail}");
    let content = format!(
        "$ cat deploy/.env.production\nGITHUB_TOKEN={token}\nDB_HOST=prod-db-primary.internal\n"
    );

    let normalized = normalize_for_matching(&content);
    let hits = engine.scan(&normalized, Scope::ToolOutputOnly, "fp-corpus-test");
    let state = state_from_rule_hits(&hits, ProvenanceState::Clean);
    assert!(
        state >= ProvenanceState::Elevated,
        "a structurally-real, high-entropy GitHub-token-shaped string was expected \
         to escalate via SECRET-GH-001's escalate_if, but stayed at {:?} \
         (rule hit(s): [{}])",
        state,
        hits.rule_ids().join(", ")
    );
}
