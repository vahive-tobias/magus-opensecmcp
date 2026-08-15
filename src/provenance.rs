// src/provenance.rs

use serde::Serialize;

use crate::registry::SourceGrade;
use crate::rules_engine::{Action, RuleHitSummary};

/// Tri-state schema conformance to close the "no schema declared" loophole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum SchemaConformance {
    NotDeclared,
    Conformant,
    Violated,
}

/// Deterministic structural classification of an inbound tool response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseForm {
    PrimitiveData,
    StructuredContainer,
    BareString,
    BareArray,
    Malformed,
}

/// The 4-tier provenance state of an agent's information environment. Each
/// state carries exactly one meaning
/// (docs/specs/spec-provenance-semantics-correction.md):
///
///   - `Clean`        — no external influence observed.
///   - `Elevated`     — external content was consumed. No detection fired.
///   - `Contaminated` — heuristic evidence fired. Uncorroborated. Recoverable.
///   - `Poisoned`     — a deterministic violation, OR corroborated heuristic
///                      evidence.
///
/// The `Contaminated`/`Poisoned` split is specifically heuristic vs.
/// deterministic evidence, and it's load-bearing: a rule hit (heuristic) has
/// a real false-positive class and needs corroboration before reaching
/// `Poisoned` (see `state_from_rule_hits`); a schema violation or malformed
/// response (deterministic — the tool's own contract was broken, or the
/// payload didn't parse) has no false-positive class and goes straight to
/// `Poisoned` (see `compute_new_state`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ProvenanceState {
    Clean = 0,
    Elevated = 1,
    Contaminated = 2,
    Poisoned = 3,
}

const LONG_STRING_THRESHOLD: usize = 200;
const AGGREGATE_STRING_BYTES_CAP: u32 = 800;

/// Number of consecutive, independently-verified-clean responses required
/// to decay one tier — `Contaminated -> Elevated` needs
/// `CLEAN_CALLS_TO_DECAY_CONTAMINATED`, `Elevated -> Clean` needs
/// `CLEAN_CALLS_TO_DECAY_ELEVATED`. A stricter bar for undoing heuristic
/// evidence (the transition F1's "decay bombing" exploit actually
/// targeted — see `docs/specs/Adversarial Review magus-opensecmcp.md` and
/// `docs/specs/spec-f1-clean-call-decay.md`) than for the lower-stakes
/// "read some stuff, nothing happened" tier.
///
/// CALIBRATION GUESS, not asserted as correct — same disclaiming language
/// membrane.rs's 135%/150% BP surcharges already use. Unlike `entropy_gt`
/// in `SECRET-GH-001` (measured against real/fake sample distributions,
/// documented in `docs/rule-calibration/`), there is no dataset these
/// numbers are fit to: this is a judgment call about how much sustained
/// good behavior should count as earned trust back, not a measured
/// detection threshold. **No `docs/rule-calibration/` entry should be
/// expected for these** — there's nothing to measure them against, and
/// someone shouldn't go looking for evidence that was never meant to
/// exist. Same reasoning as the companion F2 fix's
/// `MAX_OCCURRENCES_PER_RULE` (`rules_engine.rs`).
const CLEAN_CALLS_TO_DECAY_CONTAMINATED: u32 = 5;
const CLEAN_CALLS_TO_DECAY_ELEVATED: u32 = 3;

/// Computes the structural taint of a raw tool response payload. O(n) in
/// response size. No AI model calls, no semantic understanding.
///
/// This used to also run the 4 hardcoded literal patterns
/// ("Ignore all previous instructions", etc.) and return a match count.
/// That responsibility now belongs entirely to `rules_engine::RuleEngine`,
/// which is loaded from `locked-rules.yaml` + optional `user-rules.yaml`
/// rather than compiled into this function — see main.rs, where this
/// function's output and the rule engine's `scan()` output are combined via
/// `.max()` before being handed to the tracker. What this function still
/// owns, unchanged, is the STRUCTURAL classification (shape, size, schema
/// conformance) that doesn't depend on any pattern list at all. It now also
/// returns the concatenated text of every string value in the payload, so
/// the caller can normalize and scan it once without re-walking the JSON.
pub fn classify_response(raw_payload: &[u8]) -> (ResponseForm, u16, u16, u32, String) {
    let payload_str = match std::str::from_utf8(raw_payload) {
        Ok(s) => s,
        Err(_) => return (ResponseForm::Malformed, 0, 0, 0, String::new()),
    };

    let json: serde_json::Value = match serde_json::from_str(payload_str) {
        Ok(v) => v,
        Err(_) => return (ResponseForm::Malformed, 0, 0, 0, String::new()),
    };

    let mut string_field_count = 0u16;
    let mut long_string_count = 0u16;
    let mut total_string_bytes = 0u32;
    let mut combined_text = String::new();

    fn rec(v: &serde_json::Value, sc: &mut u16, lc: &mut u16, tb: &mut u32, text: &mut String) {
        match v {
            serde_json::Value::String(s) => {
                *sc += 1;
                *tb = tb.saturating_add(s.len() as u32);
                if s.len() >= LONG_STRING_THRESHOLD {
                    *lc += 1;
                }
                text.push_str(s);
                text.push('\n'); // keep field boundaries out of accidental cross-field matches
            }
            serde_json::Value::Array(arr) => {
                for item in arr { rec(item, sc, lc, tb, text); }
            }
            serde_json::Value::Object(map) => {
                for (_, val) in map { rec(val, sc, lc, tb, text); }
            }
            _ => {}
        }
    }
    rec(&json, &mut string_field_count, &mut long_string_count, &mut total_string_bytes, &mut combined_text);

    let form = if long_string_count > 0 {
        ResponseForm::StructuredContainer
    } else {
        match &json {
            serde_json::Value::String(_) => ResponseForm::BareString,
            serde_json::Value::Array(_) => ResponseForm::BareArray,
            serde_json::Value::Object(_) => ResponseForm::PrimitiveData,
            _ => ResponseForm::PrimitiveData, // bare number/bool/null: treat as primitive
        }
    };

    (form, string_field_count, long_string_count, total_string_bytes, combined_text)
}

/// The state machine deciding the new ProvenanceState for an inbound response,
/// from STRUCTURAL signals only (source grade, response shape, schema
/// conformance, aggregate size). For Attested/Known grades, Clean is
/// reachable whenever the response has no long string content and stays
/// under the aggregate byte cap — response SHAPE (bare string vs. object)
/// does not by itself force Elevated; only actual bulk string content
/// does (this supersedes the earlier AS-1 closed-table approach, which
/// forced Elevated for BareString/PrimitiveData unconditionally and made
/// Clean structurally unreachable for ordinary responses — see
/// docs/specs/spec-c1-provenance-trap-fix.md). Unvalidated (the v1
/// default for every server unless explicitly graded otherwise) never
/// reaches Clean at all.
///
/// Pattern-hit-driven state lives in `state_from_rule_hits` below — call
/// both and take the max. They're kept separate on purpose: this function
/// has no pattern list to get wrong, so a bug in rules.yaml (or a missing
/// user-rules.yaml) degrades pattern coverage, never the structural floor.
pub fn compute_new_state(
    source_grade: SourceGrade,
    response_form: ResponseForm,
    schema_conformance: SchemaConformance,
    total_string_bytes: u32,
    long_string_count: u16,
) -> ProvenanceState {
    if response_form == ResponseForm::Malformed { return ProvenanceState::Poisoned; }
    if schema_conformance == SchemaConformance::Violated { return ProvenanceState::Poisoned; }
    // Known, reasoned deviation, not an oversight: this is the same category
    // error as the Unvalidated case below (a trust attribute producing a
    // state), left alone this round. It's an explicit operator declaration
    // rather than a default, changing it is a behavior change with no
    // test-driven justification, and the real question it raises ("why is
    // the gateway routing to a server the operator flagged as suspicious at
    // all?") is a config-layer question, not an FSM one. See
    // docs/specs/spec-provenance-semantics-correction.md §2.
    if source_grade == SourceGrade::Suspicious { return ProvenanceState::Poisoned; }

    if source_grade == SourceGrade::Unvalidated {
        // Response form no longer distinguishes here (BareString used to
        // map to Contaminated). Source grade is a property of the SERVER;
        // provenance state is a property of the session's information
        // ENVIRONMENT — a trust attribute must not be able to manufacture
        // evidence that was never actually observed. The compensating
        // penalty for an ungraded source moved to the risk layer — see
        // membrane.rs's Unvalidated BP surcharge.
        return ProvenanceState::Elevated;
    }

    if total_string_bytes > AGGREGATE_STRING_BYTES_CAP { return ProvenanceState::Elevated; }

    // Only Attested/Known reach here (the guards above handle the rest).
    // Elevated is reserved for a structural anomaly that is not itself a
    // detection — an oversized payload (byte-cap guard above) or a
    // long-string container (below). "We read something, benign" is NOT
    // an anomaly and must stay Clean, or Clean becomes unreachable for
    // every real MCP response (which is always a top-level object ->
    // PrimitiveData). The cost of having consumed external content, if
    // any, lives in BP -- the same decision already made for the
    // Unvalidated surcharge. See docs/specs/spec-c1-provenance-trap-fix.md.
    if long_string_count > 0 {
        ProvenanceState::Elevated
    } else {
        ProvenanceState::Clean
    }
}

/// The state a response's rule hits alone would justify, given the
/// session's CURRENT state. Two fields on each hit do different jobs here,
/// deliberately:
///
///   - `action` (flag | elevate | poison), set explicitly per rule in
///     rules.yaml, is the DIRECT consequence of that specific rule firing.
///     A `poison` action always poisons immediately; an `elevate` action
///     produces `Contaminated` on first occurrence — heuristic evidence,
///     uncorroborated, recoverable — not `Poisoned` outright.
///   - `severity`, used below via `RuleHitSummary`'s counting methods, is
///     the CORROBORATION weight: it's what lets several individually
///     medium-confidence hits across different categories in one response
///     add up to something worth treating as a single elevate-strength
///     signal, without needing every rule author to hand-tune `action` for
///     that interaction.
///
/// The corroboration rule this function also enforces — a second
/// elevate-or-stronger signal while the session is ALREADY `Contaminated`
/// escalates all the way to `Poisoned` — exists because one elevate-strength
/// signal shouldn't fully poison a session on its own (that's what a
/// `poison` action is for; it's also why the threshold is `>= Contaminated`
/// rather than `>= Elevated` — `Elevated` is the normal resting state for a
/// session that has consumed substantial external content, so gating
/// corroboration on it would let a single ambiguous hit, like the security-blogpost false
/// positive `tests/fixtures/should_not_poison/` covers, poison a session
/// outright). Two independent heuristic signals, on two different tool
/// calls or within the same response, should poison. Only the tracker's
/// current state can tell us whether this is the first such signal or the
/// second, which is why this takes `current_state` as an argument rather
/// than being a pure function of the summary alone.
pub fn state_from_rule_hits(summary: &RuleHitSummary, current_state: ProvenanceState) -> ProvenanceState {
    if summary.hits.iter().any(|h| h.action == Action::Poison) {
        return ProvenanceState::Poisoned;
    }

    let has_elevate = summary.hits.iter().any(|h| h.action == Action::Elevate);
    let synthesized_elevate = summary.medium_or_above_category_count() >= crate::rules_engine::SYNTHESIS_MIN_CATEGORIES
        && summary.medium_or_above_count() >= crate::rules_engine::SYNTHESIS_MIN_HITS;

    if has_elevate || synthesized_elevate {
        return if current_state >= ProvenanceState::Contaminated {
            ProvenanceState::Poisoned
        } else {
            ProvenanceState::Contaminated
        };
    }

    ProvenanceState::Clean
}

/// Tracks the provenance state for a specific agent connection.
///
/// F1 residual risk, stated with an actual number, not just a category
/// shift (see `docs/specs/spec-f1-clean-call-decay.md`): this fix converts
/// the "decay bombing" bypass from FREE and computational (one
/// agent-controlled local value, zero server involvement — the original
/// bug) to EXPENSIVE and behavioral (`K` real round trips, real BP, a real
/// audit trail, real replay protection). It does not make
/// server-cooperated laundering impossible — an attacker who already
/// controls the malicious server can have it emit `K` genuinely boring
/// responses on purpose. At the starting constants, the minimal repeat of
/// the original exploit's maneuver needs one `Contaminated -> Elevated`
/// decay (`CLEAN_CALLS_TO_DECAY_CONTAMINATED` = 5 calls, not a full trip to
/// `Clean`) before the next real signal: `5 x 200` BP (`Low`-risk base
/// cost) `= 1,000` BP per launder cycle. Against a `9,500` BP floor
/// (`membrane::RISK_FLOOR_BP`) with no other activity, that bounds a
/// patient attacker to roughly 8-9 repetitions of "launder, then strike"
/// before the floor alone ends the session — fewer in practice, since both
/// the strikes and any other traffic also consume budget. A real,
/// quantifiable, non-trivial cost and a genuine one-way door compared to
/// today's unlimited free repetition — but a bound, not a wall. Don't read
/// this as claiming the exploit is closed unqualified.
pub struct AgentProvenanceTracker {
    pub current_state: ProvenanceState,
    /// Consecutive responses, since the last escalation or decay, that were
    /// independently verified clean (see `record_response_outcome`) — NOT
    /// a count of calls in general, and never incremented by
    /// `ingest_signature`. Replaces the removed `bytes_since_elevation` /
    /// `decay_threshold` (agent-controlled outbound byte count) entirely;
    /// see this fix's spec for why that was the actual category error, not
    /// just a miscalibrated number.
    pub clean_calls_since_elevation: u32,
    pub poisoning_server_id: Option<String>,
    /// ids of any rules.yaml rules responsible for the most recent state
    /// escalation, if any. Empty when the last escalation (if any) was
    /// purely structural (source grade / response shape / schema
    /// conformance) with no rule hits involved. Consumed by membrane.rs on
    /// the NEXT proposal's audit record — the same timing the existing
    /// `provenance_state` field already has: the state (and now its cause)
    /// becomes visible in the audit log starting with the call after the
    /// one whose response caused it, since the audit record for a call is
    /// written before that call's own downstream response exists.
    pub last_triggering_rule_ids: Vec<String>,
}

impl AgentProvenanceTracker {
    pub fn new() -> Self {
        Self {
            current_state: ProvenanceState::Clean,
            clean_calls_since_elevation: 0,
            poisoning_server_id: None,
            last_triggering_rule_ids: Vec::new(),
        }
    }

    pub fn ingest_signature(
        &mut self,
        new_state: ProvenanceState,
        mcp_server_id: &str,
        triggering_rule_ids: &[String],
    ) {
        if new_state > self.current_state {
            self.current_state = new_state;
            self.last_triggering_rule_ids = triggering_rule_ids.to_vec();
            if new_state == ProvenanceState::Poisoned {
                self.poisoning_server_id = Some(mcp_server_id.to_string());
            }
        }
    }

    /// Decay driven by verified-clean ROUND TRIPS, not agent-declared
    /// egress size: the byte count the old version read was a value the
    /// agent declared itself, with zero server involvement, so decaying
    /// on it was a free, computational bypass ("decay bombing" —
    /// `docs/specs/spec-f1-clean-call-decay.md`) rather than evidence of
    /// an actual clean response. `this_call_state` is
    /// `structural_state.max(hit_state)`
    /// for THIS SPECIFIC call's response, independent of
    /// `self.current_state` — the same `new_state` value passed to
    /// `ingest_signature` for the same response.
    ///
    /// Escalation and healing-progress are mutually exclusive per
    /// response, by construction of the if/return below, not by
    /// coincidence of how the two functions happen to be called: either
    /// this call's own response is worse than `Elevated` (branch 1 —
    /// state may go UP via `ingest_signature`, streak resets) or it isn't
    /// (branch 2 — state may go DOWN here, streak progresses) — never
    /// both for the same response.
    ///
    /// `Poisoned` never decays under any number of clean calls — checked
    /// first, unconditionally; this invariant is unchanged by this fix.
    pub fn record_response_outcome(&mut self, this_call_state: ProvenanceState) {
        if self.current_state == ProvenanceState::Poisoned { return; }

        let tier = match self.current_state {
            ProvenanceState::Contaminated => Some((CLEAN_CALLS_TO_DECAY_CONTAMINATED, ProvenanceState::Elevated)),
            ProvenanceState::Elevated => Some((CLEAN_CALLS_TO_DECAY_ELEVATED, ProvenanceState::Clean)),
            _ => None,
        };

        if let Some((threshold, next_state)) = tier {
            // A call counts toward decaying into `next_state` only if its
            // own observed state is no worse than `next_state` itself. Any
            // call landing ABOVE the target is fresh evidence against
            // decaying that far -- reset the streak. This is what makes
            // escalation and decay commute: when the threshold is crossed
            // and current_state drops to next_state, the same response's
            // ingest_signature(this_call_state) cannot re-escalate, because
            // this_call_state <= next_state by the very condition that let
            // it count.
            if this_call_state <= next_state {
                self.clean_calls_since_elevation += 1;
                if self.clean_calls_since_elevation >= threshold {
                    self.current_state = next_state;
                    self.clean_calls_since_elevation = 0;
                }
            } else {
                self.clean_calls_since_elevation = 0;
            }
        }
    }
}

impl Default for AgentProvenanceTracker {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules_engine::{Action, HitDetail, RuleHitSummary, Severity};

    fn hit(rule_id: &str, category: &str, severity: Severity, action: Action) -> HitDetail {
        HitDetail {
            rule_id: rule_id.to_string(),
            category: category.to_string(),
            severity,
            action,
            suppressed_from: None,
        }
    }

    // ── Evidence monotonicity ─────────────────────────────────────────────
    //
    // The dilution question: can ADDING a rule hit ever lower the state
    // `state_from_rule_hits` returns? If it could, an attacker would pad a
    // real signal with extra benign-looking triggers to wash it out. Reading
    // the function says no, because every input to the decision is a
    // set-membership or a count and both only grow. Enumerated anyway --
    // "reading it says no" is what was true of the VKC Mini binding rule.

    #[test]
    fn adding_a_hit_never_lowers_the_resulting_state() {
        let catalogue = [
            hit("r-low", "cat-a", Severity::Low, Action::Flag),
            hit("r-med-a", "cat-a", Severity::Medium, Action::Flag),
            hit("r-med-b", "cat-b", Severity::Medium, Action::Flag),
            hit("r-med-c", "cat-c", Severity::Medium, Action::Flag),
            hit("r-high", "cat-d", Severity::High, Action::Elevate),
            hit("r-poison", "cat-e", Severity::High, Action::Poison),
        ];

        // Every subset of the catalogue, against every starting state.
        for mask in 0u32..(1 << catalogue.len()) {
            let subset: Vec<HitDetail> = (0..catalogue.len())
                .filter(|i| mask & (1 << i) != 0)
                .map(|i| catalogue[i].clone())
                .collect();

            for current in [
                ProvenanceState::Clean,
                ProvenanceState::Elevated,
                ProvenanceState::Contaminated,
                ProvenanceState::Poisoned,
            ] {
                let base = state_from_rule_hits(&RuleHitSummary { hits: subset.clone() }, current);

                // Adding any one further hit must not reduce the outcome.
                for (i, extra) in catalogue.iter().enumerate() {
                    if mask & (1 << i) != 0 {
                        continue;
                    }
                    let mut grown = subset.clone();
                    grown.push(extra.clone());
                    let after = state_from_rule_hits(&RuleHitSummary { hits: grown }, current);
                    assert!(
                        after >= base,
                        "adding {} lowered {base:?} -> {after:?} (current={current:?}, subset={:?})",
                        extra.rule_id,
                        subset.iter().map(|h| &h.rule_id).collect::<Vec<_>>()
                    );
                }
            }
        }
    }

    #[test]
    fn a_poison_hit_dominates_every_other_combination() {
        let poison = hit("r-poison", "cat-e", Severity::High, Action::Poison);
        let padding = [
            hit("p1", "cat-a", Severity::Low, Action::Flag),
            hit("p2", "cat-b", Severity::Low, Action::Flag),
            hit("p3", "cat-c", Severity::Medium, Action::Flag),
        ];
        for mask in 0u32..(1 << padding.len()) {
            let mut hits = vec![poison.clone()];
            for (i, p) in padding.iter().enumerate() {
                if mask & (1 << i) != 0 {
                    hits.push(p.clone());
                }
            }
            for current in [ProvenanceState::Clean, ProvenanceState::Contaminated] {
                assert_eq!(
                    state_from_rule_hits(&RuleHitSummary { hits: hits.clone() }, current),
                    ProvenanceState::Poisoned,
                    "poison did not dominate with padding mask {mask:b}"
                );
            }
        }
    }

    // ── Reachable-state enumeration ───────────────────────────────────────
    //
    // Second application of the property developed for VKC Mini. The membrane
    // asked "how many verdicts are reachable"; the FSM asks the temporal form
    // of the same question: over every observation sequence the agent could
    // produce, which states are reachable, and can any of them be reached in a
    // direction the design forbids?
    //
    // The observation alphabet is exhaustive — the four per-call states are
    // everything a single response can be worth — so sequences up to length N
    // cover the whole behaviour space up to that depth, rather than sampling it.

    const ALPHABET: [ProvenanceState; 4] = [
        ProvenanceState::Clean,
        ProvenanceState::Elevated,
        ProvenanceState::Contaminated,
        ProvenanceState::Poisoned,
    ];

    /// Drive a tracker through one sequence, applying both halves of the
    /// per-response update in the order main.rs uses them.
    fn drive(seq: &[ProvenanceState]) -> AgentProvenanceTracker {
        let mut tracker = AgentProvenanceTracker::new();
        for observed in seq {
            tracker.ingest_signature(*observed, "server-x", &[]);
            tracker.record_response_outcome(*observed);
        }
        tracker
    }

    fn all_sequences(depth: usize) -> Vec<Vec<ProvenanceState>> {
        let mut out = vec![Vec::new()];
        for _ in 0..depth {
            let mut next = Vec::new();
            for prefix in &out {
                for observed in ALPHABET {
                    let mut extended = prefix.clone();
                    extended.push(observed);
                    next.push(extended);
                }
            }
            out.extend(next);
        }
        out
    }

    #[test]
    fn poisoned_is_absorbing_across_every_sequence_to_depth_six() {
        // 4^1..4^6 = 5,460 sequences. Once Poisoned is observed, no suffix of
        // any composition may return the tracker to anything else.
        let mut checked = 0usize;
        for seq in all_sequences(6) {
            if !seq.contains(&ProvenanceState::Poisoned) {
                continue;
            }
            let tracker = drive(&seq);
            assert_eq!(
                tracker.current_state,
                ProvenanceState::Poisoned,
                "sequence {seq:?} contained Poisoned but ended at {:?}",
                tracker.current_state
            );
            checked += 1;
        }
        assert!(checked > 0, "enumeration produced no Poisoned-containing sequences");
    }

    #[test]
    fn no_single_observation_lowers_the_state_except_by_completing_a_decay_streak() {
        // The one-step version of monotonicity: from any state, an observation
        // may raise the state, hold it, or lower it by exactly one tier -- and
        // lowering requires the streak to be at its threshold. Anything that
        // dropped two tiers at once, or dropped from a fresh streak, would be a
        // laundering shortcut.
        for start in ALPHABET {
            for observed in ALPHABET {
                let mut tracker = AgentProvenanceTracker::new();
                tracker.current_state = start;
                tracker.clean_calls_since_elevation = 0;

                tracker.ingest_signature(observed, "server-x", &[]);
                tracker.record_response_outcome(observed);

                assert!(
                    tracker.current_state >= start || start == ProvenanceState::Clean,
                    "single observation {observed:?} lowered {start:?} -> {:?} from a fresh streak",
                    tracker.current_state
                );
            }
        }
    }

    #[test]
    fn escalation_and_healing_are_mutually_exclusive_for_one_response() {
        // The doc comment on record_response_outcome claims this holds "by
        // construction, not by coincidence". Enumerated rather than trusted.
        for start in [ProvenanceState::Elevated, ProvenanceState::Contaminated] {
            for observed in ALPHABET {
                let mut tracker = AgentProvenanceTracker::new();
                tracker.current_state = start;
                // Streak one short of the threshold, so a qualifying call decays.
                tracker.clean_calls_since_elevation = match start {
                    ProvenanceState::Contaminated => CLEAN_CALLS_TO_DECAY_CONTAMINATED - 1,
                    _ => CLEAN_CALLS_TO_DECAY_ELEVATED - 1,
                };

                tracker.ingest_signature(observed, "server-x", &[]);
                let after_escalation = tracker.current_state;
                tracker.record_response_outcome(observed);
                let after_decay = tracker.current_state;

                let escalated = after_escalation > start;
                let healed = after_decay < after_escalation;
                assert!(
                    !(escalated && healed),
                    "observation {observed:?} from {start:?} both escalated ({after_escalation:?}) \
                     and healed ({after_decay:?}) on the same response"
                );
            }
        }
    }

    #[test]
    fn enumerate_reachable_states_and_the_cost_of_reaching_clean() {
        // Prints the reachable set and the shortest laundering path, so the
        // bound the F1 doc comment states in prose is a measured number.
        // `cargo test enumerate_reachable_states -- --nocapture`
        let mut shortest_back_to_clean: Option<usize> = None;
        for seq in all_sequences(9) {
            if !seq.contains(&ProvenanceState::Contaminated) || seq.contains(&ProvenanceState::Poisoned) {
                continue;
            }
            if drive(&seq).current_state == ProvenanceState::Clean {
                let len = seq.len();
                shortest_back_to_clean = Some(shortest_back_to_clean.map_or(len, |b| b.min(len)));
            }
        }

        eprintln!("\n=== provenance reachability ===");
        eprintln!(
            "   shortest observation sequence from a Contaminated signal back to Clean: {}",
            shortest_back_to_clean
                .map(|n| n.to_string())
                .unwrap_or_else(|| "unreachable within depth 9".to_string())
        );
        eprintln!("   Poisoned -> anything else: unreachable (asserted above)\n");

        // Whatever the number is, it must exceed a single clean call --
        // otherwise one boring response would undo a real signal.
        if let Some(n) = shortest_back_to_clean {
            assert!(n > CLEAN_CALLS_TO_DECAY_ELEVATED as usize, "laundering path too short: {n}");
        }
    }

    // ---- compute_new_state ----

    #[test]
    fn malformed_response_form_is_always_poisoned_regardless_of_source_grade() {
        for grade in [SourceGrade::Attested, SourceGrade::Known, SourceGrade::Unvalidated, SourceGrade::Suspicious] {
            let state = compute_new_state(grade, ResponseForm::Malformed, SchemaConformance::NotDeclared, 0, 0);
            assert_eq!(state, ProvenanceState::Poisoned, "grade {:?} with Malformed form must poison", grade);
        }
    }

    #[test]
    fn schema_violated_is_always_poisoned_regardless_of_everything_else() {
        for grade in [SourceGrade::Attested, SourceGrade::Known, SourceGrade::Unvalidated, SourceGrade::Suspicious] {
            for form in [ResponseForm::PrimitiveData, ResponseForm::StructuredContainer, ResponseForm::BareString, ResponseForm::BareArray] {
                let state = compute_new_state(grade, form.clone(), SchemaConformance::Violated, 0, 0);
                assert_eq!(state, ProvenanceState::Poisoned, "grade {:?} form {:?} with Violated schema must poison", grade, form);
            }
        }
    }

    /// Demonstrates the heuristic/deterministic split concretely: a schema
    /// violation reaches Poisoned in one shot, straight from Clean, for a
    /// grade (Attested) that would otherwise need TWO corroborating
    /// heuristic signals via state_from_rule_hits to get there. A
    /// deterministic contract breach has no false-positive class and needs
    /// no corroboration — unlike a rule hit, which does (see
    /// single_heuristic_hit_from_elevated_produces_contaminated_not_poisoned).
    #[test]
    fn deterministic_schema_violation_poisons_directly_with_no_corroboration_needed() {
        let state = compute_new_state(
            SourceGrade::Attested,
            ResponseForm::StructuredContainer,
            SchemaConformance::Violated,
            10,
            0,
        );
        assert_eq!(
            state,
            ProvenanceState::Poisoned,
            "a schema violation must poison directly from Clean-eligible inputs, with no corroboration step"
        );
    }

    #[test]
    fn suspicious_source_grade_is_always_poisoned_regardless_of_response_form() {
        for form in [ResponseForm::PrimitiveData, ResponseForm::StructuredContainer, ResponseForm::BareString, ResponseForm::BareArray] {
            let state = compute_new_state(SourceGrade::Suspicious, form.clone(), SchemaConformance::NotDeclared, 0, 0);
            assert_eq!(state, ProvenanceState::Poisoned, "Suspicious grade with form {:?} must poison", form);
        }
    }

    #[test]
    fn unvalidated_bare_string_is_elevated() {
        // Was Contaminated: source grade (a server property) must not be
        // able to manufacture evidence the session's information
        // environment never actually produced. See §2 of
        // spec-provenance-semantics-correction.md.
        let state = compute_new_state(SourceGrade::Unvalidated, ResponseForm::BareString, SchemaConformance::NotDeclared, 0, 0);
        assert_eq!(state, ProvenanceState::Elevated);
    }

    #[test]
    fn unvalidated_never_reaches_clean_for_any_response_form() {
        for form in [
            ResponseForm::PrimitiveData,
            ResponseForm::StructuredContainer,
            ResponseForm::BareString,
            ResponseForm::BareArray,
            ResponseForm::Malformed,
        ] {
            let state = compute_new_state(SourceGrade::Unvalidated, form.clone(), SchemaConformance::NotDeclared, 0, 0);
            assert_ne!(state, ProvenanceState::Clean, "Unvalidated + {:?} must never reach Clean", form);
        }
    }

    #[test]
    fn bytes_over_cap_forces_elevated_even_for_an_otherwise_clean_eligible_combination() {
        // Attested + StructuredContainer + long_string_count 0 would otherwise
        // reach Clean (see good_path_reaches_clean_for_attested_and_known) -
        // pushing total_string_bytes past AGGREGATE_STRING_BYTES_CAP must
        // override that.
        let state = compute_new_state(
            SourceGrade::Attested,
            ResponseForm::StructuredContainer,
            SchemaConformance::NotDeclared,
            AGGREGATE_STRING_BYTES_CAP + 1,
            0,
        );
        assert_eq!(state, ProvenanceState::Elevated);
    }

    #[test]
    fn attested_bare_string_reaches_clean_without_long_string_content() {
        let state = compute_new_state(SourceGrade::Attested, ResponseForm::BareString, SchemaConformance::NotDeclared, 0, 0);
        assert_eq!(state, ProvenanceState::Clean, "a short response must not be trapped at Elevated purely for being a bare string");
    }

    #[test]
    fn attested_primitive_data_reaches_clean_without_long_string_content() {
        let state = compute_new_state(SourceGrade::Attested, ResponseForm::PrimitiveData, SchemaConformance::NotDeclared, 0, 0);
        assert_eq!(state, ProvenanceState::Clean, "a short response must not be trapped at Elevated purely for being primitive data");
    }

    #[test]
    fn known_bare_string_reaches_clean_without_long_string_content() {
        let state = compute_new_state(SourceGrade::Known, ResponseForm::BareString, SchemaConformance::NotDeclared, 0, 0);
        assert_eq!(state, ProvenanceState::Clean, "a short response must not be trapped at Elevated purely for being a bare string");
    }

    #[test]
    fn known_primitive_data_reaches_clean_without_long_string_content() {
        let state = compute_new_state(SourceGrade::Known, ResponseForm::PrimitiveData, SchemaConformance::NotDeclared, 0, 0);
        assert_eq!(state, ProvenanceState::Clean, "a short response must not be trapped at Elevated purely for being primitive data");
    }

    #[test]
    fn good_path_reaches_clean_for_attested_and_known_structured_container() {
        for grade in [SourceGrade::Attested, SourceGrade::Known] {
            let state = compute_new_state(grade, ResponseForm::StructuredContainer, SchemaConformance::NotDeclared, 10, 0);
            assert_eq!(
                state,
                ProvenanceState::Clean,
                "grade {:?}, StructuredContainer, under cap, no long strings must reach Clean",
                grade
            );
        }
    }

    #[test]
    fn long_string_count_forces_elevated_even_for_an_otherwise_clean_eligible_combination() {
        for grade in [SourceGrade::Attested, SourceGrade::Known] {
            let state = compute_new_state(grade, ResponseForm::StructuredContainer, SchemaConformance::NotDeclared, 10, 1);
            assert_eq!(
                state,
                ProvenanceState::Elevated,
                "grade {:?} with a long string present must not reach Clean",
                grade
            );
        }
    }

    // ---- state_from_rule_hits ----

    #[test]
    fn poison_action_hit_always_poisons_regardless_of_current_state() {
        let summary = RuleHitSummary { hits: vec![hit("R-1", "cat", Severity::Critical, Action::Poison)] };
        for state in [ProvenanceState::Clean, ProvenanceState::Elevated, ProvenanceState::Contaminated, ProvenanceState::Poisoned] {
            assert_eq!(
                state_from_rule_hits(&summary, state),
                ProvenanceState::Poisoned,
                "a Poison-action hit must poison regardless of current_state {:?}",
                state
            );
        }
    }

    #[test]
    fn single_elevate_hit_from_clean_becomes_contaminated() {
        let summary = RuleHitSummary { hits: vec![hit("R-1", "cat", Severity::High, Action::Elevate)] };
        assert_eq!(state_from_rule_hits(&summary, ProvenanceState::Clean), ProvenanceState::Contaminated);
    }

    /// THE regression guard for this change. A single heuristic hit must
    /// land on Contaminated — heuristic, uncorroborated, recoverable — even
    /// when the session is already Elevated (the normal resting state for
    /// any session that has consumed substantial external content). If this collapses back
    /// to Poisoned, the corroboration threshold silently reverted to
    /// `>= Elevated`, and a single DSO-001 match — including the
    /// security-blogpost false positive
    /// tests/fixtures/should_not_poison/security_blogpost_excerpt.md
    /// deliberately covers — would poison a session outright. Nothing else
    /// in this suite would catch that regression; the name is deliberately
    /// explicit so a failure here says exactly what broke.
    #[test]
    fn single_heuristic_hit_from_elevated_produces_contaminated_not_poisoned() {
        let summary = RuleHitSummary { hits: vec![hit("R-1", "cat", Severity::High, Action::Elevate)] };
        assert_eq!(
            state_from_rule_hits(&summary, ProvenanceState::Elevated),
            ProvenanceState::Contaminated,
            "a single heuristic hit from Elevated must land on Contaminated, NOT Poisoned — \
             Elevated is the normal resting state for any session that has consumed substantial external content, so \
             corroborating against it would poison on a single ambiguous signal"
        );
    }

    /// THE corroboration case: a second elevate-strength signal while the
    /// session is ALREADY Contaminated must poison the session, not just
    /// hold it at Contaminated. Kept as its own dedicated test per
    /// docs/specs/spec-fsm-test-coverage.md, which calls this the single
    /// most important case in this file — a failure here must not be
    /// hideable inside a broader scenario.
    #[test]
    fn corroboration_second_elevate_signal_while_already_contaminated_poisons() {
        let summary = RuleHitSummary { hits: vec![hit("R-1", "cat", Severity::High, Action::Elevate)] };
        assert_eq!(state_from_rule_hits(&summary, ProvenanceState::Contaminated), ProvenanceState::Poisoned);
    }

    /// Documents actual (not assumed) behavior for the remaining
    /// current_state input. Per the code: `has_elevate` is true and
    /// `current_state >= Contaminated` is true for Poisoned too, so this
    /// function returns Poisoned for it — it does NOT return something
    /// lower than current_state on this path. The "may return lower than
    /// current_state" risk the spec asks to check for does not materialize
    /// here; it DOES materialize on the flag-only path below, which is why
    /// main.rs's `.max(structural_state, hit_state)` matters — see
    /// `flag_only_hits_return_clean_regardless_of_current_state`.
    #[test]
    fn single_elevate_hit_from_poisoned_stays_at_poisoned() {
        let summary = RuleHitSummary { hits: vec![hit("R-1", "cat", Severity::High, Action::Elevate)] };
        assert_eq!(state_from_rule_hits(&summary, ProvenanceState::Poisoned), ProvenanceState::Poisoned);
    }

    /// This function reports only what THIS response's hits alone justify —
    /// a flag-only summary returns Clean even when current_state is
    /// already Poisoned. That IS a real "lower than current_state" result.
    /// It is not a bug in this function (the module comment above
    /// documents it as intentional), but it means the ONLY thing
    /// preventing an actual regression — a session un-poisoning itself
    /// because one call's response happened to have only flag-severity
    /// hits — is main.rs's `let new_state = structural_state.max(hit_state);`
    /// before calling `ingest_signature`. If that `.max()` is ever removed
    /// or reordered, this exact scenario becomes a live regression.
    #[test]
    fn flag_only_hits_return_clean_regardless_of_current_state() {
        let summary = RuleHitSummary { hits: vec![hit("R-1", "cat", Severity::Low, Action::Flag)] };
        for state in [ProvenanceState::Clean, ProvenanceState::Elevated, ProvenanceState::Contaminated, ProvenanceState::Poisoned] {
            assert_eq!(
                state_from_rule_hits(&summary, state),
                ProvenanceState::Clean,
                "flag-only hits must report Clean from this function alone, regardless of current_state {:?}",
                state
            );
        }
    }

    #[test]
    fn synthesis_just_below_threshold_by_hit_count_does_not_synthesize() {
        // SYNTHESIS_MIN_CATEGORIES categories satisfied, but only
        // SYNTHESIS_MIN_HITS - 1 medium-or-above hits.
        let summary = RuleHitSummary {
            hits: vec![
                hit("R-1", "cat-a", Severity::Medium, Action::Flag),
                hit("R-2", "cat-b", Severity::Medium, Action::Flag),
            ],
        };
        assert_eq!(
            summary.medium_or_above_category_count(),
            crate::rules_engine::SYNTHESIS_MIN_CATEGORIES,
            "test setup sanity check: category count must meet the threshold"
        );
        assert_eq!(
            summary.medium_or_above_count(),
            crate::rules_engine::SYNTHESIS_MIN_HITS - 1,
            "test setup sanity check: hit count must be exactly one below the threshold"
        );
        assert_eq!(state_from_rule_hits(&summary, ProvenanceState::Clean), ProvenanceState::Clean);
    }

    #[test]
    fn synthesis_just_below_threshold_by_category_count_does_not_synthesize() {
        // SYNTHESIS_MIN_HITS hits satisfied, but only
        // SYNTHESIS_MIN_CATEGORIES - 1 (i.e. 1) distinct category.
        let summary = RuleHitSummary {
            hits: vec![
                hit("R-1", "cat-a", Severity::Medium, Action::Flag),
                hit("R-2", "cat-a", Severity::Medium, Action::Flag),
                hit("R-3", "cat-a", Severity::Medium, Action::Flag),
            ],
        };
        assert_eq!(
            summary.medium_or_above_count(),
            crate::rules_engine::SYNTHESIS_MIN_HITS,
            "test setup sanity check: hit count must meet the threshold"
        );
        assert_eq!(
            summary.medium_or_above_category_count(),
            crate::rules_engine::SYNTHESIS_MIN_CATEGORIES - 1,
            "test setup sanity check: category count must be exactly one below the threshold"
        );
        assert_eq!(state_from_rule_hits(&summary, ProvenanceState::Clean), ProvenanceState::Clean);
    }

    #[test]
    fn synthesis_at_threshold_synthesizes_with_same_corroboration_behavior_as_elevate() {
        let summary = RuleHitSummary {
            hits: vec![
                hit("R-1", "cat-a", Severity::Medium, Action::Flag),
                hit("R-2", "cat-a", Severity::Medium, Action::Flag),
                hit("R-3", "cat-b", Severity::Medium, Action::Flag),
            ],
        };
        assert_eq!(summary.medium_or_above_count(), crate::rules_engine::SYNTHESIS_MIN_HITS);
        assert_eq!(summary.medium_or_above_category_count(), crate::rules_engine::SYNTHESIS_MIN_CATEGORIES);

        assert_eq!(
            state_from_rule_hits(&summary, ProvenanceState::Clean),
            ProvenanceState::Contaminated,
            "at-threshold synthesis from Clean must produce Contaminated, same as a direct Elevate hit"
        );
        assert_eq!(
            state_from_rule_hits(&summary, ProvenanceState::Contaminated),
            ProvenanceState::Poisoned,
            "at-threshold synthesis while already Contaminated must poison, same as a direct Elevate hit"
        );
    }

    // ---- AgentProvenanceTracker ----

    #[test]
    fn ingest_signature_only_escalates_and_a_noop_does_not_clobber_rule_ids() {
        let mut tracker = AgentProvenanceTracker::new();
        tracker.ingest_signature(ProvenanceState::Elevated, "server-a", &["RULE-A".to_string()]);
        assert_eq!(tracker.current_state, ProvenanceState::Elevated);
        assert_eq!(tracker.last_triggering_rule_ids, vec!["RULE-A".to_string()]);

        // A no-op ingest: new_state (Clean) is at or below current_state
        // (Elevated). current_state must be unchanged AND
        // last_triggering_rule_ids must NOT be overwritten by this call's
        // (irrelevant) rule ids.
        tracker.ingest_signature(ProvenanceState::Clean, "server-b", &["RULE-B".to_string()]);
        assert_eq!(tracker.current_state, ProvenanceState::Elevated, "a non-escalating ingest must not change current_state");
        assert_eq!(
            tracker.last_triggering_rule_ids,
            vec!["RULE-A".to_string()],
            "a non-escalating ingest must not clobber the last real escalation's rule ids"
        );

        // Same-state ingest (Elevated -> Elevated) is also a no-op, since
        // the check is strictly `new_state > current_state`.
        tracker.ingest_signature(ProvenanceState::Elevated, "server-c", &["RULE-C".to_string()]);
        assert_eq!(
            tracker.last_triggering_rule_ids,
            vec!["RULE-A".to_string()],
            "an equal-state ingest must also not clobber rule ids"
        );
    }

    /// Hard invariant, not a threshold: Poisoned never decays under ANY
    /// number of independently-clean calls, including an absurd number of
    /// them — confirming there is no path back from Poisoned at all, not
    /// merely finding where decay happens to resume. Carried over verbatim
    /// (same assertion, same spirit) from the byte-threshold mechanism this
    /// replaces, per docs/specs/spec-f1-clean-call-decay.md's requirement
    /// that this invariant stay unchanged and re-exercised against the new
    /// mechanism, not just conceptually.
    #[test]
    fn poisoned_never_decays_even_with_an_absurd_number_of_clean_calls() {
        let mut tracker = AgentProvenanceTracker::new();
        tracker.ingest_signature(ProvenanceState::Poisoned, "server-a", &["MCT-001".to_string()]);
        assert_eq!(tracker.current_state, ProvenanceState::Poisoned);

        tracker.record_response_outcome(ProvenanceState::Clean);
        assert_eq!(
            tracker.current_state,
            ProvenanceState::Poisoned,
            "Poisoned must not decay even after a single verified-clean response"
        );

        // Confirm repeatedly too, not just once — there is no path back at
        // all, no matter how many clean calls follow (10,000, well past any
        // real CLEAN_CALLS_TO_DECAY_* threshold).
        for _ in 0..10_000 {
            tracker.record_response_outcome(ProvenanceState::Clean);
        }
        assert_eq!(
            tracker.current_state,
            ProvenanceState::Poisoned,
            "Poisoned must not decay no matter how many consecutive clean calls follow"
        );
    }

    /// THE direct F1 regression test: a single call — however large its
    /// arguments, since egress size is no longer read by this mechanism at
    /// all — must not decay Contaminated. Formalizes the original
    /// adversarial review's "decay bombing" proof-of-concept: one cheap,
    /// padded call used to be enough to launder Contaminated back to
    /// Elevated for free. Under the new mechanism, ONE clean call
    /// contributes exactly one count toward CLEAN_CALLS_TO_DECAY_CONTAMINATED
    /// (5) and cannot alone cross that threshold.
    #[test]
    fn single_clean_call_does_not_decay_contaminated() {
        let mut tracker = AgentProvenanceTracker::new();
        tracker.ingest_signature(ProvenanceState::Contaminated, "server-a", &["DSO-001".to_string()]);
        assert_eq!(tracker.current_state, ProvenanceState::Contaminated);

        tracker.record_response_outcome(ProvenanceState::Clean);
        assert_eq!(
            tracker.current_state,
            ProvenanceState::Contaminated,
            "THE F1 REGRESSION: a single clean call must not decay Contaminated — under the old \
             byte-threshold mechanism, one call with a large enough argument payload did exactly \
             this for free"
        );
        assert_eq!(tracker.clean_calls_since_elevation, 1);
    }

    #[test]
    fn k_consecutive_clean_calls_decay_one_tier_and_reset_the_counter() {
        let mut tracker = AgentProvenanceTracker::new();
        tracker.ingest_signature(ProvenanceState::Contaminated, "server-a", &["DSO-001".to_string()]);

        for i in 1..CLEAN_CALLS_TO_DECAY_CONTAMINATED {
            tracker.record_response_outcome(ProvenanceState::Clean);
            assert_eq!(
                tracker.current_state,
                ProvenanceState::Contaminated,
                "must not decay before the {}th consecutive clean call", i
            );
            assert_eq!(tracker.clean_calls_since_elevation, i);
        }

        // The Kth consecutive clean call decays one tier and resets the counter.
        tracker.record_response_outcome(ProvenanceState::Clean);
        assert_eq!(
            tracker.current_state,
            ProvenanceState::Elevated,
            "the Kth consecutive clean call must decay Contaminated -> Elevated"
        );
        assert_eq!(tracker.clean_calls_since_elevation, 0, "the counter must reset to zero after decaying");

        // Decaying again, Elevated -> Clean, at the (different, smaller) K for that tier.
        for i in 1..CLEAN_CALLS_TO_DECAY_ELEVATED {
            tracker.record_response_outcome(ProvenanceState::Clean);
            assert_eq!(tracker.current_state, ProvenanceState::Elevated, "must not decay before the {}th consecutive clean call", i);
        }
        tracker.record_response_outcome(ProvenanceState::Clean);
        assert_eq!(tracker.current_state, ProvenanceState::Clean, "the Kth consecutive clean call must decay Elevated -> Clean");
        assert_eq!(tracker.clean_calls_since_elevation, 0);
    }

    /// THE loophole-closing case, per docs/specs/spec-f1-clean-call-decay.md:
    /// a fresh but non-escalating hit (new_state <= tracker.current_state,
    /// but still > Elevated — i.e., still real heuristic evidence) must
    /// reset the streak to zero, even though tracker.current_state itself
    /// doesn't change as a result (ingest_signature only mutates on strict
    /// escalation). Without this, an attacker could interleave
    /// sub-threshold noise between clean calls at no cost while still
    /// progressing the streak toward decay.
    #[test]
    fn non_escalating_fresh_hit_still_resets_the_streak() {
        let mut tracker = AgentProvenanceTracker::new();
        tracker.ingest_signature(ProvenanceState::Contaminated, "server-a", &["DSO-001".to_string()]);

        // Build up partial progress toward decay.
        tracker.record_response_outcome(ProvenanceState::Clean);
        tracker.record_response_outcome(ProvenanceState::Clean);
        assert_eq!(tracker.clean_calls_since_elevation, 2);

        // A fresh Contaminated-level hit: new_state (Contaminated) is NOT
        // strictly greater than tracker.current_state (already
        // Contaminated), so ingest_signature would be a no-op here and
        // current_state doesn't change — but it must still reset the streak.
        assert_eq!(tracker.current_state, ProvenanceState::Contaminated, "test setup sanity check");
        tracker.record_response_outcome(ProvenanceState::Contaminated);
        assert_eq!(
            tracker.clean_calls_since_elevation, 0,
            "a fresh non-escalating hit (new_state == current_state, still > Elevated) must reset \
             the streak to zero, not be silently absorbed"
        );
        assert_eq!(
            tracker.current_state,
            ProvenanceState::Contaminated,
            "current_state itself is unchanged by this non-escalating hit — only the streak resets"
        );

        // Confirm the reset actually cost progress: 4 more clean calls
        // (not 3) are now needed to reach CLEAN_CALLS_TO_DECAY_CONTAMINATED.
        for _ in 0..(CLEAN_CALLS_TO_DECAY_CONTAMINATED - 1) {
            tracker.record_response_outcome(ProvenanceState::Clean);
        }
        assert_eq!(
            tracker.current_state,
            ProvenanceState::Contaminated,
            "must still not have decayed — the reset means the streak restarted from zero"
        );
        tracker.record_response_outcome(ProvenanceState::Clean);
        assert_eq!(tracker.current_state, ProvenanceState::Elevated, "must decay once the full K is reached AFTER the reset");
    }

    /// The C1 regression guard. Unlike every other decay test above, this
    /// one drives `this_call_state` from the REAL classifier
    /// (`compute_new_state`) on a real response shape, and chains it
    /// through both tracker methods in main.rs's own order -- not a
    /// hand-picked ProvenanceState literal fed to record_response_outcome
    /// alone. This is the specific coverage hole that let the C1
    /// provenance-trap bug ship: every prior decay test could pass against
    /// a classifier that structurally never produced Clean for any real
    /// response, because none of them ever asked the classifier what it
    /// would actually produce.
    #[test]
    fn decay_driven_by_real_classify_and_chained_like_main_rs_reaches_clean() {
        let mut tracker = AgentProvenanceTracker::new();
        tracker.current_state = ProvenanceState::Elevated;

        // A short, benign response from a Known server -- e.g. a "pong"
        // reply -- classifies as PrimitiveData (top-level object), zero
        // long strings, well under the byte cap.
        let this_call_state = compute_new_state(
            SourceGrade::Known,
            ResponseForm::PrimitiveData,
            SchemaConformance::NotDeclared,
            4,
            0,
        );
        assert_eq!(
            this_call_state,
            ProvenanceState::Clean,
            "precondition: a short real response must classify as Clean post-fix, or the rest of this test is meaningless"
        );

        for _ in 0..CLEAN_CALLS_TO_DECAY_ELEVATED {
            tracker.record_response_outcome(this_call_state);
            tracker.ingest_signature(this_call_state, "known-server", &[]);
        }

        assert_eq!(
            tracker.current_state,
            ProvenanceState::Clean,
            "K consecutive real-classifier-produced Clean responses, chained through both tracker methods in main.rs's actual order, must decay Elevated back to Clean"
        );
    }
}
