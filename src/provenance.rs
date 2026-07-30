// src/provenance.rs

use serde::Serialize;

use crate::registry::{RiskClass, SourceGrade};
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

/// The 4-tier provenance state of an agent's information environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ProvenanceState {
    Clean = 0,
    Elevated = 1,
    Contaminated = 2,
    Poisoned = 3,
}

const LONG_STRING_THRESHOLD: usize = 200;
const AGGREGATE_STRING_BYTES_CAP: u32 = 800;
const DECAY_MULTIPLIER: f64 = 1.5;

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
/// conformance, aggregate size). Mirrors the AS-1-closed match table:
/// PrimitiveData no longer reaches Clean unconditionally for Attested/Known
/// grades, and Unvalidated (the v1 default for every server unless
/// explicitly graded otherwise) never reaches Clean at all.
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
    if source_grade == SourceGrade::Suspicious { return ProvenanceState::Poisoned; }

    if source_grade == SourceGrade::Unvalidated {
        if response_form == ResponseForm::BareString { return ProvenanceState::Contaminated; }
        return ProvenanceState::Elevated;
    }

    if total_string_bytes > AGGREGATE_STRING_BYTES_CAP { return ProvenanceState::Elevated; }

    match (source_grade, response_form) {
        (SourceGrade::Attested, ResponseForm::BareString) => ProvenanceState::Elevated,
        (SourceGrade::Attested, ResponseForm::PrimitiveData) => ProvenanceState::Elevated,
        (SourceGrade::Known, ResponseForm::BareString) => ProvenanceState::Elevated,
        (SourceGrade::Known, ResponseForm::PrimitiveData) => ProvenanceState::Elevated,
        _ => {
            if long_string_count > 0 { ProvenanceState::Elevated }
            else { ProvenanceState::Clean }
        }
    }
}

/// The state a response's rule hits alone would justify, given the
/// session's CURRENT state. Two fields on each hit do different jobs here,
/// deliberately:
///
///   - `action` (flag | elevate | poison), set explicitly per rule in
///     rules.yaml, is the DIRECT consequence of that specific rule firing.
///     A `poison` action always poisons immediately; an `elevate` action
///     elevates on first occurrence.
///   - `severity`, used below via `RuleHitSummary`'s counting methods, is
///     the CORROBORATION weight: it's what lets several individually
///     medium-confidence hits across different categories in one response
///     add up to something worth treating as a single elevate-strength
///     signal, without needing every rule author to hand-tune `action` for
///     that interaction.
///
/// The corroboration rule this function also enforces — a second
/// elevate-or-stronger signal while the session is ALREADY at Elevated
/// escalates all the way to Poisoned — exists because one elevate-strength
/// signal shouldn't fully poison a session on its own (that's what a
/// `poison` action is for), but two independent ones, on two different tool
/// calls or within the same response, should. Only the tracker's current
/// state can tell us whether this is the first such signal or the second,
/// which is why this takes `current_state` as an argument rather than being
/// a pure function of the summary alone.
pub fn state_from_rule_hits(summary: &RuleHitSummary, current_state: ProvenanceState) -> ProvenanceState {
    if summary.hits.iter().any(|h| h.action == Action::Poison) {
        return ProvenanceState::Poisoned;
    }

    let has_elevate = summary.hits.iter().any(|h| h.action == Action::Elevate);
    let synthesized_elevate = summary.medium_or_above_category_count() >= crate::rules_engine::SYNTHESIS_MIN_CATEGORIES
        && summary.medium_or_above_count() >= crate::rules_engine::SYNTHESIS_MIN_HITS;

    if has_elevate || synthesized_elevate {
        return if current_state >= ProvenanceState::Elevated {
            ProvenanceState::Poisoned
        } else {
            ProvenanceState::Elevated
        };
    }

    ProvenanceState::Clean
}

/// Tracks the provenance state for a specific agent connection.
pub struct AgentProvenanceTracker {
    pub current_state: ProvenanceState,
    pub bytes_since_elevation: usize,
    pub decay_threshold: usize,
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
            bytes_since_elevation: 0,
            decay_threshold: 0,
            poisoning_server_id: None,
            last_triggering_rule_ids: Vec::new(),
        }
    }

    pub fn ingest_signature(
        &mut self,
        new_state: ProvenanceState,
        ingress_bytes: usize,
        mcp_server_id: &str,
        triggering_rule_ids: &[String],
    ) {
        if new_state > self.current_state {
            self.current_state = new_state;
            self.bytes_since_elevation = 0;
            self.decay_threshold = (ingress_bytes as f64 * DECAY_MULTIPLIER) as usize;
            self.last_triggering_rule_ids = triggering_rule_ids.to_vec();
            if new_state == ProvenanceState::Poisoned {
                self.poisoning_server_id = Some(mcp_server_id.to_string());
            }
        }
    }

    /// Called ONLY on the success path of a proposal evaluation. An agent
    /// cannot farm decay credit through a rejection at zero BP cost.
    pub fn record_outbound_and_decay(&mut self, egress_bytes: usize) {
        if self.current_state == ProvenanceState::Poisoned { return; }

        self.bytes_since_elevation += egress_bytes;
        if self.bytes_since_elevation > self.decay_threshold {
            self.current_state = match self.current_state {
                ProvenanceState::Contaminated => ProvenanceState::Elevated,
                ProvenanceState::Elevated => ProvenanceState::Clean,
                _ => self.current_state,
            };
            self.bytes_since_elevation = 0;
        }
    }
}

impl Default for AgentProvenanceTracker {
    fn default() -> Self { Self::new() }
}

/// Modulates a proposal's risk class based on the current tracker state, and
/// enforces the Critical gate: any Critical action requires Clean provenance,
/// full stop, independent of BP budget. This is what keeps the worst-tier
/// action safe even if DECAY_MULTIPLIER's calibration turns out to be wrong.
pub fn modulate_risk_class(
    proposal_risk: &mut RiskClass,
    state: &ProvenanceState,
) -> Result<(), &'static str> {
    match (*proposal_risk, *state) {
        (_, ProvenanceState::Clean) => {}
        (RiskClass::High, ProvenanceState::Elevated) => *proposal_risk = RiskClass::Critical,
        (RiskClass::Medium, ProvenanceState::Contaminated) => *proposal_risk = RiskClass::High,
        (RiskClass::High, ProvenanceState::Contaminated) => *proposal_risk = RiskClass::Critical,
        (_, ProvenanceState::Poisoned) => return Err("InboundPoisoningDetected"),
        _ => {}
    }

    if *proposal_risk == RiskClass::Critical && *state != ProvenanceState::Clean {
        return Err("CriticalBlockedByProvenance");
    }

    Ok(())
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

    #[test]
    fn suspicious_source_grade_is_always_poisoned_regardless_of_response_form() {
        for form in [ResponseForm::PrimitiveData, ResponseForm::StructuredContainer, ResponseForm::BareString, ResponseForm::BareArray] {
            let state = compute_new_state(SourceGrade::Suspicious, form.clone(), SchemaConformance::NotDeclared, 0, 0);
            assert_eq!(state, ProvenanceState::Poisoned, "Suspicious grade with form {:?} must poison", form);
        }
    }

    #[test]
    fn unvalidated_bare_string_is_contaminated() {
        let state = compute_new_state(SourceGrade::Unvalidated, ResponseForm::BareString, SchemaConformance::NotDeclared, 0, 0);
        assert_eq!(state, ProvenanceState::Contaminated);
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
    fn as1_closed_table_attested_bare_string_is_elevated_never_clean() {
        let state = compute_new_state(SourceGrade::Attested, ResponseForm::BareString, SchemaConformance::NotDeclared, 0, 0);
        assert_eq!(state, ProvenanceState::Elevated);
    }

    #[test]
    fn as1_closed_table_attested_primitive_data_is_elevated_never_clean() {
        let state = compute_new_state(SourceGrade::Attested, ResponseForm::PrimitiveData, SchemaConformance::NotDeclared, 0, 0);
        assert_eq!(state, ProvenanceState::Elevated);
    }

    #[test]
    fn as1_closed_table_known_bare_string_is_elevated_never_clean() {
        let state = compute_new_state(SourceGrade::Known, ResponseForm::BareString, SchemaConformance::NotDeclared, 0, 0);
        assert_eq!(state, ProvenanceState::Elevated);
    }

    #[test]
    fn as1_closed_table_known_primitive_data_is_elevated_never_clean() {
        let state = compute_new_state(SourceGrade::Known, ResponseForm::PrimitiveData, SchemaConformance::NotDeclared, 0, 0);
        assert_eq!(state, ProvenanceState::Elevated);
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
    fn single_elevate_hit_from_clean_becomes_elevated() {
        let summary = RuleHitSummary { hits: vec![hit("R-1", "cat", Severity::High, Action::Elevate)] };
        assert_eq!(state_from_rule_hits(&summary, ProvenanceState::Clean), ProvenanceState::Elevated);
    }

    /// THE corroboration case: a second elevate-strength signal while the
    /// session is ALREADY Elevated must poison the session, not just hold
    /// it at Elevated. Kept as its own dedicated test per
    /// docs/specs/spec-fsm-test-coverage.md, which calls this the single
    /// most important case in this file — a failure here must not be
    /// hideable inside a broader scenario.
    #[test]
    fn corroboration_second_elevate_signal_while_already_elevated_poisons() {
        let summary = RuleHitSummary { hits: vec![hit("R-1", "cat", Severity::High, Action::Elevate)] };
        assert_eq!(state_from_rule_hits(&summary, ProvenanceState::Elevated), ProvenanceState::Poisoned);
    }

    /// Documents actual (not assumed) behavior for the two remaining
    /// current_state inputs. Per the code: `has_elevate` is true and
    /// `current_state >= Elevated` is true for BOTH Contaminated and
    /// Poisoned, so this function returns Poisoned for both — it does NOT
    /// return something lower than current_state on this path
    /// (Contaminated(2) -> Poisoned(3) is a further escalation, not a
    /// regression). The "may return lower than current_state" risk the
    /// spec asks to check for does not materialize here; it DOES
    /// materialize on the flag-only path below, which is why main.rs's
    /// `.max(structural_state, hit_state)` matters — see
    /// `flag_only_hits_return_clean_regardless_of_current_state`.
    #[test]
    fn single_elevate_hit_from_contaminated_or_poisoned_stays_at_poisoned() {
        let summary = RuleHitSummary { hits: vec![hit("R-1", "cat", Severity::High, Action::Elevate)] };
        assert_eq!(state_from_rule_hits(&summary, ProvenanceState::Contaminated), ProvenanceState::Poisoned);
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
            ProvenanceState::Elevated,
            "at-threshold synthesis from Clean must elevate, same as a direct Elevate hit"
        );
        assert_eq!(
            state_from_rule_hits(&summary, ProvenanceState::Elevated),
            ProvenanceState::Poisoned,
            "at-threshold synthesis while already Elevated must poison, same as a direct Elevate hit"
        );
    }

    // ---- AgentProvenanceTracker ----

    #[test]
    fn ingest_signature_only_escalates_and_a_noop_does_not_clobber_rule_ids() {
        let mut tracker = AgentProvenanceTracker::new();
        tracker.ingest_signature(ProvenanceState::Elevated, 100, "server-a", &["RULE-A".to_string()]);
        assert_eq!(tracker.current_state, ProvenanceState::Elevated);
        assert_eq!(tracker.last_triggering_rule_ids, vec!["RULE-A".to_string()]);

        // A no-op ingest: new_state (Clean) is at or below current_state
        // (Elevated). current_state must be unchanged AND
        // last_triggering_rule_ids must NOT be overwritten by this call's
        // (irrelevant) rule ids.
        tracker.ingest_signature(ProvenanceState::Clean, 999, "server-b", &["RULE-B".to_string()]);
        assert_eq!(tracker.current_state, ProvenanceState::Elevated, "a non-escalating ingest must not change current_state");
        assert_eq!(
            tracker.last_triggering_rule_ids,
            vec!["RULE-A".to_string()],
            "a non-escalating ingest must not clobber the last real escalation's rule ids"
        );

        // Same-state ingest (Elevated -> Elevated) is also a no-op, since
        // the check is strictly `new_state > current_state`.
        tracker.ingest_signature(ProvenanceState::Elevated, 999, "server-c", &["RULE-C".to_string()]);
        assert_eq!(
            tracker.last_triggering_rule_ids,
            vec!["RULE-A".to_string()],
            "an equal-state ingest must also not clobber rule ids"
        );
    }

    #[test]
    fn decay_threshold_is_set_from_ingress_bytes_and_decay_multiplier_on_escalation() {
        let mut tracker = AgentProvenanceTracker::new();
        tracker.ingest_signature(ProvenanceState::Elevated, 100, "server-a", &[]);
        assert_eq!(tracker.decay_threshold, (100.0 * DECAY_MULTIPLIER) as usize);
    }

    /// Hard invariant, not a threshold: Poisoned never decays under ANY
    /// amount of egress, including an absurdly large one — confirming
    /// there is no path back from Poisoned at all, not merely finding
    /// where decay happens to resume.
    #[test]
    fn poisoned_never_decays_even_with_an_absurdly_large_egress_value() {
        let mut tracker = AgentProvenanceTracker::new();
        tracker.ingest_signature(ProvenanceState::Poisoned, 10, "server-a", &["MCT-001".to_string()]);
        assert_eq!(tracker.current_state, ProvenanceState::Poisoned);

        tracker.record_outbound_and_decay(usize::MAX / 2);
        assert_eq!(
            tracker.current_state,
            ProvenanceState::Poisoned,
            "Poisoned must not decay even under a single absurdly large egress value"
        );

        // Confirm repeatedly too, not just once — there is no path back at all.
        for _ in 0..5 {
            tracker.record_outbound_and_decay(usize::MAX / 2);
        }
        assert_eq!(
            tracker.current_state,
            ProvenanceState::Poisoned,
            "Poisoned must not decay no matter how much accumulated egress follows"
        );
    }

    #[test]
    fn contaminated_decays_to_elevated_once_egress_exceeds_threshold() {
        let mut tracker = AgentProvenanceTracker::new();
        tracker.ingest_signature(ProvenanceState::Contaminated, 100, "server-a", &[]);
        let threshold = tracker.decay_threshold;
        tracker.record_outbound_and_decay(threshold + 1);
        assert_eq!(tracker.current_state, ProvenanceState::Elevated);
    }

    #[test]
    fn elevated_decays_to_clean_once_egress_exceeds_threshold() {
        let mut tracker = AgentProvenanceTracker::new();
        tracker.ingest_signature(ProvenanceState::Elevated, 100, "server-a", &[]);
        let threshold = tracker.decay_threshold;
        tracker.record_outbound_and_decay(threshold + 1);
        assert_eq!(tracker.current_state, ProvenanceState::Clean);
    }

    #[test]
    fn below_threshold_egress_leaves_state_unchanged_and_accumulates_across_calls() {
        let mut tracker = AgentProvenanceTracker::new();
        tracker.ingest_signature(ProvenanceState::Elevated, 100, "server-a", &[]);
        let threshold = tracker.decay_threshold;
        assert!(threshold > 2, "test assumes a threshold large enough to split across two below-threshold calls");

        let half = threshold / 2;
        tracker.record_outbound_and_decay(half);
        assert_eq!(tracker.current_state, ProvenanceState::Elevated, "a single below-threshold call must not decay");
        assert_eq!(tracker.bytes_since_elevation, half, "bytes_since_elevation must accumulate, not reset, below threshold");

        // The second call is individually below threshold too, and the
        // ACCUMULATED total (half + (threshold - half) == threshold
        // exactly) is still not strictly GREATER than threshold, so this
        // must still not decay — this is the precise boundary, not just
        // "comfortably below".
        tracker.record_outbound_and_decay(threshold - half);
        assert_eq!(
            tracker.current_state,
            ProvenanceState::Elevated,
            "accumulated bytes exactly at threshold must not decay (the check is strictly greater-than)"
        );
        assert_eq!(tracker.bytes_since_elevation, threshold);
    }

    // ---- modulate_risk_class ----

    #[test]
    fn clean_state_never_changes_risk_class_for_any_variant() {
        for risk in [RiskClass::Low, RiskClass::Medium, RiskClass::High, RiskClass::Critical] {
            let mut r = risk;
            let result = modulate_risk_class(&mut r, &ProvenanceState::Clean);
            assert!(result.is_ok(), "Clean must never block, got {:?} for risk {:?}", result, risk);
            assert_eq!(r, risk, "Clean must never change the risk class, got {:?} for original {:?}", r, risk);
        }
    }

    #[test]
    fn high_elevated_bumps_to_critical() {
        // The bump table takes (High, Elevated) to Critical, but Elevated
        // != Clean, so the Critical-block gate then fires too — same
        // shape as (High, Contaminated) below. The risk class still ends
        // up Critical; the call still errors.
        let mut r = RiskClass::High;
        let result = modulate_risk_class(&mut r, &ProvenanceState::Elevated);
        assert_eq!(result, Err("CriticalBlockedByProvenance"), "bumping to Critical under a non-Clean state must then trip the Critical gate");
        assert_eq!(r, RiskClass::Critical);
    }

    #[test]
    fn medium_contaminated_bumps_to_high() {
        let mut r = RiskClass::Medium;
        let result = modulate_risk_class(&mut r, &ProvenanceState::Contaminated);
        assert!(result.is_ok(), "bumping Medium->High under Contaminated must not itself be blocked");
        assert_eq!(r, RiskClass::High);
    }

    #[test]
    fn high_contaminated_bumps_to_critical() {
        let mut r = RiskClass::High;
        let result = modulate_risk_class(&mut r, &ProvenanceState::Contaminated);
        assert_eq!(result, Err("CriticalBlockedByProvenance"), "bumping to Critical under a non-Clean state must then trip the Critical gate");
        assert_eq!(r, RiskClass::Critical, "the bump to Critical must still have applied even though the call then errors");
    }

    #[test]
    fn low_is_exempt_from_the_bump_table_under_elevated_and_contaminated() {
        for state in [ProvenanceState::Elevated, ProvenanceState::Contaminated] {
            let mut r = RiskClass::Low;
            let result = modulate_risk_class(&mut r, &state);
            assert!(result.is_ok(), "Low must not be blocked under {:?}", state);
            assert_eq!(r, RiskClass::Low, "Low must not be bumped by a catch-all arm under {:?}", state);
        }
    }

    #[test]
    fn poisoned_blocks_every_risk_class_including_low() {
        for risk in [RiskClass::Low, RiskClass::Medium, RiskClass::High, RiskClass::Critical] {
            let mut r = risk;
            let result = modulate_risk_class(&mut r, &ProvenanceState::Poisoned);
            assert_eq!(result, Err("InboundPoisoningDetected"), "Poisoned must block risk class {:?} too, not just High/Critical", risk);
        }
    }

    #[test]
    fn critical_block_fires_after_the_bump_not_before() {
        // (Medium, Contaminated) bumps to High, NOT Critical — must NOT
        // trip the Critical-block path.
        let mut medium = RiskClass::Medium;
        assert!(modulate_risk_class(&mut medium, &ProvenanceState::Contaminated).is_ok());
        assert_eq!(medium, RiskClass::High);

        // (High, Contaminated) bumps to Critical — MUST then trip it.
        let mut high = RiskClass::High;
        assert_eq!(
            modulate_risk_class(&mut high, &ProvenanceState::Contaminated),
            Err("CriticalBlockedByProvenance")
        );
        assert_eq!(high, RiskClass::Critical);
    }

    #[test]
    fn originally_critical_risk_class_with_non_clean_state_is_blocked() {
        for state in [ProvenanceState::Elevated, ProvenanceState::Contaminated] {
            let mut r = RiskClass::Critical;
            let result = modulate_risk_class(&mut r, &state);
            assert_eq!(result, Err("CriticalBlockedByProvenance"), "an originally-Critical risk class under {:?} must be blocked", state);
        }
    }
}
