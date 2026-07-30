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
