// src/membrane.rs

use crate::audit::{AuditLogger, AuditRecord};
use crate::provenance::{AgentProvenanceTracker, ProvenanceState};
use crate::quota::QuotaCounter;
use crate::registry::{AuthoritySource, RiskClass, SourceGrade};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub const RISK_FLOOR_BP: u32 = 9_500;
const SESSION_INIT_BP: u32 = 100;
const MAX_NONCE_CACHE: usize = 100_000;

#[derive(Debug, Deserialize)]
pub struct Proposal {
    pub id: String,
    pub risk_class: RiskClass,
    pub authority_source: AuthoritySource,
    pub external_content_influence: bool,
    /// The downstream server's static trust grade, resolved once at
    /// proposal-construction time (main.rs already looks this up for
    /// `compute_new_state`; this reuses that same value rather than a new
    /// lookup). Used for the Unvalidated BP surcharge below — see
    /// docs/specs/spec-provenance-semantics-correction.md §4.
    pub source_grade: SourceGrade,
    pub mcp_server_id: String,
    pub tool_name: String,
    #[serde(default)]
    pub bootstrap: bool,
    /// The real size (bytes) of this call's actual arguments - what the agent
    /// is genuinely sending outbound this turn. Previously this was faked as
    /// a near-constant `proposal.id.len() + 256` (~290 bytes, dominated by a
    /// fixed-length UUID), which was almost always LARGER than the decay
    /// threshold computed from a typical tool response - meaning any
    /// elevation decayed back to Clean on the very next call, regardless of
    /// what that call actually was. A real, variable measure of outbound
    /// content is required for the decay model to mean anything at all.
    #[serde(default)]
    pub egress_bytes: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub enum RejectionCode {
    ReplayDetected,
    /// No longer produced (see §5 of
    /// docs/specs/spec-provenance-semantics-correction.md — the predicate
    /// this named, `external_content_influence && authority_source ==
    /// User`, described a threat model this project doesn't have:
    /// `authority_source` is a static per-tool registry property here, never
    /// a per-call agent claim, so nothing was actually being laundered).
    /// Kept as a variant so historical `audit.jsonl` records referencing it
    /// stay readable.
    AuthorityLaundering,
    ExternalAuthorityViolation,
    RiskFloorExceeded,
    SessionExhausted,
    AgentLimitReached,
    InboundPoisoningDetected,
    CriticalBlockedByProvenance,
    EvaluationLimitReached,
}

impl RejectionCode {
    pub fn as_str(&self) -> &'static str {
        match self {
            RejectionCode::ReplayDetected => "ReplayDetected",
            RejectionCode::AuthorityLaundering => "AuthorityLaundering",
            RejectionCode::ExternalAuthorityViolation => "ExternalAuthorityViolation",
            RejectionCode::RiskFloorExceeded => "RiskFloorExceeded",
            RejectionCode::SessionExhausted => "SessionExhausted",
            RejectionCode::AgentLimitReached => "AgentLimitReached",
            RejectionCode::InboundPoisoningDetected => "InboundPoisoningDetected",
            RejectionCode::CriticalBlockedByProvenance => "CriticalBlockedByProvenance",
            RejectionCode::EvaluationLimitReached => "EvaluationLimitReached",
        }
    }
}

/// Modulates a proposal's risk class based on the current tracker state, and
/// enforces the Critical gate: any Critical action requires Clean provenance,
/// full stop, independent of BP budget. This is what keeps the worst-tier
/// action safe even if DECAY_MULTIPLIER's calibration turns out to be wrong.
///
/// Relocated here from provenance.rs (pure move, no behavior change) — it
/// takes a `RiskClass` and returns an operational rejection, which is a
/// decision, not an observation about the information environment; see
/// docs/specs/spec-provenance-semantics-correction.md §6.
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

pub struct Membrane {
    pub session_id: String,
    agent_accumulators: HashMap<Uuid, u32>,
    max_agents: usize,
    executed_proposals: HashSet<String>,
    pub quota: QuotaCounter,
}

impl Membrane {
    pub fn new(session_id: String, max_agents: usize, monthly_eval_limit: u32) -> Self {
        Self {
            session_id,
            agent_accumulators: HashMap::new(),
            max_agents,
            executed_proposals: HashSet::new(),
            quota: QuotaCounter::new(monthly_eval_limit),
        }
    }

    pub fn register_agent(&mut self, connection_id: Uuid) -> Result<(), RejectionCode> {
        if self.agent_accumulators.len() >= self.max_agents {
            return Err(RejectionCode::AgentLimitReached);
        }
        self.agent_accumulators.insert(connection_id, SESSION_INIT_BP);
        Ok(())
    }

    pub fn deregister_agent(&mut self, connection_id: Uuid) {
        self.agent_accumulators.remove(&connection_id);
    }

    /// Core mutation engine. Evaluates a proposal against all governance rules.
    pub fn evaluate(
        &mut self,
        proposal: &Proposal,
        connection_id: Uuid,
        tracker: &mut AgentProvenanceTracker,
        audit: &AuditLogger,
    ) -> Result<(), RejectionCode> {
        if self.quota.is_over_limit() {
            return Err(RejectionCode::EvaluationLimitReached);
        }
        self.quota.record_and_get_count();

        if self.executed_proposals.len() >= MAX_NONCE_CACHE {
            self.record_rejection(proposal, connection_id, tracker, audit, RejectionCode::SessionExhausted, 0);
            return Err(RejectionCode::SessionExhausted);
        }

        if self.executed_proposals.contains(&proposal.id) {
            return Err(RejectionCode::ReplayDetected);
        }

        let mut effective_risk = proposal.risk_class;
        if let Err(e) = modulate_risk_class(&mut effective_risk, &tracker.current_state) {
            let code = match e {
                "InboundPoisoningDetected" => RejectionCode::InboundPoisoningDetected,
                "CriticalBlockedByProvenance" => RejectionCode::CriticalBlockedByProvenance,
                _ => RejectionCode::CriticalBlockedByProvenance,
            };
            self.record_rejection(proposal, connection_id, tracker, audit, code.clone(), 0);
            return Err(code);
        }

        // AuthorityLaundering rejection retired here — see the
        // RejectionCode::AuthorityLaundering variant's own comment and
        // docs/specs/spec-provenance-semantics-correction.md §5. The 135%
        // surcharge below is the correct, proportionate response to
        // heuristic evidence; a hard block on every User-authority action
        // for the rest of the session was not, once Contaminated became
        // reachable.
        if proposal.authority_source == AuthoritySource::External && effective_risk == RiskClass::Critical {
            self.record_rejection(proposal, connection_id, tracker, audit, RejectionCode::ExternalAuthorityViolation, 0);
            return Err(RejectionCode::ExternalAuthorityViolation);
        }

        let agent_bp = *self.agent_accumulators.get(&connection_id).unwrap_or(&SESSION_INIT_BP);
        let base_bp: u32 = match effective_risk {
            RiskClass::Low => 200,
            RiskClass::Medium => 800,
            RiskClass::High => 2_000,
            RiskClass::Critical => 4_000,
        };
        // Two independent surcharges, stacking multiplicatively when both
        // apply. external_content_influence (135%) is the existing
        // heuristic-evidence surcharge. The Unvalidated surcharge (150%) is
        // new here: it's what compensates for removing
        // Unvalidated + BareString -> Contaminated from provenance.rs's
        // compute_new_state (a trust attribute must not manufacture
        // evidence the session's information environment never actually
        // observed) — without it, the default configuration a first-time
        // user gets would quietly lose protection. 150% is a CALIBRATION
        // GUESS, not asserted as correct: chosen to sit in the same range
        // as the 135% surcharge while being somewhat stronger, since an
        // ungraded source is a broader concern than a single flagged
        // response. Revisit with evidence, the way SECRET-AWS-001's
        // threshold was revisited once the corpus test produced a real
        // failing case — see
        // docs/specs/spec-provenance-semantics-correction.md §4.
        let mut contribution_bp = base_bp;
        if proposal.external_content_influence {
            contribution_bp = (contribution_bp * 135) / 100;
        }
        if proposal.source_grade == SourceGrade::Unvalidated {
            contribution_bp = (contribution_bp * 150) / 100;
        }

        if agent_bp + contribution_bp >= RISK_FLOOR_BP {
            self.record_rejection(proposal, connection_id, tracker, audit, RejectionCode::RiskFloorExceeded, agent_bp);
            return Err(RejectionCode::RiskFloorExceeded);
        }

        let new_agent_bp = agent_bp + contribution_bp;
        self.agent_accumulators.insert(connection_id, new_agent_bp);
        self.executed_proposals.insert(proposal.id.clone());

        tracker.record_outbound_and_decay(proposal.egress_bytes.max(1));

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let triggered_rule_ids = std::mem::take(&mut tracker.last_triggering_rule_ids);
        audit.log(AuditRecord {
            timestamp_unix: timestamp,
            session_id: self.session_id.clone(),
            connection_id: connection_id.to_string(),
            proposal_id: proposal.id.clone(),
            mcp_server_id: proposal.mcp_server_id.clone(),
            tool_name: proposal.tool_name.clone(),
            risk_class: proposal.risk_class,
            authority_source: proposal.authority_source,
            bootstrap: proposal.bootstrap,
            status: "Approved".to_string(),
            rejection_code: None,
            provenance_state: tracker.current_state,
            effective_risk_class: effective_risk,
            bp_consumed: contribution_bp,
            r_abs_bp_after: new_agent_bp,
            triggered_rule_ids,
        });

        Ok(())
    }

    fn record_rejection(
        &self,
        proposal: &Proposal,
        connection_id: Uuid,
        tracker: &AgentProvenanceTracker,
        audit: &AuditLogger,
        code: RejectionCode,
        bp_at_rejection: u32,
    ) {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        audit.log(AuditRecord {
            timestamp_unix: timestamp,
            session_id: self.session_id.clone(),
            connection_id: connection_id.to_string(),
            proposal_id: proposal.id.clone(),
            mcp_server_id: proposal.mcp_server_id.clone(),
            tool_name: proposal.tool_name.clone(),
            risk_class: proposal.risk_class,
            authority_source: proposal.authority_source,
            bootstrap: proposal.bootstrap,
            status: "Rejected".to_string(),
            rejection_code: Some(code.as_str().to_string()),
            provenance_state: tracker.current_state,
            effective_risk_class: proposal.risk_class,
            bp_consumed: 0,
            r_abs_bp_after: bp_at_rejection,
            triggered_rule_ids: tracker.last_triggering_rule_ids.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn temp_audit_path() -> PathBuf {
        std::env::temp_dir()
            .join(format!("magus-membrane-test-{}", Uuid::new_v4()))
            .join("audit.jsonl")
    }

    fn make_membrane(max_agents: usize, monthly_limit: u32) -> Membrane {
        Membrane::new("test-session".to_string(), max_agents, monthly_limit)
    }

    /// source_grade defaults to Known — a graded server, so it never
    /// triggers the Unvalidated surcharge by accident in tests that aren't
    /// specifically about it. Tests that need Unvalidated set
    /// `.source_grade` directly on the returned Proposal.
    fn make_proposal(
        id: &str,
        risk_class: RiskClass,
        authority_source: AuthoritySource,
        external_content_influence: bool,
    ) -> Proposal {
        Proposal {
            id: id.to_string(),
            risk_class,
            authority_source,
            external_content_influence,
            source_grade: SourceGrade::Known,
            mcp_server_id: "server-a".to_string(),
            tool_name: "tool-a".to_string(),
            bootstrap: false,
            egress_bytes: 100,
        }
    }

    #[test]
    fn replay_detection_second_call_with_same_id_is_rejected() {
        let mut membrane = make_membrane(3, 5000);
        let connection_id = Uuid::new_v4();
        membrane.register_agent(connection_id).unwrap();
        let mut tracker = AgentProvenanceTracker::new();
        let audit = AuditLogger::new_with_path(temp_audit_path(), "test-session");
        let proposal = make_proposal("prop-1", RiskClass::Low, AuthoritySource::User, false);

        assert!(
            membrane.evaluate(&proposal, connection_id, &mut tracker, &audit).is_ok(),
            "first evaluation of a fresh id must succeed"
        );
        let second = membrane.evaluate(&proposal, connection_id, &mut tracker, &audit);
        assert_eq!(second, Err(RejectionCode::ReplayDetected));
    }

    #[test]
    fn quota_exceeded_rejects_even_an_otherwise_approvable_proposal() {
        // monthly_eval_limit = 1: the first call consumes the quota; the
        // second, even though otherwise fully approvable on its own merits,
        // must be rejected purely on quota grounds.
        let mut membrane = make_membrane(3, 1);
        let connection_id = Uuid::new_v4();
        membrane.register_agent(connection_id).unwrap();
        let mut tracker = AgentProvenanceTracker::new();
        let audit = AuditLogger::new_with_path(temp_audit_path(), "test-session");

        let p1 = make_proposal("prop-1", RiskClass::Low, AuthoritySource::User, false);
        assert!(membrane.evaluate(&p1, connection_id, &mut tracker, &audit).is_ok());

        let p2 = make_proposal("prop-2", RiskClass::Low, AuthoritySource::User, false);
        let result = membrane.evaluate(&p2, connection_id, &mut tracker, &audit);
        assert_eq!(result, Err(RejectionCode::EvaluationLimitReached));
    }

    /// §5's retirement, asserted directly: a User-authority proposal with
    /// external_content_influence must be APPROVED, not rejected — this
    /// exact (authority_source, external_content_influence) combination
    /// used to be an automatic AuthorityLaundering rejection. Asserting the
    /// removal, not just its absence, so a regression back to the old
    /// blunt block is a visible test failure, not a silent revival.
    #[test]
    fn user_authority_with_external_content_influence_is_approved_not_rejected() {
        let mut membrane = make_membrane(3, 5000);
        let connection_id = Uuid::new_v4();
        membrane.register_agent(connection_id).unwrap();
        let mut tracker = AgentProvenanceTracker::new();
        let audit = AuditLogger::new_with_path(temp_audit_path(), "test-session");

        let proposal = make_proposal("prop-1", RiskClass::Medium, AuthoritySource::User, true);
        let result = membrane.evaluate(&proposal, connection_id, &mut tracker, &audit);
        assert!(result.is_ok(), "must be approved under the retired check, got {:?}", result);

        // Still costs the 135% surcharge — retiring the hard block doesn't
        // mean external_content_influence goes unpriced.
        let expected_bp = SESSION_INIT_BP + (800 * 135) / 100;
        assert_eq!(
            *membrane.agent_accumulators.get(&connection_id).unwrap(),
            expected_bp,
            "the 135% surcharge must still apply even though the hard rejection is gone"
        );
    }

    /// §4's Unvalidated BP surcharge, compensating for removing
    /// Unvalidated + BareString -> Contaminated from provenance.rs.
    #[test]
    fn unvalidated_source_grade_costs_more_bp_than_known() {
        let mut membrane = make_membrane(3, 5000);
        let connection_id = Uuid::new_v4();
        membrane.register_agent(connection_id).unwrap();
        let mut tracker = AgentProvenanceTracker::new();
        let audit = AuditLogger::new_with_path(temp_audit_path(), "test-session");

        let mut proposal = make_proposal("prop-1", RiskClass::Medium, AuthoritySource::User, false);
        proposal.source_grade = SourceGrade::Unvalidated;
        let result = membrane.evaluate(&proposal, connection_id, &mut tracker, &audit);
        assert!(result.is_ok());

        let expected_bp = SESSION_INIT_BP + (800 * 150) / 100;
        assert_eq!(
            *membrane.agent_accumulators.get(&connection_id).unwrap(),
            expected_bp,
            "Unvalidated must cost 150% of the base BP, not the flat base amount"
        );
    }

    /// Both surcharges stack multiplicatively when both apply, per §4.
    #[test]
    fn external_content_influence_and_unvalidated_surcharges_stack_multiplicatively() {
        let mut membrane = make_membrane(3, 5000);
        let connection_id = Uuid::new_v4();
        membrane.register_agent(connection_id).unwrap();
        let mut tracker = AgentProvenanceTracker::new();
        let audit = AuditLogger::new_with_path(temp_audit_path(), "test-session");

        let mut proposal = make_proposal("prop-1", RiskClass::Medium, AuthoritySource::System, true);
        proposal.source_grade = SourceGrade::Unvalidated;
        let result = membrane.evaluate(&proposal, connection_id, &mut tracker, &audit);
        assert!(result.is_ok());

        let expected_bp = SESSION_INIT_BP + (((800 * 135) / 100) * 150) / 100;
        assert_eq!(
            *membrane.agent_accumulators.get(&connection_id).unwrap(),
            expected_bp,
            "both surcharges must stack multiplicatively, not just apply the larger one"
        );
    }

    #[test]
    fn external_authority_with_critical_effective_risk_is_rejected() {
        let mut membrane = make_membrane(3, 5000);
        let connection_id = Uuid::new_v4();
        membrane.register_agent(connection_id).unwrap();
        let mut tracker = AgentProvenanceTracker::new();
        let audit = AuditLogger::new_with_path(temp_audit_path(), "test-session");

        // state is Clean, so modulate_risk_class leaves Critical unchanged
        // and doesn't itself error - effective_risk stays Critical, which
        // is what this check needs to fire on.
        let proposal = make_proposal("prop-1", RiskClass::Critical, AuthoritySource::External, false);
        let result = membrane.evaluate(&proposal, connection_id, &mut tracker, &audit);
        assert_eq!(result, Err(RejectionCode::ExternalAuthorityViolation));
    }

    #[test]
    fn risk_floor_exceeded_rejects_only_the_crossing_proposal_not_earlier_ones() {
        let mut membrane = make_membrane(3, 5000);
        let connection_id = Uuid::new_v4();
        membrane.register_agent(connection_id).unwrap();
        let mut tracker = AgentProvenanceTracker::new();
        let audit = AuditLogger::new_with_path(temp_audit_path(), "test-session");

        // SESSION_INIT_BP = 100, High risk class costs 2000 BP each (no
        // external influence, state stays Clean so no bump). 100 + 2000*4
        // = 8100 (< RISK_FLOOR_BP = 9500, all four approved); the 5th call
        // would take it to 10100 (>= 9500), which must be the one rejected.
        for i in 0..4 {
            let proposal = make_proposal(&format!("prop-{i}"), RiskClass::High, AuthoritySource::User, false);
            let result = membrane.evaluate(&proposal, connection_id, &mut tracker, &audit);
            assert!(result.is_ok(), "proposal {i} should have been approved before the floor was crossed");
        }

        let crossing = make_proposal("prop-crossing", RiskClass::High, AuthoritySource::User, false);
        let result = membrane.evaluate(&crossing, connection_id, &mut tracker, &audit);
        assert_eq!(result, Err(RejectionCode::RiskFloorExceeded));
    }

    #[test]
    fn external_content_influence_costs_135_percent_of_base_bp() {
        let mut membrane = make_membrane(3, 5000);
        let connection_id = Uuid::new_v4();
        membrane.register_agent(connection_id).unwrap();
        let mut tracker = AgentProvenanceTracker::new();
        let audit = AuditLogger::new_with_path(temp_audit_path(), "test-session");

        // Medium base BP = 800; with external_content_influence, cost =
        // (800 * 135) / 100 = 1080, not the flat 800. AuthoritySource is
        // System, not User, specifically so this doesn't also trip the
        // separate AuthorityLaundering check (scoped to
        // external_content_influence && authority_source == User).
        let proposal = make_proposal("prop-1", RiskClass::Medium, AuthoritySource::System, true);
        let result = membrane.evaluate(&proposal, connection_id, &mut tracker, &audit);
        assert!(result.is_ok());

        let expected_bp = SESSION_INIT_BP + 1080;
        assert_eq!(
            *membrane.agent_accumulators.get(&connection_id).unwrap(),
            expected_bp,
            "external_content_influence must cost 135% of the base BP, not the flat base amount"
        );
    }

    #[test]
    fn successful_evaluation_records_id_updates_bp_and_actually_triggers_decay() {
        let mut membrane = make_membrane(3, 5000);
        let connection_id = Uuid::new_v4();
        membrane.register_agent(connection_id).unwrap();
        let mut tracker = AgentProvenanceTracker::new();
        let audit = AuditLogger::new_with_path(temp_audit_path(), "test-session");

        // Put the tracker into Elevated with a small decay_threshold so
        // this call's egress_bytes is guaranteed to cross it - proving
        // record_outbound_and_decay was actually invoked (a real tracker
        // state change), not just that evaluate() returned Ok.
        tracker.ingest_signature(ProvenanceState::Elevated, 1, "server-a", &[]);
        let threshold = tracker.decay_threshold;
        assert_eq!(tracker.current_state, ProvenanceState::Elevated);

        let mut proposal = make_proposal("prop-1", RiskClass::Low, AuthoritySource::User, false);
        proposal.egress_bytes = threshold + 100;

        let result = membrane.evaluate(&proposal, connection_id, &mut tracker, &audit);
        assert!(result.is_ok());
        assert!(
            membrane.executed_proposals.contains("prop-1"),
            "the proposal id must be recorded as executed"
        );
        assert_eq!(
            *membrane.agent_accumulators.get(&connection_id).unwrap(),
            SESSION_INIT_BP + 200, // Low risk class base BP
        );
        assert_eq!(
            tracker.current_state,
            ProvenanceState::Clean,
            "decay must actually have moved Elevated -> Clean given egress past threshold, not merely left evaluate() returning Ok"
        );
    }

    #[test]
    fn session_exhaustion_once_executed_proposals_reaches_max_nonce_cache() {
        // MAX_NONCE_CACHE is 100_000. Calling evaluate() that many times to
        // get here would mean 100_000 real file-backed audit log writes -
        // slow, and it doesn't exercise anything evaluate() does
        // differently at scale. This test lives in the same module as
        // Membrane, so it can populate the private executed_proposals set
        // directly to the real MAX_NONCE_CACHE boundary, then call
        // evaluate() once against a fresh id - this still tests the actual
        // real constant's boundary condition, just without the O(100_000)
        // I/O cost of getting there through the public API.
        let mut membrane = make_membrane(3, 1_000_000);
        let connection_id = Uuid::new_v4();
        membrane.register_agent(connection_id).unwrap();
        let mut tracker = AgentProvenanceTracker::new();
        let audit = AuditLogger::new_with_path(temp_audit_path(), "test-session");

        for i in 0..MAX_NONCE_CACHE {
            membrane.executed_proposals.insert(format!("preexisting-{i}"));
        }
        assert_eq!(membrane.executed_proposals.len(), MAX_NONCE_CACHE);

        let proposal = make_proposal("fresh-id", RiskClass::Low, AuthoritySource::User, false);
        let result = membrane.evaluate(&proposal, connection_id, &mut tracker, &audit);
        assert_eq!(result, Err(RejectionCode::SessionExhausted));
    }

    #[test]
    fn audit_record_content_matches_actual_outcome_for_rejection_and_approval() {
        let path = temp_audit_path();
        let mut membrane = make_membrane(3, 5000);
        let connection_id = Uuid::new_v4();
        membrane.register_agent(connection_id).unwrap();
        let audit = AuditLogger::new_with_path(path.clone(), "test-session");

        // Rejection case: tracker already Poisoned with a known
        // triggering rule id - modulate_risk_class rejects immediately
        // with InboundPoisoningDetected, and record_rejection logs
        // tracker.last_triggering_rule_ids as-is.
        let mut poisoned_tracker = AgentProvenanceTracker::new();
        poisoned_tracker.ingest_signature(ProvenanceState::Poisoned, 10, "server-a", &["MCT-001".to_string()]);
        let rejected = make_proposal("prop-rejected", RiskClass::Low, AuthoritySource::User, false);
        assert_eq!(
            membrane.evaluate(&rejected, connection_id, &mut poisoned_tracker, &audit),
            Err(RejectionCode::InboundPoisoningDetected)
        );

        // Approval case: a fresh, Clean tracker so this proposal actually
        // goes through.
        let mut clean_tracker = AgentProvenanceTracker::new();
        let approved = make_proposal("prop-approved", RiskClass::Low, AuthoritySource::User, false);
        assert!(membrane.evaluate(&approved, connection_id, &mut clean_tracker, &audit).is_ok());

        let contents = std::fs::read_to_string(&path).expect("audit log file must exist and be readable");
        // First line is the session_start header written by
        // new_with_path; real records follow.
        let records: Vec<serde_json::Value> = contents
            .lines()
            .skip(1)
            .map(|line| serde_json::from_str(line).expect("each audit line must be valid JSON"))
            .collect();

        let rejection_record = records
            .iter()
            .find(|r| r["proposal_id"] == "prop-rejected")
            .expect("rejection record must be present in the audit log");
        assert_eq!(rejection_record["rejection_code"], "InboundPoisoningDetected");
        assert_eq!(rejection_record["provenance_state"], "Poisoned");
        assert_eq!(rejection_record["triggered_rule_ids"], serde_json::json!(["MCT-001"]));

        let approval_record = records
            .iter()
            .find(|r| r["proposal_id"] == "prop-approved")
            .expect("approval record must be present in the audit log");
        assert_eq!(approval_record["status"], "Approved");
        assert_eq!(approval_record["rejection_code"], serde_json::Value::Null);
        assert_eq!(approval_record["provenance_state"], "Clean");
    }

    #[test]
    fn registering_beyond_max_agents_is_rejected() {
        let mut membrane = make_membrane(2, 5000);
        assert!(membrane.register_agent(Uuid::new_v4()).is_ok());
        assert!(membrane.register_agent(Uuid::new_v4()).is_ok());
        let result = membrane.register_agent(Uuid::new_v4());
        assert_eq!(result, Err(RejectionCode::AgentLimitReached));
    }

    #[test]
    fn deregistering_frees_a_slot_for_a_new_registration() {
        let mut membrane = make_membrane(1, 5000);
        let first = Uuid::new_v4();
        assert!(membrane.register_agent(first).is_ok());
        assert_eq!(membrane.register_agent(Uuid::new_v4()), Err(RejectionCode::AgentLimitReached));

        membrane.deregister_agent(first);
        assert!(
            membrane.register_agent(Uuid::new_v4()).is_ok(),
            "deregistering must free a slot for a new registration"
        );
    }

    // ---- modulate_risk_class ----
    // Relocated from provenance.rs (pure move, no behavior change) — see
    // docs/specs/spec-provenance-semantics-correction.md §6. Unchanged in
    // content; if any of these needed its assertions altered to pass after
    // the move, something else went wrong.

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
