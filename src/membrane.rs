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
    /// OP-3 capability tag: does this tool communicate outside the local
    /// machine? Operator-declared in `config.yaml`, resolved in main.rs from
    /// `entry.communicates_externally` at the existing construction site.
    /// Applied as a one-tier risk bump in `modulate_risk_class`, AFTER the
    /// provenance state table — see that function's doc comment for why the
    /// ordering is load-bearing.
    pub communicates_externally: bool,
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

/// Modulates a proposal's risk class based on the current tracker state and
/// the OP-3 capability tag, and enforces the Critical gate: any Critical
/// action requires Clean provenance, full stop, independent of BP budget.
/// This is what keeps the worst-tier action safe even if DECAY_MULTIPLIER's
/// calibration turns out to be wrong.
///
/// Relocated here from provenance.rs (pure move, no behavior change) — it
/// takes a `RiskClass` and returns an operational rejection, which is a
/// decision, not an observation about the information environment; see
/// docs/specs/spec-provenance-semantics-correction.md §6.
///
/// **Ordering is load-bearing: the state table runs FIRST, the
/// `communicates_externally` tag bump SECOND, the Critical gate LAST.** Do
/// not reorder this. The two orderings are not equivalent — they diverge on
/// (Medium, Elevated) and (Low, Contaminated). Tag-first would hard-block
/// every tagged Medium-risk tool the instant a session reaches Elevated,
/// which is the normal resting state for any session that has consumed
/// substantial external content, not an edge case — the same "security feature gets switched
/// off under deadline pressure" failure this project already avoided twice
/// (the Elevated-vs-Contaminated gating decision in SEC-06, and the
/// corroboration threshold in the provenance semantics correction).
/// Tag-after instead modifies an already-state-adjusted risk: the state
/// table answers how degraded the session's information environment is;
/// the tag answers how consequential this particular action is. See
/// docs/specs/spec-op3-capability-tag.md for the full 16-cell table and
/// worked reasoning.
pub fn modulate_risk_class(
    proposal_risk: &mut RiskClass,
    state: &ProvenanceState,
    communicates_externally: bool,
) -> Result<(), &'static str> {
    match (*proposal_risk, *state) {
        (_, ProvenanceState::Clean) => {}
        (_, ProvenanceState::Elevated) => {} // not a signal -- no bump; see docs/specs/spec-c1-provenance-trap-fix.md
        (RiskClass::Medium, ProvenanceState::Contaminated) => *proposal_risk = RiskClass::High,
        (RiskClass::High, ProvenanceState::Contaminated) => *proposal_risk = RiskClass::Critical,
        (_, ProvenanceState::Poisoned) => return Err("InboundPoisoningDetected"),
        _ => {}
    }

    if communicates_externally {
        *proposal_risk = match *proposal_risk {
            RiskClass::Low => RiskClass::Medium,
            RiskClass::Medium => RiskClass::High,
            RiskClass::High | RiskClass::Critical => RiskClass::Critical, // saturates
        };
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
        if let Err(e) = modulate_risk_class(&mut effective_risk, &tracker.current_state, proposal.communicates_externally) {
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

        // Decay no longer happens here — see
        // docs/specs/spec-f1-clean-call-decay.md. It used to be driven by
        // this proposal's own (agent-controlled, pre-response)
        // `egress_bytes`, which was the actual F1 "decay bombing" bug: a
        // free, computational bypass keyed on a value the agent fabricates
        // before the corresponding response is even known. Decay is now
        // `AgentProvenanceTracker::record_response_outcome`, called from
        // main.rs post-response, keyed on THIS call's own verified
        // response classification — independent of `evaluate()` entirely.

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
            communicates_externally: proposal.communicates_externally,
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
            communicates_externally: proposal.communicates_externally,
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
    /// specifically about it. communicates_externally defaults to false for
    /// the same reason (untagged, so OP-3's bump never leaks into a test
    /// that isn't about it). Tests that need either set the field directly
    /// on the returned Proposal.
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
            communicates_externally: false,
            source_grade: SourceGrade::Known,
            mcp_server_id: "server-a".to_string(),
            tool_name: "tool-a".to_string(),
            bootstrap: false,
        }
    }

    // ── Verdict-steerability enumeration ──────────────────────────────────
    //
    // Adapted from the uniqueness property developed for VKC Mini, where a
    // deterministic membrane admitted two valid commands for one input and so
    // handed the choice — and therefore the authority — to a learned
    // component. This membrane has no learned component, so the question
    // takes its stateful form: the agent does not choose among verdicts, but
    // it does choose the PATH, and a verdict reachable by more than one path
    // is a verdict the agent has some say in.
    //
    // The dimensions are split by who controls them:
    //
    //   agent-influenced   provenance state (which servers it calls, what
    //                      comes back), accumulated BP (call ordering),
    //                      external_content_influence (whether it reads
    //                      external material first)
    //   operator-declared  communicates_externally (config.yaml),
    //                      source_grade (registry)
    //
    // Steerability along the agent-influenced axes is not by itself a defect —
    // a risk budget is meant to be path-dependent. What must hold is that
    // every axis moves in ONE direction: degrading the session's information
    // environment may restrict, never unlock. These tests assert that
    // monotonicity, which is the property that would actually be a hole if it
    // failed, and which no per-rule review would surface.

    const ALL_STATES: [ProvenanceState; 4] = [
        ProvenanceState::Clean,
        ProvenanceState::Elevated,
        ProvenanceState::Contaminated,
        ProvenanceState::Poisoned,
    ];

    const ALL_RISKS: [RiskClass; 4] = [
        RiskClass::Low,
        RiskClass::Medium,
        RiskClass::High,
        RiskClass::Critical,
    ];

    /// Evaluate one action in one agent-influenced configuration, on a fresh
    /// session each time so the accumulator does not carry between points.
    fn verdict_at(
        risk: RiskClass,
        state: ProvenanceState,
        external_influence: bool,
        grade: SourceGrade,
        externally_communicating: bool,
        authority: AuthoritySource,
    ) -> Result<(), RejectionCode> {
        let mut membrane = make_membrane(3, 5000);
        let connection_id = Uuid::new_v4();
        membrane.register_agent(connection_id).unwrap();
        let mut tracker = AgentProvenanceTracker::new();
        tracker.current_state = state;
        let audit = AuditLogger::new_with_path(temp_audit_path(), "test-session");

        let mut proposal = make_proposal("prop-enum", risk, authority, external_influence);
        proposal.source_grade = grade;
        proposal.communicates_externally = externally_communicating;

        membrane.evaluate(&proposal, connection_id, &mut tracker, &audit)
    }

    #[test]
    fn degrading_provenance_never_unlocks_an_action() {
        // Clean is the most permissive information environment. Nothing the
        // agent can do to degrade it may turn a refusal into an approval.
        for risk in ALL_RISKS {
            for influence in [false, true] {
                for grade in [SourceGrade::Known, SourceGrade::Unvalidated] {
                    for external in [false, true] {
                        let clean = verdict_at(
                            risk, ProvenanceState::Clean, influence, grade, external,
                            AuthoritySource::User,
                        );
                        if clean.is_ok() {
                            continue; // allowed at Clean: degradation may restrict it, fine
                        }
                        for state in ALL_STATES {
                            let degraded = verdict_at(
                                risk, state, influence, grade, external,
                                AuthoritySource::User,
                            );
                            assert!(
                                degraded.is_err(),
                                "monotonicity violated: {risk:?} refused at Clean but ALLOWED at \
                                 {state:?} (influence={influence}, grade={grade:?}, external={external})"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn external_content_influence_never_makes_an_action_more_permissive() {
        for risk in ALL_RISKS {
            for state in ALL_STATES {
                for grade in [SourceGrade::Known, SourceGrade::Unvalidated] {
                    let without = verdict_at(risk, state, false, grade, false, AuthoritySource::User);
                    let with = verdict_at(risk, state, true, grade, false, AuthoritySource::User);
                    if without.is_err() {
                        assert!(
                            with.is_err(),
                            "surcharge inverted: {risk:?}/{state:?}/{grade:?} refused WITHOUT \
                             external influence but allowed WITH it"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn unvalidated_source_never_makes_an_action_more_permissive() {
        for risk in ALL_RISKS {
            for state in ALL_STATES {
                for influence in [false, true] {
                    let known = verdict_at(risk, state, influence, SourceGrade::Known, false, AuthoritySource::User);
                    let unvalidated =
                        verdict_at(risk, state, influence, SourceGrade::Unvalidated, false, AuthoritySource::User);
                    if known.is_err() {
                        assert!(
                            unvalidated.is_err(),
                            "surcharge inverted: {risk:?}/{state:?} refused for a Known source \
                             but allowed for an Unvalidated one"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn the_capability_tag_never_makes_an_action_more_permissive() {
        // communicates_externally is operator-declared, not agent-controlled,
        // so this is not a steerability check — it verifies the OP-3 bump
        // cannot invert, which would silently reward tagging a tool.
        for risk in ALL_RISKS {
            for state in ALL_STATES {
                let untagged = verdict_at(risk, state, false, SourceGrade::Known, false, AuthoritySource::User);
                let tagged = verdict_at(risk, state, false, SourceGrade::Known, true, AuthoritySource::User);
                if untagged.is_err() {
                    assert!(
                        tagged.is_err(),
                        "OP-3 bump inverted: {risk:?}/{state:?} refused untagged but allowed when \
                         tagged communicates_externally"
                    );
                }
            }
        }
    }

    #[test]
    fn enumerate_the_agent_steerable_surface() {
        // Prints the boundary map: for each action shape, the most degraded
        // provenance state at which it is still allowed. "Is any verdict
        // different somewhere?" is not a useful question here — Poisoned
        // refuses everything by design, so every shape would trivially answer
        // yes. The informative quantity is WHERE each shape's boundary sits.
        // Run with `cargo test enumerate_the_agent_steerable_surface -- --nocapture`.
        eprintln!(
            "\n=== last provenance state at which each action shape is still allowed ===\n\
             (influence = external_content_influence; '-' means refused even at Clean)\n"
        );
        eprintln!("   {:<34} {:<12} {:<12}", "action shape", "influence=no", "influence=yes");

        for risk in ALL_RISKS {
            for grade in [SourceGrade::Known, SourceGrade::Unvalidated] {
                for external in [false, true] {
                    let boundary = |influence: bool| -> String {
                        let mut last = None;
                        for state in ALL_STATES {
                            if verdict_at(risk, state, influence, grade, external, AuthoritySource::User).is_ok() {
                                last = Some(state);
                            }
                        }
                        match last {
                            Some(s) => format!("{s:?}"),
                            None => "-".to_string(),
                        }
                    };
                    eprintln!(
                        "   {:<34} {:<12} {:<12}",
                        format!("{risk:?}/{grade:?}/ext={external}"),
                        boundary(false),
                        boundary(true)
                    );
                }
            }
        }
        eprintln!();

        // The one thing that must hold regardless: a Critical action must
        // never be allowed anywhere the session is not Clean.
        for grade in [SourceGrade::Known, SourceGrade::Unvalidated] {
            for influence in [false, true] {
                for state in ALL_STATES {
                    if state == ProvenanceState::Clean {
                        continue;
                    }
                    assert!(
                        verdict_at(RiskClass::Critical, state, influence, grade, false, AuthoritySource::User)
                            .is_err(),
                        "Critical allowed at {state:?} (grade={grade:?}, influence={influence})"
                    );
                }
            }
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

    /// Renamed from `..._and_actually_triggers_decay`: per
    /// docs/specs/spec-f1-clean-call-decay.md, decay moved entirely out of
    /// `Membrane::evaluate` into
    /// `AgentProvenanceTracker::record_response_outcome`, called from
    /// main.rs post-response — `evaluate()` no longer touches
    /// `tracker.current_state` at all (it only reads it, via
    /// `modulate_risk_class`), so there is nothing decay-related left for
    /// this test to exercise through this entry point. Decay itself is
    /// covered directly in provenance.rs's own `AgentProvenanceTracker`
    /// tests now.
    #[test]
    fn successful_evaluation_records_id_and_updates_bp() {
        let mut membrane = make_membrane(3, 5000);
        let connection_id = Uuid::new_v4();
        membrane.register_agent(connection_id).unwrap();
        let mut tracker = AgentProvenanceTracker::new();
        let audit = AuditLogger::new_with_path(temp_audit_path(), "test-session");

        let proposal = make_proposal("prop-1", RiskClass::Low, AuthoritySource::User, false);

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
        poisoned_tracker.ingest_signature(ProvenanceState::Poisoned, "server-a", &["MCT-001".to_string()]);
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
            let result = modulate_risk_class(&mut r, &ProvenanceState::Clean, false);
            assert!(result.is_ok(), "Clean must never block, got {:?} for risk {:?}", result, risk);
            assert_eq!(r, risk, "Clean must never change the risk class, got {:?} for original {:?}", r, risk);
        }
    }

    #[test]
    fn high_action_at_elevated_is_not_bumped_and_not_blocked() {
        // Elevated is the normal resting state for a session that has
        // consumed substantial external content -- it must not, on its
        // own, escalate a High-risk action to Critical and trip the
        // Critical gate. This was the C1 provenance-trap bug: Elevated
        // was structurally unreachable-from, so this row permanently
        // blocked every High-risk action after the first real response.
        let mut r = RiskClass::High;
        let result = modulate_risk_class(&mut r, &ProvenanceState::Elevated, false);
        assert!(result.is_ok(), "Elevated alone must not block a High-risk action, got {:?}", result);
        assert_eq!(r, RiskClass::High, "Elevated alone must not bump risk class, got {:?}", r);
    }

    #[test]
    fn medium_contaminated_bumps_to_high() {
        let mut r = RiskClass::Medium;
        let result = modulate_risk_class(&mut r, &ProvenanceState::Contaminated, false);
        assert!(result.is_ok(), "bumping Medium->High under Contaminated must not itself be blocked");
        assert_eq!(r, RiskClass::High);
    }

    #[test]
    fn high_contaminated_bumps_to_critical() {
        let mut r = RiskClass::High;
        let result = modulate_risk_class(&mut r, &ProvenanceState::Contaminated, false);
        assert_eq!(result, Err("CriticalBlockedByProvenance"), "bumping to Critical under a non-Clean state must then trip the Critical gate");
        assert_eq!(r, RiskClass::Critical, "the bump to Critical must still have applied even though the call then errors");
    }

    #[test]
    fn low_is_exempt_from_the_bump_table_under_elevated_and_contaminated() {
        for state in [ProvenanceState::Elevated, ProvenanceState::Contaminated] {
            let mut r = RiskClass::Low;
            let result = modulate_risk_class(&mut r, &state, false);
            assert!(result.is_ok(), "Low must not be blocked under {:?}", state);
            assert_eq!(r, RiskClass::Low, "Low must not be bumped by a catch-all arm under {:?}", state);
        }
    }

    #[test]
    fn poisoned_blocks_every_risk_class_including_low() {
        for risk in [RiskClass::Low, RiskClass::Medium, RiskClass::High, RiskClass::Critical] {
            let mut r = risk;
            let result = modulate_risk_class(&mut r, &ProvenanceState::Poisoned, false);
            assert_eq!(result, Err("InboundPoisoningDetected"), "Poisoned must block risk class {:?} too, not just High/Critical", risk);
        }
    }

    #[test]
    fn critical_block_fires_after_the_bump_not_before() {
        // (Medium, Contaminated) bumps to High, NOT Critical — must NOT
        // trip the Critical-block path.
        let mut medium = RiskClass::Medium;
        assert!(modulate_risk_class(&mut medium, &ProvenanceState::Contaminated, false).is_ok());
        assert_eq!(medium, RiskClass::High);

        // (High, Contaminated) bumps to Critical — MUST then trip it.
        let mut high = RiskClass::High;
        assert_eq!(
            modulate_risk_class(&mut high, &ProvenanceState::Contaminated, false),
            Err("CriticalBlockedByProvenance")
        );
        assert_eq!(high, RiskClass::Critical);
    }

    #[test]
    fn originally_critical_risk_class_with_non_clean_state_is_blocked() {
        for state in [ProvenanceState::Elevated, ProvenanceState::Contaminated] {
            let mut r = RiskClass::Critical;
            let result = modulate_risk_class(&mut r, &state, false);
            assert_eq!(result, Err("CriticalBlockedByProvenance"), "an originally-Critical risk class under {:?} must be blocked", state);
        }
    }

    // ---- OP-3: communicates_externally capability tag ----
    // See docs/specs/spec-op3-capability-tag.md. The bump applies AFTER the
    // state table (checked below), not before — the ordering is load-bearing.

    #[test]
    fn tagged_bump_raises_risk_class_by_exactly_one_tier_at_clean() {
        // At Clean the state table is a no-op, so this isolates the tag
        // bump itself, tier by tier.
        let mut low = RiskClass::Low;
        assert!(modulate_risk_class(&mut low, &ProvenanceState::Clean, true).is_ok());
        assert_eq!(low, RiskClass::Medium);

        let mut medium = RiskClass::Medium;
        assert!(modulate_risk_class(&mut medium, &ProvenanceState::Clean, true).is_ok());
        assert_eq!(medium, RiskClass::High);

        let mut high = RiskClass::High;
        assert!(modulate_risk_class(&mut high, &ProvenanceState::Clean, true).is_ok());
        assert_eq!(high, RiskClass::Critical);
    }

    #[test]
    fn tagged_bump_saturates_at_critical_rather_than_overflowing() {
        let mut r = RiskClass::Critical;
        // Critical + Clean: state table is a no-op, tag bump must not wrap
        // or panic — it stays Critical, and Clean means it's still approved.
        let result = modulate_risk_class(&mut r, &ProvenanceState::Clean, true);
        assert!(result.is_ok());
        assert_eq!(r, RiskClass::Critical);
    }

    /// THE regression guard for this change. A tagged Medium tool at
    /// Elevated must be ALLOWED, bumped to High — not blocked. If the tag
    /// bump is ever applied BEFORE the state table instead of after, this
    /// exact case inverts: (Medium -> tag -> High) then the state table's
    /// (High, Elevated) arm fires and bumps again to Critical, which then
    /// trips the Critical gate and hard-blocks a call that should have been
    /// a graduated, non-blocking cost increase. Elevated is the normal
    /// resting state for any session that has read anything — this is not
    /// an edge case, it is the common path every tagged Medium-risk tool
    /// takes shortly after session start. Named so its failure message
    /// alone identifies an inverted ordering, the way
    /// single_heuristic_hit_from_elevated_produces_contaminated_not_poisoned
    /// does for the provenance semantics correction.
    #[test]
    fn tagged_medium_at_elevated_is_allowed_as_high_tag_must_apply_after_state_table_not_before() {
        let mut r = RiskClass::Medium;
        let result = modulate_risk_class(&mut r, &ProvenanceState::Elevated, true);
        assert!(
            result.is_ok(),
            "a tagged Medium tool at Elevated must be ALLOWED as High, not blocked — \
             got {:?}. If this fails, the tag bump is being applied BEFORE the state \
             table instead of after, which hard-blocks every tagged Medium-risk tool \
             the instant a session reaches Elevated (the normal resting state for any \
             session that has read anything, not an edge case).",
            result
        );
        assert_eq!(r, RiskClass::High, "correct ordering bumps Medium -> High, not Medium -> High -> Critical");
    }

    /// The accepted cost of the correct ordering (§ of the spec's 16-cell
    /// table): a tagged Low tool under Contaminated reaches Medium, not
    /// High. Recovered by the BP layer (Contaminated's 135% surcharge on
    /// top of the tag-bumped Medium base rate), not by a bigger risk bump.
    #[test]
    fn tagged_low_at_contaminated_reaches_medium_not_high() {
        let mut r = RiskClass::Low;
        let result = modulate_risk_class(&mut r, &ProvenanceState::Contaminated, true);
        assert!(result.is_ok());
        assert_eq!(r, RiskClass::Medium);
    }

    /// Confirms the tag reuses the EXISTING Critical gate rather than a new
    /// parallel one: a tagged High tool at Elevated hits the state table's
    /// (_, Elevated) no-op arm first (post-C1-fix, Elevated alone no longer
    /// bumps risk — see docs/specs/spec-c1-provenance-trap-fix.md), so it's
    /// the tag bump itself that takes High -> Critical here, and the
    /// existing gate then fires exactly as it would for any other Critical
    /// proposal under non-Clean state. Same outcome as before the fix,
    /// different arm doing the work — this test still exercises "does the
    /// tag reuse the existing gate," just via the tag bump instead of the
    /// state table now that the state table doesn't produce Critical here.
    #[test]
    fn tagged_high_at_elevated_is_blocked_by_the_existing_critical_gate() {
        let mut r = RiskClass::High;
        let result = modulate_risk_class(&mut r, &ProvenanceState::Elevated, true);
        assert_eq!(result, Err("CriticalBlockedByProvenance"));
        assert_eq!(r, RiskClass::Critical);
    }

    /// The tag doesn't change what a poisoned session does — Poisoned's
    /// early return in the state table fires before the tag bump is ever
    /// reached, for every risk class, tagged or not.
    #[test]
    fn tagged_tool_at_poisoned_still_gets_inbound_poisoning_detected() {
        for risk in [RiskClass::Low, RiskClass::Medium, RiskClass::High, RiskClass::Critical] {
            let mut r = risk;
            let result = modulate_risk_class(&mut r, &ProvenanceState::Poisoned, true);
            assert_eq!(result, Err("InboundPoisoningDetected"), "tagged risk {:?} at Poisoned must still be InboundPoisoningDetected", risk);
        }
    }

    /// End-to-end through Membrane::evaluate, not just modulate_risk_class
    /// directly: a tagged Low proposal at Clean state consumes the Medium
    /// base rate (800 BP), not the Low rate (200 BP) — because
    /// effective_risk is already tag-bumped by the time base_bp is looked
    /// up, no separate BP-tier lookup for the tag is needed.
    #[test]
    fn tagged_low_proposal_consumes_medium_base_rate() {
        let mut membrane = make_membrane(3, 5000);
        let connection_id = Uuid::new_v4();
        membrane.register_agent(connection_id).unwrap();
        let mut tracker = AgentProvenanceTracker::new();
        let audit = AuditLogger::new_with_path(temp_audit_path(), "test-session");

        let mut proposal = make_proposal("prop-1", RiskClass::Low, AuthoritySource::User, false);
        proposal.communicates_externally = true;
        let result = membrane.evaluate(&proposal, connection_id, &mut tracker, &audit);
        assert!(result.is_ok());

        let expected_bp = SESSION_INIT_BP + 800; // Medium base rate, not Low's 200
        assert_eq!(
            *membrane.agent_accumulators.get(&connection_id).unwrap(),
            expected_bp,
            "a tagged Low proposal must be charged the Medium base rate"
        );
    }

    /// The tag stacks with the existing surcharges: tagged Low (-> Medium
    /// base 800) with external_content_influence (135%) and an Unvalidated
    /// source (150%), all multiplicative.
    #[test]
    fn tagged_proposal_stacks_with_existing_surcharges() {
        let mut membrane = make_membrane(3, 5000);
        let connection_id = Uuid::new_v4();
        membrane.register_agent(connection_id).unwrap();
        let mut tracker = AgentProvenanceTracker::new();
        let audit = AuditLogger::new_with_path(temp_audit_path(), "test-session");

        let mut proposal = make_proposal("prop-1", RiskClass::Low, AuthoritySource::System, true);
        proposal.communicates_externally = true;
        proposal.source_grade = SourceGrade::Unvalidated;
        let result = membrane.evaluate(&proposal, connection_id, &mut tracker, &audit);
        assert!(result.is_ok());

        let expected_bp = SESSION_INIT_BP + (((800 * 135) / 100) * 150) / 100;
        assert_eq!(
            *membrane.agent_accumulators.get(&connection_id).unwrap(),
            expected_bp,
            "the tag-bumped base rate must still stack multiplicatively with both existing surcharges"
        );
    }
}
