// src/membrane.rs

use crate::audit::{AuditLogger, AuditRecord};
use crate::provenance::{modulate_risk_class, AgentProvenanceTracker};
use crate::quota::QuotaCounter;
use crate::registry::{AuthoritySource, RiskClass};
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

        if proposal.external_content_influence && proposal.authority_source == AuthoritySource::User {
            self.record_rejection(proposal, connection_id, tracker, audit, RejectionCode::AuthorityLaundering, 0);
            return Err(RejectionCode::AuthorityLaundering);
        }
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
        let contribution_bp = if proposal.external_content_influence {
            (base_bp * 135) / 100
        } else {
            base_bp
        };

        if agent_bp + contribution_bp >= RISK_FLOOR_BP {
            self.record_rejection(proposal, connection_id, tracker, audit, RejectionCode::RiskFloorExceeded, agent_bp);
            return Err(RejectionCode::RiskFloorExceeded);
        }

        let new_agent_bp = agent_bp + contribution_bp;
        self.agent_accumulators.insert(connection_id, new_agent_bp);
        self.executed_proposals.insert(proposal.id.clone());

        tracker.record_outbound_and_decay(proposal.egress_bytes.max(1));

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
            status: "Approved".to_string(),
            rejection_code: None,
            provenance_state: tracker.current_state,
            effective_risk_class: effective_risk,
            bp_consumed: contribution_bp,
            r_abs_bp_after: new_agent_bp,
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
        });
    }
}
