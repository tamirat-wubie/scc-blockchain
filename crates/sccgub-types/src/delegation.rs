use serde::{Deserialize, Serialize};

use crate::tension::TensionValue;
use crate::{AgentId, Hash};

/// Capability delegation — bounded authority leases for agents, robots, and services.
///
/// Architecture rule: put control off-chain, put authority on-chain.
/// A CapabilityLease is the on-chain artifact that proves "this agent
/// may do X in zone Y until time Z with budget B."
///
/// Leases are:
/// - Bounded in scope (allowed prefixes, zones, operations)
/// - Bounded in time (valid_from..valid_until block heights)
/// - Bounded in budget (max spend, max actions)
/// - Revocable by the delegator at any time
/// - Auditable (every grant and revocation is a chain event)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityLease {
    /// Unique lease identifier.
    pub lease_id: Hash,
    /// Who granted this capability.
    pub delegator: AgentId,
    /// Who holds this capability.
    pub delegate: AgentId,
    /// What operations are allowed.
    pub scope: CapabilityScope,
    /// Block height at which this lease becomes valid.
    pub valid_from: u64,
    /// Block height at which this lease expires (0 = no expiry).
    pub valid_until: u64,
    /// Maximum total spend under this lease.
    pub budget: TensionValue,
    /// Amount already spent under this lease.
    pub spent: TensionValue,
    /// Maximum number of actions allowed.
    pub max_actions: u64,
    /// Actions already taken.
    pub actions_taken: u64,
    /// Whether the delegator has revoked this lease.
    pub revoked: bool,
    /// Whether co-signature from delegator is required for each action.
    pub require_cosign: bool,
}

/// What a capability lease permits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityScope {
    /// Allowed state key prefixes for writes.
    pub write_prefixes: Vec<Vec<u8>>,
    /// Allowed state key prefixes for reads.
    pub read_prefixes: Vec<Vec<u8>>,
    /// Allowed operation types.
    pub allowed_operations: Vec<OperationType>,
    /// Geofence or zone constraints (opaque identifiers for off-chain validation).
    pub zone_constraints: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationType {
    StateWrite,
    AssetTransfer,
    ContractInvoke,
    MissionSubmit,
    EvidenceCommit,
    EscrowCreate,
}

impl CapabilityLease {
    /// Check if this lease is currently valid.
    pub fn is_valid(&self, current_height: u64) -> bool {
        !self.revoked
            && current_height >= self.valid_from
            && (self.valid_until == 0 || current_height <= self.valid_until)
    }

    /// Check if this lease has remaining budget.
    pub fn has_budget(&self, amount: TensionValue) -> bool {
        self.spent.raw() + amount.raw() <= self.budget.raw()
    }

    /// Check if this lease has remaining actions.
    pub fn has_actions(&self) -> bool {
        self.max_actions == 0 || self.actions_taken < self.max_actions
    }

    /// Check if an operation is allowed by this lease's scope.
    pub fn allows_operation(&self, op: OperationType) -> bool {
        self.scope.allowed_operations.is_empty() || self.scope.allowed_operations.contains(&op)
    }

    /// Check if a write target is within scope.
    pub fn allows_write(&self, target: &[u8]) -> bool {
        if self.scope.write_prefixes.is_empty() {
            return false; // Default-deny.
        }
        self.scope
            .write_prefixes
            .iter()
            .any(|p| target.starts_with(p))
    }

    /// Record a spend against this lease. Returns error if over budget.
    pub fn record_spend(&mut self, amount: TensionValue) -> Result<(), String> {
        if !self.has_budget(amount) {
            return Err(format!(
                "Lease budget exceeded: spent {} + {} > budget {}",
                self.spent, amount, self.budget
            ));
        }
        self.spent = self.spent + amount;
        self.actions_taken += 1;
        Ok(())
    }
}

/// Mission state machine — lifecycle for robot/agent tasks.
///
/// Missions are the semantic unit for agent coordination.
/// Every mission transition is a chain event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MissionState {
    /// Mission proposed but not yet accepted.
    Proposed,
    /// Mission accepted by the assigned agent.
    Accepted,
    /// Mission is actively being executed.
    Executing,
    /// Agent reports degraded capability (partial failure).
    Degraded,
    /// Mission paused (operator or self-imposed).
    Paused,
    /// Mission recovered from degraded state.
    Recovered,
    /// Mission completed successfully.
    Completed,
    /// Mission failed.
    Failed,
    /// Mission outcome disputed.
    Disputed,
    /// Dispute resolved, final settlement applied.
    Settled,
    /// Mission cancelled before completion.
    Cancelled,
}

impl MissionState {
    /// Valid state transitions (fail-closed: unlisted transitions are rejected).
    pub fn can_transition_to(&self, next: MissionState) -> bool {
        matches!(
            (self, next),
            (MissionState::Proposed, MissionState::Accepted)
                | (MissionState::Proposed, MissionState::Cancelled)
                | (MissionState::Accepted, MissionState::Executing)
                | (MissionState::Accepted, MissionState::Cancelled)
                | (MissionState::Executing, MissionState::Degraded)
                | (MissionState::Executing, MissionState::Paused)
                | (MissionState::Executing, MissionState::Completed)
                | (MissionState::Executing, MissionState::Failed)
                | (MissionState::Degraded, MissionState::Paused)
                | (MissionState::Degraded, MissionState::Recovered)
                | (MissionState::Degraded, MissionState::Failed)
                | (MissionState::Paused, MissionState::Executing)
                | (MissionState::Paused, MissionState::Cancelled)
                | (MissionState::Recovered, MissionState::Executing)
                | (MissionState::Completed, MissionState::Disputed)
                | (MissionState::Completed, MissionState::Settled)
                | (MissionState::Failed, MissionState::Disputed)
                | (MissionState::Failed, MissionState::Settled)
                | (MissionState::Disputed, MissionState::Settled)
        )
    }
}

/// Mission record on the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mission {
    pub mission_id: Hash,
    pub assigner: AgentId,
    pub assignee: AgentId,
    pub state: MissionState,
    /// Capability lease governing this mission.
    pub lease_id: Hash,
    /// Escrow ID for mission payment (locked at acceptance).
    pub escrow_id: Option<Hash>,
    /// Block height of last state transition.
    pub last_transition_height: u64,
    /// Evidence commitments (hashes of off-chain proof bundles).
    pub evidence_hashes: Vec<Hash>,
    /// Description of the mission objective.
    pub objective: String,
}

/// Off-chain evidence commitment anchored on-chain.
///
/// Architecture: evidence lives off-chain. The chain stores only the
/// hash commitment, timestamp, signer, and schema version.
/// Full evidence is retrievable from off-chain storage using the hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCommitment {
    /// Hash of the full evidence bundle (off-chain).
    pub evidence_hash: Hash,
    /// Who produced this evidence.
    pub producer: AgentId,
    /// Block height at which this was committed.
    pub committed_at: u64,
    /// Schema version for the evidence format.
    pub schema_version: u32,
    /// What mission this evidence relates to.
    pub mission_id: Hash,
    /// Type of evidence.
    pub evidence_type: EvidenceType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvidenceType {
    /// Periodic checkpoint during mission execution.
    Checkpoint,
    /// Proof of delivery / task completion.
    CompletionProof,
    /// Sensor data summary hash.
    SensorDigest,
    /// Guardrail execution attestation (TEE-signed).
    GuardrailAttestation,
    /// Exception report (degraded mode, safety event).
    ExceptionReport,
    /// Operator override record.
    OverrideRecord,
}

/// Autonomy budget — pre-authorized action envelope.
///
/// Instead of requiring chain round-trip for every decision,
/// the chain authorizes a bounded envelope ahead of time.
/// The agent acts within it without waiting for settlement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomyBudget {
    pub agent_id: AgentId,
    /// Maximum spend without chain confirmation.
    pub max_unconfirmed_spend: TensionValue,
    /// Maximum actions without chain confirmation.
    pub max_unconfirmed_actions: u64,
    /// Current unconfirmed spend.
    pub pending_spend: TensionValue,
    /// Current unconfirmed actions.
    pub pending_actions: u64,
    /// Block height at which this budget was last settled.
    pub last_settled_height: u64,
}

impl AutonomyBudget {
    /// Check if the agent can take an action without chain confirmation.
    pub fn can_act_locally(&self, spend: TensionValue) -> bool {
        self.pending_spend.raw() + spend.raw() <= self.max_unconfirmed_spend.raw()
            && (self.max_unconfirmed_actions == 0
                || self.pending_actions < self.max_unconfirmed_actions)
    }

    /// Record a local action (pre-chain-confirmation).
    pub fn record_local_action(&mut self, spend: TensionValue) -> Result<(), String> {
        if !self.can_act_locally(spend) {
            return Err("Autonomy budget exceeded — chain confirmation required".into());
        }
        self.pending_spend = self.pending_spend + spend;
        self.pending_actions += 1;
        Ok(())
    }

    /// Settle: reset pending counters after chain confirmation.
    pub fn settle(&mut self, height: u64) {
        self.pending_spend = TensionValue::ZERO;
        self.pending_actions = 0;
        self.last_settled_height = height;
    }
}

/// Agent safety mode — explicit degraded states for graceful containment.
///
/// When an agent becomes uncertain, rate-limited, out-of-bounds, or contradictory,
/// the system degrades into a predefined mode rather than hard-rejecting.
/// These modes are chain-visible: every transition records the agent's safety mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SafetyMode {
    /// Normal operation — full capabilities.
    Normal,
    /// Read-only — agent can observe but not mutate state.
    ReadOnly,
    /// No-spend — agent can write state but not transfer assets.
    NoSpend,
    /// Shadow mode — actions are recorded but not committed to state.
    /// Used for testing new agents or after suspected compromise.
    Shadow,
    /// Operator-only — all agent actions require human co-sign.
    OperatorOnly,
    /// Safe return — agent must return to a safe state (e.g., robot home).
    SafeReturn,
    /// Full quarantine — no actions permitted, awaiting investigation.
    Quarantine,
}

impl SafetyMode {
    /// Whether the agent can write state in this mode.
    pub fn can_write(&self) -> bool {
        matches!(self, SafetyMode::Normal | SafetyMode::NoSpend)
    }

    /// Whether the agent can transfer assets in this mode.
    pub fn can_spend(&self) -> bool {
        matches!(self, SafetyMode::Normal)
    }

    /// Whether actions are committed (vs shadow-recorded).
    pub fn commits_state(&self) -> bool {
        !matches!(self, SafetyMode::Shadow | SafetyMode::Quarantine)
    }

    /// Whether operator co-sign is required.
    pub fn requires_operator(&self) -> bool {
        matches!(self, SafetyMode::OperatorOnly | SafetyMode::SafeReturn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_lease_validity() {
        let lease = CapabilityLease {
            lease_id: [1u8; 32],
            delegator: [2u8; 32],
            delegate: [3u8; 32],
            scope: CapabilityScope {
                write_prefixes: vec![b"robot/data/".to_vec()],
                read_prefixes: vec![],
                allowed_operations: vec![OperationType::StateWrite],
                zone_constraints: vec![],
            },
            valid_from: 10,
            valid_until: 100,
            budget: TensionValue::from_integer(5000),
            spent: TensionValue::ZERO,
            max_actions: 50,
            actions_taken: 0,
            revoked: false,
            require_cosign: false,
        };

        assert!(!lease.is_valid(5)); // Too early.
        assert!(lease.is_valid(50)); // In range.
        assert!(!lease.is_valid(101)); // Expired.
    }

    #[test]
    fn test_capability_budget_tracking() {
        let mut lease = CapabilityLease {
            lease_id: [1u8; 32],
            delegator: [2u8; 32],
            delegate: [3u8; 32],
            scope: CapabilityScope {
                write_prefixes: vec![b"robot/".to_vec()],
                read_prefixes: vec![],
                allowed_operations: vec![],
                zone_constraints: vec![],
            },
            valid_from: 0,
            valid_until: 0,
            budget: TensionValue::from_integer(100),
            spent: TensionValue::ZERO,
            max_actions: 0,
            actions_taken: 0,
            revoked: false,
            require_cosign: false,
        };

        assert!(lease.record_spend(TensionValue::from_integer(60)).is_ok());
        assert!(lease.record_spend(TensionValue::from_integer(60)).is_err()); // Over budget.
        assert_eq!(lease.actions_taken, 1);
    }

    #[test]
    fn test_capability_revocation() {
        let mut lease = CapabilityLease {
            lease_id: [1u8; 32],
            delegator: [2u8; 32],
            delegate: [3u8; 32],
            scope: CapabilityScope {
                write_prefixes: vec![],
                read_prefixes: vec![],
                allowed_operations: vec![],
                zone_constraints: vec![],
            },
            valid_from: 0,
            valid_until: 0,
            budget: TensionValue::from_integer(1000),
            spent: TensionValue::ZERO,
            max_actions: 0,
            actions_taken: 0,
            revoked: false,
            require_cosign: false,
        };

        assert!(lease.is_valid(50));
        lease.revoked = true;
        assert!(!lease.is_valid(50));
    }

    #[test]
    fn test_mission_state_transitions() {
        assert!(MissionState::Proposed.can_transition_to(MissionState::Accepted));
        assert!(MissionState::Executing.can_transition_to(MissionState::Degraded));
        assert!(MissionState::Degraded.can_transition_to(MissionState::Recovered));
        assert!(MissionState::Completed.can_transition_to(MissionState::Disputed));
        assert!(MissionState::Disputed.can_transition_to(MissionState::Settled));

        // Invalid transitions.
        assert!(!MissionState::Proposed.can_transition_to(MissionState::Completed));
        assert!(!MissionState::Settled.can_transition_to(MissionState::Executing));
        assert!(!MissionState::Cancelled.can_transition_to(MissionState::Executing));
    }

    #[test]
    fn test_autonomy_budget() {
        let mut budget = AutonomyBudget {
            agent_id: [1u8; 32],
            max_unconfirmed_spend: TensionValue::from_integer(500),
            max_unconfirmed_actions: 10,
            pending_spend: TensionValue::ZERO,
            pending_actions: 0,
            last_settled_height: 0,
        };

        assert!(budget.can_act_locally(TensionValue::from_integer(200)));
        budget
            .record_local_action(TensionValue::from_integer(200))
            .unwrap();
        budget
            .record_local_action(TensionValue::from_integer(200))
            .unwrap();

        // Third action would exceed budget.
        assert!(!budget.can_act_locally(TensionValue::from_integer(200)));

        // Settle resets.
        budget.settle(100);
        assert!(budget.can_act_locally(TensionValue::from_integer(200)));
        assert_eq!(budget.last_settled_height, 100);
    }

    #[test]
    fn test_write_scope_default_deny() {
        let lease = CapabilityLease {
            lease_id: [1u8; 32],
            delegator: [2u8; 32],
            delegate: [3u8; 32],
            scope: CapabilityScope {
                write_prefixes: vec![], // Empty = no access.
                read_prefixes: vec![],
                allowed_operations: vec![],
                zone_constraints: vec![],
            },
            valid_from: 0,
            valid_until: 0,
            budget: TensionValue::from_integer(1000),
            spent: TensionValue::ZERO,
            max_actions: 0,
            actions_taken: 0,
            revoked: false,
            require_cosign: false,
        };

        assert!(!lease.allows_write(b"anything"));
    }
}
