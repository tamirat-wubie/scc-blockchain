use serde::{Deserialize, Serialize};

use crate::tension::TensionValue;
use crate::{AgentId, Hash, TransitionId};

/// Typed causal events emitted during block execution.
///
/// Every state change produces one or more events. Events are included
/// in the block's receipt, forming a complete audit trail.
///
/// This is the foundation of the policy-aware settlement model:
/// every transfer carries intent, every approval has a receipt,
/// every governance change is explainable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ChainEvent {
    /// A state key was written or updated.
    StateWrite {
        tx_id: TransitionId,
        key: Vec<u8>,
        actor: AgentId,
    },

    /// An asset was transferred between agents.
    Transfer {
        tx_id: TransitionId,
        from: AgentId,
        to: AgentId,
        amount: TensionValue,
        /// Declared purpose from the transition intent.
        purpose: String,
    },

    /// A fee was charged and collected into treasury.
    FeeCharged {
        tx_id: TransitionId,
        payer: AgentId,
        amount: TensionValue,
        gas_used: u64,
    },

    /// A block reward was distributed to a validator.
    RewardDistributed {
        block_height: u64,
        validator: AgentId,
        amount: TensionValue,
    },

    /// An escrow was created.
    EscrowCreated {
        escrow_id: Hash,
        sender: AgentId,
        recipient: AgentId,
        amount: TensionValue,
    },

    /// Escrowed funds were released to recipient.
    EscrowReleased {
        escrow_id: Hash,
        recipient: AgentId,
        amount: TensionValue,
    },

    /// Escrowed funds were refunded to sender.
    EscrowRefunded {
        escrow_id: Hash,
        sender: AgentId,
        amount: TensionValue,
    },

    /// A governance proposal changed status.
    GovernanceChange {
        proposal_id: Hash,
        action: GovernanceAction,
        actor: AgentId,
        block_height: u64,
    },

    /// A validator was slashed for misbehavior.
    ValidatorSlashed {
        validator: AgentId,
        reason: String,
        penalty: TensionValue,
    },

    /// A new block was finalized (reached settlement finality).
    BlockFinalized {
        block_height: u64,
        block_hash: Hash,
        finality_class: String,
    },

    /// An invariant violation was detected.
    InvariantViolation {
        invariant_id: String,
        details: String,
        block_height: u64,
    },

    // === Artifact layer events ===
    /// An external artifact was registered on-chain.
    ArtifactRegistered {
        artifact_id: Hash,
        created_by: Hash,
        content_hash: Hash,
        schema_name: String,
    },

    /// An attestation was created for an artifact.
    AttestationCreated {
        attestation_id: Hash,
        artifact_id: Hash,
        authority: Hash,
        kind: String,
    },

    /// A lineage edge was recorded (derivation graph).
    LineageEdgeRecorded {
        parent: Hash,
        child: Hash,
        transform: String,
        actor: Hash,
    },

    /// An access grant was created for an artifact.
    AccessGrantCreated {
        grant_id: Hash,
        artifact_id: Hash,
        grantee: Hash,
    },

    /// An access grant was revoked.
    AccessGrantRevoked { grant_id: Hash, revoked_by: Hash },

    /// A session was opened or closed.
    SessionLifecycle {
        session_id: Hash,
        action: String,
        block_height: u64,
    },

    /// A dispute was filed or resolved.
    DisputeLifecycle {
        dispute_id: Hash,
        target_artifact: Hash,
        action: String,
        block_height: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GovernanceAction {
    ProposalSubmitted,
    ProposalVoted { approve: bool },
    ProposalAccepted,
    ProposalRejected,
    ProposalTimelocked { until: u64 },
    ProposalActivated,
    EmergencyActivated,
    EmergencyDeactivated,
}

/// Block-level event log — accumulated during block production.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BlockEventLog {
    pub events: Vec<ChainEvent>,
}

impl BlockEventLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn emit(&mut self, event: ChainEvent) {
        self.events.push(event);
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    /// Filter events by type for query.
    pub fn transfers(&self) -> Vec<&ChainEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e, ChainEvent::Transfer { .. }))
            .collect()
    }

    pub fn governance_changes(&self) -> Vec<&ChainEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e, ChainEvent::GovernanceChange { .. }))
            .collect()
    }

    pub fn fees(&self) -> Vec<&ChainEvent> {
        self.events
            .iter()
            .filter(|e| matches!(e, ChainEvent::FeeCharged { .. }))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_log_emit_and_filter() {
        let mut log = BlockEventLog::new();

        log.emit(ChainEvent::Transfer {
            tx_id: [1u8; 32],
            from: [2u8; 32],
            to: [3u8; 32],
            amount: TensionValue::from_integer(100),
            purpose: "payment".into(),
        });

        log.emit(ChainEvent::FeeCharged {
            tx_id: [1u8; 32],
            payer: [2u8; 32],
            amount: TensionValue::from_integer(5),
            gas_used: 10_000,
        });

        log.emit(ChainEvent::GovernanceChange {
            proposal_id: [4u8; 32],
            action: GovernanceAction::ProposalSubmitted,
            actor: [5u8; 32],
            block_height: 10,
        });

        assert_eq!(log.event_count(), 3);
        assert_eq!(log.transfers().len(), 1);
        assert_eq!(log.fees().len(), 1);
        assert_eq!(log.governance_changes().len(), 1);
    }

    #[test]
    fn test_event_serialization_roundtrip() {
        let event = ChainEvent::EscrowCreated {
            escrow_id: [42u8; 32],
            sender: [1u8; 32],
            recipient: [2u8; 32],
            amount: TensionValue::from_integer(500),
        };

        let json = serde_json::to_string(&event).unwrap();
        let recovered: ChainEvent = serde_json::from_str(&json).unwrap();

        match recovered {
            ChainEvent::EscrowCreated { amount, .. } => {
                assert_eq!(amount, TensionValue::from_integer(500));
            }
            _ => panic!("Wrong event type after deserialization"),
        }
    }
}
