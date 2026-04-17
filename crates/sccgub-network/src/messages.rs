use serde::{Deserialize, Serialize};

use sccgub_consensus::protocol::Vote;
use sccgub_consensus::safety::SafetyCertificate;
use sccgub_types::block::Block;
use sccgub_types::transition::SymbolicTransition;
use sccgub_types::Hash;

/// Network message types for validator-to-validator communication.
///
/// All messages are serialized with bincode for compact, deterministic encoding.
/// Messages are signed by the sender's Ed25519 key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// Announce this validator's presence to the network.
    Hello(HelloMessage),
    /// Propose a new block for consensus.
    BlockProposal(BlockProposalMessage),
    /// Cast a consensus vote (prevote or precommit).
    ConsensusVote(Vote),
    /// Equivocation evidence (two conflicting votes).
    EquivocationEvidence(EquivocationEvidenceMessage),
    /// Propagate a transaction to the mempool.
    TransactionGossip(TransactionGossipMessage),
    /// Request a specific block by height.
    BlockRequest(BlockRequestMessage),
    /// Response to a block request.
    BlockResponse(BlockResponseMessage),
    /// Share law set hash for Phase 4 synchronization.
    LawSync(LawSyncMessage),
    /// Finality certificate announcement.
    FinalityCertificate(SafetyCertificate),
    /// Heartbeat (liveness check).
    Heartbeat(HeartbeatMessage),
}

/// Hello message — sent on connection to introduce a validator.
///
/// N-56: `timestamp_ms` is signed into the canonical bytes and enforced
/// within a staleness window by the receiver, preventing Hello-replay
/// attacks that would otherwise let an attacker hijack a victim
/// validator's entry in the peer registry by replaying a previously
/// captured valid Hello.  Older nodes that send `timestamp_ms = 0`
/// (via `#[serde(default)]`) are rejected by the staleness check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloMessage {
    pub validator_id: Hash,
    pub chain_id: Hash,
    pub current_height: u64,
    pub finalized_height: u64,
    pub protocol_version: u32,
    #[serde(default)]
    pub epoch: u64,
    #[serde(default)]
    pub known_peers: Vec<String>,
    /// Unix time in milliseconds when this Hello was constructed.
    #[serde(default)]
    pub timestamp_ms: u64,
    pub signature: Vec<u8>,
}

/// Block proposal — leader broadcasts a candidate block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockProposalMessage {
    pub proposer_id: Hash,
    pub block: Block,
    pub round: u32,
    pub signature: Vec<u8>,
}

/// Equivocation evidence -- two conflicting votes from the same validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EquivocationEvidenceMessage {
    pub vote_a: Vote,
    pub vote_b: Vote,
    /// Validator set epoch used in vote signatures.
    pub epoch: u64,
}

/// Transaction gossip — propagate unconfirmed transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionGossipMessage {
    pub sender_id: Hash,
    pub transaction: SymbolicTransition,
}

/// Block request — ask a peer for a specific block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequestMessage {
    pub requester_id: Hash,
    pub height: u64,
}

/// Block response — reply to a block request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponseMessage {
    pub responder_id: Hash,
    pub block: Option<Block>,
    pub height: u64,
}

/// Law set hash for Phase 4 synchronization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LawSyncMessage {
    pub validator_id: Hash,
    pub height: u64,
    pub law_set_hash: Hash,
    #[serde(default)]
    pub protocol_version: u32,
    pub signature: Vec<u8>,
}

/// Heartbeat — periodic liveness signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeartbeatMessage {
    pub validator_id: Hash,
    pub current_height: u64,
    #[serde(default)]
    pub protocol_version: u32,
    #[serde(default)]
    pub epoch: u64,
    pub timestamp_ms: u64,
}

impl NetworkMessage {
    /// Serialize to compact binary (bincode).
    pub fn to_bytes(&self) -> Vec<u8> {
        sccgub_crypto::canonical::canonical_bytes(self)
    }

    /// Deserialize from binary bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        sccgub_crypto::canonical::from_canonical_bytes(bytes)
    }

    /// Get the message type as a string (for logging).
    pub fn message_type(&self) -> &'static str {
        match self {
            Self::Hello(_) => "Hello",
            Self::BlockProposal(_) => "BlockProposal",
            Self::ConsensusVote(_) => "ConsensusVote",
            Self::EquivocationEvidence(_) => "EquivocationEvidence",
            Self::TransactionGossip(_) => "TransactionGossip",
            Self::BlockRequest(_) => "BlockRequest",
            Self::BlockResponse(_) => "BlockResponse",
            Self::LawSync(_) => "LawSync",
            Self::FinalityCertificate(_) => "FinalityCertificate",
            Self::Heartbeat(_) => "Heartbeat",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hello_roundtrip() {
        let msg = NetworkMessage::Hello(HelloMessage {
            validator_id: [1u8; 32],
            chain_id: [2u8; 32],
            current_height: 100,
            finalized_height: 95,
            protocol_version: 1,
            epoch: 0,
            known_peers: vec!["127.0.0.1:9000".to_string()],
            timestamp_ms: 1_700_000_000_000,
            signature: vec![0u8; 64],
        });

        let bytes = msg.to_bytes();
        let restored = NetworkMessage::from_bytes(&bytes).unwrap();
        assert_eq!(restored.message_type(), "Hello");
    }

    #[test]
    fn test_heartbeat_roundtrip() {
        let msg = NetworkMessage::Heartbeat(HeartbeatMessage {
            validator_id: [3u8; 32],
            current_height: 50,
            protocol_version: 1,
            epoch: 0,
            timestamp_ms: 1234567890,
        });

        let bytes = msg.to_bytes();
        assert!(bytes.len() < 200); // Bincode should be compact.
        let restored = NetworkMessage::from_bytes(&bytes).unwrap();
        assert_eq!(restored.message_type(), "Heartbeat");
    }

    #[test]
    fn test_block_request_roundtrip() {
        let msg = NetworkMessage::BlockRequest(BlockRequestMessage {
            requester_id: [4u8; 32],
            height: 999,
        });

        let bytes = msg.to_bytes();
        let restored = NetworkMessage::from_bytes(&bytes).unwrap();
        assert_eq!(restored.message_type(), "BlockRequest");
    }

    #[test]
    fn test_equivocation_evidence_roundtrip() {
        let vote = Vote {
            validator_id: [9u8; 32],
            block_hash: [7u8; 32],
            height: 12,
            round: 0,
            vote_type: sccgub_consensus::protocol::VoteType::Precommit,
            signature: vec![0u8; 64],
        };
        let msg = NetworkMessage::EquivocationEvidence(EquivocationEvidenceMessage {
            vote_a: vote.clone(),
            vote_b: vote,
            epoch: 1,
        });
        let bytes = msg.to_bytes();
        let restored = NetworkMessage::from_bytes(&bytes).unwrap();
        assert_eq!(restored.message_type(), "EquivocationEvidence");
    }

    // ── N-49 coverage: remaining message variant roundtrips ──────────

    #[test]
    fn test_consensus_vote_roundtrip() {
        let msg = NetworkMessage::ConsensusVote(Vote {
            validator_id: [6u8; 32],
            block_hash: [7u8; 32],
            height: 42,
            round: 1,
            vote_type: sccgub_consensus::protocol::VoteType::Prevote,
            signature: vec![0u8; 64],
        });
        let bytes = msg.to_bytes();
        let restored = NetworkMessage::from_bytes(&bytes).unwrap();
        assert_eq!(restored.message_type(), "ConsensusVote");
    }

    #[test]
    fn test_transaction_gossip_roundtrip() {
        use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
        use sccgub_types::governance::PrecedenceLevel;
        use sccgub_types::mfidel::MfidelAtomicSeal;
        use sccgub_types::transition::*;
        use std::collections::BTreeSet;

        let tx = SymbolicTransition {
            tx_id: [1u8; 32],
            actor: AgentIdentity {
                agent_id: [1u8; 32],
                public_key: [0u8; 32],
                mfidel_seal: MfidelAtomicSeal::from_height(0),
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: BTreeSet::new(),
                responsibility: ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::StateWrite,
                target: b"data/test".to_vec(),
                declared_purpose: "test".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: b"data/test".to_vec(),
                value: b"hello".to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: [1u8; 32],
                when: sccgub_types::timestamp::CausalTimestamp::genesis(),
                r#where: b"data/test".to_vec(),
                why: CausalJustification {
                    invoking_rule: [2u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "test".into(),
            },
            nonce: 1,
            signature: vec![0u8; 64],
        };
        let msg = NetworkMessage::TransactionGossip(TransactionGossipMessage {
            sender_id: [8u8; 32],
            transaction: tx,
        });
        let bytes = msg.to_bytes();
        let restored = NetworkMessage::from_bytes(&bytes).unwrap();
        assert_eq!(restored.message_type(), "TransactionGossip");
    }

    #[test]
    fn test_block_response_none_roundtrip() {
        let msg = NetworkMessage::BlockResponse(BlockResponseMessage {
            responder_id: [10u8; 32],
            block: None,
            height: 99,
        });
        let bytes = msg.to_bytes();
        let restored = NetworkMessage::from_bytes(&bytes).unwrap();
        assert_eq!(restored.message_type(), "BlockResponse");
    }

    #[test]
    fn test_law_sync_roundtrip() {
        let msg = NetworkMessage::LawSync(LawSyncMessage {
            validator_id: [11u8; 32],
            height: 77,
            law_set_hash: [12u8; 32],
            protocol_version: 1,
            signature: vec![0u8; 64],
        });
        let bytes = msg.to_bytes();
        let restored = NetworkMessage::from_bytes(&bytes).unwrap();
        assert_eq!(restored.message_type(), "LawSync");
    }

    #[test]
    fn test_finality_certificate_roundtrip() {
        let cert = SafetyCertificate {
            chain_id: [0xCC; 32],
            epoch: 1,
            height: 10,
            block_hash: [0xAA; 32],
            round: 0,
            precommit_signatures: vec![([1u8; 32], vec![0u8; 64])],
            quorum: 1,
            validator_count: 1,
        };
        let msg = NetworkMessage::FinalityCertificate(cert);
        let bytes = msg.to_bytes();
        let restored = NetworkMessage::from_bytes(&bytes).unwrap();
        assert_eq!(restored.message_type(), "FinalityCertificate");
    }

    #[test]
    fn test_from_bytes_rejects_garbage() {
        let result = NetworkMessage::from_bytes(&[0xFF, 0xFF, 0xFF]);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes_rejects_empty() {
        let result = NetworkMessage::from_bytes(&[]);
        assert!(result.is_err());
    }
}
