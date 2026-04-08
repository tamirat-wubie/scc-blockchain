// Future-ready primitives for post-quantum migration, account abstraction,
// state management, zero-knowledge commitments, and AI agent safety.
//
// These are consensus-layer foundations that allow the chain to evolve
// without protocol-breaking changes. Each primitive is designed to be
// activated through governance proposals when ready.

use serde::{Deserialize, Serialize};

use crate::tension::TensionValue;
use crate::{AgentId, Hash};

/// Cryptographic algorithm identifier — enables hybrid and migration schemes.
/// NIST finalized ML-DSA (Dilithium), ML-KEM, SLH-DSA in Aug 2024.
/// Chain must support algorithm negotiation for smooth migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// Current default.
    Ed25519,
    /// NIST post-quantum lattice signature (FIPS 204).
    MlDsa44,
    MlDsa65,
    MlDsa87,
    /// Stateless hash-based (FIPS 205) — conservative fallback.
    SlhDsaShake128s,
    /// Hybrid: Ed25519 + ML-DSA-65 (transition period).
    HybridEd25519MlDsa65,
}

/// A signature with explicit algorithm tag for crypto agility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaggedSignature {
    pub algorithm: SignatureAlgorithm,
    pub signature_bytes: Vec<u8>,
    /// For hybrid: secondary signature bytes.
    pub secondary_bytes: Option<Vec<u8>>,
}

impl TaggedSignature {
    pub fn min_length(&self) -> usize {
        match self.algorithm {
            SignatureAlgorithm::Ed25519 => 64,
            SignatureAlgorithm::MlDsa44 => 2420,
            SignatureAlgorithm::MlDsa65 => 3293,
            SignatureAlgorithm::MlDsa87 => 4595,
            SignatureAlgorithm::SlhDsaShake128s => 7856,
            SignatureAlgorithm::HybridEd25519MlDsa65 => 64, // Primary must be valid.
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.signature_bytes.len() < self.min_length() {
            return Err(format!(
                "{:?} signature too short: {} bytes, need >= {}",
                self.algorithm,
                self.signature_bytes.len(),
                self.min_length()
            ));
        }
        if self.algorithm == SignatureAlgorithm::HybridEd25519MlDsa65 {
            match &self.secondary_bytes {
                Some(sec) if sec.len() >= 3293 => {}
                Some(sec) => {
                    return Err(format!(
                        "Hybrid secondary (ML-DSA-65) too short: {} bytes",
                        sec.len()
                    ));
                }
                None => return Err("Hybrid signature requires secondary_bytes".into()),
            }
        }
        Ok(())
    }
}

// ============================================================================
// 2. SESSION KEYS / ACCOUNT ABSTRACTION
// ============================================================================

/// Session key — temporary delegated signing authority.
/// Enables gasless UX: user signs once, app submits on behalf within bounds.
/// Modeled after ERC-4337 session keys.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKey {
    pub session_id: Hash,
    /// The master account that delegated this session.
    pub master_account: AgentId,
    /// Temporary public key authorized for this session.
    pub session_public_key: [u8; 32],
    /// Allowed operation types during this session.
    pub allowed_operations: Vec<String>,
    /// Maximum spend per transaction.
    pub max_spend_per_tx: TensionValue,
    /// Maximum total spend for the session.
    pub max_total_spend: TensionValue,
    /// Spend used so far.
    pub spent: TensionValue,
    /// Maximum number of transactions.
    pub max_transactions: u64,
    /// Transactions executed so far.
    pub transactions_used: u64,
    /// Block height at which this session expires.
    pub expires_at_block: u64,
    /// Whether the session has been revoked.
    pub revoked: bool,
}

impl SessionKey {
    pub fn is_valid(&self, current_height: u64) -> bool {
        !self.revoked
            && current_height <= self.expires_at_block
            && (self.max_transactions == 0 || self.transactions_used < self.max_transactions)
    }

    pub fn can_spend(&self, amount: TensionValue) -> bool {
        amount.raw() <= self.max_spend_per_tx.raw()
            && self.spent.raw().saturating_add(amount.raw()) <= self.max_total_spend.raw()
    }

    pub fn record_use(&mut self, amount: TensionValue) -> Result<(), String> {
        if !self.can_spend(amount) {
            return Err("Session key spend limit exceeded".into());
        }
        self.spent = self.spent + amount;
        self.transactions_used += 1;
        Ok(())
    }
}

// ============================================================================
// 3. STATE PRUNING / ARCHIVAL POLICY
// ============================================================================

/// State retention policy — controls what gets pruned vs. archived.
/// Prevents unbounded state growth (a key blockchain scalability bottleneck).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RetentionClass {
    /// Always kept in active state (balances, nonces, governance).
    Permanent,
    /// Kept for N blocks, then pruned (receipts, events, session data).
    BlockBound { max_blocks: u64 },
    /// Kept until explicitly deleted (compliance-sensitive data).
    UntilDeleted,
    /// Archived after N blocks (moved to cold storage, hash remains on-chain).
    ArchiveAfter { blocks: u64 },
}

/// State entry metadata for pruning decisions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateRetention {
    pub key_prefix: Vec<u8>,
    pub class: RetentionClass,
    /// Estimated size contribution per entry (bytes).
    pub avg_entry_size: u64,
}

/// Default retention policies for known state domains.
pub fn default_retention_policies() -> Vec<StateRetention> {
    vec![
        StateRetention {
            key_prefix: b"balance/".to_vec(),
            class: RetentionClass::Permanent,
            avg_entry_size: 80,
        },
        StateRetention {
            key_prefix: b"nonce/".to_vec(),
            class: RetentionClass::Permanent,
            avg_entry_size: 48,
        },
        StateRetention {
            key_prefix: b"receipt/".to_vec(),
            class: RetentionClass::ArchiveAfter { blocks: 10_000 },
            avg_entry_size: 512,
        },
        StateRetention {
            key_prefix: b"event/".to_vec(),
            class: RetentionClass::ArchiveAfter { blocks: 5_000 },
            avg_entry_size: 256,
        },
        StateRetention {
            key_prefix: b"session/".to_vec(),
            class: RetentionClass::BlockBound { max_blocks: 1_000 },
            avg_entry_size: 128,
        },
    ]
}

// ============================================================================
// 4. ZERO-KNOWLEDGE COMMITMENT SUPPORT
// ============================================================================

/// ZK commitment — prove a property without revealing the value.
/// Enables: privacy-preserving balance proofs, selective disclosure,
/// compliance attestation without data exposure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkCommitment {
    /// What is being committed to (e.g., "balance_sufficient", "age_over_18").
    pub claim_type: String,
    /// Pedersen-style commitment: C = g^v * h^r.
    pub commitment_hash: Hash,
    /// Proof that the commitment satisfies the claim.
    pub proof_bytes: Vec<u8>,
    /// Schema version for the proof format.
    pub proof_schema: String,
    /// Who produced this commitment.
    pub prover: AgentId,
    /// Block height at which this was committed.
    pub committed_at_block: u64,
}

impl ZkCommitment {
    pub fn validate(&self) -> Result<(), String> {
        if self.claim_type.is_empty() {
            return Err("claim_type is required".into());
        }
        if self.commitment_hash == [0u8; 32] {
            return Err("commitment_hash is required".into());
        }
        if self.proof_bytes.is_empty() {
            return Err("proof_bytes is required".into());
        }
        if self.proof_schema.is_empty() {
            return Err("proof_schema is required".into());
        }
        if self.prover == [0u8; 32] {
            return Err("prover is required".into());
        }
        Ok(())
    }
}

// ============================================================================
// 5. AI AGENT CIRCUIT BREAKER
// ============================================================================

/// Circuit breaker for AI agents — automatic safety containment.
/// When an agent exceeds anomaly thresholds, the breaker trips and
/// the agent is downgraded to a restricted safety mode.
///
/// Modeled after production circuit breaker patterns:
/// Closed (normal) → Open (halted) → Half-Open (testing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CircuitBreakerState {
    /// Normal operation — all actions permitted within policy.
    Closed,
    /// Tripped — agent halted, no actions permitted.
    Open { tripped_at_block: u64 },
    /// Testing — limited actions to verify agent is safe.
    HalfOpen { test_budget: u64 },
}

/// Circuit breaker configuration for an AI agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCircuitBreaker {
    pub agent_id: AgentId,
    pub state: CircuitBreakerState,
    /// Maximum consecutive failures before tripping.
    pub failure_threshold: u32,
    /// Current consecutive failure count.
    pub failure_count: u32,
    /// Maximum spend rate (per block) before tripping.
    pub max_spend_rate: TensionValue,
    /// Current block spend.
    pub current_block_spend: TensionValue,
    /// Blocks to wait before transitioning Open → HalfOpen.
    pub cooldown_blocks: u64,
    /// Blocks to test in HalfOpen before returning to Closed.
    pub test_blocks: u64,
}

impl AgentCircuitBreaker {
    /// Record a successful action (resets failure count).
    pub fn record_success(&mut self) {
        self.failure_count = 0;
        if let CircuitBreakerState::HalfOpen { test_budget } = &mut self.state {
            if *test_budget > 0 {
                *test_budget -= 1;
            }
            if *test_budget == 0 {
                self.state = CircuitBreakerState::Closed;
            }
        }
    }

    /// Record a failure. May trip the breaker.
    pub fn record_failure(&mut self, current_block: u64) {
        self.failure_count += 1;
        if self.failure_count >= self.failure_threshold {
            self.state = CircuitBreakerState::Open {
                tripped_at_block: current_block,
            };
        }
    }

    /// Record spend. May trip if rate exceeded.
    pub fn record_spend(&mut self, amount: TensionValue, current_block: u64) {
        self.current_block_spend = self.current_block_spend + amount;
        if self.current_block_spend > self.max_spend_rate {
            self.state = CircuitBreakerState::Open {
                tripped_at_block: current_block,
            };
        }
    }

    /// Check if the agent can act.
    pub fn can_act(&self) -> bool {
        matches!(
            self.state,
            CircuitBreakerState::Closed | CircuitBreakerState::HalfOpen { .. }
        )
    }

    /// Try to transition Open → HalfOpen after cooldown.
    pub fn try_recover(&mut self, current_block: u64) {
        if let CircuitBreakerState::Open { tripped_at_block } = self.state {
            if current_block >= tripped_at_block + self.cooldown_blocks {
                self.state = CircuitBreakerState::HalfOpen {
                    test_budget: self.test_blocks,
                };
                self.failure_count = 0;
                self.current_block_spend = TensionValue::ZERO;
            }
        }
    }

    /// Reset spend counter at the start of each block.
    pub fn new_block(&mut self) {
        self.current_block_spend = TensionValue::ZERO;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tagged_signature_ed25519() {
        let sig = TaggedSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            signature_bytes: vec![0u8; 64],
            secondary_bytes: None,
        };
        assert!(sig.validate().is_ok());
    }

    #[test]
    fn test_tagged_signature_too_short() {
        let sig = TaggedSignature {
            algorithm: SignatureAlgorithm::Ed25519,
            signature_bytes: vec![0u8; 32],
            secondary_bytes: None,
        };
        assert!(sig.validate().is_err());
    }

    #[test]
    fn test_hybrid_signature_requires_secondary() {
        let sig = TaggedSignature {
            algorithm: SignatureAlgorithm::HybridEd25519MlDsa65,
            signature_bytes: vec![0u8; 64],
            secondary_bytes: None,
        };
        assert!(sig.validate().is_err());
    }

    #[test]
    fn test_session_key_validity() {
        let sk = SessionKey {
            session_id: [1u8; 32],
            master_account: [2u8; 32],
            session_public_key: [3u8; 32],
            allowed_operations: vec!["transfer".into()],
            max_spend_per_tx: TensionValue::from_integer(100),
            max_total_spend: TensionValue::from_integer(1000),
            spent: TensionValue::ZERO,
            max_transactions: 10,
            transactions_used: 0,
            expires_at_block: 500,
            revoked: false,
        };
        assert!(sk.is_valid(100));
        assert!(!sk.is_valid(501)); // Expired.
        assert!(sk.can_spend(TensionValue::from_integer(50)));
        assert!(!sk.can_spend(TensionValue::from_integer(200))); // Over per-tx limit.
    }

    #[test]
    fn test_session_key_spend_tracking() {
        let mut sk = SessionKey {
            session_id: [1u8; 32],
            master_account: [2u8; 32],
            session_public_key: [3u8; 32],
            allowed_operations: vec![],
            max_spend_per_tx: TensionValue::from_integer(100),
            max_total_spend: TensionValue::from_integer(200),
            spent: TensionValue::ZERO,
            max_transactions: 0,
            transactions_used: 0,
            expires_at_block: 1000,
            revoked: false,
        };
        assert!(sk.record_use(TensionValue::from_integer(80)).is_ok());
        assert!(sk.record_use(TensionValue::from_integer(80)).is_ok());
        assert!(sk.record_use(TensionValue::from_integer(80)).is_err()); // Over total.
    }

    #[test]
    fn test_circuit_breaker_lifecycle() {
        let mut cb = AgentCircuitBreaker {
            agent_id: [1u8; 32],
            state: CircuitBreakerState::Closed,
            failure_threshold: 3,
            failure_count: 0,
            max_spend_rate: TensionValue::from_integer(1000),
            current_block_spend: TensionValue::ZERO,
            cooldown_blocks: 10,
            test_blocks: 5,
        };

        assert!(cb.can_act());

        // Three failures → trip.
        cb.record_failure(100);
        cb.record_failure(100);
        assert!(cb.can_act()); // Still under threshold.
        cb.record_failure(100);
        assert!(!cb.can_act()); // Tripped.

        // Too early to recover.
        cb.try_recover(105);
        assert!(!cb.can_act());

        // After cooldown → half-open.
        cb.try_recover(110);
        assert!(cb.can_act());
        assert!(matches!(cb.state, CircuitBreakerState::HalfOpen { .. }));

        // Successful tests → closed.
        for _ in 0..5 {
            cb.record_success();
        }
        assert!(matches!(cb.state, CircuitBreakerState::Closed));
    }

    #[test]
    fn test_circuit_breaker_spend_rate() {
        let mut cb = AgentCircuitBreaker {
            agent_id: [1u8; 32],
            state: CircuitBreakerState::Closed,
            failure_threshold: 10,
            failure_count: 0,
            max_spend_rate: TensionValue::from_integer(500),
            current_block_spend: TensionValue::ZERO,
            cooldown_blocks: 10,
            test_blocks: 5,
        };

        cb.record_spend(TensionValue::from_integer(400), 1);
        assert!(cb.can_act());

        cb.record_spend(TensionValue::from_integer(200), 1); // Over rate.
        assert!(!cb.can_act());
    }

    #[test]
    fn test_zk_commitment_validation() {
        let zk = ZkCommitment {
            claim_type: "balance_sufficient".into(),
            commitment_hash: [1u8; 32],
            proof_bytes: vec![0u8; 128],
            proof_schema: "groth16-v1".into(),
            prover: [2u8; 32],
            committed_at_block: 100,
        };
        assert!(zk.validate().is_ok());

        let mut bad = zk.clone();
        bad.proof_bytes = vec![];
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_default_retention_policies() {
        let policies = default_retention_policies();
        assert!(policies.len() >= 4);
        assert!(policies.iter().any(|p| p.key_prefix == b"balance/"));
    }
}
