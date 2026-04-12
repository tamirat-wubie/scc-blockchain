use sccgub_state::balances::BalanceLedger;
use sccgub_state::world::ManagedWorldState;
use sccgub_types::block::Block;
use sccgub_types::tension::TensionValue;

/// Runtime invariant monitor — checks consensus-critical invariants after
/// every block production/validation to detect violations before they propagate.
///
/// Invariants are numbered for traceability:
/// - INV-1: Supply conservation (total supply never changes except at genesis/mint).
/// - INV-2: Nonce monotonicity (per-agent nonces strictly increase).
/// - INV-3: State root integrity (trie root matches committed header).
/// - INV-4: No fork (deterministic finality mode produces unique blocks per height).
/// - INV-5: Tension homeostasis (tension stays within budget).
/// - INV-6: Receipt completeness (every accepted tx has a receipt).
/// - INV-7: Causal acyclicity (no cycles in causal graph).
///
/// Check all runtime invariants. Returns list of violations (empty = healthy).
pub fn check_invariants(
    block: &Block,
    state: &ManagedWorldState,
    balances: &BalanceLedger,
    expected_supply: TensionValue,
) -> Vec<InvariantViolation> {
    let mut violations = Vec::new();

    // INV-1: Supply conservation.
    let actual_supply = balances.total_supply();
    if actual_supply != expected_supply {
        violations.push(InvariantViolation {
            id: "INV-1",
            name: "Supply conservation",
            details: format!(
                "Expected supply {}, actual {}",
                expected_supply, actual_supply
            ),
            severity: Severity::Critical,
        });
    }

    // INV-3: State root integrity.
    let computed_root = state.state_root();
    if computed_root != block.header.state_root {
        violations.push(InvariantViolation {
            id: "INV-3",
            name: "State root integrity",
            details: format!(
                "Computed root {} != header root {}",
                hex::encode(computed_root),
                hex::encode(block.header.state_root)
            ),
            severity: Severity::Critical,
        });
    }

    // INV-5: Tension homeostasis.
    let budget = state.state.tension_field.budget.current_budget;
    if block.header.tension_after > block.header.tension_before + budget {
        violations.push(InvariantViolation {
            id: "INV-5",
            name: "Tension homeostasis",
            details: format!(
                "tension_after {} > tension_before {} + budget {}",
                block.header.tension_after, block.header.tension_before, budget
            ),
            severity: Severity::Critical,
        });
    }

    // INV-6: Receipt completeness.
    if !block.body.transitions.is_empty() && block.receipts.len() != block.body.transitions.len() {
        violations.push(InvariantViolation {
            id: "INV-6",
            name: "Receipt completeness",
            details: format!(
                "{} transitions but {} receipts",
                block.body.transitions.len(),
                block.receipts.len()
            ),
            severity: Severity::High,
        });
    }

    // INV-6b: All receipts in a committed block must be Accept.
    for (i, receipt) in block.receipts.iter().enumerate() {
        if !receipt.verdict.is_accepted() {
            violations.push(InvariantViolation {
                id: "INV-6",
                name: "Receipt verdict",
                details: format!("Receipt {} has verdict: {}", i, receipt.verdict),
                severity: Severity::Critical,
            });
        }
    }

    // INV-7: Causal acyclicity (basic check — no self-referencing edges).
    for edge in &block.causal_delta.new_edges {
        let (src, tgt) = edge.endpoints();
        if src == tgt {
            violations.push(InvariantViolation {
                id: "INV-7",
                name: "Causal acyclicity",
                details: "Self-referencing causal edge detected".into(),
                severity: Severity::High,
            });
        }
    }

    violations
}

/// Check nonce monotonicity across a block's transitions.
pub fn check_nonce_monotonicity(block: &Block) -> Vec<InvariantViolation> {
    let mut violations = Vec::new();
    let mut seen: std::collections::HashMap<[u8; 32], u128> = std::collections::HashMap::new();

    for (i, tx) in block.body.transitions.iter().enumerate() {
        if let Some(&prev_nonce) = seen.get(&tx.actor.agent_id) {
            if tx.nonce <= prev_nonce {
                violations.push(InvariantViolation {
                    id: "INV-2",
                    name: "Nonce monotonicity",
                    details: format!(
                        "Tx {} nonce {} <= previous {} for agent {}",
                        i,
                        tx.nonce,
                        prev_nonce,
                        hex::encode(tx.actor.agent_id)
                    ),
                    severity: Severity::Critical,
                });
            }
        }
        seen.insert(tx.actor.agent_id, tx.nonce);
    }

    violations
}

#[derive(Debug, Clone)]
pub struct InvariantViolation {
    pub id: &'static str,
    pub name: &'static str,
    pub details: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// System must halt — data integrity compromised.
    Critical,
    /// Investigation required — may indicate a bug.
    High,
    /// Anomaly detected — log and monitor.
    Warning,
}

impl std::fmt::Display for InvariantViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{:?}] {} ({}): {}",
            self.severity, self.id, self.name, self.details
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::tension::TensionValue;

    #[test]
    fn test_healthy_block_no_violations() {
        // A genesis block with matching supply should have no violations.
        let block = sccgub_types::block::Block {
            header: sccgub_types::block::BlockHeader {
                chain_id: [0u8; 32],
                block_id: [0u8; 32],
                parent_id: [0u8; 32],
                height: 0,
                timestamp: sccgub_types::timestamp::CausalTimestamp::genesis(),
                state_root: [0u8; 32], // Will match empty state.
                transition_root: [0u8; 32],
                receipt_root: [0u8; 32],
                causal_root: [0u8; 32],
                proof_root: [0u8; 32],
                governance_hash: [0u8; 32],
                tension_before: TensionValue::ZERO,
                tension_after: TensionValue::ZERO,
                mfidel_seal: sccgub_types::mfidel::MfidelAtomicSeal::from_height(0),
                balance_root: [0u8; 32],
                validator_id: [1u8; 32],
                version: 1,
            },
            body: sccgub_types::block::BlockBody {
                transitions: vec![],
                transition_count: 0,
                total_tension_delta: TensionValue::ZERO,
                constraint_satisfaction: vec![],
                genesis_consensus_params: None,
            },
            receipts: vec![],
            causal_delta: sccgub_types::causal::CausalGraphDelta::default(),
            proof: sccgub_types::proof::CausalProof {
                block_height: 0,
                transitions_proven: vec![],
                phi_traversal_log: sccgub_types::proof::PhiTraversalLog::default(),
                governance_snapshot_hash: [0u8; 32],
                tension_before: TensionValue::ZERO,
                tension_after: TensionValue::ZERO,
                constraint_results: vec![],
                recursion_depth: 0,
                validator_signature: vec![],
                causal_hash: [0u8; 32],
            },
            governance: sccgub_types::governance::GovernanceSnapshot {
                state_hash: [0u8; 32],
                active_norm_count: 0,
                emergency_mode: false,
                finality_mode: sccgub_types::governance::FinalityMode::Deterministic,
                governance_limits: sccgub_types::governance::GovernanceLimitsSnapshot::default(),
                finality_config: sccgub_types::governance::FinalityConfigSnapshot::default(),
            },
        };

        let state = ManagedWorldState::new();
        // Set state_root to match the block header (empty state).
        let root = state.state_root();
        let mut block = block;
        block.header.state_root = root;

        let balances = BalanceLedger::new();
        let violations = check_invariants(&block, &state, &balances, TensionValue::ZERO);
        assert!(
            violations.is_empty(),
            "No violations expected: {:?}",
            violations.iter().map(|v| v.to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_supply_conservation_violation() {
        let state = ManagedWorldState::new();
        let root = state.state_root();

        // Reuse the same block template as above but with mismatched supply.
        let block = sccgub_types::block::Block {
            header: sccgub_types::block::BlockHeader {
                chain_id: [0u8; 32],
                block_id: [0u8; 32],
                parent_id: [0u8; 32],
                height: 0,
                timestamp: sccgub_types::timestamp::CausalTimestamp::genesis(),
                state_root: root,
                transition_root: [0u8; 32],
                receipt_root: [0u8; 32],
                causal_root: [0u8; 32],
                proof_root: [0u8; 32],
                governance_hash: [0u8; 32],
                tension_before: TensionValue::ZERO,
                tension_after: TensionValue::ZERO,
                mfidel_seal: sccgub_types::mfidel::MfidelAtomicSeal::from_height(0),
                balance_root: [0u8; 32],
                validator_id: [1u8; 32],
                version: 1,
            },
            body: sccgub_types::block::BlockBody {
                transitions: vec![],
                transition_count: 0,
                total_tension_delta: TensionValue::ZERO,
                constraint_satisfaction: vec![],
                genesis_consensus_params: None,
            },
            receipts: vec![],
            causal_delta: sccgub_types::causal::CausalGraphDelta::default(),
            proof: sccgub_types::proof::CausalProof {
                block_height: 0,
                transitions_proven: vec![],
                phi_traversal_log: sccgub_types::proof::PhiTraversalLog::default(),
                governance_snapshot_hash: [0u8; 32],
                tension_before: TensionValue::ZERO,
                tension_after: TensionValue::ZERO,
                constraint_results: vec![],
                recursion_depth: 0,
                validator_signature: vec![],
                causal_hash: [0u8; 32],
            },
            governance: sccgub_types::governance::GovernanceSnapshot {
                state_hash: [0u8; 32],
                active_norm_count: 0,
                emergency_mode: false,
                finality_mode: sccgub_types::governance::FinalityMode::Deterministic,
                governance_limits: sccgub_types::governance::GovernanceLimitsSnapshot::default(),
                finality_config: sccgub_types::governance::FinalityConfigSnapshot::default(),
            },
        };

        let mut balances = BalanceLedger::new();
        balances.credit(&[1u8; 32], TensionValue::from_integer(500));

        // Expected 1000 but actual is 500 — violation.
        let violations =
            check_invariants(&block, &state, &balances, TensionValue::from_integer(1000));
        assert!(violations.iter().any(|v| v.id == "INV-1"));
    }
}
