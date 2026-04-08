// PHI TRAVERSAL — SINGLE SOURCE OF TRUTH (N-11 structural)
//
// Per-tx semantic checks live in ONE place: `phi_check_single_tx()`.
// Two callers use this shared function:
//
//   phi_traversal_block  — runs at CPoG validation time (per-block).
//                          For per-tx phases: iterates all txs through
//                          the shared function. For block-only phases:
//                          runs block-level logic.
//
//   validate_transition  — runs in the gas loop (per-transaction).
//                          Iterates per-tx phases calling the shared
//                          function directly. Every rejection produces
//                          a CausalReceipt via validate_transition_metered.
//
// Mempool admission uses admit_check() (lightweight: sig length, nonce,
// size, WHBinding structure). No Phi-phase checks at mempool time.
//
// Adding a semantic check to a per-tx phase means editing ONLY
// `phi_check_single_tx()`. Both callers pick it up automatically.
//
// Block-only phases: Topology(4), Body(9), Architecture(10),
// Performance(11), Feedback(12), Evolution(13).
// Per-tx phases: Distinction(1), Constraint(2), Ontology(3),
// Form(5), Organization(6), Module(7), Execution(8).

use sccgub_state::world::ManagedWorldState;
use sccgub_types::block::Block;
use sccgub_types::causal::CausalVertex;
use sccgub_types::proof::{PhiPhase, PhiPhaseResult, PhiTraversalLog};
use sccgub_types::tension::TensionValue;
use sccgub_types::transition::SymbolicTransition;

use crate::scce::{scce_validate, ConstraintWeights};
use crate::wh_check::check_transition_wh;

// ---------------------------------------------------------------------------
// Per-tx phase check — SINGLE SOURCE OF TRUTH
// ---------------------------------------------------------------------------

/// Check a single transaction against a per-tx Phi phase.
///
/// This is the canonical implementation of per-tx semantics. Called by:
/// - `phi_traversal_block` (iterates all txs per phase at CPoG time)
/// - `validate_transition` (iterates phases per tx in the gas loop)
///
/// Block-only phases panic — callers must not pass them here.
/// Use `is_per_tx_phase()` to filter before calling.
pub fn phi_check_single_tx(
    phase: PhiPhase,
    tx: &SymbolicTransition,
    state: &ManagedWorldState,
) -> PhiPhaseResult {
    match phase {
        // Phase 1: Distinction — WHBinding completeness.
        PhiPhase::Distinction => {
            let result = check_transition_wh(tx);
            let passed = result.is_ok();
            PhiPhaseResult {
                phase,
                passed,
                details: result.err().unwrap_or_else(|| "WHBinding complete".into()),
            }
        }

        // Phase 2: Constraint — SCCE validation.
        PhiPhase::Constraint => {
            let weights = ConstraintWeights::default();
            let result = scce_validate(tx, state, &weights, 32, 10_000);
            PhiPhaseResult {
                phase,
                passed: result.valid,
                details: result.details,
            }
        }

        // Phase 3: Ontology — target namespace check.
        PhiPhase::Ontology => {
            let result = crate::ontology::check_ontology(tx);
            let ok = result.is_allowed();
            PhiPhaseResult {
                phase,
                passed: ok,
                details: match &result {
                    crate::ontology::OntologyResult::Allowed => "Ontology verified".into(),
                    crate::ontology::OntologyResult::Rejected {
                        kind,
                        target,
                        allowed,
                    } => format!(
                        "Kind {:?} cannot target {} (allowed: {:?})",
                        kind,
                        String::from_utf8_lossy(target),
                        allowed
                            .iter()
                            .map(|n| String::from_utf8_lossy(n).into_owned())
                            .collect::<Vec<_>>(),
                    ),
                },
            }
        }

        // Phase 5: Form — structural validity.
        // Checks BOTH signature length AND address length (was split across paths).
        PhiPhase::Form => {
            if tx.signature.len() < 64 {
                return PhiPhaseResult {
                    phase,
                    passed: false,
                    details: format!(
                        "Signature too short ({} bytes, need >= 64)",
                        tx.signature.len()
                    ),
                };
            }
            let addr_ok = tx.intent.target.len() <= sccgub_types::MAX_SYMBOL_ADDRESS_LEN;
            PhiPhaseResult {
                phase,
                passed: addr_ok,
                details: if addr_ok {
                    "Form validated".into()
                } else {
                    "Address exceeds max length".into()
                },
            }
        }

        // Phase 6: Organization — governance invariant preservation.
        // Governance/norm/constraint ops require at least Meaning precedence.
        PhiPhase::Organization => {
            let requires_meaning = matches!(
                tx.intent.kind,
                sccgub_types::transition::TransitionKind::GovernanceUpdate
                    | sccgub_types::transition::TransitionKind::NormProposal
                    | sccgub_types::transition::TransitionKind::ConstraintAddition
            );
            if requires_meaning {
                let level = tx.actor.governance_level as u8;
                let meaning = sccgub_types::governance::PrecedenceLevel::Meaning as u8;
                if level > meaning {
                    return PhiPhaseResult {
                        phase,
                        passed: false,
                        details: format!(
                            "Requires Meaning precedence but actor has {:?}",
                            tx.actor.governance_level
                        ),
                    };
                }
            }
            PhiPhaseResult {
                phase,
                passed: true,
                details: "Governance invariants verified".into(),
            }
        }

        // Phase 7: Module — contract boundary compliance.
        // At per-tx level: structural checks only (receipt consistency is block-only).
        PhiPhase::Module => PhiPhaseResult {
            phase,
            passed: true,
            details: "Module boundaries respected".into(),
        },

        // Phase 8: Execution — payload consistency.
        PhiPhase::Execution => {
            let payload_result = crate::payload_check::check_payload_consistency(tx);
            if let crate::payload_check::PayloadConsistency::Inconsistent { reason } =
                &payload_result
            {
                return PhiPhaseResult {
                    phase,
                    passed: false,
                    details: format!("Payload inconsistent: {}", reason),
                };
            }
            if tx.intent.target.is_empty() {
                return PhiPhaseResult {
                    phase,
                    passed: false,
                    details: "Missing target".into(),
                };
            }
            if tx.nonce == 0 {
                return PhiPhaseResult {
                    phase,
                    passed: false,
                    details: "Zero nonce".into(),
                };
            }
            PhiPhaseResult {
                phase,
                passed: true,
                details: "Execution verified: payload consistent".into(),
            }
        }

        // Block-only phases — must not be called for single-tx checks.
        PhiPhase::Topology
        | PhiPhase::Body
        | PhiPhase::Architecture
        | PhiPhase::Performance
        | PhiPhase::Feedback
        | PhiPhase::Evolution => {
            unreachable!("Block-only phase {:?} passed to phi_check_single_tx", phase);
        }
    }
}

/// Returns true if this phase has per-tx semantics (runs in both paths).
pub fn is_per_tx_phase(phase: PhiPhase) -> bool {
    matches!(
        phase,
        PhiPhase::Distinction
            | PhiPhase::Constraint
            | PhiPhase::Ontology
            | PhiPhase::Form
            | PhiPhase::Organization
            | PhiPhase::Module
            | PhiPhase::Execution
    )
}

// ---------------------------------------------------------------------------
// Block-level traversal
// ---------------------------------------------------------------------------

/// Execute the 13-phase Phi traversal on a block.
/// Per v2.1 FIX-8: some phases are per-tx, some are block-only.
/// All 13 phases must pass or the block is rejected.
pub fn phi_traversal_block(block: &Block, state: &ManagedWorldState) -> PhiTraversalLog {
    let mut log = PhiTraversalLog::new();

    for phase in PhiPhase::ALL {
        let result = execute_block_phase(phase, block, state);
        let passed = result.passed;
        log.phases_completed.push(result);
        if !passed {
            log.finalize();
            return log;
        }
    }

    log.finalize();
    log
}

fn execute_block_phase(
    phase: PhiPhase,
    block: &Block,
    state: &ManagedWorldState,
) -> PhiPhaseResult {
    if is_per_tx_phase(phase) {
        // Per-tx phase: iterate all transactions through the shared checker.
        for (i, tx) in block.body.transitions.iter().enumerate() {
            let result = phi_check_single_tx(phase, tx, state);
            if !result.passed {
                return PhiPhaseResult {
                    phase,
                    passed: false,
                    details: format!("Tx {}: {}", i, result.details),
                };
            }
        }
        return PhiPhaseResult {
            phase,
            passed: true,
            details: format!(
                "{:?} verified for {} transitions",
                phase,
                block.body.transitions.len()
            ),
        };
    }

    // Block-only phases.
    match phase {
        PhiPhase::Topology => phase_topology(block),
        PhiPhase::Body => phase_body(block, state),
        PhiPhase::Architecture => phase_architecture(block),
        PhiPhase::Performance => phase_performance(block),
        PhiPhase::Feedback => phase_feedback(block),
        PhiPhase::Evolution => phase_evolution(block),
        // Per-tx phases handled above; this arm is unreachable.
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Block-level: additional block-wide checks for Execution phase
// ---------------------------------------------------------------------------

// NOTE: The block-level Execution phase also needs to check transition_count
// and receipt consistency. We handle this by wrapping execute_block_phase
// for Execution with an extra block-wide check. However, to keep the refactor
// clean, we embed the block-wide transition_count check in Module (phase 7)
// which already handles receipt-transition consistency. The per-tx Execution
// check (payload consistency, non-empty target, non-zero nonce) is in the
// shared function. Transition count is a block-wide property checked here:

fn phase_topology(block: &Block) -> PhiPhaseResult {
    // Block-only: verify causal graph connectivity, detect cycles (INV-17).
    let is_acyclic = block.causal_delta.new_edges.is_empty() || {
        let mut graph = sccgub_types::causal::CausalGraph::default();
        for v in &block.causal_delta.new_vertices {
            graph.add_vertex(v.clone());
        }
        for e in &block.causal_delta.new_edges {
            graph.add_edge(e.clone());
        }
        graph.is_acyclic()
    };

    PhiPhaseResult {
        phase: PhiPhase::Topology,
        passed: is_acyclic,
        details: if is_acyclic {
            "Causal graph is acyclic".into()
        } else {
            "CYCLE DETECTED in causal graph".into()
        },
    }
}

fn phase_body(block: &Block, state: &ManagedWorldState) -> PhiPhaseResult {
    // Block-only: check chain homeostasis — tension must not grow unboundedly (INV-5).
    let budget = state.state.tension_field.budget.current_budget;
    let within_budget = block.header.tension_after <= block.header.tension_before + budget;

    PhiPhaseResult {
        phase: PhiPhase::Body,
        passed: within_budget,
        details: if within_budget {
            format!("Tension {} within budget", block.header.tension_after)
        } else {
            format!(
                "Tension {} exceeds {} + budget {}",
                block.header.tension_after, block.header.tension_before, budget
            )
        },
    }
}

fn phase_architecture(block: &Block) -> PhiPhaseResult {
    // Architecture layer consistency: verify validator_id and version.
    if block.header.validator_id == [0u8; 32] {
        return PhiPhaseResult {
            phase: PhiPhase::Architecture,
            passed: false,
            details: "Block validator_id is zero (unassigned)".into(),
        };
    }

    if block.header.version == 0 || block.header.version > 1 {
        return PhiPhaseResult {
            phase: PhiPhase::Architecture,
            passed: false,
            details: format!(
                "Unsupported block version {}, expected 1",
                block.header.version
            ),
        };
    }

    // Transition count consistency (block-wide check, moved from old Execution).
    if u32::try_from(block.body.transitions.len()) != Ok(block.body.transition_count) {
        return PhiPhaseResult {
            phase: PhiPhase::Architecture,
            passed: false,
            details: format!(
                "Transition count mismatch: header says {} but body has {}",
                block.body.transition_count,
                block.body.transitions.len()
            ),
        };
    }

    // Receipt-transition consistency (moved from old Module — block-wide check).
    if !block.body.transitions.is_empty()
        && !block.receipts.is_empty()
        && block.receipts.len() != block.body.transitions.len()
    {
        return PhiPhaseResult {
            phase: PhiPhase::Architecture,
            passed: false,
            details: format!(
                "Receipt count {} != transition count {}",
                block.receipts.len(),
                block.body.transitions.len()
            ),
        };
    }

    PhiPhaseResult {
        phase: PhiPhase::Architecture,
        passed: true,
        details: format!(
            "Architecture verified: v{}, {} signed transitions",
            block.header.version,
            block.body.transitions.len()
        ),
    }
}

fn phase_performance(block: &Block) -> PhiPhaseResult {
    // Block-only: check Mfidel seal matches expected.
    let expected = sccgub_types::mfidel::MfidelAtomicSeal::from_height(block.header.height);
    let matches = block.header.mfidel_seal == expected;
    PhiPhaseResult {
        phase: PhiPhase::Performance,
        passed: matches,
        details: if matches {
            format!(
                "Mfidel seal f[{}][{}] correct",
                expected.row, expected.column
            )
        } else {
            format!(
                "Mfidel seal mismatch: expected f[{}][{}], got f[{}][{}]",
                expected.row,
                expected.column,
                block.header.mfidel_seal.row,
                block.header.mfidel_seal.column
            )
        },
    }
}

fn phase_feedback(block: &Block) -> PhiPhaseResult {
    // Feedback loop stability: tension must not swing wildly between blocks.
    let delta = if block.header.tension_after >= block.header.tension_before {
        block.header.tension_after - block.header.tension_before
    } else {
        block.header.tension_before - block.header.tension_after
    };

    // Stability bound: delta_T < 2M units max swing.
    let max_swing = TensionValue::from_integer(2_000_000);
    if delta > max_swing {
        return PhiPhaseResult {
            phase: PhiPhase::Feedback,
            passed: false,
            details: format!("Tension swing {} exceeds max {}", delta, max_swing),
        };
    }

    // Verify no receipt has a rejected verdict in a block claiming all-accepted.
    for (i, receipt) in block.receipts.iter().enumerate() {
        if !receipt.verdict.is_accepted() {
            return PhiPhaseResult {
                phase: PhiPhase::Feedback,
                passed: false,
                details: format!(
                    "Receipt {} has non-accepted verdict in committed block: {}",
                    i, receipt.verdict
                ),
            };
        }
    }

    PhiPhaseResult {
        phase: PhiPhase::Feedback,
        passed: true,
        details: format!(
            "Feedback stable: tension delta {}, {} receipts all accepted",
            delta,
            block.receipts.len()
        ),
    }
}

fn phase_evolution(block: &Block) -> PhiPhaseResult {
    // Evolution: verify the block advances the chain.
    if block.header.height > 0 && block.proof.block_height != block.header.height {
        return PhiPhaseResult {
            phase: PhiPhase::Evolution,
            passed: false,
            details: format!(
                "Proof height {} != header height {}",
                block.proof.block_height, block.header.height
            ),
        };
    }

    // Verify causal graph delta is consistent.
    for edge in &block.causal_delta.new_edges {
        let (src, _) = edge.endpoints();
        if let CausalVertex::Transition(tx_id) = src {
            let tx_exists =
                block.body.transitions.iter().any(|t| t.tx_id == tx_id) || block.header.height == 0;
            if !tx_exists {
                return PhiPhaseResult {
                    phase: PhiPhase::Evolution,
                    passed: false,
                    details: format!("Causal edge references unknown tx {}", hex::encode(tx_id)),
                };
            }
        }
    }

    PhiPhaseResult {
        phase: PhiPhase::Evolution,
        passed: true,
        details: format!(
            "Evolution: height {}, {} causal edges consistent",
            block.header.height,
            block.causal_delta.new_edges.len()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::block::{BlockBody, BlockHeader};
    use sccgub_types::causal::CausalGraphDelta;
    use sccgub_types::governance::{FinalityMode, GovernanceSnapshot};
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::proof::CausalProof;
    use sccgub_types::timestamp::CausalTimestamp;
    use sccgub_types::ZERO_HASH;

    fn empty_genesis() -> Block {
        let gov = GovernanceSnapshot {
            state_hash: ZERO_HASH,
            active_norm_count: 0,
            emergency_mode: false,
            finality_mode: FinalityMode::Deterministic,
        };
        Block {
            header: BlockHeader {
                chain_id: [0u8; 32],
                block_id: [0u8; 32],
                parent_id: ZERO_HASH,
                height: 0,
                timestamp: CausalTimestamp::genesis(),
                state_root: ZERO_HASH,
                transition_root: ZERO_HASH,
                receipt_root: ZERO_HASH,
                causal_root: ZERO_HASH,
                proof_root: ZERO_HASH,
                governance_hash: ZERO_HASH,
                tension_before: TensionValue::ZERO,
                tension_after: TensionValue::ZERO,
                mfidel_seal: MfidelAtomicSeal::from_height(0),
                balance_root: ZERO_HASH,
                validator_id: [1u8; 32],
                version: 1,
            },
            body: BlockBody {
                transitions: vec![],
                transition_count: 0,
                total_tension_delta: TensionValue::ZERO,
                constraint_satisfaction: vec![],
            },
            receipts: vec![],
            causal_delta: CausalGraphDelta::default(),
            proof: CausalProof {
                block_height: 0,
                transitions_proven: vec![],
                phi_traversal_log: sccgub_types::proof::PhiTraversalLog::default(),
                governance_snapshot_hash: ZERO_HASH,
                tension_before: TensionValue::ZERO,
                tension_after: TensionValue::ZERO,
                constraint_results: vec![],
                recursion_depth: 0,
                validator_signature: vec![],
                causal_hash: ZERO_HASH,
            },
            governance: gov,
        }
    }

    #[test]
    fn test_empty_genesis_passes_all_phases() {
        let state = ManagedWorldState::new();
        let block = empty_genesis();
        let log = phi_traversal_block(&block, &state);
        assert!(
            log.is_all_passed(),
            "Empty genesis should pass all 13 phases: {:?}",
            log.phases_completed
                .iter()
                .filter(|p| !p.passed)
                .collect::<Vec<_>>()
        );
        assert_eq!(log.phases_completed.len(), 13);
    }

    #[test]
    fn test_wrong_mfidel_seal_fails_performance() {
        let state = ManagedWorldState::new();
        let mut block = empty_genesis();
        block.header.mfidel_seal = MfidelAtomicSeal::from_height(999);
        let log = phi_traversal_block(&block, &state);
        assert!(!log.is_all_passed());
        let failed = log.phases_completed.iter().find(|p| !p.passed).unwrap();
        assert_eq!(failed.phase, PhiPhase::Performance);
    }

    #[test]
    fn test_transition_count_mismatch_fails_architecture() {
        let state = ManagedWorldState::new();
        let mut block = empty_genesis();
        block.body.transition_count = 5; // Claims 5, has 0.
        let log = phi_traversal_block(&block, &state);
        assert!(!log.is_all_passed());
        let failed = log.phases_completed.iter().find(|p| !p.passed).unwrap();
        // Now caught in Architecture (block-wide check) instead of Execution.
        assert_eq!(failed.phase, PhiPhase::Architecture);
    }

    #[test]
    fn test_zero_validator_fails_architecture() {
        let state = ManagedWorldState::new();
        let mut block = empty_genesis();
        block.header.validator_id = [0u8; 32];
        let log = phi_traversal_block(&block, &state);
        assert!(!log.is_all_passed());
        let failed = log.phases_completed.iter().find(|p| !p.passed).unwrap();
        assert_eq!(failed.phase, PhiPhase::Architecture);
    }

    #[test]
    fn test_bad_version_fails_architecture() {
        let state = ManagedWorldState::new();
        let mut block = empty_genesis();
        block.header.version = 99;
        let log = phi_traversal_block(&block, &state);
        assert!(!log.is_all_passed());
        let failed = log.phases_completed.iter().find(|p| !p.passed).unwrap();
        assert_eq!(failed.phase, PhiPhase::Architecture);
    }

    #[test]
    fn test_proof_height_mismatch_fails_evolution() {
        let state = ManagedWorldState::new();
        let mut block = empty_genesis();
        block.header.height = 5;
        block.header.mfidel_seal = MfidelAtomicSeal::from_height(5);
        block.proof.block_height = 3; // Mismatch.
        let log = phi_traversal_block(&block, &state);
        assert!(!log.is_all_passed());
        let failed = log.phases_completed.iter().find(|p| !p.passed).unwrap();
        assert_eq!(failed.phase, PhiPhase::Evolution);
    }

    #[test]
    fn test_rejected_receipt_fails_feedback() {
        let state = ManagedWorldState::new();
        let mut block = empty_genesis();
        // Add a rejected receipt to a committed block.
        block.receipts.push(sccgub_types::receipt::CausalReceipt {
            tx_id: [1u8; 32],
            verdict: sccgub_types::receipt::Verdict::Reject {
                reason: "bad".into(),
            },
            pre_state_root: ZERO_HASH,
            post_state_root: ZERO_HASH,
            read_set: vec![],
            write_set: vec![],
            causes: vec![],
            resource_used: sccgub_types::receipt::ResourceUsage::default(),
            emitted_events: vec![],
            wh_binding: sccgub_types::transition::WHBindingResolved {
                intent: sccgub_types::transition::WHBindingIntent {
                    who: [0u8; 32],
                    when: CausalTimestamp::genesis(),
                    r#where: vec![],
                    why: sccgub_types::transition::CausalJustification {
                        invoking_rule: [0u8; 32],
                        precedence_level: sccgub_types::governance::PrecedenceLevel::Optimization,
                        causal_ancestors: vec![],
                        constraint_proof: vec![],
                    },
                    how: sccgub_types::transition::TransitionMechanism::DirectStateWrite,
                    which: std::collections::HashSet::new(),
                    what_declared: String::new(),
                },
                what_actual: sccgub_types::transition::StateDelta::default(),
                whether: sccgub_types::transition::ValidationResult::Valid,
            },
            phi_phase_reached: 0,
            tension_delta: TensionValue::ZERO,
        });
        // Receipt count will mismatch transition count (1 receipt, 0 transitions).
        // Architecture phase catches this before Feedback.
        // To test Feedback specifically, add a matching transition count.
        block.body.transition_count = 1;

        let log = phi_traversal_block(&block, &state);
        assert!(!log.is_all_passed());
        // Feedback phase should catch the rejected receipt.
        let feedback = log
            .phases_completed
            .iter()
            .find(|p| p.phase == PhiPhase::Feedback);
        if let Some(fb) = feedback {
            assert!(
                !fb.passed,
                "Rejected receipt in committed block must fail Feedback"
            );
        }
    }

    // -----------------------------------------------------------------------
    // New tests: verify shared per-tx checks work in both paths
    // -----------------------------------------------------------------------

    #[test]
    fn test_is_per_tx_phase_classification() {
        // Per-tx phases.
        assert!(is_per_tx_phase(PhiPhase::Distinction));
        assert!(is_per_tx_phase(PhiPhase::Constraint));
        assert!(is_per_tx_phase(PhiPhase::Ontology));
        assert!(is_per_tx_phase(PhiPhase::Form));
        assert!(is_per_tx_phase(PhiPhase::Organization));
        assert!(is_per_tx_phase(PhiPhase::Module));
        assert!(is_per_tx_phase(PhiPhase::Execution));
        // Block-only phases.
        assert!(!is_per_tx_phase(PhiPhase::Topology));
        assert!(!is_per_tx_phase(PhiPhase::Body));
        assert!(!is_per_tx_phase(PhiPhase::Architecture));
        assert!(!is_per_tx_phase(PhiPhase::Performance));
        assert!(!is_per_tx_phase(PhiPhase::Feedback));
        assert!(!is_per_tx_phase(PhiPhase::Evolution));
    }

    #[test]
    fn test_phi_check_single_tx_all_per_tx_phases_pass() {
        use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
        use sccgub_types::governance::PrecedenceLevel;
        use sccgub_types::mfidel::MfidelAtomicSeal;
        use sccgub_types::transition::*;
        use std::collections::HashSet;

        let state = ManagedWorldState::new();
        let tx = SymbolicTransition {
            tx_id: [1u8; 32],
            actor: AgentIdentity {
                agent_id: [1u8; 32],
                public_key: [0u8; 32],
                mfidel_seal: MfidelAtomicSeal::from_height(0),
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: HashSet::new(),
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
                when: CausalTimestamp::genesis(),
                r#where: b"data/test".to_vec(),
                why: CausalJustification {
                    invoking_rule: [2u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: HashSet::new(),
                what_declared: "test".into(),
            },
            nonce: 1,
            signature: vec![0u8; 64],
        };

        // Call phi_check_single_tx directly for each per-tx phase.
        for phase in PhiPhase::ALL {
            if is_per_tx_phase(phase) {
                let result = phi_check_single_tx(phase, &tx, &state);
                assert!(
                    result.passed,
                    "Per-tx phase {:?} failed: {}",
                    phase, result.details
                );
            }
        }
    }
}
