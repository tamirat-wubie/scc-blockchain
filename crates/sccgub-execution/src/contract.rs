use sccgub_state::world::ManagedWorldState;
use sccgub_types::contract::SymbolicCausalContract;
use sccgub_types::receipt::Verdict;
use sccgub_types::tension::TensionValue;
use sccgub_types::transition::{StateDelta, StateWrite, SymbolicTransition};

/// Maximum computation steps for contract execution (decidability bound).
pub const DEFAULT_MAX_STEPS: u64 = 10_000;

/// Execute a Symbolic Causal Contract.
/// Contracts are decidable — they terminate within bounded steps by construction.
pub fn execute_contract(
    contract: &SymbolicCausalContract,
    transition: &SymbolicTransition,
    _state: &ManagedWorldState,
    max_steps: u64,
) -> ContractExecutionResult {
    let mut steps = 0u64;

    // Authorization: actor must have sufficient governance level.
    let actor_level = transition.actor.governance_level as u8;
    let required_level = contract.governance_level as u8;
    if actor_level > required_level {
        return ContractExecutionResult {
            verdict: Verdict::Reject {
                reason: format!(
                    "Insufficient authority: actor has {:?}, contract requires {:?}",
                    transition.actor.governance_level, contract.governance_level
                ),
            },
            state_delta: StateDelta::default(),
            steps_used: 0,
            tension_delta: TensionValue::ZERO,
        };
    }

    // Phase 1: Check preconditions against contract laws.
    for law in &contract.laws {
        steps = steps.saturating_add(1);
        if steps > max_steps {
            return reject_step_limit(steps, max_steps, "precondition check");
        }
        // A precondition is satisfied if the transition declares it in its preconditions.
        let satisfied = transition.preconditions.iter().any(|pc| pc.id == law.id);
        if !satisfied {
            return ContractExecutionResult {
                verdict: Verdict::Reject {
                    reason: format!(
                        "Precondition not satisfied: constraint {}",
                        hex::encode(law.id)
                    ),
                },
                state_delta: StateDelta::default(),
                steps_used: steps,
                tension_delta: TensionValue::ZERO,
            };
        }
    }

    // Phase 2: Execute based on payload.
    let state_delta = match &transition.payload {
        sccgub_types::transition::OperationPayload::InvokeContract {
            contract_id: _,
            method,
            args,
        } => {
            steps = steps.saturating_add(1);
            if steps > max_steps {
                return reject_step_limit(steps, max_steps, "method execution");
            }
            // Validate method name is non-empty and args are bounded.
            if method.is_empty() {
                return ContractExecutionResult {
                    verdict: Verdict::Reject {
                        reason: "Empty method name".into(),
                    },
                    state_delta: StateDelta::default(),
                    steps_used: steps,
                    tension_delta: TensionValue::ZERO,
                };
            }
            if args.len() > 1_048_576 {
                return ContractExecutionResult {
                    verdict: Verdict::Reject {
                        reason: "Method args exceed 1MB limit".into(),
                    },
                    state_delta: StateDelta::default(),
                    steps_used: steps,
                    tension_delta: TensionValue::ZERO,
                };
            }
            let result_key = format!(
                "contract/{}/result/{}",
                hex::encode(contract.contract_id),
                method
            );
            StateDelta {
                writes: vec![StateWrite {
                    address: result_key.into_bytes(),
                    value: args.to_vec(),
                }],
                deletes: vec![],
            }
        }
        sccgub_types::transition::OperationPayload::Write { key, value } => {
            steps = steps.saturating_add(1);
            StateDelta {
                writes: vec![StateWrite {
                    address: key.clone(),
                    value: value.clone(),
                }],
                deletes: vec![],
            }
        }
        _ => StateDelta::default(),
    };

    // Phase 3: Check postconditions.
    for law in &contract.laws {
        steps = steps.saturating_add(1);
        if steps > max_steps {
            return reject_step_limit(steps, max_steps, "postcondition check");
        }
        let satisfied = transition.postconditions.iter().any(|pc| pc.id == law.id);
        if !satisfied {
            return ContractExecutionResult {
                verdict: Verdict::Reject {
                    reason: format!(
                        "Postcondition not satisfied: constraint {}",
                        hex::encode(law.id)
                    ),
                },
                state_delta: StateDelta::default(),
                steps_used: steps,
                tension_delta: TensionValue::ZERO,
            };
        }
    }

    ContractExecutionResult {
        verdict: Verdict::Accept,
        state_delta,
        steps_used: steps,
        tension_delta: TensionValue::ZERO,
    }
}

fn reject_step_limit(steps: u64, max: u64, phase: &str) -> ContractExecutionResult {
    ContractExecutionResult {
        verdict: Verdict::Reject {
            reason: format!("Exceeded max steps ({}) during {}", max, phase),
        },
        state_delta: StateDelta::default(),
        steps_used: steps,
        tension_delta: TensionValue::ZERO,
    }
}

/// Verify that a contract's ID matches the hash of its content.
pub fn verify_contract_id(contract: &SymbolicCausalContract) -> bool {
    let content = serde_json::to_vec(&(&contract.name, &contract.laws, &contract.deployer))
        .unwrap_or_default();
    let expected = sccgub_crypto::hash::blake3_hash(&content);
    contract.contract_id == expected
}

#[derive(Debug, Clone)]
pub struct ContractExecutionResult {
    pub verdict: Verdict,
    pub state_delta: StateDelta,
    pub steps_used: u64,
    pub tension_delta: TensionValue,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::contract::SymbolicCausalContract;
    use sccgub_types::governance::PrecedenceLevel;
    use sccgub_types::transition::Constraint;

    fn test_contract() -> SymbolicCausalContract {
        SymbolicCausalContract {
            contract_id: [42u8; 32],
            name: "TestContract".into(),
            laws: vec![Constraint {
                id: [1u8; 32],
                expression: "balance >= 0".into(),
            }],
            state: std::collections::HashMap::new(),
            history: vec![],
            deployer: [0u8; 32],
            governance_level: PrecedenceLevel::Meaning,
            deployed_at: 0,
        }
    }

    fn test_agent(level: PrecedenceLevel) -> sccgub_types::agent::AgentIdentity {
        let key = sccgub_crypto::keys::generate_keypair();
        let pk = *key.verifying_key().as_bytes();
        sccgub_types::agent::AgentIdentity {
            agent_id: sccgub_crypto::hash::blake3_hash(&pk),
            public_key: pk,
            mfidel_seal: sccgub_types::mfidel::MfidelAtomicSeal::from_height(1),
            registration_block: 0,
            governance_level: level,
            norm_set: std::collections::HashSet::new(),
            responsibility: sccgub_types::agent::ResponsibilityState::default(),
        }
    }

    fn test_tx(agent: sccgub_types::agent::AgentIdentity, contract: &SymbolicCausalContract) -> SymbolicTransition {
        SymbolicTransition {
            tx_id: [0u8; 32],
            actor: agent,
            intent: sccgub_types::transition::TransitionIntent {
                kind: sccgub_types::transition::TransitionKind::ContractInvoke,
                target: b"contract".to_vec(),
                declared_purpose: "test".into(),
            },
            // Include contract's laws as preconditions and postconditions.
            preconditions: contract.laws.clone(),
            postconditions: contract.laws.clone(),
            payload: sccgub_types::transition::OperationPayload::Write {
                key: b"k".to_vec(),
                value: b"v".to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: sccgub_types::transition::WHBindingIntent {
                who: [1u8; 32],
                when: sccgub_types::timestamp::CausalTimestamp::genesis(),
                r#where: b"contract".to_vec(),
                why: sccgub_types::transition::CausalJustification {
                    invoking_rule: [2u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: sccgub_types::transition::TransitionMechanism::DirectStateWrite,
                which: std::collections::HashSet::new(),
                what_declared: "test".into(),
            },
            nonce: 0,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn test_authorized_execution() {
        let contract = test_contract();
        let agent = test_agent(PrecedenceLevel::Meaning);
        let tx = test_tx(agent, &contract);
        let state = ManagedWorldState::new();
        let result = execute_contract(&contract, &tx, &state, 1000);
        assert!(result.verdict.is_accepted());
    }

    #[test]
    fn test_unauthorized_rejected() {
        let contract = test_contract(); // Requires Meaning.
        let agent = test_agent(PrecedenceLevel::Optimization); // Only Optimization.
        let tx = test_tx(agent, &contract);
        let state = ManagedWorldState::new();
        let result = execute_contract(&contract, &tx, &state, 1000);
        assert!(!result.verdict.is_accepted(), "Should reject unauthorized actor");
    }

    #[test]
    fn test_missing_precondition_rejected() {
        let contract = test_contract();
        let agent = test_agent(PrecedenceLevel::Meaning);
        let mut tx = test_tx(agent, &contract);
        tx.preconditions = vec![]; // Remove preconditions.
        let state = ManagedWorldState::new();
        let result = execute_contract(&contract, &tx, &state, 1000);
        assert!(!result.verdict.is_accepted(), "Should reject missing precondition");
    }

    #[test]
    fn test_step_limit() {
        let contract = test_contract();
        let agent = test_agent(PrecedenceLevel::Meaning);
        let tx = test_tx(agent, &contract);
        let state = ManagedWorldState::new();
        let result = execute_contract(&contract, &tx, &state, 0);
        assert!(!result.verdict.is_accepted());
    }
}
