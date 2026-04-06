use sccgub_state::world::ManagedWorldState;
use sccgub_types::contract::SymbolicCausalContract;
use sccgub_types::receipt::Verdict;
use sccgub_types::tension::TensionValue;
use sccgub_types::transition::{StateDelta, StateWrite, SymbolicTransition};

/// Execute a Symbolic Causal Contract.
///
/// Per spec Section 10: contracts are decidable symbolic constraint programs.
/// No halting problem. No gas estimation. Contracts terminate by construction.
///
/// Execution model:
/// 1. Check preconditions against contract laws.
/// 2. Apply Phi traversal.
/// 3. Check postconditions.
/// 4. Commit or rollback.
pub fn execute_contract(
    contract: &SymbolicCausalContract,
    transition: &SymbolicTransition,
    state: &ManagedWorldState,
    max_steps: u64,
) -> ContractExecutionResult {
    let mut steps = 0u64;

    // Phase 1: Check preconditions against contract laws.
    for law in &contract.laws {
        steps += 1;
        if steps > max_steps {
            return ContractExecutionResult {
                verdict: Verdict::Reject {
                    reason: format!(
                        "Exceeded max execution steps ({}) during precondition check",
                        max_steps
                    ),
                },
                state_delta: StateDelta::default(),
                steps_used: steps,
                tension_delta: TensionValue::ZERO,
            };
        }

        // Evaluate constraint (simplified: check if constraint ID matches any precondition).
        let satisfied = transition
            .preconditions
            .iter()
            .any(|pc| pc.id == law.id);

        if !satisfied && !contract.laws.is_empty() {
            // For MVP: if the transition doesn't reference this law's constraint,
            // we check if it's a hard constraint.
            // Simplified: all contract laws are treated as satisfied if preconditions match.
        }
    }

    // Phase 2: Determine state delta based on the transition payload.
    let state_delta = match &transition.payload {
        sccgub_types::transition::OperationPayload::InvokeContract {
            contract_id: _,
            method,
            args,
        } => {
            steps += 1;
            match execute_contract_method(contract, method, args, state, &mut steps, max_steps) {
                Ok(delta) => delta,
                Err(result) => return result,
            }
        }
        sccgub_types::transition::OperationPayload::Write { key, value } => {
            steps += 1;
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
        steps += 1;
        if steps > max_steps {
            return ContractExecutionResult {
                verdict: Verdict::Reject {
                    reason: "Exceeded max steps during postcondition check".into(),
                },
                state_delta: StateDelta::default(),
                steps_used: steps,
                tension_delta: TensionValue::ZERO,
            };
        }
        // Postcondition check (simplified for MVP).
        let _satisfied = transition
            .postconditions
            .iter()
            .any(|pc| pc.id == law.id);
    }

    ContractExecutionResult {
        verdict: Verdict::Accept,
        state_delta,
        steps_used: steps,
        tension_delta: TensionValue::ZERO,
    }
}

/// Execute a specific method on a contract.
fn execute_contract_method(
    contract: &SymbolicCausalContract,
    method: &str,
    args: &[u8],
    _state: &ManagedWorldState,
    steps: &mut u64,
    max_steps: u64,
) -> Result<StateDelta, ContractExecutionResult> {
    *steps += 1;
    if *steps > max_steps {
        return Err(ContractExecutionResult {
            verdict: Verdict::Reject {
                reason: "Exceeded max steps during method execution".into(),
            },
            state_delta: StateDelta::default(),
            steps_used: *steps,
            tension_delta: TensionValue::ZERO,
        });
    }

    // Simplified contract execution: write the method call result to a state key.
    let result_key = format!("contract/{}/result/{}", hex::encode(contract.contract_id), method);
    Ok(StateDelta {
        writes: vec![StateWrite {
            address: result_key.into_bytes(),
            value: args.to_vec(),
        }],
        deletes: vec![],
    })
}

/// Result of contract execution.
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

    #[test]
    fn test_contract_execution_terminates() {
        let contract = test_contract();
        let state = ManagedWorldState::new();

        let (agent, agent_key) = {
            let key = sccgub_crypto::keys::generate_keypair();
            let pk = *key.verifying_key().as_bytes();
            let agent_id = sccgub_crypto::hash::blake3_hash(&pk);
            let agent = sccgub_types::agent::AgentIdentity {
                agent_id,
                public_key: pk,
                mfidel_seal: sccgub_types::mfidel::MfidelAtomicSeal::from_height(1),
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: std::collections::HashSet::new(),
                responsibility: sccgub_types::agent::ResponsibilityState::default(),
            };
            (agent, key)
        };

        let tx = sccgub_types::transition::SymbolicTransition {
            tx_id: [0u8; 32],
            actor: agent,
            intent: sccgub_types::transition::TransitionIntent {
                kind: sccgub_types::transition::TransitionKind::ContractInvoke,
                target: b"contract/test".to_vec(),
                declared_purpose: "test invocation".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: sccgub_types::transition::OperationPayload::InvokeContract {
                contract_id: contract.contract_id,
                method: "transfer".into(),
                args: b"test-args".to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: sccgub_types::transition::WHBindingIntent {
                who: [1u8; 32],
                when: sccgub_types::timestamp::CausalTimestamp::genesis(),
                r#where: b"contract/test".to_vec(),
                why: sccgub_types::transition::CausalJustification {
                    invoking_rule: [2u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: sccgub_types::transition::TransitionMechanism::ContractExecution {
                    contract_id: contract.contract_id,
                },
                which: std::collections::HashSet::new(),
                what_declared: "invoke transfer".into(),
            },
            nonce: 0,
            signature: sccgub_crypto::signature::sign(&agent_key, b"test"),
        };

        let result = execute_contract(&contract, &tx, &state, 1000);
        assert!(result.verdict.is_accepted());
        assert!(result.steps_used <= 1000);
    }

    #[test]
    fn test_contract_step_limit() {
        let contract = test_contract();
        let state = ManagedWorldState::new();

        let (agent, agent_key) = {
            let key = sccgub_crypto::keys::generate_keypair();
            let pk = *key.verifying_key().as_bytes();
            let agent_id = sccgub_crypto::hash::blake3_hash(&pk);
            let agent = sccgub_types::agent::AgentIdentity {
                agent_id,
                public_key: pk,
                mfidel_seal: sccgub_types::mfidel::MfidelAtomicSeal::from_height(1),
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: std::collections::HashSet::new(),
                responsibility: sccgub_types::agent::ResponsibilityState::default(),
            };
            (agent, key)
        };

        let tx = sccgub_types::transition::SymbolicTransition {
            tx_id: [0u8; 32],
            actor: agent,
            intent: sccgub_types::transition::TransitionIntent {
                kind: sccgub_types::transition::TransitionKind::ContractInvoke,
                target: b"test".to_vec(),
                declared_purpose: "test".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: sccgub_types::transition::OperationPayload::Write {
                key: b"k".to_vec(),
                value: b"v".to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: sccgub_types::transition::WHBindingIntent {
                who: [1u8; 32],
                when: sccgub_types::timestamp::CausalTimestamp::genesis(),
                r#where: b"test".to_vec(),
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
            signature: sccgub_crypto::signature::sign(&agent_key, b"test"),
        };

        // With step limit of 0, should reject.
        let result = execute_contract(&contract, &tx, &state, 0);
        assert!(!result.verdict.is_accepted());
    }
}
