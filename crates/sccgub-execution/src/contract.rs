use sccgub_state::world::ManagedWorldState;
use sccgub_types::contract::SymbolicCausalContract;
use sccgub_types::receipt::Verdict;
use sccgub_types::tension::TensionValue;
use sccgub_types::transition::{StateDelta, StateWrite, SymbolicTransition};
use std::collections::BTreeSet;

pub fn default_max_steps_for_state(state: &ManagedWorldState) -> u64 {
    state.consensus_params.default_max_steps
}

pub fn execute_contract_with_state_params(
    contract: &SymbolicCausalContract,
    transition: &SymbolicTransition,
    state: &ManagedWorldState,
) -> ContractExecutionResult {
    execute_contract(
        contract,
        transition,
        state,
        default_max_steps_for_state(state),
    )
}

/// Execute a Symbolic Causal Contract.
/// Contracts are decidable — they terminate within bounded steps by construction.
pub fn execute_contract(
    contract: &SymbolicCausalContract,
    transition: &SymbolicTransition,
    state: &ManagedWorldState,
    max_steps: u64,
) -> ContractExecutionResult {
    let mut steps = 0u64;
    let actor_level = transition.actor.governance_level as u8;

    // Authorization: actor must have sufficient governance level.
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

    // Phase 1: Evaluate preconditions using the formal predicate engine.
    // Each contract law is parsed as a predicate and evaluated against state.
    for law in &contract.laws {
        steps = steps.saturating_add(1);
        if steps > max_steps {
            return reject_step_limit(steps, max_steps, "precondition check");
        }
        let predicate = parse_constraint_expression(&law.expression);
        let result = crate::constraints::evaluate(&predicate, state, actor_level);
        if !result.satisfied {
            return ContractExecutionResult {
                verdict: Verdict::Reject {
                    reason: format!(
                        "Precondition failed for constraint {}: {}",
                        hex::encode(law.id),
                        result.details
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
            let max_arg_size = state.consensus_params.max_state_entry_size as usize;
            if args.len() > max_arg_size {
                return ContractExecutionResult {
                    verdict: Verdict::Reject {
                        reason: format!("Method args exceed {} byte limit", max_arg_size),
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

    // Phase 3: Evaluate postconditions using the formal predicate engine.
    for law in &contract.laws {
        steps = steps.saturating_add(1);
        if steps > max_steps {
            return reject_step_limit(steps, max_steps, "postcondition check");
        }
        let predicate = parse_constraint_expression(&law.expression);
        let result = crate::constraints::evaluate(&predicate, state, actor_level);
        if !result.satisfied {
            return ContractExecutionResult {
                verdict: Verdict::Reject {
                    reason: format!(
                        "Postcondition failed for constraint {}: {}",
                        hex::encode(law.id),
                        result.details
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

/// Public re-export for SCCE constraint walker.
pub fn parse_constraint_expression_pub(expr: &str) -> crate::constraints::Predicate {
    parse_constraint_expression(expr)
}

/// Parse a constraint expression string into a Predicate.
/// Supports simple forms: "exists:<key>", "equals:<key>=<value>",
/// "governance:<level>", or "true" / "false".
fn parse_constraint_expression(expr: &str) -> crate::constraints::Predicate {
    let expr = expr.trim();
    if expr == "true" || expr.is_empty() {
        return crate::constraints::Predicate::True;
    }
    if expr == "false" {
        return crate::constraints::Predicate::False;
    }
    if let Some(key) = expr.strip_prefix("exists:") {
        return crate::constraints::Predicate::Exists {
            key: key.as_bytes().to_vec(),
        };
    }
    if let Some(rest) = expr.strip_prefix("equals:") {
        if let Some((key, value)) = rest.split_once('=') {
            return crate::constraints::Predicate::Equals {
                key: key.as_bytes().to_vec(),
                value: value.as_bytes().to_vec(),
            };
        }
    }
    if let Some(level_str) = expr.strip_prefix("governance:") {
        if let Ok(level) = level_str.parse::<u8>() {
            return crate::constraints::Predicate::MinGovernanceLevel { level };
        }
    }
    // Surface the parse failure rather than masquerading as False.
    // The receipt will carry the reason, so a typo is observable.
    crate::constraints::Predicate::Invalid {
        reason: format!("unknown expression form: {}", expr),
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
    let content = sccgub_crypto::canonical::canonical_bytes(&(
        &contract.name,
        &contract.laws,
        &contract.deployer,
    ));
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
                expression: "governance:2".into(), // Requires Meaning level (2).
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
            norm_set: BTreeSet::new(),
            responsibility: sccgub_types::agent::ResponsibilityState::default(),
        }
    }

    fn test_tx(
        agent: sccgub_types::agent::AgentIdentity,
        _contract: &SymbolicCausalContract,
    ) -> SymbolicTransition {
        SymbolicTransition {
            tx_id: [0u8; 32],
            actor: agent,
            intent: sccgub_types::transition::TransitionIntent {
                kind: sccgub_types::transition::TransitionKind::ContractInvoke,
                target: b"contract".to_vec(),
                declared_purpose: "test".into(),
            },
            // Preconditions/postconditions are now evaluated by the predicate engine
            // against state, not matched by ID. These are kept for canonical bytes.
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
                r#where: b"contract".to_vec(),
                why: sccgub_types::transition::CausalJustification {
                    invoking_rule: [2u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: sccgub_types::transition::TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
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
        assert!(
            !result.verdict.is_accepted(),
            "Should reject unauthorized actor"
        );
    }

    #[test]
    fn test_failing_predicate_rejected() {
        // Contract with a law that requires a key to exist in state.
        let mut contract = test_contract();
        contract.laws = vec![Constraint {
            id: [2u8; 32],
            expression: "exists:required_key".into(), // Key doesn't exist in empty state.
        }];
        let agent = test_agent(PrecedenceLevel::Meaning);
        let tx = test_tx(agent, &contract);
        let state = ManagedWorldState::new(); // Empty state — key doesn't exist.
        let result = execute_contract(&contract, &tx, &state, 1000);
        assert!(
            !result.verdict.is_accepted(),
            "Should reject when predicate evaluates to false"
        );
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

    #[test]
    fn test_execute_contract_with_state_params_uses_consensus_default() {
        let contract = test_contract();
        let agent = test_agent(PrecedenceLevel::Meaning);
        let tx = test_tx(agent, &contract);
        let state = ManagedWorldState::with_consensus_params(
            sccgub_types::consensus_params::ConsensusParams {
                default_max_steps: 0,
                ..sccgub_types::consensus_params::ConsensusParams::default()
            },
        );
        let result = execute_contract_with_state_params(&contract, &tx, &state);

        assert!(!result.verdict.is_accepted());
        assert_eq!(default_max_steps_for_state(&state), 0);
        assert_eq!(result.steps_used, 1);
    }

    #[test]
    fn test_execute_contract_respects_consensus_arg_limit() {
        let contract = test_contract();
        let agent = test_agent(PrecedenceLevel::Meaning);
        let mut tx = test_tx(agent, &contract);
        tx.payload = sccgub_types::transition::OperationPayload::InvokeContract {
            contract_id: contract.contract_id,
            method: "run".into(),
            args: vec![1, 2, 3, 4, 5],
        };
        let state = ManagedWorldState::with_consensus_params(
            sccgub_types::consensus_params::ConsensusParams {
                max_state_entry_size: 4,
                ..sccgub_types::consensus_params::ConsensusParams::default()
            },
        );

        let result = execute_contract_with_state_params(&contract, &tx, &state);

        assert!(!result.verdict.is_accepted());
        assert!(matches!(
            &result.verdict,
            Verdict::Reject { reason } if reason.contains("4 byte limit")
        ));
        assert_eq!(result.steps_used, 2);
    }
}
