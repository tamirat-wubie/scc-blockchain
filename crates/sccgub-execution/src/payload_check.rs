// Phi Phase 8 (Execution) — payload consistency check.
//
// Verifies that a transition's payload is internally consistent with
// its declared intent.target and intent.kind. Catches the attack where
// an attacker constructs a transition whose intent declares one thing
// but whose payload does something different.
//
// Phase 3 (Ontology) enforces target ∈ allowed namespaces for kind.
// Phase 8 adds the dual: payload addresses must match intent.target.

use sccgub_types::transition::{OperationPayload, SymbolicTransition, TransitionKind};

#[derive(Debug, Clone)]
pub enum PayloadConsistency {
    Consistent,
    Inconsistent { reason: String },
}

impl PayloadConsistency {
    pub fn is_consistent(&self) -> bool {
        matches!(self, PayloadConsistency::Consistent)
    }
}

/// Human-readable name for a payload variant (for error messages).
fn payload_variant_name(payload: &OperationPayload) -> &'static str {
    match payload {
        OperationPayload::Write { .. } => "Write",
        OperationPayload::AssetTransfer { .. } => "AssetTransfer",
        OperationPayload::RegisterAgent { .. } => "RegisterAgent",
        OperationPayload::ProposeNorm { .. } => "ProposeNorm",
        OperationPayload::DeployContract { .. } => "DeployContract",
        OperationPayload::InvokeContract { .. } => "InvokeContract",
        OperationPayload::Noop => "Noop",
    }
}

/// Verify the transition's payload is consistent with its declared intent.
pub fn check_payload_consistency(tx: &SymbolicTransition) -> PayloadConsistency {
    let target = &tx.intent.target;
    let kind = tx.intent.kind;

    match (&tx.payload, kind) {
        // Write: key must equal declared target.
        (OperationPayload::Write { key, .. }, TransitionKind::StateWrite)
        | (OperationPayload::Write { key, .. }, TransitionKind::ContractInvoke)
        | (OperationPayload::Write { key, .. }, TransitionKind::GovernanceUpdate) => {
            if key != target {
                return PayloadConsistency::Inconsistent {
                    reason: format!(
                        "Write key {} != intent.target {}",
                        String::from_utf8_lossy(key),
                        String::from_utf8_lossy(target),
                    ),
                };
            }
            PayloadConsistency::Consistent
        }

        // AssetTransfer: target must be sender's balance key.
        (OperationPayload::AssetTransfer { from, .. }, TransitionKind::AssetTransfer) => {
            let expected = sccgub_types::namespace::balance_key(from);
            if *target != expected {
                return PayloadConsistency::Inconsistent {
                    reason: format!(
                        "AssetTransfer target {} != sender balance key {}",
                        String::from_utf8_lossy(target),
                        String::from_utf8_lossy(&expected),
                    ),
                };
            }
            PayloadConsistency::Consistent
        }

        // RegisterAgent: target must be agents/<pk>.
        (OperationPayload::RegisterAgent { public_key }, TransitionKind::AgentRegistration) => {
            let expected = sccgub_types::namespace::agent_key(public_key);
            if *target != expected {
                return PayloadConsistency::Inconsistent {
                    reason: format!(
                        "RegisterAgent target {} != agents/<pk> {}",
                        String::from_utf8_lossy(target),
                        String::from_utf8_lossy(&expected),
                    ),
                };
            }
            PayloadConsistency::Consistent
        }

        // ProposeNorm: target must be in norms/ namespace.
        (OperationPayload::ProposeNorm { .. }, TransitionKind::NormProposal) => {
            if !target.starts_with(sccgub_types::namespace::NS_NORMS) {
                return PayloadConsistency::Inconsistent {
                    reason: format!(
                        "ProposeNorm target {} not in norms/",
                        String::from_utf8_lossy(target),
                    ),
                };
            }
            PayloadConsistency::Consistent
        }

        // DeployContract: target must be in contract/ namespace.
        (OperationPayload::DeployContract { .. }, TransitionKind::ContractDeploy) => {
            if !target.starts_with(sccgub_types::namespace::NS_CONTRACT) {
                return PayloadConsistency::Inconsistent {
                    reason: format!(
                        "DeployContract target {} not in contract/",
                        String::from_utf8_lossy(target),
                    ),
                };
            }
            PayloadConsistency::Consistent
        }

        // InvokeContract: target in contract/ or data/ (both allowed by ontology).
        (OperationPayload::InvokeContract { .. }, TransitionKind::ContractInvoke) => {
            if !target.starts_with(sccgub_types::namespace::NS_CONTRACT)
                && !target.starts_with(sccgub_types::namespace::NS_DATA)
            {
                return PayloadConsistency::Inconsistent {
                    reason: format!(
                        "InvokeContract target {} not in contract/ or data/",
                        String::from_utf8_lossy(target),
                    ),
                };
            }
            PayloadConsistency::Consistent
        }

        // Noop: always allowed (testing primitive, writes nothing).
        (OperationPayload::Noop, _) => PayloadConsistency::Consistent,

        // Mismatch: payload variant doesn't match kind.
        (payload, kind) => PayloadConsistency::Inconsistent {
            reason: format!(
                "Payload {} is not valid for TransitionKind {:?}",
                payload_variant_name(payload),
                kind,
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
    use sccgub_types::governance::PrecedenceLevel;
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::timestamp::CausalTimestamp;
    use sccgub_types::transition::*;
    use std::collections::HashSet;

    fn tx_with(
        kind: TransitionKind,
        target: Vec<u8>,
        payload: OperationPayload,
    ) -> SymbolicTransition {
        SymbolicTransition {
            tx_id: [0u8; 32],
            actor: AgentIdentity {
                agent_id: [1u8; 32],
                public_key: [0u8; 32],
                mfidel_seal: MfidelAtomicSeal::from_height(1),
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: HashSet::new(),
                responsibility: ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind,
                target: target.clone(),
                declared_purpose: "test".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload,
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: [1u8; 32],
                when: CausalTimestamp::genesis(),
                r#where: target,
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
            nonce: 0,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn write_matching_key_consistent() {
        let target = b"data/foo".to_vec();
        let tx = tx_with(
            TransitionKind::StateWrite,
            target.clone(),
            OperationPayload::Write {
                key: target,
                value: vec![1],
            },
        );
        assert!(check_payload_consistency(&tx).is_consistent());
    }

    #[test]
    fn write_diverging_key_rejected() {
        let tx = tx_with(
            TransitionKind::StateWrite,
            b"data/foo".to_vec(),
            OperationPayload::Write {
                key: b"balance/victim".to_vec(),
                value: vec![0xff; 32],
            },
        );
        assert!(!check_payload_consistency(&tx).is_consistent());
    }

    #[test]
    fn transfer_correct_sender_consistent() {
        let from = [7u8; 32];
        let to = [8u8; 32];
        let target = sccgub_types::namespace::balance_key(&from);
        let tx = tx_with(
            TransitionKind::AssetTransfer,
            target,
            OperationPayload::AssetTransfer {
                from,
                to,
                amount: 100,
            },
        );
        assert!(check_payload_consistency(&tx).is_consistent());
    }

    #[test]
    fn transfer_wrong_sender_rejected() {
        let from = [7u8; 32];
        let to = [8u8; 32];
        let target = sccgub_types::namespace::balance_key(&to); // Wrong — should be from.
        let tx = tx_with(
            TransitionKind::AssetTransfer,
            target,
            OperationPayload::AssetTransfer {
                from,
                to,
                amount: 100,
            },
        );
        assert!(!check_payload_consistency(&tx).is_consistent());
    }

    #[test]
    fn kind_payload_mismatch_rejected() {
        let tx = tx_with(
            TransitionKind::StateWrite,
            b"data/foo".to_vec(),
            OperationPayload::AssetTransfer {
                from: [1u8; 32],
                to: [2u8; 32],
                amount: 1,
            },
        );
        assert!(!check_payload_consistency(&tx).is_consistent());
    }

    #[test]
    fn noop_always_consistent() {
        let tx = tx_with(
            TransitionKind::AssetTransfer,
            sccgub_types::namespace::balance_key(&[1u8; 32]),
            OperationPayload::Noop,
        );
        assert!(check_payload_consistency(&tx).is_consistent());
    }

    #[test]
    fn register_agent_matching_pk_consistent() {
        let pk = [9u8; 32];
        let target = sccgub_types::namespace::agent_key(&pk);
        let tx = tx_with(
            TransitionKind::AgentRegistration,
            target,
            OperationPayload::RegisterAgent { public_key: pk },
        );
        assert!(check_payload_consistency(&tx).is_consistent());
    }

    #[test]
    fn register_agent_wrong_target_rejected() {
        let pk = [9u8; 32];
        let other = [10u8; 32];
        let target = sccgub_types::namespace::agent_key(&other);
        let tx = tx_with(
            TransitionKind::AgentRegistration,
            target,
            OperationPayload::RegisterAgent { public_key: pk },
        );
        assert!(!check_payload_consistency(&tx).is_consistent());
    }

    #[test]
    fn deploy_contract_in_namespace_consistent() {
        let tx = tx_with(
            TransitionKind::ContractDeploy,
            b"contract/staging".to_vec(),
            OperationPayload::DeployContract { code: vec![0; 100] },
        );
        assert!(check_payload_consistency(&tx).is_consistent());
    }

    #[test]
    fn deploy_contract_outside_namespace_rejected() {
        let tx = tx_with(
            TransitionKind::ContractDeploy,
            b"data/sneaky".to_vec(),
            OperationPayload::DeployContract { code: vec![0; 100] },
        );
        assert!(!check_payload_consistency(&tx).is_consistent());
    }

    #[test]
    fn propose_norm_in_namespace_consistent() {
        let tx = tx_with(
            TransitionKind::NormProposal,
            b"norms/proposal_001".to_vec(),
            OperationPayload::ProposeNorm {
                name: "x".into(),
                description: "y".into(),
            },
        );
        assert!(check_payload_consistency(&tx).is_consistent());
    }

    #[test]
    fn propose_norm_outside_namespace_rejected() {
        let tx = tx_with(
            TransitionKind::NormProposal,
            b"data/sneaky".to_vec(),
            OperationPayload::ProposeNorm {
                name: "x".into(),
                description: "y".into(),
            },
        );
        assert!(!check_payload_consistency(&tx).is_consistent());
    }

    #[test]
    fn governance_update_write_matching_target_consistent() {
        let target = b"norms/governance/proposals/vote".to_vec();
        let tx = tx_with(
            TransitionKind::GovernanceUpdate,
            target.clone(),
            OperationPayload::Write {
                key: target,
                value: vec![1, 2, 3],
            },
        );
        assert!(check_payload_consistency(&tx).is_consistent());
    }

    #[test]
    fn governance_update_write_target_mismatch_rejected() {
        let target = b"norms/governance/proposals/vote".to_vec();
        let tx = tx_with(
            TransitionKind::GovernanceUpdate,
            target,
            OperationPayload::Write {
                key: b"norms/governance/params/propose".to_vec(),
                value: vec![1, 2, 3],
            },
        );
        assert!(!check_payload_consistency(&tx).is_consistent());
    }
}
