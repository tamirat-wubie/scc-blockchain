// Phi Phase 3 (Ontology) — TransitionKind to namespace binding.
//
// Each TransitionKind is restricted to writing under a specific set of
// namespace prefixes. This converts `kind` from a self-declared label
// into a verified scope. Default-deny: targets matching no namespace
// are rejected. Adding a new namespace requires updating this table.

use sccgub_types::transition::{SymbolicTransition, TransitionKind};

/// Namespace prefix type.
pub type Namespace = &'static [u8];

/// Allowed namespace prefixes for each TransitionKind.
///
/// This table is consensus-critical. Changing it is a hard fork.
/// Future: promote to ConsensusParams (Patch 03) for governance-mutability.
fn allowed_namespaces(kind: TransitionKind) -> &'static [Namespace] {
    match kind {
        // Generic state — user data only. Cannot touch reserved namespaces.
        TransitionKind::StateWrite => &[NS_DATA],
        TransitionKind::StateRead => &[NS_DATA, NS_BALANCE, NS_NORMS, NS_AGENTS],

        // Asset operations — balance ledger and escrow only.
        TransitionKind::AssetTransfer => &[NS_BALANCE, NS_ESCROW],

        // Governance operations.
        TransitionKind::GovernanceUpdate => &[NS_NORMS, NS_TREASURY],
        TransitionKind::NormProposal => &[NS_NORMS],
        TransitionKind::ConstraintAddition => &[NS_CONSTRAINTS],

        // Agent lifecycle.
        TransitionKind::AgentRegistration => &[NS_AGENTS],

        // Contract operations — scoped to contract/ prefix only.
        TransitionKind::ContractDeploy => &[NS_CONTRACT],
        TransitionKind::ContractInvoke => &[NS_CONTRACT],

        // Dispute resolution — deny everything until dispute machinery exists.
        // Empty allowlist is an INTENTIONAL GATE: any TransitionKind variant
        // without an implementation should map to &[] here. This forces the
        // kind to be wired through the table when the implementation lands,
        // preventing "unimplemented kind silently accepted" bugs.
        TransitionKind::DisputeResolution => &[],
    }
}

/// Result of an ontology check.
#[derive(Debug, Clone)]
pub enum OntologyResult {
    Allowed,
    Rejected {
        kind: TransitionKind,
        target: Vec<u8>,
        allowed: Vec<&'static [u8]>,
    },
}

impl OntologyResult {
    pub fn is_allowed(&self) -> bool {
        matches!(self, OntologyResult::Allowed)
    }
}

// Namespace key builders and constants live in sccgub_types::namespace.
// Re-export for convenience.
pub use sccgub_types::namespace::{balance_key, contract_key, data_key, norm_key};

// Import NS_ constants from the single source of truth.
// NS_SYSTEM and NS_DISPUTES are not imported — no kind maps to them.
use sccgub_types::namespace::{
    NS_AGENTS, NS_BALANCE, NS_CONSTRAINTS, NS_CONTRACT, NS_DATA, NS_ESCROW, NS_NORMS, NS_TREASURY,
};

/// Phi Phase 3: verify the transition's target falls within the
/// namespaces allowed for its declared kind. Default-deny.
pub fn check_ontology(tx: &SymbolicTransition) -> OntologyResult {
    let target = &tx.intent.target;
    if target.is_empty() {
        return OntologyResult::Rejected {
            kind: tx.intent.kind,
            target: vec![],
            allowed: allowed_namespaces(tx.intent.kind).to_vec(),
        };
    }

    let allowed = allowed_namespaces(tx.intent.kind);
    for ns in allowed {
        if target.starts_with(ns) {
            return OntologyResult::Allowed;
        }
    }

    OntologyResult::Rejected {
        kind: tx.intent.kind,
        target: target.clone(),
        allowed: allowed.to_vec(),
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
    use std::collections::BTreeSet;

    fn tx_with(kind: TransitionKind, target: &[u8]) -> SymbolicTransition {
        SymbolicTransition {
            tx_id: [0u8; 32],
            actor: AgentIdentity {
                agent_id: [1u8; 32],
                public_key: [0u8; 32],
                mfidel_seal: MfidelAtomicSeal::from_height(1),
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: BTreeSet::new(),
                responsibility: ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind,
                target: target.to_vec(),
                declared_purpose: "test".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Noop,
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: [1u8; 32],
                when: CausalTimestamp::genesis(),
                r#where: target.to_vec(),
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
            nonce: 0,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn asset_transfer_to_balance_allowed() {
        let tx = tx_with(TransitionKind::AssetTransfer, b"balance/abc123");
        assert!(check_ontology(&tx).is_allowed());
    }

    #[test]
    fn asset_transfer_to_system_rejected() {
        let tx = tx_with(TransitionKind::AssetTransfer, b"system/consensus_params");
        assert!(!check_ontology(&tx).is_allowed());
    }

    #[test]
    fn state_write_to_data_allowed() {
        let tx = tx_with(TransitionKind::StateWrite, b"data/userprefs/theme");
        assert!(check_ontology(&tx).is_allowed());
    }

    #[test]
    fn state_write_to_balance_rejected() {
        let tx = tx_with(TransitionKind::StateWrite, b"balance/victim");
        assert!(!check_ontology(&tx).is_allowed());
    }

    #[test]
    fn state_write_to_system_rejected() {
        let tx = tx_with(TransitionKind::StateWrite, b"system/anything");
        assert!(!check_ontology(&tx).is_allowed());
    }

    #[test]
    fn empty_target_rejected() {
        let tx = tx_with(TransitionKind::StateWrite, b"");
        assert!(!check_ontology(&tx).is_allowed());
    }

    #[test]
    fn unknown_namespace_rejected() {
        let tx = tx_with(TransitionKind::StateRead, b"random/unknown/key");
        assert!(!check_ontology(&tx).is_allowed());
    }

    #[test]
    fn governance_update_to_norms_allowed() {
        let tx = tx_with(TransitionKind::GovernanceUpdate, b"norms/safety_001");
        assert!(check_ontology(&tx).is_allowed());
    }

    #[test]
    fn governance_update_to_constraints_rejected() {
        let tx = tx_with(TransitionKind::GovernanceUpdate, b"constraints/foo\0c0");
        assert!(!check_ontology(&tx).is_allowed());
    }

    #[test]
    fn constraint_addition_to_constraints_allowed() {
        let tx = tx_with(
            TransitionKind::ConstraintAddition,
            b"constraints/some_symbol\0c0",
        );
        assert!(check_ontology(&tx).is_allowed());
    }

    #[test]
    fn contract_invoke_to_contract_allowed() {
        let tx = tx_with(
            TransitionKind::ContractInvoke,
            b"contract/my_contract/state",
        );
        assert!(check_ontology(&tx).is_allowed());
    }

    #[test]
    fn contract_invoke_to_data_rejected() {
        let tx = tx_with(TransitionKind::ContractInvoke, b"data/contract_state/foo");
        assert!(!check_ontology(&tx).is_allowed());
    }

    #[test]
    fn contract_invoke_to_balance_rejected() {
        let tx = tx_with(TransitionKind::ContractInvoke, b"balance/victim");
        assert!(!check_ontology(&tx).is_allowed());
    }

    #[test]
    fn dispute_resolution_denied_until_machinery_exists() {
        let tx = tx_with(TransitionKind::DisputeResolution, b"disputes/case_001");
        assert!(
            !check_ontology(&tx).is_allowed(),
            "DisputeResolution must be denied until dispute machinery is implemented"
        );
    }

    #[test]
    fn no_kind_can_write_to_system() {
        // Verify that NO transition kind includes NS_SYSTEM.
        let all_kinds = [
            TransitionKind::StateWrite,
            TransitionKind::StateRead,
            TransitionKind::AssetTransfer,
            TransitionKind::GovernanceUpdate,
            TransitionKind::NormProposal,
            TransitionKind::ConstraintAddition,
            TransitionKind::AgentRegistration,
            TransitionKind::ContractDeploy,
            TransitionKind::ContractInvoke,
            TransitionKind::DisputeResolution,
        ];
        for kind in &all_kinds {
            let tx = tx_with(*kind, b"system/anything");
            assert!(
                !check_ontology(&tx).is_allowed(),
                "Kind {:?} must NOT be allowed to write to system/",
                kind
            );
        }
    }
}
