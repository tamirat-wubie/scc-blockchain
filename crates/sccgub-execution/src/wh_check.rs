use sccgub_types::transition::{SymbolicTransition, WHBindingIntent};
use sccgub_types::ZERO_HASH;

/// Check WHBinding completeness — no transition enters a block without complete WHBindingIntent.
/// Per v2.1 INV-11: validates all 7 WH fields.
pub fn check_wh_binding_intent(intent: &WHBindingIntent) -> Result<(), String> {
    // WHO: must be a real agent (non-zero).
    if intent.who == ZERO_HASH {
        return Err("WHBinding: 'who' is empty (zero hash)".into());
    }
    // WHERE: must target a non-empty address.
    if intent.r#where.is_empty() {
        return Err("WHBinding: 'where' is empty".into());
    }
    // WHAT: declared intent must be non-empty.
    if intent.what_declared.is_empty() {
        return Err("WHBinding: 'what_declared' is empty".into());
    }
    // WHY: must have a valid invoking rule.
    if intent.why.invoking_rule == ZERO_HASH {
        return Err("WHBinding: 'why.invoking_rule' is empty".into());
    }
    // WHEN: lamport counter 0 is valid (genesis), but causal_depth should be consistent.
    // We allow genesis timestamps, so no strict check here beyond structural validity.

    // HOW: mechanism must be specified (always valid since it's an enum — no check needed).

    // Cross-check: WHBinding 'who' must match the actor claiming it.
    // (This is checked externally against the transaction actor.)

    Ok(())
}

/// Check a full transition's WHBinding completeness, including cross-checks.
pub fn check_transition_wh(tx: &SymbolicTransition) -> Result<(), String> {
    check_wh_binding_intent(&tx.wh_binding_intent)?;

    // Cross-check: WHBinding 'who' must match the transaction actor.
    if tx.wh_binding_intent.who != tx.actor.agent_id {
        return Err(format!(
            "WHBinding 'who' ({}) does not match actor ({})",
            hex::encode(tx.wh_binding_intent.who),
            hex::encode(tx.actor.agent_id)
        ));
    }

    // Cross-check: WHBinding 'where' should match intent target.
    if tx.wh_binding_intent.r#where != tx.intent.target {
        return Err("WHBinding 'where' does not match intent target".into());
    }

    // Cross-check: WHBinding precedence must not exceed actor's governance level.
    let claimed = tx.wh_binding_intent.why.precedence_level as u8;
    let actual = tx.actor.governance_level as u8;
    if claimed < actual {
        return Err(format!(
            "WHBinding claims precedence {:?} but actor only has {:?}",
            tx.wh_binding_intent.why.precedence_level, tx.actor.governance_level
        ));
    }

    // G-5.3: WHEN — timestamp must not be in the past (causal ordering).
    // Lamport 0 is valid for genesis; otherwise depth should be >= 1.
    if tx.wh_binding_intent.when.lamport_counter == 0 && tx.wh_binding_intent.when.causal_depth > 0
    {
        return Err("WHBinding 'when': zero lamport counter with non-zero causal depth".into());
    }

    // G-5.4: HOW — mechanism must match the payload kind.
    let how_ok = match (&tx.wh_binding_intent.how, &tx.payload) {
        (
            sccgub_types::transition::TransitionMechanism::DirectStateWrite,
            sccgub_types::transition::OperationPayload::Write { .. },
        ) => true,
        (
            sccgub_types::transition::TransitionMechanism::ContractExecution { .. },
            sccgub_types::transition::OperationPayload::InvokeContract { .. },
        ) => true,
        (_, sccgub_types::transition::OperationPayload::Noop) => true, // Noop always ok.
        (
            sccgub_types::transition::TransitionMechanism::GovernanceAction,
            sccgub_types::transition::OperationPayload::ProposeNorm { .. },
        ) => true,
        (
            sccgub_types::transition::TransitionMechanism::DirectStateWrite,
            sccgub_types::transition::OperationPayload::AssetTransfer { .. },
        ) => true, // Transfers are direct state writes on the balance trie.
        (
            sccgub_types::transition::TransitionMechanism::DirectStateWrite,
            sccgub_types::transition::OperationPayload::RegisterAgent { .. },
        ) => true,
        (
            sccgub_types::transition::TransitionMechanism::DirectStateWrite,
            sccgub_types::transition::OperationPayload::DeployContract { .. },
        ) => true,
        _ => false,
    };
    if !how_ok {
        return Err(format!(
            "WHBinding 'how' ({:?}) does not match payload variant",
            tx.wh_binding_intent.how
        ));
    }

    // G-5.5: WHICH — declared constraint scope must match actual carried constraints.
    // `which` is the set of ConstraintIds the tx declares it depends on.
    // `preconditions ∪ postconditions` is the set of constraints actually carried.
    // Strict equality: every declared constraint must be carried, and every carried
    // constraint must be declared. Subset would allow undeclared constraints to slip in.
    let carried: std::collections::BTreeSet<sccgub_types::ConstraintId> = tx
        .preconditions
        .iter()
        .chain(tx.postconditions.iter())
        .map(|c| c.id)
        .collect();
    let declared = &tx.wh_binding_intent.which;
    if &carried != declared {
        let undeclared: Vec<_> = carried.difference(declared).map(hex::encode).collect();
        let unsupported: Vec<_> = declared.difference(&carried).map(hex::encode).collect();
        return Err(format!(
            "WHBinding 'which' does not match carried constraints: undeclared={:?} unsupported={:?}",
            undeclared, unsupported
        ));
    }

    Ok(())
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

    fn valid_agent() -> AgentIdentity {
        AgentIdentity {
            agent_id: [1u8; 32],
            public_key: [0u8; 32],
            mfidel_seal: MfidelAtomicSeal::from_height(1),
            registration_block: 0,
            governance_level: PrecedenceLevel::Meaning,
            norm_set: BTreeSet::new(),
            responsibility: ResponsibilityState::default(),
        }
    }

    fn valid_intent() -> WHBindingIntent {
        WHBindingIntent {
            who: [1u8; 32],
            when: CausalTimestamp::genesis(),
            r#where: b"some/address".to_vec(),
            why: CausalJustification {
                invoking_rule: [2u8; 32],
                precedence_level: PrecedenceLevel::Meaning,
                causal_ancestors: vec![],
                constraint_proof: vec![],
            },
            how: TransitionMechanism::DirectStateWrite,
            which: BTreeSet::new(),
            what_declared: "Write data to state".into(),
        }
    }

    fn valid_tx() -> SymbolicTransition {
        SymbolicTransition {
            tx_id: [0u8; 32],
            actor: valid_agent(),
            intent: TransitionIntent {
                kind: TransitionKind::StateWrite,
                target: b"some/address".to_vec(),
                declared_purpose: "test".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Noop,
            causal_chain: vec![],
            wh_binding_intent: valid_intent(),
            nonce: 1,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn test_valid_wh_binding() {
        assert!(check_wh_binding_intent(&valid_intent()).is_ok());
    }

    #[test]
    fn test_valid_tx_wh_cross_check() {
        assert!(check_transition_wh(&valid_tx()).is_ok());
    }

    #[test]
    fn test_missing_who() {
        let mut intent = valid_intent();
        intent.who = ZERO_HASH;
        assert!(check_wh_binding_intent(&intent).is_err());
    }

    #[test]
    fn test_missing_where() {
        let mut intent = valid_intent();
        intent.r#where = vec![];
        assert!(check_wh_binding_intent(&intent).is_err());
    }

    #[test]
    fn test_who_mismatch() {
        let mut tx = valid_tx();
        tx.wh_binding_intent.who = [99u8; 32]; // Different from actor.
        assert!(check_transition_wh(&tx).is_err());
    }

    #[test]
    fn test_where_mismatch() {
        let mut tx = valid_tx();
        tx.wh_binding_intent.r#where = b"different/address".to_vec();
        assert!(check_transition_wh(&tx).is_err());
    }

    #[test]
    fn test_precedence_escalation_rejected() {
        let mut tx = valid_tx();
        tx.actor.governance_level = PrecedenceLevel::Optimization; // Low authority.
        tx.wh_binding_intent.why.precedence_level = PrecedenceLevel::Safety; // Claims high.
        assert!(check_transition_wh(&tx).is_err());
    }

    // G-5.5: WHICH cross-check tests.

    #[test]
    fn test_g55_empty_which_empty_constraints_passes() {
        let tx = valid_tx();
        assert!(tx.wh_binding_intent.which.is_empty());
        assert!(tx.preconditions.is_empty());
        assert!(tx.postconditions.is_empty());
        assert!(check_transition_wh(&tx).is_ok());
    }

    #[test]
    fn test_g55_carried_constraint_undeclared_rejected() {
        let mut tx = valid_tx();
        tx.preconditions.push(Constraint {
            id: [42u8; 32],
            expression: "true".into(),
        });
        // which is still empty — violation.
        let result = check_transition_wh(&tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("which"));
    }

    #[test]
    fn test_g55_declared_constraint_uncarried_rejected() {
        let mut tx = valid_tx();
        tx.wh_binding_intent.which.insert([99u8; 32]);
        // preconditions/postconditions still empty — violation.
        let result = check_transition_wh(&tx);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("which"));
    }

    #[test]
    fn test_g55_matched_which_and_constraints_passes() {
        let mut tx = valid_tx();
        let cid = [7u8; 32];
        tx.preconditions.push(Constraint {
            id: cid,
            expression: "true".into(),
        });
        tx.wh_binding_intent.which.insert(cid);
        assert!(check_transition_wh(&tx).is_ok());
    }

    #[test]
    fn test_g55_postcondition_must_also_be_declared() {
        let mut tx = valid_tx();
        let cid = [11u8; 32];
        tx.postconditions.push(Constraint {
            id: cid,
            expression: "true".into(),
        });
        // which is empty — violation.
        let result = check_transition_wh(&tx);
        assert!(result.is_err());
        // Now declare it.
        tx.wh_binding_intent.which.insert(cid);
        assert!(check_transition_wh(&tx).is_ok());
    }

    #[test]
    fn test_g55_duplicate_constraint_ids_treated_as_set() {
        let mut tx = valid_tx();
        let cid = [13u8; 32];
        tx.preconditions.push(Constraint {
            id: cid,
            expression: "true".into(),
        });
        tx.preconditions.push(Constraint {
            id: cid,
            expression: "also true".into(),
        });
        tx.wh_binding_intent.which.insert(cid);
        assert!(check_transition_wh(&tx).is_ok());
    }
}
