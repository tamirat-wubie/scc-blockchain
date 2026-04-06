use sccgub_types::transition::{SymbolicTransition, WHBindingIntent};

/// Check WHBinding completeness — no transition enters a block without complete WHBindingIntent.
/// Per v2.1 INV-11.
pub fn check_wh_binding_intent(intent: &WHBindingIntent) -> Result<(), String> {
    if intent.who == [0u8; 32] {
        return Err("WHBinding: 'who' is empty (zero hash)".into());
    }
    if intent.r#where.is_empty() {
        return Err("WHBinding: 'where' is empty".into());
    }
    if intent.what_declared.is_empty() {
        return Err("WHBinding: 'what_declared' is empty".into());
    }
    // 'why' must have a valid invoking rule
    if intent.why.invoking_rule == [0u8; 32] {
        return Err("WHBinding: 'why.invoking_rule' is empty".into());
    }
    Ok(())
}

/// Check a full transition's WHBinding completeness.
pub fn check_transition_wh(tx: &SymbolicTransition) -> Result<(), String> {
    check_wh_binding_intent(&tx.wh_binding_intent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::governance::PrecedenceLevel;
    use sccgub_types::transition::{CausalJustification, TransitionMechanism, WHBindingIntent};
    use sccgub_types::timestamp::CausalTimestamp;
    use std::collections::HashSet;

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
            which: HashSet::new(),
            what_declared: "Write data to state".into(),
        }
    }

    #[test]
    fn test_valid_wh_binding() {
        assert!(check_wh_binding_intent(&valid_intent()).is_ok());
    }

    #[test]
    fn test_missing_who() {
        let mut intent = valid_intent();
        intent.who = [0u8; 32];
        assert!(check_wh_binding_intent(&intent).is_err());
    }

    #[test]
    fn test_missing_where() {
        let mut intent = valid_intent();
        intent.r#where = vec![];
        assert!(check_wh_binding_intent(&intent).is_err());
    }
}
