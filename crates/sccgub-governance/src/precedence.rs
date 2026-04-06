use sccgub_types::governance::PrecedenceLevel;

/// Check if a governance action is permitted based on the actor's precedence level.
/// Lower number = higher authority. GENESIS > SAFETY > MEANING > EMOTION > OPTIMIZATION.
pub fn is_authorized(actor_level: PrecedenceLevel, required_level: PrecedenceLevel) -> bool {
    (actor_level as u8) <= (required_level as u8)
}

/// Check if modifying governance requires sufficient authority.
/// Governance changes require at least MEANING precedence.
/// Chain evolution requires GENESIS precedence.
pub fn check_governance_change(
    actor_level: PrecedenceLevel,
    change_type: GovernanceChangeType,
) -> Result<(), String> {
    let required = match change_type {
        GovernanceChangeType::NormAddition => PrecedenceLevel::Meaning,
        GovernanceChangeType::NormMutation => PrecedenceLevel::Meaning,
        GovernanceChangeType::ConstraintAddition => PrecedenceLevel::Meaning,
        GovernanceChangeType::GovernanceUpgrade => PrecedenceLevel::Genesis,
        GovernanceChangeType::StateSchemaChange => PrecedenceLevel::Safety,
        GovernanceChangeType::EmergencyActivation => PrecedenceLevel::Safety,
    };

    if is_authorized(actor_level, required) {
        Ok(())
    } else {
        Err(format!(
            "Insufficient authority: actor has {:?}, requires {:?}",
            actor_level, required
        ))
    }
}

#[derive(Debug, Clone, Copy)]
pub enum GovernanceChangeType {
    NormAddition,
    NormMutation,
    ConstraintAddition,
    GovernanceUpgrade,
    StateSchemaChange,
    EmergencyActivation,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_genesis_overrides_all() {
        assert!(is_authorized(PrecedenceLevel::Genesis, PrecedenceLevel::Optimization));
        assert!(is_authorized(PrecedenceLevel::Genesis, PrecedenceLevel::Safety));
    }

    #[test]
    fn test_optimization_cannot_override_safety() {
        assert!(!is_authorized(PrecedenceLevel::Optimization, PrecedenceLevel::Safety));
    }

    #[test]
    fn test_norm_requires_meaning() {
        assert!(check_governance_change(PrecedenceLevel::Meaning, GovernanceChangeType::NormAddition).is_ok());
        assert!(check_governance_change(PrecedenceLevel::Optimization, GovernanceChangeType::NormAddition).is_err());
    }
}
