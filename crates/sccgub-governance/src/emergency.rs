use sccgub_types::governance::GovernanceState;
use sccgub_types::tension::{TensionField, TensionValue};

/// Emergency governance trigger per spec Section 7.4.
/// When total tension exceeds repair capacity, emergency mode activates:
/// - Tighten norm constraints
/// - Reduce transition throughput
/// - Increase validation depth
/// - Restrict governance modifications
/// - Allocate repair resources
#[derive(Debug, Clone)]
pub struct EmergencyPolicy {
    /// Tension threshold at which emergency mode activates.
    pub activation_threshold: TensionValue,
    /// Tension threshold at which emergency mode deactivates.
    pub deactivation_threshold: TensionValue,
    /// Maximum transitions per block during emergency.
    pub emergency_max_txs: u32,
    /// Normal maximum transitions per block.
    pub normal_max_txs: u32,
}

impl EmergencyPolicy {
    /// Validate policy parameters. Activation must exceed deactivation (hysteresis).
    pub fn validate(&self) -> Result<(), String> {
        if self.activation_threshold <= self.deactivation_threshold {
            return Err("activation_threshold must be > deactivation_threshold".into());
        }
        if self.emergency_max_txs == 0 {
            return Err("emergency_max_txs must be > 0".into());
        }
        if self.normal_max_txs == 0 {
            return Err("normal_max_txs must be > 0".into());
        }
        if self.normal_max_txs < self.emergency_max_txs {
            return Err("normal_max_txs must be >= emergency_max_txs".into());
        }
        Ok(())
    }
}

impl Default for EmergencyPolicy {
    fn default() -> Self {
        Self {
            activation_threshold: TensionValue::from_integer(800),
            deactivation_threshold: TensionValue::from_integer(400),
            emergency_max_txs: 10,
            normal_max_txs: 1000,
        }
    }
}

/// Check if emergency governance should be activated or deactivated.
/// Returns the new emergency mode state and any actions to take.
pub fn evaluate_emergency(
    tension: &TensionField,
    governance: &GovernanceState,
    policy: &EmergencyPolicy,
) -> EmergencyDecision {
    let total = tension.total;

    if governance.emergency_mode {
        // Already in emergency — check if we can deactivate.
        if total <= policy.deactivation_threshold {
            EmergencyDecision::Deactivate {
                reason: format!(
                    "Tension {} dropped below deactivation threshold {}",
                    total, policy.deactivation_threshold
                ),
                normal_max_txs: policy.normal_max_txs,
            }
        } else {
            EmergencyDecision::MaintainEmergency {
                tension: total,
                max_txs: policy.emergency_max_txs,
            }
        }
    } else {
        // Not in emergency — check if we need to activate.
        if total >= policy.activation_threshold {
            EmergencyDecision::Activate {
                reason: format!(
                    "Tension {} exceeds activation threshold {}",
                    total, policy.activation_threshold
                ),
                max_txs: policy.emergency_max_txs,
            }
        } else {
            EmergencyDecision::Normal {
                max_txs: policy.normal_max_txs,
            }
        }
    }
}

/// Decision from emergency governance evaluation.
#[derive(Debug, Clone)]
pub enum EmergencyDecision {
    /// Normal operation.
    Normal { max_txs: u32 },
    /// Activate emergency mode.
    Activate { reason: String, max_txs: u32 },
    /// Emergency mode remains active.
    MaintainEmergency { tension: TensionValue, max_txs: u32 },
    /// Deactivate emergency mode. Carries the normal max_txs from policy.
    Deactivate { reason: String, normal_max_txs: u32 },
}

impl EmergencyDecision {
    pub fn max_txs_per_block(&self) -> u32 {
        match self {
            Self::Normal { max_txs } => *max_txs,
            Self::Activate { max_txs, .. } => *max_txs,
            Self::MaintainEmergency { max_txs, .. } => *max_txs,
            Self::Deactivate { normal_max_txs, .. } => *normal_max_txs,
        }
    }

    pub fn is_emergency(&self) -> bool {
        matches!(self, Self::Activate { .. } | Self::MaintainEmergency { .. })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::tension::TensionBudget;
    use std::collections::HashMap;

    fn make_tension(total: i64) -> TensionField {
        TensionField {
            total: TensionValue::from_integer(total),
            map: HashMap::new(),
            budget: TensionBudget::default(),
        }
    }

    #[test]
    fn test_normal_operation() {
        let tension = make_tension(100);
        let gov = GovernanceState::default();
        let policy = EmergencyPolicy::default();

        let decision = evaluate_emergency(&tension, &gov, &policy);
        assert!(!decision.is_emergency());
        assert_eq!(decision.max_txs_per_block(), 1000);
    }

    #[test]
    fn test_emergency_activation() {
        let tension = make_tension(900);
        let gov = GovernanceState::default();
        let policy = EmergencyPolicy::default();

        let decision = evaluate_emergency(&tension, &gov, &policy);
        assert!(decision.is_emergency());
        assert_eq!(decision.max_txs_per_block(), 10);
    }

    #[test]
    fn test_emergency_deactivation() {
        let tension = make_tension(200);
        let mut gov = GovernanceState::default();
        gov.emergency_mode = true;
        let policy = EmergencyPolicy::default();

        let decision = evaluate_emergency(&tension, &gov, &policy);
        assert!(!decision.is_emergency());
        assert!(matches!(decision, EmergencyDecision::Deactivate { .. }));
    }

    #[test]
    fn test_emergency_maintained() {
        let tension = make_tension(600);
        let mut gov = GovernanceState::default();
        gov.emergency_mode = true;
        let policy = EmergencyPolicy::default();

        let decision = evaluate_emergency(&tension, &gov, &policy);
        assert!(decision.is_emergency());
    }

    #[test]
    fn test_validate_valid_policy() {
        let policy = EmergencyPolicy::default();
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn test_validate_activation_must_exceed_deactivation() {
        let policy = EmergencyPolicy {
            activation_threshold: TensionValue::from_integer(100),
            deactivation_threshold: TensionValue::from_integer(200),
            ..EmergencyPolicy::default()
        };
        assert!(policy.validate().is_err());
    }

    #[test]
    fn test_validate_zero_max_txs_rejected() {
        let policy = EmergencyPolicy {
            emergency_max_txs: 0,
            ..EmergencyPolicy::default()
        };
        assert!(policy.validate().is_err());

        let policy2 = EmergencyPolicy {
            normal_max_txs: 0,
            ..EmergencyPolicy::default()
        };
        assert!(policy2.validate().is_err());
    }

    #[test]
    fn test_validate_normal_must_exceed_emergency() {
        let policy = EmergencyPolicy {
            emergency_max_txs: 100,
            normal_max_txs: 50,
            ..EmergencyPolicy::default()
        };
        assert!(policy.validate().is_err());
    }
}
