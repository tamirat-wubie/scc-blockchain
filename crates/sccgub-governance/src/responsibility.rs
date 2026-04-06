use sccgub_types::agent::{ResponsibilityEntry, ResponsibilityState};
use sccgub_types::tension::TensionValue;
use sccgub_types::TransitionId;

/// Apply temporal decay to a responsibility state.
/// R_i(t) = R_i(t_0) · e^{-λ(t - t_0)}
/// Approximated in discrete time with fixed-point arithmetic.
pub fn apply_decay(state: &mut ResponsibilityState, current_height: u64) {
    let decay = state.decay_factor;

    // Decay positive contributions.
    for entry in &mut state.positive_contributions {
        let age = current_height.saturating_sub(entry.block_height);
        if age > 0 {
            // Approximate exponential decay: multiply by (1 - λ) for each step.
            let one = TensionValue(TensionValue::SCALE);
            let factor = one - decay;
            for _ in 0..age.min(100) {
                entry.r_value = entry.r_value.mul_fp(factor);
            }
        }
    }

    // Same for negative contributions.
    for entry in &mut state.negative_contributions {
        let age = current_height.saturating_sub(entry.block_height);
        if age > 0 {
            let one = TensionValue(TensionValue::SCALE);
            let factor = one - decay;
            for _ in 0..age.min(100) {
                entry.r_value = entry.r_value.mul_fp(factor);
            }
        }
    }

    // Recompute net responsibility.
    let pos_sum: TensionValue = state
        .positive_contributions
        .iter()
        .fold(TensionValue::ZERO, |acc, e| acc + e.r_value);
    let neg_sum: TensionValue = state
        .negative_contributions
        .iter()
        .fold(TensionValue::ZERO, |acc, e| acc + e.r_value);
    state.net_responsibility = pos_sum - neg_sum;
}

/// Record a positive contribution.
pub fn record_positive(
    state: &mut ResponsibilityState,
    tx_id: TransitionId,
    value: TensionValue,
    height: u64,
) {
    state.positive_contributions.push(ResponsibilityEntry {
        transition_id: tx_id,
        r_value: value,
        block_height: height,
    });
    state.net_responsibility = state.net_responsibility + value;
}

/// Record a negative contribution.
pub fn record_negative(
    state: &mut ResponsibilityState,
    tx_id: TransitionId,
    value: TensionValue,
    height: u64,
) {
    state.negative_contributions.push(ResponsibilityEntry {
        transition_id: tx_id,
        r_value: value,
        block_height: height,
    });
    state.net_responsibility = state.net_responsibility - value;
}

/// Check INV-13 (v2.1): |Σ R_i_net| <= R_max_imbalance.
pub fn check_responsibility_bound(
    states: &[&ResponsibilityState],
    max_imbalance: TensionValue,
) -> bool {
    let total_net: TensionValue = states
        .iter()
        .fold(TensionValue::ZERO, |acc, s| acc + s.net_responsibility);
    total_net.raw().unsigned_abs() <= max_imbalance.raw().unsigned_abs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_contributions() {
        let mut state = ResponsibilityState::default();
        record_positive(&mut state, [1u8; 32], TensionValue::from_integer(10), 1);
        assert_eq!(state.net_responsibility, TensionValue::from_integer(10));

        record_negative(&mut state, [2u8; 32], TensionValue::from_integer(3), 2);
        assert_eq!(state.net_responsibility, TensionValue::from_integer(7));
    }

    #[test]
    fn test_responsibility_bound() {
        let mut s1 = ResponsibilityState::default();
        s1.net_responsibility = TensionValue::from_integer(50);

        let mut s2 = ResponsibilityState::default();
        s2.net_responsibility = TensionValue::from_integer(-30);

        let max = TensionValue::from_integer(100);
        assert!(check_responsibility_bound(&[&s1, &s2], max));

        let strict_max = TensionValue::from_integer(10);
        assert!(!check_responsibility_bound(&[&s1, &s2], strict_max));
    }
}
