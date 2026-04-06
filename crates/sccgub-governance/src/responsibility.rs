use sccgub_types::agent::{ResponsibilityEntry, ResponsibilityState};
use sccgub_types::tension::TensionValue;
use sccgub_types::TransitionId;

/// Maximum entries per contribution list before pruning.
const MAX_CONTRIBUTIONS: usize = 1000;

/// Apply temporal decay to a responsibility state.
/// R_i(t) = R_i(t_0) · e^{-λ(t - t_0)}
/// Approximated using exponentiation by squaring for efficiency.
/// Updates block_height on each entry to prevent double-decay.
pub fn apply_decay(state: &mut ResponsibilityState, current_height: u64) {
    let decay = state.decay_factor;
    let one = TensionValue(TensionValue::SCALE);
    let factor = one - decay;

    fn decay_entry(entry: &mut ResponsibilityEntry, factor: TensionValue, current_height: u64) {
        let age = current_height.saturating_sub(entry.block_height);
        if age > 0 {
            // Exponentiation by squaring: factor^age
            let decayed = exp_by_squaring(factor, age.min(200));
            entry.r_value = entry.r_value.mul_fp(decayed);
            entry.block_height = current_height; // Prevent double-decay.
        }
    }

    for entry in &mut state.positive_contributions {
        decay_entry(entry, factor, current_height);
    }
    for entry in &mut state.negative_contributions {
        decay_entry(entry, factor, current_height);
    }

    // Prune near-zero entries to prevent unbounded growth.
    let threshold = TensionValue(1); // ~10^-18, effectively zero.
    state.positive_contributions.retain(|e| e.r_value.raw().unsigned_abs() > threshold.raw().unsigned_abs());
    state.negative_contributions.retain(|e| e.r_value.raw().unsigned_abs() > threshold.raw().unsigned_abs());

    // Hard cap on contribution list size.
    if state.positive_contributions.len() > MAX_CONTRIBUTIONS {
        state.positive_contributions.drain(0..state.positive_contributions.len() - MAX_CONTRIBUTIONS);
    }
    if state.negative_contributions.len() > MAX_CONTRIBUTIONS {
        state.negative_contributions.drain(0..state.negative_contributions.len() - MAX_CONTRIBUTIONS);
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

/// Fixed-point exponentiation by squaring: base^exp.
fn exp_by_squaring(base: TensionValue, exp: u64) -> TensionValue {
    if exp == 0 {
        return TensionValue(TensionValue::SCALE); // 1.0
    }
    let mut result = TensionValue(TensionValue::SCALE);
    let mut b = base;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = result.mul_fp(b);
        }
        b = b.mul_fp(b);
        e >>= 1;
    }
    result
}

/// Record a positive contribution. Enforces MAX_CONTRIBUTIONS cap.
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
    if state.positive_contributions.len() > MAX_CONTRIBUTIONS {
        let drain = state.positive_contributions.len() - MAX_CONTRIBUTIONS;
        state.positive_contributions.drain(0..drain);
    }
}

/// Record a negative contribution. Enforces MAX_CONTRIBUTIONS cap.
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
    if state.negative_contributions.len() > MAX_CONTRIBUTIONS {
        let drain = state.negative_contributions.len() - MAX_CONTRIBUTIONS;
        state.negative_contributions.drain(0..drain);
    }
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
