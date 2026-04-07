use sccgub_types::tension::{TensionBudget, TensionField, TensionValue};
use sccgub_types::SymbolAddress;

/// Check if a tension delta is within the block's tension budget.
pub fn is_within_budget(
    tension_before: TensionValue,
    tension_after: TensionValue,
    budget: &TensionBudget,
) -> bool {
    let delta = tension_after - tension_before;
    delta <= budget.current_budget
}

/// Update tension for a specific symbol address.
pub fn apply_tension_delta(field: &mut TensionField, address: &SymbolAddress, delta: TensionValue) {
    let current = field
        .map
        .entry(address.clone())
        .or_insert(TensionValue::ZERO);
    *current = *current + delta;
    field.total = field.total + delta;
}

/// Check homeostasis: tension must not grow unboundedly (INV-5).
pub fn check_homeostasis(field: &TensionField) -> bool {
    is_within_budget(TensionValue::ZERO, field.total, &field.budget)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_within_budget() {
        let budget = TensionBudget::default();
        let before = TensionValue::ZERO;
        let after = TensionValue::from_integer(500);
        assert!(is_within_budget(before, after, &budget));
    }

    #[test]
    fn test_exceeds_budget() {
        let budget = TensionBudget::default();
        let before = TensionValue::ZERO;
        let after = TensionValue::from_integer(2000); // budget default is 1000
        assert!(!is_within_budget(before, after, &budget));
    }
}
