use sccgub_types::agent::ValidatorAuthority;
use sccgub_types::tension::TensionValue;

/// Validator selection function.
/// Selects the best validator based on weighted score:
///   score = w1·norm_compliance + w2·causal_reliability + w3·governance_level
/// Per spec Section 5.2.
pub fn select_validator(validators: &[ValidatorAuthority]) -> Option<&ValidatorAuthority> {
    let eligible: Vec<&ValidatorAuthority> = validators.iter().filter(|v| v.active).collect();

    if eligible.is_empty() {
        return None;
    }

    // Weights (fixed-point).
    let w1 = TensionValue::from_integer(4); // norm compliance weight
    let w2 = TensionValue::from_integer(3); // reliability weight
    let w3 = TensionValue::from_integer(3); // governance level weight

    eligible.into_iter().max_by_key(|v| {
        let gov_score = TensionValue::from_integer(5_i64.saturating_sub(v.governance_level as i64).max(0));
        let score =
            w1.mul_fp(v.norm_compliance) + w2.mul_fp(v.causal_reliability) + w3.mul_fp(gov_score);
        score.raw()
    })
}

/// Round-robin proposer selection for DETERMINISTIC finality mode.
/// Validators are sorted by node_id for deterministic ordering across all nodes.
pub fn round_robin_proposer(
    validators: &[ValidatorAuthority],
    round: u64,
) -> Option<ValidatorAuthority> {
    let mut active: Vec<&ValidatorAuthority> = validators.iter().filter(|v| v.active).collect();
    if active.is_empty() {
        return None;
    }
    // Sort by node_id for deterministic ordering regardless of input order.
    active.sort_by_key(|v| v.node_id);
    let idx = (round as usize) % active.len();
    Some(active[idx].clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::governance::PrecedenceLevel;

    fn test_validator(id: u8, compliance: i64, reliability: i64) -> ValidatorAuthority {
        ValidatorAuthority {
            node_id: [id; 32],
            governance_level: PrecedenceLevel::Meaning,
            norm_compliance: TensionValue::from_integer(compliance),
            causal_reliability: TensionValue::from_integer(reliability),
            active: true,
        }
    }

    #[test]
    fn test_select_best_validator() {
        let validators = vec![
            test_validator(1, 8, 7),
            test_validator(2, 9, 9),
            test_validator(3, 5, 5),
        ];
        let best = select_validator(&validators).unwrap();
        assert_eq!(best.node_id, [2u8; 32]);
    }

    #[test]
    fn test_round_robin() {
        let validators = vec![test_validator(1, 5, 5), test_validator(2, 5, 5)];
        let v0 = round_robin_proposer(&validators, 0).unwrap();
        let v1 = round_robin_proposer(&validators, 1).unwrap();
        assert_ne!(v0.node_id, v1.node_id);
    }
}
