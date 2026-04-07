use sccgub_state::world::ManagedWorldState;
use sccgub_types::SymbolAddress;

/// Formal constraint evaluator for symbolic causal contracts.
///
/// Replaces string-based constraint expressions with a structured
/// predicate system that can be evaluated deterministically.
///
/// Addresses: $17B in smart contract exploit losses (2025) by making
/// constraint satisfaction verifiable and decidable.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum Predicate {
    /// Check that a state key exists.
    Exists { key: SymbolAddress },
    /// Check that a state key does NOT exist.
    NotExists { key: SymbolAddress },
    /// Check that a value at a key equals a specific byte pattern.
    Equals { key: SymbolAddress, value: Vec<u8> },
    /// Check that a numeric value at a key is >= threshold.
    BalanceAtLeast {
        agent: sccgub_types::AgentId,
        min_balance: i128,
    },
    /// Check that the actor has a minimum governance level.
    MinGovernanceLevel { level: u8 },
    /// Logical AND of multiple predicates.
    And(Vec<Predicate>),
    /// Logical OR of multiple predicates.
    Or(Vec<Predicate>),
    /// Logical NOT.
    Not(Box<Predicate>),
    /// Always true (no constraint).
    True,
    /// Always false (unreachable).
    False,
}

/// Result of constraint evaluation.
#[derive(Debug, Clone)]
pub struct ConstraintResult {
    pub satisfied: bool,
    pub details: String,
}

/// Evaluate a predicate against the current state.
/// This is a pure function — deterministic across all validators.
pub fn evaluate(
    predicate: &Predicate,
    state: &ManagedWorldState,
    actor_governance_level: u8,
) -> ConstraintResult {
    match predicate {
        Predicate::Exists { key } => {
            let exists = state.trie.contains(key);
            ConstraintResult {
                satisfied: exists,
                details: if exists {
                    format!("Key '{}' exists", String::from_utf8_lossy(key))
                } else {
                    format!("Key '{}' does not exist", String::from_utf8_lossy(key))
                },
            }
        }
        Predicate::NotExists { key } => {
            let exists = state.trie.contains(key);
            ConstraintResult {
                satisfied: !exists,
                details: if !exists {
                    format!("Key '{}' confirmed absent", String::from_utf8_lossy(key))
                } else {
                    format!("Key '{}' unexpectedly exists", String::from_utf8_lossy(key))
                },
            }
        }
        Predicate::Equals { key, value } => {
            let actual = state.trie.get(key);
            let matches = actual == Some(value);
            ConstraintResult {
                satisfied: matches,
                details: if matches {
                    "Value matches".into()
                } else {
                    "Value mismatch".into()
                },
            }
        }
        Predicate::BalanceAtLeast { agent, min_balance } => {
            let balance_key = format!("balance/{}", hex::encode(agent)).into_bytes();
            let actual = state
                .trie
                .get(&balance_key)
                .and_then(|v| {
                    if v.len() == 16 {
                        let bytes: [u8; 16] = v.as_slice().try_into().ok()?;
                        Some(i128::from_le_bytes(bytes))
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let satisfied = actual >= *min_balance;
            ConstraintResult {
                satisfied,
                details: format!("Balance {} vs min {}", actual, min_balance),
            }
        }
        Predicate::MinGovernanceLevel { level } => {
            let satisfied = actor_governance_level <= *level;
            ConstraintResult {
                satisfied,
                details: format!(
                    "Actor level {} vs required {}",
                    actor_governance_level, level
                ),
            }
        }
        Predicate::And(predicates) => {
            for p in predicates {
                let r = evaluate(p, state, actor_governance_level);
                if !r.satisfied {
                    return ConstraintResult {
                        satisfied: false,
                        details: format!("AND failed: {}", r.details),
                    };
                }
            }
            ConstraintResult {
                satisfied: true,
                details: "All AND conditions met".into(),
            }
        }
        Predicate::Or(predicates) => {
            for p in predicates {
                let r = evaluate(p, state, actor_governance_level);
                if r.satisfied {
                    return ConstraintResult {
                        satisfied: true,
                        details: format!("OR satisfied: {}", r.details),
                    };
                }
            }
            ConstraintResult {
                satisfied: false,
                details: "No OR conditions met".into(),
            }
        }
        Predicate::Not(inner) => {
            let r = evaluate(inner, state, actor_governance_level);
            ConstraintResult {
                satisfied: !r.satisfied,
                details: format!("NOT({})", r.details),
            }
        }
        Predicate::True => ConstraintResult {
            satisfied: true,
            details: "Always true".into(),
        },
        Predicate::False => ConstraintResult {
            satisfied: false,
            details: "Always false".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::transition::{StateDelta, StateWrite};

    #[test]
    fn test_exists_predicate() {
        let mut state = ManagedWorldState::new();
        state.apply_delta(&StateDelta {
            writes: vec![StateWrite {
                address: b"key1".to_vec(),
                value: b"val".to_vec(),
            }],
            deletes: vec![],
        });

        let p = Predicate::Exists {
            key: b"key1".to_vec(),
        };
        assert!(evaluate(&p, &state, 0).satisfied);

        let p2 = Predicate::Exists {
            key: b"missing".to_vec(),
        };
        assert!(!evaluate(&p2, &state, 0).satisfied);
    }

    #[test]
    fn test_equals_predicate() {
        let mut state = ManagedWorldState::new();
        state.apply_delta(&StateDelta {
            writes: vec![StateWrite {
                address: b"x".to_vec(),
                value: b"42".to_vec(),
            }],
            deletes: vec![],
        });

        let p = Predicate::Equals {
            key: b"x".to_vec(),
            value: b"42".to_vec(),
        };
        assert!(evaluate(&p, &state, 0).satisfied);

        let p2 = Predicate::Equals {
            key: b"x".to_vec(),
            value: b"99".to_vec(),
        };
        assert!(!evaluate(&p2, &state, 0).satisfied);
    }

    #[test]
    fn test_and_or_not() {
        let state = ManagedWorldState::new();

        let p = Predicate::And(vec![Predicate::True, Predicate::True]);
        assert!(evaluate(&p, &state, 0).satisfied);

        let p2 = Predicate::And(vec![Predicate::True, Predicate::False]);
        assert!(!evaluate(&p2, &state, 0).satisfied);

        let p3 = Predicate::Or(vec![Predicate::False, Predicate::True]);
        assert!(evaluate(&p3, &state, 0).satisfied);

        let p4 = Predicate::Not(Box::new(Predicate::False));
        assert!(evaluate(&p4, &state, 0).satisfied);
    }

    #[test]
    fn test_governance_level() {
        let state = ManagedWorldState::new();

        // Actor level 2 (Meaning) meets requirement of 2.
        let p = Predicate::MinGovernanceLevel { level: 2 };
        assert!(evaluate(&p, &state, 2).satisfied);

        // Actor level 4 (Optimization) does NOT meet requirement of 2.
        assert!(!evaluate(&p, &state, 4).satisfied);
    }

    #[test]
    fn test_complex_contract_precondition() {
        let mut state = ManagedWorldState::new();
        state.apply_delta(&StateDelta {
            writes: vec![
                StateWrite {
                    address: b"contract/active".to_vec(),
                    value: b"true".to_vec(),
                },
                StateWrite {
                    address: b"contract/version".to_vec(),
                    value: b"2".to_vec(),
                },
            ],
            deletes: vec![],
        });

        // Complex precondition: contract must be active AND version must be "2"
        // AND actor must have at least Meaning level (2).
        let precondition = Predicate::And(vec![
            Predicate::Equals {
                key: b"contract/active".to_vec(),
                value: b"true".to_vec(),
            },
            Predicate::Equals {
                key: b"contract/version".to_vec(),
                value: b"2".to_vec(),
            },
            Predicate::MinGovernanceLevel { level: 2 },
        ]);

        // Actor with Meaning level (2) passes.
        assert!(evaluate(&precondition, &state, 2).satisfied);

        // Actor with Optimization level (4) fails governance check.
        assert!(!evaluate(&precondition, &state, 4).satisfied);
    }
}
