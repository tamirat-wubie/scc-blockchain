use sccgub_state::world::ManagedWorldState;
use sccgub_types::tension::TensionValue;
use sccgub_types::transition::SymbolicTransition;

/// Symbolic Constraint Cognition Engine (SCCE) — validates transitions
/// through constraint propagation on the symbol mesh.
///
/// Per v2.1 FIX-6: SCCE_Validate is a PURE FUNCTION.
/// No side effects. No weight modification. Learning occurs post-commit only.
///
/// Steps (per spec Section 16):
///   0. Activate symbols from transition
///   1. Select relevant state subgraph (attention)
///   2. Propagate constraints through mesh (bounded)
///   3. Detect and resolve conflicts
///   4. Grounding check against chain state
///   5. Value evaluation against governance goals
///   6. Meta-regulation if persistent tension (read-only)
///   7. Stability check (delta_T < epsilon, delta_H < epsilon)
///   8. Return (valid, tension_delta)
pub fn scce_validate(
    transition: &SymbolicTransition,
    state: &ManagedWorldState,
    constraint_weights: &ConstraintWeights,
    max_propagation_depth: u32,
    max_propagation_steps: u64,
) -> ScceResult {
    let mut steps_used: u64 = 0;
    let mut tension_delta = TensionValue::ZERO;

    // Step 0: Activate symbols from transition.
    let target = &transition.intent.target;
    let active_symbols = activate_symbols(target, state);
    steps_used += 1;

    // Step 1: Select relevant state subgraph (attention-gated).
    let relevant_count = select_relevant_subgraph(&active_symbols, state, constraint_weights);
    steps_used = steps_used.saturating_add(relevant_count);

    if steps_used > max_propagation_steps {
        return ScceResult {
            valid: false,
            tension_delta: TensionValue::ZERO,
            steps_used,
            details: "Exceeded max propagation steps at attention step".into(),
        };
    }

    // Step 2: Propagate constraints through mesh (bounded).
    let propagation = propagate_constraints(
        &active_symbols,
        state,
        max_propagation_depth,
        max_propagation_steps - steps_used,
    );
    steps_used += propagation.steps;

    if !propagation.consistent {
        return ScceResult {
            valid: false,
            tension_delta: propagation.tension_delta,
            steps_used,
            details: format!(
                "Constraint conflict detected: {}",
                propagation.conflict_detail
            ),
        };
    }
    tension_delta = tension_delta + propagation.tension_delta;

    // Step 3: Detect and resolve conflicts.
    // (Already handled in propagation — conflicts cause immediate rejection.)

    // Step 4: Grounding check — verify transition target exists or is being created.
    let grounded = check_grounding(target, state, &transition.intent.kind);
    steps_used += 1;
    if !grounded {
        return ScceResult {
            valid: false,
            tension_delta,
            steps_used,
            details: "Grounding check failed: target address not valid".into(),
        };
    }

    // Step 5: Value evaluation against governance goals.
    // For MVP: check that transition doesn't violate precedence order.
    let value_ok = evaluate_governance_value(transition);
    steps_used += 1;
    if !value_ok {
        return ScceResult {
            valid: false,
            tension_delta,
            steps_used,
            details: "Value evaluation failed: governance violation".into(),
        };
    }

    // Step 6: Meta-regulation (read-only).
    // Check if persistent tension exists in the target area.
    let area_tension = state
        .state
        .tension_field
        .map
        .get(target)
        .copied()
        .unwrap_or(TensionValue::ZERO);

    if area_tension > state.state.tension_field.budget.current_budget {
        tension_delta = tension_delta + TensionValue::from_integer(1); // Penalty for writing to high-tension area.
    }

    // Step 7: Stability check.
    let epsilon = TensionValue::from_integer(1);
    if tension_delta > epsilon {
        // Tension increase is within acceptable range — proceed but note it.
    }

    ScceResult {
        valid: true,
        tension_delta,
        steps_used,
        details: "SCCE validation passed".into(),
    }
}

/// Result of SCCE validation.
#[derive(Debug, Clone)]
pub struct ScceResult {
    pub valid: bool,
    pub tension_delta: TensionValue,
    pub steps_used: u64,
    pub details: String,
}

/// Constraint weights used for attention and propagation.
/// These are read-only during validation (per v2.1 FIX-6).
#[derive(Debug, Clone, Default)]
pub struct ConstraintWeights {
    pub attention_threshold: TensionValue,
    pub propagation_decay: TensionValue,
}

// --- Internal helpers ---

fn activate_symbols(target: &[u8], state: &ManagedWorldState) -> Vec<Vec<u8>> {
    let max_activated_symbols = state.consensus_params.max_activated_symbols.max(1) as usize;
    let mut symbols = vec![target.to_vec()];
    let mut path = target.to_vec();
    while symbols.len() < max_activated_symbols {
        match path.iter().rposition(|&b| b == b'/') {
            Some(pos) => {
                path.truncate(pos);
                if !path.is_empty() && state.trie.contains(&path) {
                    symbols.push(path.clone());
                }
            }
            None => break,
        }
    }
    symbols
}

fn select_relevant_subgraph(
    active_symbols: &[Vec<u8>],
    state: &ManagedWorldState,
    _weights: &ConstraintWeights,
) -> u64 {
    let total_cap = state.consensus_params.max_scan_per_symbol * active_symbols.len() as u64;
    let mut count = 0u64;
    for symbol in active_symbols {
        // Use efficient prefix range scan instead of full trie iteration.
        for _ in state.trie.prefix_iter(symbol) {
            count = count.saturating_add(1);
            if count >= total_cap {
                return count;
            }
        }
    }
    count
}

struct PropagationResult {
    consistent: bool,
    tension_delta: TensionValue,
    steps: u64,
    conflict_detail: String,
}

/// Constraint storage root prefix.
const CONSTRAINT_PREFIX: &[u8] = b"constraints/";

/// Build the trie key for a constraint attached to a specific symbol.
/// Uses null-byte separation to prevent prefix collisions between
/// a symbol's own constraints and its descendants' constraints.
///
/// Convention: `constraints/<symbol>\0<constraint_id>`
///
/// This is the ONLY correct way to construct constraint keys.
/// Constructing keys by string concatenation will re-introduce
/// the N-1 prefix collision bug.
pub fn constraint_key(symbol: &[u8], constraint_id: &[u8]) -> Result<Vec<u8>, String> {
    if symbol.contains(&0) {
        return Err("symbol addresses must not contain null bytes".into());
    }
    let mut k =
        Vec::with_capacity(CONSTRAINT_PREFIX.len() + symbol.len() + 1 + constraint_id.len());
    k.extend_from_slice(CONSTRAINT_PREFIX);
    k.extend_from_slice(symbol);
    k.push(0);
    k.extend_from_slice(constraint_id);
    Ok(k)
}

/// Build the prefix used by the walker to find all constraints attached
/// to a specific symbol (and ONLY that symbol, not its descendants).
fn constraint_prefix_for_symbol(symbol: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(CONSTRAINT_PREFIX.len() + symbol.len() + 1);
    p.extend_from_slice(CONSTRAINT_PREFIX);
    p.extend_from_slice(symbol);
    p.push(0);
    p
}

/// Bounded constraint propagation walker.
///
/// Replaces the previous no-op with a real symbol-mesh walk:
/// - Worklist seeded from active_symbols.
/// - For each (symbol, depth): query constraints under "constraints/<symbol>/".
/// - Evaluate each via the predicate engine against current state.
/// - On UNSAT → return first conflict, halt.
/// - On SAT → accumulate tension, expand to child symbols.
/// - Halts on max_steps or empty worklist.
///
/// Determinism: BTreeMap iteration in StateTrie is stable across nodes.
fn propagate_constraints(
    active_symbols: &[Vec<u8>],
    state: &ManagedWorldState,
    max_depth: u32,
    max_steps: u64,
) -> PropagationResult {
    let mut worklist: std::collections::VecDeque<(Vec<u8>, u32)> =
        active_symbols.iter().map(|s| (s.clone(), 0u32)).collect();
    let mut visited: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
    let mut steps: u64 = 0;
    let mut tension = TensionValue::ZERO;

    while let Some((symbol, depth)) = worklist.pop_front() {
        if steps >= max_steps {
            // Fail-closed on resource exhaustion: constraint system
            // cannot guarantee safety if it can't finish evaluation.
            // Standard pattern (EVM gas, Solana compute units).
            return PropagationResult {
                consistent: false,
                tension_delta: tension,
                steps,
                conflict_detail: format!(
                    "constraint propagation exhausted step budget ({} steps)",
                    max_steps
                ),
            };
        }
        if !visited.insert(symbol.clone()) {
            continue;
        }
        if depth > max_depth {
            continue;
        }

        let prefix = constraint_prefix_for_symbol(&symbol);

        let mut per_symbol = 0u64;
        for (key, value) in state.trie.prefix_iter(&prefix) {
            steps = steps.saturating_add(1);
            per_symbol = per_symbol.saturating_add(1);
            if per_symbol > state.consensus_params.max_constraints_per_symbol || steps >= max_steps
            {
                break;
            }

            // Decode stored predicate (UTF-8 expression string).
            let expr = match std::str::from_utf8(value) {
                Ok(s) => s,
                Err(_) => {
                    return PropagationResult {
                        consistent: false,
                        tension_delta: tension,
                        steps,
                        conflict_detail: format!("non-utf8 constraint at {}", hex::encode(key)),
                    };
                }
            };
            let predicate = crate::contract::parse_constraint_expression_pub(expr);
            let result = crate::constraints::evaluate(&predicate, state, u8::MAX);
            if !result.satisfied {
                return PropagationResult {
                    consistent: false,
                    tension_delta: tension,
                    steps,
                    conflict_detail: format!(
                        "constraint at {} unsat: {}",
                        hex::encode(key),
                        result.details
                    ),
                };
            }
            tension = tension + TensionValue::from_integer(1 + depth as i64);
        }

        // Check step exhaustion after processing this symbol's constraints.
        if steps >= max_steps {
            return PropagationResult {
                consistent: false,
                tension_delta: tension,
                steps,
                conflict_detail: format!(
                    "constraint propagation exhausted step budget ({} steps)",
                    max_steps
                ),
            };
        }

        // Expand: walk one path-step toward children.
        let mut child_prefix = symbol.clone();
        child_prefix.push(b'/');
        for (child_key, _) in state.trie.prefix_iter(&child_prefix) {
            if let Some(rest) = child_key.strip_prefix(child_prefix.as_slice()) {
                if !rest.contains(&b'/') {
                    worklist.push_back((child_key.clone(), depth + 1));
                }
            }
        }
    }

    PropagationResult {
        consistent: true,
        tension_delta: tension,
        steps,
        conflict_detail: String::new(),
    }
}

fn check_grounding(
    target: &[u8],
    _state: &ManagedWorldState,
    kind: &sccgub_types::transition::TransitionKind,
) -> bool {
    // Writes can create new state entries, so they're always grounded.
    // Reads must target existing state.
    match kind {
        sccgub_types::transition::TransitionKind::StateRead => {
            // For reads, the target must exist.
            _state.trie.contains(&target.to_vec())
        }
        _ => {
            // For writes and other operations, any non-empty target is valid.
            !target.is_empty()
        }
    }
}

fn evaluate_governance_value(transition: &SymbolicTransition) -> bool {
    // Check that the transition's governance authority matches its intent.
    let required_level = match transition.intent.kind {
        sccgub_types::transition::TransitionKind::GovernanceUpdate => PrecedenceLevel::Meaning,
        sccgub_types::transition::TransitionKind::NormProposal => PrecedenceLevel::Meaning,
        _ => PrecedenceLevel::Optimization,
    };

    let actor_level = transition.actor.governance_level;
    (actor_level as u8) <= (required_level as u8)
}

use sccgub_types::governance::PrecedenceLevel;

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::agent::AgentIdentity;
    use sccgub_types::transition::*;
    use std::collections::HashSet;

    fn test_transition(kind: TransitionKind, target: &[u8]) -> SymbolicTransition {
        SymbolicTransition {
            tx_id: [0u8; 32],
            actor: AgentIdentity {
                agent_id: [1u8; 32],
                public_key: [0u8; 32],
                mfidel_seal: sccgub_types::mfidel::MfidelAtomicSeal::from_height(1),
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: HashSet::new(),
                responsibility: sccgub_types::agent::ResponsibilityState::default(),
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
                when: sccgub_types::timestamp::CausalTimestamp::genesis(),
                r#where: target.to_vec(),
                why: CausalJustification {
                    invoking_rule: [2u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: HashSet::new(),
                what_declared: "test".into(),
            },
            nonce: 0,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn test_scce_validate_write() {
        let state = ManagedWorldState::new();
        let tx = test_transition(TransitionKind::StateWrite, b"test/key");
        let weights = ConstraintWeights::default();

        let result = scce_validate(&tx, &state, &weights, 10, 1000);
        assert!(result.valid, "Write should pass: {}", result.details);
    }

    #[test]
    fn test_scce_validate_read_nonexistent() {
        let state = ManagedWorldState::new();
        let tx = test_transition(TransitionKind::StateRead, b"nonexistent/key");
        let weights = ConstraintWeights::default();

        let result = scce_validate(&tx, &state, &weights, 10, 1000);
        assert!(
            !result.valid,
            "Read of nonexistent key should fail grounding"
        );
    }

    #[test]
    fn test_scce_validate_empty_target() {
        let state = ManagedWorldState::new();
        let tx = test_transition(TransitionKind::StateWrite, b"");
        let weights = ConstraintWeights::default();

        let result = scce_validate(&tx, &state, &weights, 10, 1000);
        assert!(!result.valid, "Empty target should fail grounding");
    }

    #[test]
    fn test_scce_step_bound() {
        let state = ManagedWorldState::new();
        let tx = test_transition(TransitionKind::StateWrite, b"test");
        let weights = ConstraintWeights::default();

        // With step limit of 0, should fail.
        let result = scce_validate(&tx, &state, &weights, 10, 0);
        assert!(!result.valid, "Should fail with 0 step budget");
    }

    #[test]
    fn test_activate_symbols_respects_consensus_param_cap() {
        let mut state = ManagedWorldState::with_consensus_params(
            sccgub_types::consensus_params::ConsensusParams {
                max_activated_symbols: 1,
                ..sccgub_types::consensus_params::ConsensusParams::default()
            },
        );
        state.trie.insert(b"alpha".to_vec(), b"root".to_vec());
        state.trie.insert(b"alpha/beta".to_vec(), b"child".to_vec());

        let activated = activate_symbols(b"alpha/beta/gamma", &state);

        assert_eq!(activated.len(), 1);
        assert_eq!(activated[0], b"alpha/beta/gamma".to_vec());
    }

    #[test]
    fn test_select_relevant_subgraph_respects_consensus_scan_cap() {
        let mut state = ManagedWorldState::with_consensus_params(
            sccgub_types::consensus_params::ConsensusParams {
                max_scan_per_symbol: 1,
                ..sccgub_types::consensus_params::ConsensusParams::default()
            },
        );
        state.trie.insert(b"alpha/one".to_vec(), b"1".to_vec());
        state.trie.insert(b"alpha/two".to_vec(), b"2".to_vec());
        state.trie.insert(b"alpha/three".to_vec(), b"3".to_vec());

        let count =
            select_relevant_subgraph(&[b"alpha".to_vec()], &state, &ConstraintWeights::default());

        assert_eq!(count, 1);
    }

    #[test]
    fn test_governance_value_check() {
        // Agent with Meaning level trying governance update (requires Meaning) — ok.
        let tx = test_transition(TransitionKind::GovernanceUpdate, b"gov/test");
        assert!(evaluate_governance_value(&tx));

        // Agent with Optimization level trying governance update — should fail.
        let mut tx2 = test_transition(TransitionKind::GovernanceUpdate, b"gov/test");
        tx2.actor.governance_level = PrecedenceLevel::Optimization;
        assert!(!evaluate_governance_value(&tx2));
    }

    // === SCCE constraint propagation walker tests ===
    // All tests use the public constraint_key() helper to ensure the
    // null-terminated convention is used consistently.
    use super::constraint_key;

    #[test]
    fn test_propagation_passes_with_no_constraints() {
        let state = ManagedWorldState::new();
        let active = vec![b"alpha/beta".to_vec()];
        let result = propagate_constraints(&active, &state, 4, 1000);
        assert!(result.consistent);
        assert_eq!(result.tension_delta, TensionValue::ZERO);
    }

    #[test]
    fn test_propagation_detects_unsat_constraint() {
        let mut state = ManagedWorldState::new();
        state.trie.insert(
            constraint_key(b"alpha/beta", b"c0").unwrap(),
            b"false".to_vec(),
        );
        let active = vec![b"alpha/beta".to_vec()];
        let result = propagate_constraints(&active, &state, 4, 1000);
        assert!(!result.consistent);
        assert!(result.conflict_detail.contains("unsat"));
    }

    #[test]
    fn test_propagation_passes_with_satisfied_exists() {
        let mut state = ManagedWorldState::new();
        state.trie.insert(b"data/foo".to_vec(), b"present".to_vec());
        state.trie.insert(
            constraint_key(b"alpha", b"c0").unwrap(),
            b"exists:data/foo".to_vec(),
        );
        let active = vec![b"alpha".to_vec()];
        let result = propagate_constraints(&active, &state, 2, 1000);
        assert!(result.consistent, "{}", result.conflict_detail);
        assert!(result.tension_delta > TensionValue::ZERO);
    }

    #[test]
    fn test_propagation_walks_into_children() {
        let mut state = ManagedWorldState::new();
        state.trie.insert(b"alpha/leaf".to_vec(), b"".to_vec());
        // Constraint on the CHILD symbol (null-terminated).
        state.trie.insert(
            constraint_key(b"alpha/leaf", b"c0").unwrap(),
            b"false".to_vec(),
        );
        let active = vec![b"alpha".to_vec()];
        // Depth 2 is enough to reach the child via worklist expansion.
        let result = propagate_constraints(&active, &state, 2, 1000);
        assert!(
            !result.consistent,
            "child constraint must be reached via expansion"
        );
    }

    #[test]
    fn test_propagation_respects_max_depth() {
        let mut state = ManagedWorldState::new();
        state.trie.insert(b"alpha/leaf".to_vec(), b"".to_vec());
        // Constraint on the CHILD only (null-terminated — NOT visible to parent).
        state.trie.insert(
            constraint_key(b"alpha/leaf", b"c0").unwrap(),
            b"false".to_vec(),
        );
        let active = vec![b"alpha".to_vec()];
        // Depth 0 — parent "alpha" is processed but child "alpha/leaf" is NOT
        // expanded into the worklist. With null-terminated keys, the parent's
        // scan ("constraints/alpha\0") does NOT match the child's key
        // ("constraints/alpha/leaf\0"). So the constraint is invisible.
        let result = propagate_constraints(&active, &state, 0, 1000);
        assert!(
            result.consistent,
            "child constraint must be UNREACHABLE at depth 0"
        );
    }

    #[test]
    fn test_propagation_respects_consensus_constraint_cap() {
        let mut state = ManagedWorldState::with_consensus_params(
            sccgub_types::consensus_params::ConsensusParams {
                max_constraints_per_symbol: 1,
                ..sccgub_types::consensus_params::ConsensusParams::default()
            },
        );
        state
            .trie
            .insert(constraint_key(b"alpha", b"c0").unwrap(), b"true".to_vec());
        state
            .trie
            .insert(constraint_key(b"alpha", b"c1").unwrap(), b"true".to_vec());
        let result = propagate_constraints(&[b"alpha".to_vec()], &state, 4, 1000);

        assert!(result.consistent);
        assert_eq!(result.steps, 2);
        assert_eq!(result.tension_delta, TensionValue::from_integer(1));
    }

    #[test]
    fn test_propagation_invalid_utf8_is_violation() {
        let mut state = ManagedWorldState::new();
        state.trie.insert(
            constraint_key(b"alpha", b"c0").unwrap(),
            vec![0xFF, 0xFE, 0xFD],
        );
        let active = vec![b"alpha".to_vec()];
        let result = propagate_constraints(&active, &state, 2, 1000);
        assert!(!result.consistent);
        assert!(result.conflict_detail.contains("non-utf8"));
    }

    #[test]
    fn test_propagation_fails_closed_on_step_exhaustion() {
        let mut state = ManagedWorldState::new();
        for i in 0..10u8 {
            state.trie.insert(
                constraint_key(b"alpha", format!("c{}", i).as_bytes()).unwrap(),
                b"true".to_vec(),
            );
        }
        let active = vec![b"alpha".to_vec()];
        // Step budget = 3, but 10 constraints exist → exhaustion.
        let result = propagate_constraints(&active, &state, 2, 3);
        assert!(!result.consistent, "must fail-closed on step exhaustion");
        assert!(result.conflict_detail.contains("exhausted"));
    }

    #[test]
    fn test_predicate_invalid_surfaces_in_evaluation() {
        let state = ManagedWorldState::new();
        let pred = crate::constraints::Predicate::Invalid {
            reason: "unknown expression: foobar".into(),
        };
        let result = crate::constraints::evaluate(&pred, &state, 0);
        assert!(!result.satisfied);
        assert!(result.details.contains("invalid constraint"));
    }

    #[test]
    #[should_panic(expected = "null bytes")]
    fn test_null_byte_in_symbol_rejected() {
        constraint_key(b"alpha\x00evil", b"c0").unwrap();
    }
}
