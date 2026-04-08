use crate::balances::BalanceLedger;
use crate::world::ManagedWorldState;
use sccgub_types::tension::TensionValue;
use sccgub_types::transition::{OperationPayload, StateDelta, StateWrite, SymbolicTransition};

/// Apply a block's transitions to state + balances, then write balances to trie.
/// This is the SINGLE SOURCE OF TRUTH for state application.
/// Used by: chain.rs produce_block, cpog.rs validation, cmd_verify, cmd_import, from_blocks.
///
///
/// Safety: follows checks-effects-interactions pattern —
/// all transfers computed, then state writes applied, then balance trie commitment.
/// No external calls between state reads and writes.
pub fn apply_block_transitions(
    state: &mut ManagedWorldState,
    balances: &mut BalanceLedger,
    transitions: &[SymbolicTransition],
) {
    // Guard: reject duplicate tx_ids within a single block apply.
    // This prevents reentrancy-style double-apply of the same transition.
    let mut applied_ids = std::collections::HashSet::new();

    for tx in transitions {
        if !applied_ids.insert(tx.tx_id) {
            eprintln!(
                "INVARIANT VIOLATION: duplicate tx_id {} in block apply",
                hex::encode(tx.tx_id)
            );
            continue;
        }

        match &tx.payload {
            OperationPayload::Write { key, value } => {
                state.apply_delta(&StateDelta {
                    writes: vec![StateWrite {
                        address: key.clone(),
                        value: value.clone(),
                    }],
                    deletes: vec![],
                });
            }
            OperationPayload::AssetTransfer { from, to, amount } => {
                // Transfer must not fail during apply — validation should have caught it.
                // If it does fail, log it (indicates a consensus bug).
                if let Err(e) = balances.transfer(from, to, TensionValue(*amount)) {
                    eprintln!(
                        "INVARIANT VIOLATION: transfer failed during state apply: {}",
                        e
                    );
                }
            }
            _ => {}
        }
    }

    // Write ALL balance entries into trie for unified state root commitment.
    // Sort by agent_id for deterministic insertion order.
    let mut sorted_balances: Vec<_> = balances.balances.iter().collect();
    sorted_balances.sort_by_key(|(k, _)| *k);
    for (agent_id, balance) in sorted_balances {
        let key = format!("balance/{}", hex::encode(agent_id)).into_bytes();
        state.apply_delta(&StateDelta {
            writes: vec![StateWrite {
                address: key,
                value: balance.raw().to_le_bytes().to_vec(),
            }],
            deletes: vec![],
        });
    }
}

/// Initialize genesis balance in state trie + balance ledger.
pub fn apply_genesis_mint(
    state: &mut ManagedWorldState,
    balances: &mut BalanceLedger,
    validator_id: &[u8; 32],
) {
    let amount = TensionValue::from_integer(1_000_000);
    balances.credit(validator_id, amount);
    let key = format!("balance/{}", hex::encode(validator_id)).into_bytes();
    state.apply_delta(&StateDelta {
        writes: vec![StateWrite {
            address: key,
            value: amount.raw().to_le_bytes().to_vec(),
        }],
        deletes: vec![],
    });
}

/// Reconstruct balance ledger from trie balance entries.
///
/// Reads all keys starting with "balance/" and deserializes
/// i128 values from little-endian bytes.
pub fn balances_from_trie(state: &ManagedWorldState) -> BalanceLedger {
    let mut balances = BalanceLedger::new();
    for (key, value) in state.trie.iter() {
        if key.starts_with(b"balance/") && value.len() == 16 {
            if let Ok(agent_bytes) = hex::decode(&key[8..]) {
                if agent_bytes.len() == 32 {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&agent_bytes);
                    let mut raw = [0u8; 16];
                    raw.copy_from_slice(value);
                    balances
                        .balances
                        .insert(id, TensionValue(i128::from_le_bytes(raw)));
                }
            }
        }
    }
    balances
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
    use sccgub_types::governance::PrecedenceLevel;
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::timestamp::CausalTimestamp;
    use sccgub_types::transition::*;
    use std::collections::HashSet;

    fn make_write_tx(key: &[u8], value: &[u8], nonce: u128) -> SymbolicTransition {
        let mut tx_id = [0u8; 32];
        tx_id[0] = nonce as u8;
        tx_id[1] = key.first().copied().unwrap_or(0);

        SymbolicTransition {
            tx_id,
            actor: AgentIdentity {
                agent_id: [1u8; 32],
                public_key: [0u8; 32],
                mfidel_seal: MfidelAtomicSeal::from_height(0),
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: HashSet::new(),
                responsibility: ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::StateWrite,
                target: key.to_vec(),
                declared_purpose: "test".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: key.to_vec(),
                value: value.to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: [1u8; 32],
                when: CausalTimestamp::genesis(),
                r#where: key.to_vec(),
                why: CausalJustification {
                    invoking_rule: [0u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: HashSet::new(),
                what_declared: "test".into(),
            },
            nonce,
            signature: vec![0u8; 64],
        }
    }

    fn make_transfer_tx(
        from: [u8; 32],
        to: [u8; 32],
        amount: i128,
        nonce: u128,
    ) -> SymbolicTransition {
        let mut tx_id = [0u8; 32];
        tx_id[0] = nonce as u8;
        tx_id[1] = from[0];

        SymbolicTransition {
            tx_id,
            actor: AgentIdentity {
                agent_id: from,
                public_key: [0u8; 32],
                mfidel_seal: MfidelAtomicSeal::from_height(0),
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: HashSet::new(),
                responsibility: ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::AssetTransfer,
                target: b"transfer".to_vec(),
                declared_purpose: "test transfer".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::AssetTransfer { from, to, amount },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: from,
                when: CausalTimestamp::genesis(),
                r#where: b"transfer".to_vec(),
                why: CausalJustification {
                    invoking_rule: [0u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: HashSet::new(),
                what_declared: "test".into(),
            },
            nonce,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn test_apply_writes_to_trie() {
        let mut state = ManagedWorldState::new();
        let mut balances = BalanceLedger::new();

        let txs = vec![
            make_write_tx(b"key/a", b"val_a", 1),
            make_write_tx(b"key/b", b"val_b", 2),
        ];

        apply_block_transitions(&mut state, &mut balances, &txs);

        assert_eq!(state.trie.get(&b"key/a".to_vec()), Some(&b"val_a".to_vec()));
        assert_eq!(state.trie.get(&b"key/b".to_vec()), Some(&b"val_b".to_vec()));
    }

    #[test]
    fn test_apply_transfers_update_balances() {
        let mut state = ManagedWorldState::new();
        let mut balances = BalanceLedger::new();
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        balances.credit(&alice, TensionValue::from_integer(1000));

        let amount = TensionValue::from_integer(300).raw();
        let txs = vec![make_transfer_tx(alice, bob, amount, 1)];

        apply_block_transitions(&mut state, &mut balances, &txs);

        assert_eq!(balances.balance_of(&alice), TensionValue::from_integer(700));
        assert_eq!(balances.balance_of(&bob), TensionValue::from_integer(300));
    }

    #[test]
    fn test_apply_writes_balances_to_trie() {
        let mut state = ManagedWorldState::new();
        let mut balances = BalanceLedger::new();
        let validator = [1u8; 32];
        balances.credit(&validator, TensionValue::from_integer(5000));

        apply_block_transitions(&mut state, &mut balances, &[]);

        // Balance should be in the trie.
        let key = format!("balance/{}", hex::encode(validator)).into_bytes();
        assert!(state.trie.get(&key).is_some());
    }

    #[test]
    fn test_apply_duplicate_txid_skipped() {
        let mut state = ManagedWorldState::new();
        let mut balances = BalanceLedger::new();

        let tx = make_write_tx(b"dup/key", b"first", 1);
        let mut dup = make_write_tx(b"dup/key", b"second", 2);
        dup.tx_id = tx.tx_id; // Same tx_id.

        apply_block_transitions(&mut state, &mut balances, &[tx, dup]);

        // Only first should be applied.
        assert_eq!(
            state.trie.get(&b"dup/key".to_vec()),
            Some(&b"first".to_vec())
        );
    }

    #[test]
    fn test_genesis_mint() {
        let mut state = ManagedWorldState::new();
        let mut balances = BalanceLedger::new();
        let validator = [42u8; 32];

        apply_genesis_mint(&mut state, &mut balances, &validator);

        assert_eq!(
            balances.balance_of(&validator),
            TensionValue::from_integer(1_000_000)
        );
        // Balance in trie.
        let key = format!("balance/{}", hex::encode(validator)).into_bytes();
        assert!(state.trie.get(&key).is_some());
    }

    #[test]
    fn test_balances_from_trie_roundtrip() {
        let mut state = ManagedWorldState::new();
        let mut balances = BalanceLedger::new();
        let a1 = [1u8; 32];
        let a2 = [2u8; 32];

        balances.credit(&a1, TensionValue::from_integer(500));
        balances.credit(&a2, TensionValue::from_integer(300));

        // Write balances to trie.
        apply_block_transitions(&mut state, &mut balances, &[]);

        // Reconstruct.
        let recovered = balances_from_trie(&state);
        assert_eq!(recovered.balance_of(&a1), TensionValue::from_integer(500));
        assert_eq!(recovered.balance_of(&a2), TensionValue::from_integer(300));
        assert_eq!(recovered.total_supply(), balances.total_supply());
    }
}
