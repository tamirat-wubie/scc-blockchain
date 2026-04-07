use crate::balances::BalanceLedger;
use crate::world::ManagedWorldState;
use sccgub_types::tension::TensionValue;
use sccgub_types::transition::{OperationPayload, StateDelta, StateWrite, SymbolicTransition};

/// Apply a block's transitions to state + balances, then write balances to trie.
/// This is the SINGLE SOURCE OF TRUTH for state application.
/// Used by: chain.rs produce_block, cpog.rs validation, cmd_verify, cmd_import, from_blocks.
pub fn apply_block_transitions(
    state: &mut ManagedWorldState,
    balances: &mut BalanceLedger,
    transitions: &[SymbolicTransition],
) {
    for tx in transitions {
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
                let _ = balances.transfer(from, to, TensionValue(*amount));
            }
            _ => {}
        }
    }

    // Write ALL balance entries into trie for unified state root commitment.
    for (agent_id, balance) in &balances.balances {
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
