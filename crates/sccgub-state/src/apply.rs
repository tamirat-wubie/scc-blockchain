use crate::balances::BalanceLedger;
use crate::treasury::{
    commit_treasury_state, state_has_treasury_keys, treasury_state_writes, Treasury,
};
use crate::world::ManagedWorldState;
use sccgub_crypto::canonical::canonical_bytes;
use sccgub_crypto::hash::blake3_hash_concat;
use sccgub_types::block::LEGACY_BLOCK_VERSION;
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::receipt::CausalReceipt;
use sccgub_types::tension::TensionValue;
use sccgub_types::transition::{OperationPayload, StateDelta, StateWrite, SymbolicTransition};

fn commit_balance_accounts(
    state: &mut ManagedWorldState,
    balances: &BalanceLedger,
    changed_accounts: &std::collections::HashSet<[u8; 32]>,
) {
    let mut dirty_accounts: Vec<_> = changed_accounts.iter().copied().collect();
    dirty_accounts.sort_unstable();

    for agent_id in dirty_accounts {
        let key = sccgub_types::namespace::balance_key(&agent_id);
        let value = balances.balance_of(&agent_id).raw().to_le_bytes().to_vec();
        state.apply_delta(&StateDelta {
            writes: vec![StateWrite {
                address: key,
                value,
            }],
            deletes: vec![],
        });
    }
}

fn merge_state_deltas(left: &StateDelta, right: &StateDelta) -> StateDelta {
    let mut writes = Vec::with_capacity(left.writes.len() + right.writes.len());
    writes.extend(left.writes.clone());
    writes.extend(right.writes.clone());

    let mut deletes = Vec::with_capacity(left.deletes.len() + right.deletes.len());
    deletes.extend(left.deletes.clone());
    deletes.extend(right.deletes.clone());

    StateDelta { writes, deletes }
}

/// Resolve the validator reward/mint account for a given block version.
///
/// v1 preserves the legacy signer-public-key account for replay compatibility.
/// v2 and later fund the canonical validator agent account derived from the
/// validator public key plus the genesis Mfidel seal.
pub fn validator_spend_account(block_version: u32, validator_public_key: &[u8; 32]) -> [u8; 32] {
    if block_version == LEGACY_BLOCK_VERSION {
        *validator_public_key
    } else {
        blake3_hash_concat(&[
            validator_public_key,
            &canonical_bytes(&MfidelAtomicSeal::from_height(0)),
        ])
    }
}

/// Deterministically resolve the funding account for a transaction fee.
///
/// v1 preserves the legacy signer-public-key fallback for replay compatibility.
/// v2 and later charge only the canonical actor account keyed by `actor.agent_id`.
pub fn resolve_fee_payer(
    block_version: u32,
    balances: &BalanceLedger,
    tx: &SymbolicTransition,
    fee: TensionValue,
) -> Result<[u8; 32], String> {
    if fee.raw() <= 0 {
        return Ok(tx.actor.agent_id);
    }

    let actor_balance = balances.balance_of(&tx.actor.agent_id);
    if actor_balance.raw() >= fee.raw() {
        return Ok(tx.actor.agent_id);
    }

    let signer_account = tx.actor.public_key;
    if block_version == LEGACY_BLOCK_VERSION && signer_account != tx.actor.agent_id {
        let signer_balance = balances.balance_of(&signer_account);
        if signer_balance.raw() >= fee.raw() {
            return Ok(signer_account);
        }
    }

    Err(format!(
        "Insufficient fee balance for tx {}: actor {} has {}, signer {} has {}, fee {}",
        hex::encode(tx.tx_id),
        hex::encode(tx.actor.agent_id),
        actor_balance,
        hex::encode(signer_account),
        balances.balance_of(&signer_account),
        fee
    ))
}

#[derive(Debug, Clone)]
pub struct BlockEconomicsOutcome {
    pub tx_deltas: Vec<StateDelta>,
    pub tx_fees: Vec<TensionValue>,
    pub tx_fee_payers: Vec<[u8; 32]>,
    pub total_fees: TensionValue,
    pub actual_reward: TensionValue,
}

/// Apply fee collection and block reward using only consensus-visible inputs.
///
/// Fees are derived from accepted receipts plus the gas price, then charged to
/// the resolved fee payer account before payload transitions run. The treasury
/// state is committed into the trie whenever economics changed, or whenever the
/// trie already contains treasury keys and must remain stable across replay.
#[allow(clippy::too_many_arguments)]
pub fn apply_block_economics(
    state: &mut ManagedWorldState,
    balances: &mut BalanceLedger,
    treasury: &mut Treasury,
    transitions: &[SymbolicTransition],
    receipts: &[CausalReceipt],
    block_version: u32,
    validator_public_key: &[u8; 32],
    gas_price: TensionValue,
    requested_reward: TensionValue,
) -> Result<BlockEconomicsOutcome, String> {
    if !receipts.is_empty() && receipts.len() != transitions.len() {
        return Err(format!(
            "Receipt count mismatch for economics replay: {} transitions, {} receipts",
            transitions.len(),
            receipts.len()
        ));
    }

    let mut changed_balance_accounts = std::collections::HashSet::new();
    let mut tx_deltas = Vec::with_capacity(transitions.len());
    let mut tx_fees = Vec::with_capacity(transitions.len());
    let mut tx_fee_payers = Vec::with_capacity(transitions.len());
    let mut total_fees = TensionValue::ZERO;

    if receipts.is_empty() {
        for tx in transitions {
            tx_deltas.push(StateDelta::default());
            tx_fees.push(TensionValue::ZERO);
            tx_fee_payers.push(tx.actor.agent_id);
        }
    } else {
        for (tx, receipt) in transitions.iter().zip(receipts.iter()) {
            if receipt.tx_id != tx.tx_id {
                return Err(format!(
                    "Receipt/transition mismatch: tx {} paired with receipt {}",
                    hex::encode(tx.tx_id),
                    hex::encode(receipt.tx_id)
                ));
            }
            if !receipt.verdict.is_accepted() {
                return Err(format!(
                    "Included receipt for tx {} is not accepted",
                    hex::encode(tx.tx_id)
                ));
            }

            let fee = TensionValue(
                (receipt.resource_used.compute_steps as i128).saturating_mul(gas_price.raw()),
            );
            let payer = resolve_fee_payer(block_version, balances, tx, fee)?;
            let mut fee_delta = StateDelta::default();

            if fee.raw() > 0 {
                balances.debit(&payer, fee).map_err(|e| {
                    format!(
                        "Fee debit failed for tx {} from payer {}: {}",
                        hex::encode(tx.tx_id),
                        hex::encode(payer),
                        e
                    )
                })?;
                changed_balance_accounts.insert(payer);
                treasury.collect_fee(fee);
                total_fees = total_fees + fee;

                fee_delta = StateDelta {
                    writes: {
                        let mut writes =
                            Vec::with_capacity(1 + treasury_state_writes(treasury).len());
                        writes.push(StateWrite {
                            address: sccgub_types::namespace::balance_key(&payer),
                            value: balances.balance_of(&payer).raw().to_le_bytes().to_vec(),
                        });
                        writes.extend(treasury_state_writes(treasury));
                        writes
                    },
                    deletes: vec![],
                };
            }

            tx_deltas.push(fee_delta);
            tx_fees.push(fee);
            tx_fee_payers.push(payer);
        }
    }

    let validator_reward_account = validator_spend_account(block_version, validator_public_key);
    let actual_reward = treasury.distribute_reward(requested_reward);
    if actual_reward.raw() > 0 {
        balances.credit(&validator_reward_account, actual_reward);
        changed_balance_accounts.insert(validator_reward_account);
    }

    commit_balance_accounts(state, balances, &changed_balance_accounts);
    if total_fees.raw() > 0 || actual_reward.raw() > 0 || state_has_treasury_keys(state) {
        commit_treasury_state(state, treasury);
    }

    Ok(BlockEconomicsOutcome {
        tx_deltas,
        tx_fees,
        tx_fee_payers,
        total_fees,
        actual_reward,
    })
}

/// Apply a block's transitions to state + balances, then write changed balances to trie.
/// This is the SINGLE SOURCE OF TRUTH for state application.
/// Used by: chain.rs produce_block, cpog.rs validation, cmd_verify, cmd_import, from_blocks.
///
/// N-9: Returns a `Vec<StateDelta>` of per-transition deltas in input order.
/// Each entry captures the actual writes performed by the corresponding transition.
/// Duplicate-tx_id rejections produce an empty `StateDelta::default()` at that index
/// so caller indexing matches the input slice. Callers that need per-tx attribution
/// (e.g., for `WHBindingResolved.what_actual`) should consume this vec; callers that
/// only need the side effects on `state` and `balances` may discard it.
///
/// Safety: follows checks-effects-interactions pattern —
/// all transfers computed, then state writes applied, then changed-balance trie commitment.
/// No external calls between state reads and writes.
pub fn apply_block_transitions(
    state: &mut ManagedWorldState,
    balances: &mut BalanceLedger,
    transitions: &[SymbolicTransition],
) -> Vec<StateDelta> {
    // Guard: reject duplicate tx_ids within a single block apply.
    // This prevents reentrancy-style double-apply of the same transition.
    let mut applied_ids = std::collections::HashSet::new();
    let mut changed_balance_accounts = std::collections::HashSet::new();
    let mut per_tx_deltas: Vec<StateDelta> = Vec::with_capacity(transitions.len());

    for tx in transitions {
        if !applied_ids.insert(tx.tx_id) {
            eprintln!(
                "INVARIANT VIOLATION: duplicate tx_id {} in block apply",
                hex::encode(tx.tx_id)
            );
            per_tx_deltas.push(StateDelta::default());
            continue;
        }

        let tx_delta = match &tx.payload {
            OperationPayload::Write { key, value } => {
                let delta = StateDelta {
                    writes: vec![StateWrite {
                        address: key.clone(),
                        value: value.clone(),
                    }],
                    deletes: vec![],
                };
                state.apply_delta(&delta);
                delta
            }
            OperationPayload::AssetTransfer { from, to, amount } => {
                // Transfer must not fail during apply — validation should have caught it.
                match balances.transfer(from, to, TensionValue(*amount)) {
                    Ok(()) => {
                        changed_balance_accounts.insert(*from);
                        changed_balance_accounts.insert(*to);
                        // Capture both balance writes for per-tx attribution.
                        let from_bal = balances.balance_of(from).raw().to_le_bytes().to_vec();
                        let to_bal = balances.balance_of(to).raw().to_le_bytes().to_vec();
                        StateDelta {
                            writes: vec![
                                StateWrite {
                                    address: sccgub_types::namespace::balance_key(from),
                                    value: from_bal,
                                },
                                StateWrite {
                                    address: sccgub_types::namespace::balance_key(to),
                                    value: to_bal,
                                },
                            ],
                            deletes: vec![],
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "INVARIANT VIOLATION: transfer failed during state apply: {}",
                            e
                        );
                        StateDelta::default()
                    }
                }
            }
            _ => StateDelta::default(),
        };
        per_tx_deltas.push(tx_delta);
    }

    // Commit only balance entries changed by this block's transitions.
    commit_balance_accounts(state, balances, &changed_balance_accounts);

    per_tx_deltas
}

pub fn combine_receipt_deltas(
    economics_deltas: &[StateDelta],
    transition_deltas: &[StateDelta],
) -> Result<Vec<StateDelta>, String> {
    if economics_deltas.len() != transition_deltas.len() {
        return Err(format!(
            "Per-tx delta length mismatch: economics={}, transitions={}",
            economics_deltas.len(),
            transition_deltas.len()
        ));
    }

    Ok(economics_deltas
        .iter()
        .zip(transition_deltas.iter())
        .map(|(economics, transition)| merge_state_deltas(economics, transition))
        .collect())
}

/// Initialize genesis balance in state trie + balance ledger.
pub fn apply_genesis_mint(
    state: &mut ManagedWorldState,
    balances: &mut BalanceLedger,
    validator_id: &[u8; 32],
) {
    let amount = TensionValue::from_integer(1_000_000);
    balances.credit(validator_id, amount);
    state.apply_delta(&StateDelta {
        writes: vec![StateWrite {
            address: sccgub_types::namespace::balance_key(validator_id),
            value: amount.raw().to_le_bytes().to_vec(),
        }],
        deletes: vec![],
    });
}

/// Reconstruct balance ledger from trie balance entries.
///
/// Reads all keys starting with "balance/" and deserializes
/// i128 values from little-endian bytes.
///
/// Fails on any malformed entry under the balance namespace (N-21).
/// A malformed entry means the trie was produced by a buggy or malicious
/// validator, and importing it silently would cause balance drift between
/// nodes that parse the entries differently.
pub fn balances_from_trie(state: &ManagedWorldState) -> Result<BalanceLedger, String> {
    let mut balances = BalanceLedger::new();
    for (key, value) in state.trie.iter() {
        if key.starts_with(sccgub_types::namespace::NS_BALANCE) {
            let suffix = &key[sccgub_types::namespace::NS_BALANCE.len()..];
            if value.len() != 16 {
                return Err(format!(
                    "Malformed balance entry: key {} has value length {} (expected 16)",
                    String::from_utf8_lossy(key),
                    value.len()
                ));
            }
            let agent_bytes = hex::decode(suffix).map_err(|e| {
                format!(
                    "Malformed balance key: {} (hex decode failed: {})",
                    String::from_utf8_lossy(key),
                    e
                )
            })?;
            if agent_bytes.len() != 32 {
                return Err(format!(
                    "Malformed balance key: {} (agent ID {} bytes, expected 32)",
                    String::from_utf8_lossy(key),
                    agent_bytes.len()
                ));
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&agent_bytes);
            let mut raw = [0u8; 16];
            raw.copy_from_slice(value);
            balances.import_balance(id, TensionValue(i128::from_le_bytes(raw)));
        }
    }
    Ok(balances)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::treasury::{default_block_reward, treasury_from_trie, Treasury};
    use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
    use sccgub_types::governance::PrecedenceLevel;
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::receipt::{CausalReceipt, ResourceUsage, Verdict};
    use sccgub_types::timestamp::CausalTimestamp;
    use sccgub_types::transition::*;
    use std::collections::BTreeSet;

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
                norm_set: BTreeSet::new(),
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
                which: BTreeSet::new(),
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
                norm_set: BTreeSet::new(),
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
                which: BTreeSet::new(),
                what_declared: "test".into(),
            },
            nonce,
            signature: vec![0u8; 64],
        }
    }

    fn make_accept_receipt(tx: &SymbolicTransition, gas_used: u64) -> CausalReceipt {
        CausalReceipt {
            tx_id: tx.tx_id,
            verdict: Verdict::Accept,
            pre_state_root: [0u8; 32],
            post_state_root: [0xFF; 32],
            read_set: vec![],
            write_set: vec![],
            causes: vec![],
            resource_used: ResourceUsage {
                compute_steps: gas_used,
                state_reads: 0,
                state_writes: 0,
                proof_size_bytes: 0,
            },
            emitted_events: vec![],
            wh_binding: WHBindingResolved {
                intent: tx.wh_binding_intent.clone(),
                what_actual: StateDelta::default(),
                whether: ValidationResult::Valid,
            },
            phi_phase_reached: 13,
            tension_delta: TensionValue::ZERO,
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
        let alice = [1u8; 32];
        let bob = [2u8; 32];

        apply_genesis_mint(&mut state, &mut balances, &alice);
        let txs = vec![make_transfer_tx(
            alice,
            bob,
            TensionValue::from_integer(300).raw(),
            1,
        )];

        apply_block_transitions(&mut state, &mut balances, &txs);

        let alice_key = sccgub_types::namespace::balance_key(&alice);
        let bob_key = sccgub_types::namespace::balance_key(&bob);
        assert!(state.trie.get(&alice_key).is_some());
        assert!(state.trie.get(&bob_key).is_some());
    }

    #[test]
    fn test_apply_commits_only_changed_balances() {
        let mut state = ManagedWorldState::new();
        let mut balances = BalanceLedger::new();
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        let carol = [3u8; 32];

        apply_genesis_mint(&mut state, &mut balances, &alice);
        apply_block_transitions(
            &mut state,
            &mut balances,
            &[make_transfer_tx(
                alice,
                bob,
                TensionValue::from_integer(100).raw(),
                1,
            )],
        );

        let alice_key = sccgub_types::namespace::balance_key(&alice);
        let bob_key = sccgub_types::namespace::balance_key(&bob);
        let alice_version_before = state
            .state
            .symbol_store
            .get(&alice_key)
            .expect("alice balance must be committed")
            .version;
        let bob_version_before = state
            .state
            .symbol_store
            .get(&bob_key)
            .expect("bob balance must be committed")
            .version;

        apply_block_transitions(
            &mut state,
            &mut balances,
            &[make_transfer_tx(
                alice,
                carol,
                TensionValue::from_integer(25).raw(),
                2,
            )],
        );

        assert_eq!(
            state
                .state
                .symbol_store
                .get(&alice_key)
                .expect("alice balance must be committed")
                .version,
            alice_version_before + 1,
            "changed balance should be rewritten"
        );
        assert_eq!(
            state
                .state
                .symbol_store
                .get(&bob_key)
                .expect("bob balance must remain present")
                .version,
            bob_version_before,
            "unchanged balance must not be rewritten"
        );
    }

    #[test]
    fn test_apply_commits_only_touched_balances_large_set() {
        let mut state = ManagedWorldState::new();
        let mut balances = BalanceLedger::new();
        let alice = [1u8; 32];
        apply_genesis_mint(&mut state, &mut balances, &alice);

        let mut recipients = Vec::new();
        for i in 2..=21u8 {
            recipients.push([i; 32]);
        }

        let mut seed_txs = Vec::new();
        for (idx, recipient) in recipients.iter().enumerate() {
            seed_txs.push(make_transfer_tx(
                alice,
                *recipient,
                TensionValue::from_integer(10).raw(),
                (idx as u128) + 1,
            ));
        }
        apply_block_transitions(&mut state, &mut balances, &seed_txs);

        let mut versions_before = std::collections::BTreeMap::new();
        let alice_key = sccgub_types::namespace::balance_key(&alice);
        let alice_version = state
            .state
            .symbol_store
            .get(&alice_key)
            .expect("alice balance must exist")
            .version;
        versions_before.insert(alice_key, alice_version);
        for recipient in &recipients {
            let key = sccgub_types::namespace::balance_key(recipient);
            let version = state
                .state
                .symbol_store
                .get(&key)
                .expect("recipient balance must exist")
                .version;
            versions_before.insert(key, version);
        }

        let sender = recipients[0];
        let receiver = recipients[1];
        apply_block_transitions(
            &mut state,
            &mut balances,
            &[make_transfer_tx(
                sender,
                receiver,
                TensionValue::from_integer(5).raw(),
                1,
            )],
        );

        let sender_key = sccgub_types::namespace::balance_key(&sender);
        let receiver_key = sccgub_types::namespace::balance_key(&receiver);
        for (key, before) in versions_before {
            let after = state
                .state
                .symbol_store
                .get(&key)
                .expect("balance entry must exist")
                .version;
            if key == sender_key || key == receiver_key {
                assert_eq!(after, before + 1, "touched balance should be rewritten");
            } else {
                assert_eq!(after, before, "untouched balance must not be rewritten");
            }
        }
    }

    #[test]
    fn test_apply_does_not_commit_external_balance_mutation_without_transition() {
        let mut state = ManagedWorldState::new();
        let mut balances = BalanceLedger::new();
        let validator = [7u8; 32];

        apply_genesis_mint(&mut state, &mut balances, &validator);
        let key = sccgub_types::namespace::balance_key(&validator);
        let version_before = state
            .state
            .symbol_store
            .get(&key)
            .expect("genesis balance must exist")
            .version;

        balances.credit(&validator, TensionValue::from_integer(10));
        apply_block_transitions(&mut state, &mut balances, &[]);

        assert_eq!(
            state.trie.get(&key),
            Some(
                &TensionValue::from_integer(1_000_000)
                    .raw()
                    .to_le_bytes()
                    .to_vec()
            ),
            "off-path balance mutations must not change trie commitment"
        );
        assert_eq!(
            state
                .state
                .symbol_store
                .get(&key)
                .expect("balance entry must remain present")
                .version,
            version_before,
            "trie version must stay unchanged without a committed balance transition"
        );
    }

    #[test]
    fn test_apply_block_economics_commits_fee_and_reward() {
        let mut state = ManagedWorldState::new();
        let mut balances = BalanceLedger::new();
        let mut treasury = Treasury::new();
        let payer = [9u8; 32];
        let validator = [8u8; 32];
        let validator_reward_account = validator_spend_account(2, &validator);
        let tx = make_write_tx(b"data/econ", b"value", 1);
        let mut funded_tx = tx.clone();
        funded_tx.actor.agent_id = payer;
        funded_tx.actor.public_key = payer;
        funded_tx.wh_binding_intent.who = payer;

        apply_genesis_mint(&mut state, &mut balances, &payer);

        let outcome = apply_block_economics(
            &mut state,
            &mut balances,
            &mut treasury,
            &[funded_tx.clone()],
            &[make_accept_receipt(&funded_tx, 2)],
            2,
            &validator,
            TensionValue::from_integer(1),
            default_block_reward(),
        )
        .expect("economics apply should succeed");

        assert_eq!(outcome.total_fees, TensionValue::from_integer(2));
        assert_eq!(outcome.actual_reward, TensionValue::from_integer(2));
        assert_eq!(
            balances.balance_of(&payer),
            TensionValue::from_integer(999_998)
        );
        assert_eq!(
            balances.balance_of(&validator_reward_account),
            TensionValue::from_integer(2)
        );
        assert_eq!(treasury.pending_fees, TensionValue::ZERO);

        let recovered = treasury_from_trie(&state).expect("treasury state must roundtrip");
        assert_eq!(
            recovered.total_fees_collected,
            TensionValue::from_integer(2)
        );
        assert_eq!(
            recovered.total_rewards_distributed,
            TensionValue::from_integer(2)
        );
    }

    #[test]
    fn test_resolve_fee_payer_falls_back_to_signer_account_in_v1() {
        let mut balances = BalanceLedger::new();
        let mut tx = make_write_tx(b"data/fallback", b"value", 1);
        tx.actor.agent_id = [3u8; 32];
        tx.actor.public_key = [4u8; 32];
        balances.credit(&tx.actor.public_key, TensionValue::from_integer(5));

        let payer = resolve_fee_payer(1, &balances, &tx, TensionValue::from_integer(2))
            .expect("signer fallback should cover fee");

        assert_eq!(payer, tx.actor.public_key);
        assert_eq!(balances.balance_of(&tx.actor.agent_id), TensionValue::ZERO);
        assert_eq!(
            balances.balance_of(&tx.actor.public_key),
            TensionValue::from_integer(5)
        );
    }

    #[test]
    fn test_resolve_fee_payer_v2_rejects_signer_fallback() {
        let mut balances = BalanceLedger::new();
        let mut tx = make_write_tx(b"data/no-fallback", b"value", 1);
        tx.actor.agent_id = [5u8; 32];
        tx.actor.public_key = [6u8; 32];
        balances.credit(&tx.actor.public_key, TensionValue::from_integer(5));

        let err = resolve_fee_payer(2, &balances, &tx, TensionValue::from_integer(2))
            .expect_err("v2 should not silently fall back to signer account");

        assert!(err.contains("Insufficient fee balance"));
        assert_eq!(balances.balance_of(&tx.actor.agent_id), TensionValue::ZERO);
        assert_eq!(
            balances.balance_of(&tx.actor.public_key),
            TensionValue::from_integer(5)
        );
    }

    #[test]
    fn test_validator_spend_account_v2_is_canonical_agent() {
        let validator_pk = [7u8; 32];
        let derived = validator_spend_account(2, &validator_pk);
        let expected = blake3_hash_concat(&[
            &validator_pk,
            &canonical_bytes(&MfidelAtomicSeal::from_height(0)),
        ]);

        assert_eq!(derived, expected);
        assert_ne!(derived, validator_pk);
    }

    #[test]
    fn test_combine_receipt_deltas_merges_economics_and_payload_writes() {
        let economics = StateDelta {
            writes: vec![StateWrite {
                address: b"balance/payer".to_vec(),
                value: b"99".to_vec(),
            }],
            deletes: vec![],
        };
        let payload = StateDelta {
            writes: vec![StateWrite {
                address: b"data/key".to_vec(),
                value: b"value".to_vec(),
            }],
            deletes: vec![],
        };

        let combined =
            combine_receipt_deltas(&[economics], &[payload]).expect("delta merge must succeed");

        assert_eq!(combined.len(), 1);
        assert_eq!(combined[0].writes.len(), 2);
        assert_eq!(combined[0].writes[0].address, b"balance/payer".to_vec());
        assert_eq!(combined[0].writes[1].address, b"data/key".to_vec());
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
        let key = sccgub_types::namespace::balance_key(&validator);
        assert!(state.trie.get(&key).is_some());
    }

    #[test]
    fn test_balances_from_trie_roundtrip() {
        let mut state = ManagedWorldState::new();
        let mut balances = BalanceLedger::new();
        let a1 = [1u8; 32];
        let a2 = [2u8; 32];

        apply_genesis_mint(&mut state, &mut balances, &a1);
        apply_block_transitions(
            &mut state,
            &mut balances,
            &[make_transfer_tx(
                a1,
                a2,
                TensionValue::from_integer(300).raw(),
                1,
            )],
        );

        // Reconstruct.
        let recovered = balances_from_trie(&state).expect("roundtrip should succeed");
        assert_eq!(
            recovered.balance_of(&a1),
            TensionValue::from_integer(999_700)
        );
        assert_eq!(recovered.balance_of(&a2), TensionValue::from_integer(300));
        assert_eq!(recovered.total_supply(), balances.total_supply());
    }

    #[test]
    fn test_balances_from_trie_rejects_malformed_hex() {
        let mut state = ManagedWorldState::new();
        // Insert a well-formed balance.
        let key = sccgub_types::namespace::balance_key(&[1u8; 32]);
        state.trie.insert(
            key,
            TensionValue::from_integer(100).raw().to_le_bytes().to_vec(),
        );
        // N-21: Insert a malformed key under balance/ with non-hex suffix.
        state
            .trie
            .insert(b"balance/not_valid_hex!!!".to_vec(), vec![0u8; 16]);

        let result = balances_from_trie(&state);
        assert!(
            result.is_err(),
            "Malformed hex key under balance/ must fail import"
        );
    }

    #[test]
    fn test_balances_from_trie_rejects_wrong_value_length() {
        let mut state = ManagedWorldState::new();
        let key = sccgub_types::namespace::balance_key(&[1u8; 32]);
        // 8 bytes instead of 16.
        state.trie.insert(key, vec![0u8; 8]);

        let result = balances_from_trie(&state);
        assert!(
            result.is_err(),
            "Wrong value length under balance/ must fail import"
        );
    }
}
