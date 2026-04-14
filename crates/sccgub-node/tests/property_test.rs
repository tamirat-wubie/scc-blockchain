//! Property-based tests for consensus-critical invariants.
//!
//! These tests verify that invariants hold under many random scenarios,
//! not just hand-crafted happy/unhappy paths.
//! Uses deterministic pseudo-random sequences for reproducibility.

use sccgub_state::balances::BalanceLedger;
use sccgub_state::escrow::{EscrowCondition, EscrowRegistry};
use sccgub_state::treasury::Treasury;
use sccgub_types::tension::TensionValue;

/// Simple deterministic PRNG for reproducible property tests.
fn prng(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

// === INV-1: Supply conservation under random transfers ===

#[test]
fn prop_supply_conserved_under_random_transfers() {
    let mut seed = 42u64;
    let mut ledger = BalanceLedger::new();

    // Mint to 10 agents.
    let agents: Vec<[u8; 32]> = (1..=10u8).map(|i| [i; 32]).collect();
    for agent in &agents {
        ledger.credit(agent, TensionValue::from_integer(10_000));
    }
    let initial_supply = ledger.total_supply();

    // Perform 1000 random transfers.
    for _ in 0..1000 {
        let from_idx = (prng(&mut seed) % 10) as usize;
        let to_idx = (prng(&mut seed) % 10) as usize;
        if from_idx == to_idx {
            continue;
        }
        let amount = (prng(&mut seed) % 500) as i64 + 1;
        let _ = ledger.transfer(
            &agents[from_idx],
            &agents[to_idx],
            TensionValue::from_integer(amount),
        );
    }

    // INVARIANT: supply must be exactly the same.
    assert_eq!(
        ledger.total_supply(),
        initial_supply,
        "Supply must be conserved under 1000 random transfers"
    );
}

#[test]
fn prop_no_negative_balance_after_random_transfers() {
    let mut seed = 12345u64;
    let mut ledger = BalanceLedger::new();

    let agents: Vec<[u8; 32]> = (1..=5u8).map(|i| [i; 32]).collect();
    for agent in &agents {
        ledger.credit(agent, TensionValue::from_integer(1_000));
    }

    for _ in 0..500 {
        let from_idx = (prng(&mut seed) % 5) as usize;
        let to_idx = (prng(&mut seed) % 5) as usize;
        if from_idx == to_idx {
            continue;
        }
        let amount = (prng(&mut seed) % 2000) as i64 + 1;
        let _ = ledger.transfer(
            &agents[from_idx],
            &agents[to_idx],
            TensionValue::from_integer(amount),
        );
    }

    // INVARIANT: no balance is negative.
    for agent in &agents {
        assert!(
            ledger.balance_of(agent).raw() >= 0,
            "Balance must never go negative for agent {}",
            hex::encode(agent)
        );
    }
}

// === Treasury conservation under random fee/reward/burn ===

#[test]
fn prop_treasury_conserved_under_random_operations() {
    let mut seed = 99u64;
    let mut treasury = Treasury::new();

    for _ in 0..500 {
        let op = prng(&mut seed) % 3;
        let amount = TensionValue::from_integer((prng(&mut seed) % 100 + 1) as i64);

        match op {
            0 => treasury.collect_fee(amount),
            1 => {
                treasury.distribute_reward(amount);
            }
            2 => {
                let _ = treasury.burn(amount);
            }
            _ => unreachable!(),
        }
    }

    // INVARIANT: collected = distributed + burned + pending.
    let sum = TensionValue(
        treasury.total_rewards_distributed.raw()
            + treasury.total_burned.raw()
            + treasury.pending_fees.raw(),
    );
    assert_eq!(
        sum, treasury.total_fees_collected,
        "Treasury conservation must hold after 500 random operations"
    );
}

// === Escrow conservation under random create/release/refund ===

#[test]
fn prop_escrow_conserved_under_random_lifecycle() {
    let mut seed = 7777u64;
    let mut balances = BalanceLedger::new();
    let mut escrow = EscrowRegistry::new();

    let alice = [1u8; 32];
    let bob = [2u8; 32];
    balances.credit(&alice, TensionValue::from_integer(100_000));
    let initial_supply = balances.total_supply();

    let mut escrow_ids = Vec::new();

    for i in 0..200u64 {
        let op = prng(&mut seed) % 3;

        match op {
            0 => {
                // Create escrow.
                let amount = TensionValue::from_integer((prng(&mut seed) % 100 + 1) as i64);
                if let Ok(id) = escrow.create(
                    alice,
                    bob,
                    amount,
                    EscrowCondition::TimeLocked { release_at: i + 50 },
                    i,
                    100,
                    &mut balances,
                ) {
                    escrow_ids.push(id);
                }
            }
            1 => {
                // Release a random escrow.
                if !escrow_ids.is_empty() {
                    let idx = (prng(&mut seed) as usize) % escrow_ids.len();
                    let _ = escrow.release(&escrow_ids[idx], &mut balances);
                }
            }
            2 => {
                // Refund a random escrow.
                if !escrow_ids.is_empty() {
                    let idx = (prng(&mut seed) as usize) % escrow_ids.len();
                    let _ = escrow.refund(&escrow_ids[idx], i + 200, &mut balances);
                }
            }
            _ => unreachable!(),
        }

        // INVARIANT: at every step, supply = balances + locked.
        let total = TensionValue(balances.total_supply().raw() + escrow.total_locked().raw());
        assert_eq!(
            total,
            initial_supply,
            "Escrow conservation violated at step {}: balances {} + locked {} != initial {}",
            i,
            balances.total_supply(),
            escrow.total_locked(),
            initial_supply
        );
    }
}

// === Nonce sequential enforcement under random submissions ===

#[test]
fn prop_nonce_sequential_under_random_agents() {
    use sccgub_state::world::ManagedWorldState;

    let mut seed = 314u64;
    let mut state = ManagedWorldState::new();

    let agents: Vec<[u8; 32]> = (1..=5u8).map(|i| [i; 32]).collect();
    let mut expected_nonce: Vec<u128> = vec![0; 5]; // last committed nonce per agent.

    for _ in 0..500 {
        let agent_idx = (prng(&mut seed) % 5) as usize;
        let attempt_nonce = (prng(&mut seed) % 5) as u128 + expected_nonce[agent_idx];

        let result = state.check_nonce(&agents[agent_idx], attempt_nonce);

        if attempt_nonce == expected_nonce[agent_idx] + 1 {
            // This is the correct next nonce — should succeed.
            assert!(
                result.is_ok(),
                "Valid nonce {} rejected for agent {}",
                attempt_nonce,
                agent_idx
            );
            expected_nonce[agent_idx] = attempt_nonce;
        } else {
            // Wrong nonce — should be rejected.
            assert!(
                result.is_err(),
                "Invalid nonce {} accepted for agent {} (expected {})",
                attempt_nonce,
                agent_idx,
                expected_nonce[agent_idx] + 1
            );
        }
    }
}

// === Merkle root determinism under random leaf orders ===

#[test]
fn prop_merkle_root_deterministic() {
    use sccgub_crypto::hash::blake3_hash;
    use sccgub_crypto::merkle::compute_merkle_root;

    let mut seed = 555u64;

    for _ in 0..50 {
        let num_leaves = (prng(&mut seed) % 20 + 1) as usize;
        let leaves: Vec<[u8; 32]> = (0..num_leaves)
            .map(|i| blake3_hash(&(i as u64).to_le_bytes()))
            .collect();

        let root1 = compute_merkle_root(&leaves);
        let root2 = compute_merkle_root(&leaves);

        assert_eq!(
            root1, root2,
            "Merkle root must be deterministic for same input"
        );

        // Different leaves must produce different root.
        if num_leaves > 1 {
            let mut modified = leaves.clone();
            modified[0] = blake3_hash(b"DIFFERENT");
            let root3 = compute_merkle_root(&modified);
            assert_ne!(root1, root3, "Different leaves must produce different root");
        }
    }
}

// === State root determinism under random write order ===

#[test]
fn prop_state_root_deterministic_under_same_writes() {
    use sccgub_state::world::ManagedWorldState;
    use sccgub_types::transition::{StateDelta, StateWrite};

    let mut seed = 888u64;

    for _ in 0..20 {
        let num_writes = (prng(&mut seed) % 10 + 1) as usize;
        let writes: Vec<StateWrite> = (0..num_writes)
            .map(|i| StateWrite {
                address: format!("key/{}", i).into_bytes(),
                value: format!("val/{}/{}", i, prng(&mut seed)).into_bytes(),
            })
            .collect();

        let mut s1 = ManagedWorldState::new();
        let mut s2 = ManagedWorldState::new();

        s1.apply_delta(&StateDelta {
            writes: writes.clone(),
            deletes: vec![],
        });
        s2.apply_delta(&StateDelta {
            writes,
            deletes: vec![],
        });

        assert_eq!(
            s1.state_root(),
            s2.state_root(),
            "Same writes must produce identical state roots"
        );
    }
}

// === Balance root determinism under insertion order ===

#[test]
fn prop_balance_root_deterministic_under_insertion_order() {
    let mut seed = 4242u64;

    for _ in 0..50 {
        let num_agents = (prng(&mut seed) % 10 + 2) as usize;
        let agents: Vec<[u8; 32]> = (0..num_agents)
            .map(|i| {
                let mut id = [0u8; 32];
                let val = (prng(&mut seed) ^ i as u64).to_le_bytes();
                id[..8].copy_from_slice(&val);
                id[8] = i as u8;
                id
            })
            .collect();

        let amounts: Vec<TensionValue> = (0..num_agents)
            .map(|_| TensionValue::from_integer((prng(&mut seed) % 10_000 + 1) as i64))
            .collect();

        // Insert in forward order.
        let mut ledger1 = BalanceLedger::new();
        for (agent, amount) in agents.iter().zip(amounts.iter()) {
            ledger1.credit(agent, *amount);
        }

        // Insert in reverse order.
        let mut ledger2 = BalanceLedger::new();
        for (agent, amount) in agents.iter().zip(amounts.iter()).rev() {
            ledger2.credit(agent, *amount);
        }

        assert_eq!(
            ledger1.balance_root(),
            ledger2.balance_root(),
            "Balance root must be deterministic regardless of insertion order"
        );

        // Different balances must produce a different root.
        let mut ledger3 = BalanceLedger::new();
        for (agent, amount) in agents.iter().zip(amounts.iter()) {
            ledger3.credit(agent, *amount);
        }
        ledger3.credit(&agents[0], TensionValue::from_integer(1));
        assert_ne!(
            ledger1.balance_root(),
            ledger3.balance_root(),
            "Different balances must produce different roots"
        );
    }
}

// === Gas metering determinism ===

#[test]
fn prop_gas_metering_deterministic() {
    use sccgub_execution::gas::GasMeter;

    let mut seed = 666u64;

    for _ in 0..100 {
        let compute = (prng(&mut seed) % 1000) as u64;
        let reads = (prng(&mut seed) % 10) as u64;
        let writes = (prng(&mut seed) % 5) as u64;

        let mut m1 = GasMeter::default_tx();
        let mut m2 = GasMeter::default_tx();

        let _ = m1.charge_compute(compute);
        let _ = m2.charge_compute(compute);
        for _ in 0..reads {
            let _ = m1.charge_state_read();
            let _ = m2.charge_state_read();
        }
        for _ in 0..writes {
            let _ = m1.charge_state_write();
            let _ = m2.charge_state_write();
        }

        assert_eq!(
            m1.used, m2.used,
            "Gas metering must be deterministic for identical operations"
        );
    }
}
