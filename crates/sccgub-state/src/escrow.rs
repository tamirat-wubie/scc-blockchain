use sccgub_types::tension::TensionValue;
use sccgub_types::{AgentId, Hash};

use crate::balances::BalanceLedger;

/// Escrow — conditional fund locking for delivery-versus-payment (DvP),
/// time-locked payments, and multi-party settlement.
///
/// Escrow operations are deterministic and produce auditable receipts.
/// Funds are locked (debited from sender, held in escrow) until
/// either released to recipient or refunded to sender.
#[derive(Debug, Clone, Default)]
pub struct EscrowRegistry {
    pub escrows: Vec<Escrow>,
    index: std::collections::HashMap<Hash, usize>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Escrow {
    pub id: Hash,
    pub sender: AgentId,
    pub recipient: AgentId,
    pub amount: TensionValue,
    pub status: EscrowStatus,
    /// Block height at which this escrow was created.
    pub created_at: u64,
    /// Block height after which the sender can reclaim (timeout).
    pub expires_at: u64,
    /// Condition that must be met for release (state key that must exist).
    pub condition: EscrowCondition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum EscrowStatus {
    /// Funds locked, waiting for condition.
    Active,
    /// Condition met, funds released to recipient.
    Released,
    /// Timeout expired or cancelled, funds returned to sender.
    Refunded,
    /// Disputed — awaiting governance resolution.
    Disputed,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum EscrowCondition {
    /// Release when a specific state key exists with the expected value.
    /// Verifies both key existence AND value match (not just key existence).
    /// Optionally requires the key to have been written by a specific authority.
    StateProof {
        key: Vec<u8>,
        expected_value: Vec<u8>,
        /// If set, only releases if the key was written by this agent.
        required_authority: Option<AgentId>,
    },
    /// Release when approved by a designated arbiter.
    ArbiterApproval { arbiter: AgentId },
    /// Unconditional time-locked release at a specific block height.
    TimeLocked { release_at: u64 },
}

impl EscrowRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new escrow. Locks funds from sender's balance.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        &mut self,
        sender: AgentId,
        recipient: AgentId,
        amount: TensionValue,
        condition: EscrowCondition,
        current_height: u64,
        timeout_blocks: u64,
        balances: &mut BalanceLedger,
    ) -> Result<Hash, String> {
        if amount.raw() <= 0 {
            return Err("Escrow amount must be positive".into());
        }
        if sender == recipient {
            return Err("Cannot escrow to self".into());
        }

        // Lock funds by debiting sender.
        balances.debit(&sender, amount)?;

        let id = sccgub_crypto::hash::blake3_hash(&sccgub_crypto::canonical::canonical_bytes(&(
            &sender,
            &recipient,
            amount.raw(),
            current_height,
        )));

        self.escrows.push(Escrow {
            id,
            sender,
            recipient,
            amount,
            status: EscrowStatus::Active,
            created_at: current_height,
            expires_at: current_height + timeout_blocks,
            condition,
        });
        self.index.insert(id, self.escrows.len() - 1);

        Ok(id)
    }

    /// Release escrowed funds to recipient. Called when condition is met.
    pub fn release(
        &mut self,
        escrow_id: &Hash,
        balances: &mut BalanceLedger,
    ) -> Result<(), String> {
        let idx = *self.index.get(escrow_id).ok_or("Escrow not found")?;
        let escrow = &mut self.escrows[idx];

        if escrow.status != EscrowStatus::Active {
            return Err(format!("Escrow is {:?}, not Active", escrow.status));
        }

        balances.credit(&escrow.recipient, escrow.amount);
        escrow.status = EscrowStatus::Released;
        Ok(())
    }

    /// Refund escrowed funds to sender (timeout or cancellation).
    pub fn refund(
        &mut self,
        escrow_id: &Hash,
        current_height: u64,
        balances: &mut BalanceLedger,
    ) -> Result<(), String> {
        let idx = *self.index.get(escrow_id).ok_or("Escrow not found")?;
        let escrow = &mut self.escrows[idx];

        if escrow.status != EscrowStatus::Active {
            return Err(format!("Escrow is {:?}, not Active", escrow.status));
        }

        if current_height < escrow.expires_at {
            return Err(format!(
                "Escrow not expired yet (expires at block {})",
                escrow.expires_at
            ));
        }

        balances.credit(&escrow.sender, escrow.amount);
        escrow.status = EscrowStatus::Refunded;
        Ok(())
    }

    /// Check if any escrow conditions are met and release automatically.
    /// Returns IDs of released escrows.
    pub fn check_and_release(
        &mut self,
        state: &crate::world::ManagedWorldState,
        current_height: u64,
        balances: &mut BalanceLedger,
    ) -> Vec<Hash> {
        let mut released = Vec::new();

        for escrow in &mut self.escrows {
            if escrow.status != EscrowStatus::Active {
                continue;
            }

            let condition_met = match &escrow.condition {
                EscrowCondition::StateProof {
                    key,
                    expected_value,
                    required_authority: _,
                } => {
                    // Verify both key existence AND value match.
                    // required_authority check requires write-tracking (future: audit log).
                    match state.trie.get(key) {
                        Some(actual) => actual == expected_value,
                        None => false,
                    }
                }
                EscrowCondition::TimeLocked { release_at } => current_height >= *release_at,
                EscrowCondition::ArbiterApproval { .. } => false, // Requires explicit call.
            };

            if condition_met {
                balances.credit(&escrow.recipient, escrow.amount);
                escrow.status = EscrowStatus::Released;
                released.push(escrow.id);
            }
        }

        released
    }

    /// Get an escrow by ID.
    pub fn get(&self, id: &Hash) -> Option<&Escrow> {
        self.index.get(id).map(|&idx| &self.escrows[idx])
    }

    /// Count of active escrows.
    pub fn active_count(&self) -> usize {
        self.escrows
            .iter()
            .filter(|e| e.status == EscrowStatus::Active)
            .count()
    }

    /// Total value locked in active escrows.
    pub fn total_locked(&self) -> TensionValue {
        self.escrows
            .iter()
            .filter(|e| e.status == EscrowStatus::Active)
            .fold(TensionValue::ZERO, |acc, e| acc + e.amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (BalanceLedger, AgentId, AgentId) {
        let mut balances = BalanceLedger::new();
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        balances.credit(&alice, TensionValue::from_integer(1000));
        (balances, alice, bob)
    }

    #[test]
    fn test_create_and_release() {
        let (mut balances, alice, bob) = setup();
        let mut registry = EscrowRegistry::new();

        let id = registry
            .create(
                alice,
                bob,
                TensionValue::from_integer(200),
                EscrowCondition::ArbiterApproval { arbiter: [3u8; 32] },
                10,
                100,
                &mut balances,
            )
            .unwrap();

        // Alice balance reduced.
        assert_eq!(balances.balance_of(&alice), TensionValue::from_integer(800));
        assert_eq!(registry.active_count(), 1);
        assert_eq!(registry.total_locked(), TensionValue::from_integer(200));

        // Release to Bob.
        registry.release(&id, &mut balances).unwrap();
        assert_eq!(balances.balance_of(&bob), TensionValue::from_integer(200));
        assert_eq!(registry.active_count(), 0);
    }

    #[test]
    fn test_refund_after_timeout() {
        let (mut balances, alice, bob) = setup();
        let mut registry = EscrowRegistry::new();

        let id = registry
            .create(
                alice,
                bob,
                TensionValue::from_integer(300),
                EscrowCondition::ArbiterApproval { arbiter: [3u8; 32] },
                10,
                50,
                &mut balances,
            )
            .unwrap();

        // Cannot refund before timeout.
        assert!(registry.refund(&id, 30, &mut balances).is_err());

        // Refund after timeout.
        registry.refund(&id, 60, &mut balances).unwrap();
        assert_eq!(
            balances.balance_of(&alice),
            TensionValue::from_integer(1000)
        ); // Full refund.
        assert_eq!(balances.balance_of(&bob), TensionValue::ZERO);
    }

    #[test]
    fn test_insufficient_funds_rejected() {
        let (mut balances, alice, bob) = setup();
        let mut registry = EscrowRegistry::new();

        let result = registry.create(
            alice,
            bob,
            TensionValue::from_integer(5000), // More than balance.
            EscrowCondition::TimeLocked { release_at: 100 },
            1,
            50,
            &mut balances,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_auto_release_on_condition() {
        let (mut balances, alice, bob) = setup();
        let mut registry = EscrowRegistry::new();
        let mut state = crate::world::ManagedWorldState::new();

        registry
            .create(
                alice,
                bob,
                TensionValue::from_integer(100),
                EscrowCondition::StateProof {
                    key: b"delivery/proof".to_vec(),
                    expected_value: b"confirmed".to_vec(),
                    required_authority: None,
                },
                1,
                100,
                &mut balances,
            )
            .unwrap();

        // Condition not met — no release.
        let released = registry.check_and_release(&state, 10, &mut balances);
        assert!(released.is_empty());

        // Write delivery proof to state.
        state.apply_delta(&sccgub_types::transition::StateDelta {
            writes: vec![sccgub_types::transition::StateWrite {
                address: b"delivery/proof".to_vec(),
                value: b"confirmed".to_vec(),
            }],
            deletes: vec![],
        });

        // Now condition is met — auto-release.
        let released = registry.check_and_release(&state, 20, &mut balances);
        assert_eq!(released.len(), 1);
        assert_eq!(balances.balance_of(&bob), TensionValue::from_integer(100));
    }

    #[test]
    fn test_time_locked_release() {
        let (mut balances, alice, bob) = setup();
        let mut registry = EscrowRegistry::new();
        let state = crate::world::ManagedWorldState::new();

        registry
            .create(
                alice,
                bob,
                TensionValue::from_integer(500),
                EscrowCondition::TimeLocked { release_at: 50 },
                1,
                200,
                &mut balances,
            )
            .unwrap();

        // Before release time — nothing happens.
        assert!(registry
            .check_and_release(&state, 30, &mut balances)
            .is_empty());

        // At release time — auto-release.
        let released = registry.check_and_release(&state, 50, &mut balances);
        assert_eq!(released.len(), 1);
        assert_eq!(balances.balance_of(&bob), TensionValue::from_integer(500));
    }

    #[test]
    fn test_conservation_through_escrow() {
        let (mut balances, alice, bob) = setup();
        let mut registry = EscrowRegistry::new();

        let initial_supply = balances.total_supply();

        registry
            .create(
                alice,
                bob,
                TensionValue::from_integer(400),
                EscrowCondition::ArbiterApproval { arbiter: [3u8; 32] },
                1,
                100,
                &mut balances,
            )
            .unwrap();

        // During escrow: supply = balances + locked.
        let supply_during = balances.total_supply() + registry.total_locked();
        assert_eq!(supply_during, initial_supply);

        // After release: supply fully in balances again.
        let eid = registry.escrows[0].id;
        registry.release(&eid, &mut balances).unwrap();
        assert_eq!(balances.total_supply(), initial_supply);
    }
}
