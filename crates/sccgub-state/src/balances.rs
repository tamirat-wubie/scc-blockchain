use std::collections::HashMap;

use sccgub_types::tension::TensionValue;
use sccgub_types::AgentId;

/// Balance ledger for asset tracking.
/// Balances are stored as fixed-point TensionValues for deterministic arithmetic.
#[derive(Debug, Clone, Default)]
pub struct BalanceLedger {
    pub balances: HashMap<AgentId, TensionValue>,
}

impl BalanceLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Get an agent's balance (0 if not found).
    pub fn balance_of(&self, agent: &AgentId) -> TensionValue {
        self.balances.get(agent).copied().unwrap_or(TensionValue::ZERO)
    }

    /// Credit an agent's balance (e.g., reward, mint).
    pub fn credit(&mut self, agent: &AgentId, amount: TensionValue) {
        let current = self.balance_of(agent);
        self.balances.insert(*agent, current + amount);
    }

    /// Debit an agent's balance. Returns Err if insufficient funds.
    pub fn debit(&mut self, agent: &AgentId, amount: TensionValue) -> Result<(), String> {
        let current = self.balance_of(agent);
        if current.raw() < amount.raw() {
            return Err(format!(
                "Insufficient balance: have {}, need {}",
                current, amount
            ));
        }
        self.balances.insert(*agent, current - amount);
        Ok(())
    }

    /// Transfer from one agent to another.
    pub fn transfer(
        &mut self,
        from: &AgentId,
        to: &AgentId,
        amount: TensionValue,
    ) -> Result<(), String> {
        if amount.raw() <= 0 {
            return Err("Transfer amount must be positive".into());
        }
        if from == to {
            return Err("Cannot transfer to self".into());
        }
        self.debit(from, amount)?;
        self.credit(to, amount);
        Ok(())
    }

    /// Total supply across all accounts.
    pub fn total_supply(&self) -> TensionValue {
        self.balances
            .values()
            .fold(TensionValue::ZERO, |acc, v| acc + *v)
    }

    /// Number of accounts with non-zero balance.
    pub fn account_count(&self) -> usize {
        self.balances.values().filter(|v| v.raw() > 0).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credit_and_balance() {
        let mut ledger = BalanceLedger::new();
        let agent = [1u8; 32];
        assert_eq!(ledger.balance_of(&agent), TensionValue::ZERO);

        ledger.credit(&agent, TensionValue::from_integer(100));
        assert_eq!(ledger.balance_of(&agent), TensionValue::from_integer(100));
    }

    #[test]
    fn test_debit_sufficient() {
        let mut ledger = BalanceLedger::new();
        let agent = [1u8; 32];
        ledger.credit(&agent, TensionValue::from_integer(100));

        assert!(ledger.debit(&agent, TensionValue::from_integer(60)).is_ok());
        assert_eq!(ledger.balance_of(&agent), TensionValue::from_integer(40));
    }

    #[test]
    fn test_debit_insufficient() {
        let mut ledger = BalanceLedger::new();
        let agent = [1u8; 32];
        ledger.credit(&agent, TensionValue::from_integer(50));

        assert!(ledger.debit(&agent, TensionValue::from_integer(100)).is_err());
        // Balance unchanged on failure.
        assert_eq!(ledger.balance_of(&agent), TensionValue::from_integer(50));
    }

    #[test]
    fn test_transfer() {
        let mut ledger = BalanceLedger::new();
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        ledger.credit(&alice, TensionValue::from_integer(200));

        ledger
            .transfer(&alice, &bob, TensionValue::from_integer(75))
            .unwrap();

        assert_eq!(ledger.balance_of(&alice), TensionValue::from_integer(125));
        assert_eq!(ledger.balance_of(&bob), TensionValue::from_integer(75));
        assert_eq!(ledger.total_supply(), TensionValue::from_integer(200));
    }

    #[test]
    fn test_transfer_insufficient() {
        let mut ledger = BalanceLedger::new();
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        ledger.credit(&alice, TensionValue::from_integer(50));

        assert!(ledger
            .transfer(&alice, &bob, TensionValue::from_integer(100))
            .is_err());
    }

    #[test]
    fn test_transfer_to_self_rejected() {
        let mut ledger = BalanceLedger::new();
        let alice = [1u8; 32];
        ledger.credit(&alice, TensionValue::from_integer(100));

        assert!(ledger
            .transfer(&alice, &alice, TensionValue::from_integer(10))
            .is_err());
    }

    #[test]
    fn test_transfer_negative_rejected() {
        let mut ledger = BalanceLedger::new();
        let alice = [1u8; 32];
        let bob = [2u8; 32];
        ledger.credit(&alice, TensionValue::from_integer(100));

        assert!(ledger
            .transfer(&alice, &bob, TensionValue::ZERO)
            .is_err());
    }

    #[test]
    fn test_total_supply_conservation() {
        let mut ledger = BalanceLedger::new();
        let agents: Vec<[u8; 32]> = (1..=5).map(|i| [i as u8; 32]).collect();

        // Mint 1000 to first agent.
        ledger.credit(&agents[0], TensionValue::from_integer(1000));

        // Transfer around.
        ledger.transfer(&agents[0], &agents[1], TensionValue::from_integer(200)).unwrap();
        ledger.transfer(&agents[0], &agents[2], TensionValue::from_integer(300)).unwrap();
        ledger.transfer(&agents[1], &agents[3], TensionValue::from_integer(100)).unwrap();
        ledger.transfer(&agents[2], &agents[4], TensionValue::from_integer(50)).unwrap();

        // Total supply must be conserved.
        assert_eq!(ledger.total_supply(), TensionValue::from_integer(1000));
    }
}
