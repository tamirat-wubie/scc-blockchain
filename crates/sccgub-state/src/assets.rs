use std::collections::HashMap;

use sccgub_types::tension::TensionValue;
use sccgub_types::{AgentId, Hash};

/// Asset identifier.
pub type AssetId = Hash;

/// Multi-asset balance ledger.
/// Supports multiple asset classes (tokens, RWA, NFTs, fiat stablecoins).
/// Each asset is independently tracked with supply conservation.
///
/// Addresses: RWA tokenization ($30B market by 2026), East African
/// cross-border payments (multi-currency), and regulated asset custody.
#[derive(Debug, Clone, Default)]
pub struct MultiAssetLedger {
    /// Balances: (agent_id, asset_id) -> amount.
    pub balances: HashMap<(AgentId, AssetId), TensionValue>,
    /// Total supply per asset.
    pub total_supply: HashMap<AssetId, TensionValue>,
    /// Asset metadata.
    pub asset_info: HashMap<AssetId, AssetInfo>,
}

/// Metadata for a registered asset.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AssetInfo {
    pub id: AssetId,
    pub name: String,
    pub asset_type: AssetType,
    pub issuer: AgentId,
    pub created_at_height: u64,
    pub frozen: bool,
}

/// Types of assets that can be tokenized.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AssetType {
    /// Native chain token.
    Native,
    /// Stablecoin (pegged to fiat).
    Stablecoin { currency: String },
    /// Bond / fixed income.
    Bond { maturity_height: u64 },
    /// Real estate tokenization.
    RealEstate,
    /// Commodity token.
    Commodity { commodity: String },
    /// Custom domain asset.
    Custom { domain: String },
}

impl MultiAssetLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a new asset type.
    pub fn register_asset(&mut self, info: AssetInfo) -> Result<(), String> {
        if self.asset_info.contains_key(&info.id) {
            return Err("Asset already registered".into());
        }
        self.total_supply.insert(info.id, TensionValue::ZERO);
        self.asset_info.insert(info.id, info);
        Ok(())
    }

    /// Mint new tokens of an asset.
    pub fn mint(
        &mut self,
        asset_id: &AssetId,
        to: &AgentId,
        amount: TensionValue,
    ) -> Result<(), String> {
        let info = self
            .asset_info
            .get(asset_id)
            .ok_or("Asset not registered")?;
        if info.frozen {
            return Err("Asset is frozen — cannot mint".into());
        }
        if amount.raw() <= 0 {
            return Err("Mint amount must be positive".into());
        }
        let key = (*to, *asset_id);
        let balance = self.balances.entry(key).or_insert(TensionValue::ZERO);
        *balance = *balance + amount;
        let supply = self
            .total_supply
            .entry(*asset_id)
            .or_insert(TensionValue::ZERO);
        *supply = *supply + amount;
        Ok(())
    }

    /// Burn tokens of an asset.
    pub fn burn(
        &mut self,
        asset_id: &AssetId,
        from: &AgentId,
        amount: TensionValue,
    ) -> Result<(), String> {
        let info = self
            .asset_info
            .get(asset_id)
            .ok_or("Asset not registered")?;
        if info.frozen {
            return Err("Asset is frozen — cannot burn".into());
        }
        let key = (*from, *asset_id);
        let balance = self
            .balances
            .get(&key)
            .copied()
            .unwrap_or(TensionValue::ZERO);
        if balance.raw() < amount.raw() {
            return Err("Insufficient balance for burn".into());
        }
        self.balances.insert(key, balance - amount);
        let supply = self
            .total_supply
            .entry(*asset_id)
            .or_insert(TensionValue::ZERO);
        *supply = *supply - amount;
        Ok(())
    }

    /// Transfer an asset between agents.
    pub fn transfer(
        &mut self,
        asset_id: &AssetId,
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
        let info = self
            .asset_info
            .get(asset_id)
            .ok_or("Asset not registered")?;
        {
            if info.frozen {
                return Err("Asset is frozen".into());
            }
        }

        let from_key = (*from, *asset_id);
        let from_balance = self
            .balances
            .get(&from_key)
            .copied()
            .unwrap_or(TensionValue::ZERO);
        if from_balance.raw() < amount.raw() {
            return Err("Insufficient balance".into());
        }
        self.balances.insert(from_key, from_balance - amount);

        let to_key = (*to, *asset_id);
        let to_balance = self
            .balances
            .get(&to_key)
            .copied()
            .unwrap_or(TensionValue::ZERO);
        self.balances.insert(to_key, to_balance + amount);
        Ok(())
    }

    /// Get balance of a specific asset for an agent.
    pub fn balance_of(&self, agent: &AgentId, asset: &AssetId) -> TensionValue {
        self.balances
            .get(&(*agent, *asset))
            .copied()
            .unwrap_or(TensionValue::ZERO)
    }

    /// Get total supply of an asset.
    pub fn supply_of(&self, asset: &AssetId) -> TensionValue {
        self.total_supply
            .get(asset)
            .copied()
            .unwrap_or(TensionValue::ZERO)
    }

    /// Freeze an asset (halt all transfers).
    pub fn freeze_asset(&mut self, asset_id: &AssetId) -> Result<(), String> {
        let info = self.asset_info.get_mut(asset_id).ok_or("Asset not found")?;
        info.frozen = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn native_asset() -> AssetId {
        [1u8; 32]
    }

    fn stablecoin() -> AssetId {
        [2u8; 32]
    }

    #[test]
    fn test_register_and_mint() {
        let mut ledger = MultiAssetLedger::new();
        ledger
            .register_asset(AssetInfo {
                id: native_asset(),
                name: "SCCG".into(),
                asset_type: AssetType::Native,
                issuer: [0u8; 32],
                created_at_height: 0,
                frozen: false,
            })
            .unwrap();

        let alice = [10u8; 32];
        ledger
            .mint(&native_asset(), &alice, TensionValue::from_integer(1000))
            .unwrap();
        assert_eq!(
            ledger.balance_of(&alice, &native_asset()),
            TensionValue::from_integer(1000)
        );
        assert_eq!(
            ledger.supply_of(&native_asset()),
            TensionValue::from_integer(1000)
        );
    }

    #[test]
    fn test_multi_asset_transfer() {
        let mut ledger = MultiAssetLedger::new();

        // Register two assets.
        for (id, name) in [(native_asset(), "SCCG"), (stablecoin(), "USDT")] {
            ledger
                .register_asset(AssetInfo {
                    id,
                    name: name.into(),
                    asset_type: AssetType::Native,
                    issuer: [0u8; 32],
                    created_at_height: 0,
                    frozen: false,
                })
                .unwrap();
        }

        let alice = [10u8; 32];
        let bob = [11u8; 32];

        ledger
            .mint(&native_asset(), &alice, TensionValue::from_integer(1000))
            .unwrap();
        ledger
            .mint(&stablecoin(), &alice, TensionValue::from_integer(500))
            .unwrap();

        // Transfer native token.
        ledger
            .transfer(
                &native_asset(),
                &alice,
                &bob,
                TensionValue::from_integer(300),
            )
            .unwrap();

        assert_eq!(
            ledger.balance_of(&alice, &native_asset()),
            TensionValue::from_integer(700)
        );
        assert_eq!(
            ledger.balance_of(&bob, &native_asset()),
            TensionValue::from_integer(300)
        );

        // Stablecoin balance unchanged.
        assert_eq!(
            ledger.balance_of(&alice, &stablecoin()),
            TensionValue::from_integer(500)
        );

        // Supply conserved.
        assert_eq!(
            ledger.supply_of(&native_asset()),
            TensionValue::from_integer(1000)
        );
    }

    #[test]
    fn test_burn() {
        let mut ledger = MultiAssetLedger::new();
        ledger
            .register_asset(AssetInfo {
                id: native_asset(),
                name: "SCCG".into(),
                asset_type: AssetType::Native,
                issuer: [0u8; 32],
                created_at_height: 0,
                frozen: false,
            })
            .unwrap();

        let alice = [10u8; 32];
        ledger
            .mint(&native_asset(), &alice, TensionValue::from_integer(1000))
            .unwrap();
        ledger
            .burn(&native_asset(), &alice, TensionValue::from_integer(400))
            .unwrap();

        assert_eq!(
            ledger.balance_of(&alice, &native_asset()),
            TensionValue::from_integer(600)
        );
        assert_eq!(
            ledger.supply_of(&native_asset()),
            TensionValue::from_integer(600)
        );
    }

    #[test]
    fn test_frozen_asset() {
        let mut ledger = MultiAssetLedger::new();
        ledger
            .register_asset(AssetInfo {
                id: native_asset(),
                name: "SCCG".into(),
                asset_type: AssetType::Native,
                issuer: [0u8; 32],
                created_at_height: 0,
                frozen: false,
            })
            .unwrap();

        let alice = [10u8; 32];
        let bob = [11u8; 32];
        ledger
            .mint(&native_asset(), &alice, TensionValue::from_integer(1000))
            .unwrap();

        ledger.freeze_asset(&native_asset()).unwrap();
        assert!(ledger
            .transfer(
                &native_asset(),
                &alice,
                &bob,
                TensionValue::from_integer(100)
            )
            .is_err());
    }
}
