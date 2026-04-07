use serde::{Deserialize, Serialize};

use crate::governance::PrecedenceLevel;
use crate::tension::TensionValue;
use crate::Hash;

/// Bridge adapter framework for interoperability with external chains.
/// Enables cross-chain communication while preserving causal integrity.
///
/// This addresses the fracture risk of isolation — a governed chain that
/// cannot interoperate with existing ecosystems will not achieve adoption.
///
/// Per spec: cross-chain bridges require norm compatibility, not just proof relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeAdapter {
    /// Unique identifier for this bridge.
    pub id: Hash,
    /// Human-readable name (e.g., "ethereum-mainnet", "fabric-network-1").
    pub name: String,
    /// Target chain type.
    pub chain_type: ExternalChainType,
    /// Minimum governance level required to operate this bridge.
    pub required_level: PrecedenceLevel,
    /// Whether the bridge is active.
    pub active: bool,
    /// Maximum transfer amount per transaction.
    pub max_transfer: TensionValue,
    /// Required confirmations on the external chain before accepting.
    pub required_confirmations: u32,
}

/// Supported external chain types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExternalChainType {
    /// EVM-compatible chains (Ethereum, Polygon, BSC, etc.).
    Evm { chain_id: u64 },
    /// Cosmos/IBC chains.
    Cosmos { chain_id: String },
    /// Hyperledger Fabric networks.
    Fabric { network_id: String },
    /// Other SCCGUB chains.
    Sccgub { chain_hash: Hash },
    /// Generic external system (API-based).
    Generic { protocol: String },
}

/// Cross-chain message that can be relayed through a bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeMessage {
    /// Source chain identifier.
    pub source_chain: Hash,
    /// Destination chain identifier.
    pub dest_chain: Hash,
    /// Bridge adapter used.
    pub bridge_id: Hash,
    /// Message type.
    pub message_type: BridgeMessageType,
    /// Proof from the source chain (format depends on chain type).
    pub source_proof: Vec<u8>,
    /// Block height on source chain when the message was created.
    pub source_height: u64,
    /// Number of confirmations on source chain.
    pub confirmations: u32,
}

/// Types of cross-chain messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BridgeMessageType {
    /// Transfer assets from external chain to SCCGUB.
    InboundTransfer {
        recipient: Hash,
        amount: TensionValue,
        external_tx_hash: Vec<u8>,
    },
    /// Transfer assets from SCCGUB to external chain.
    OutboundTransfer {
        sender: Hash,
        amount: TensionValue,
        external_address: Vec<u8>,
    },
    /// State attestation from external chain.
    StateAttestation {
        key: Vec<u8>,
        value: Vec<u8>,
        proof: Vec<u8>,
    },
    /// Governance event notification.
    GovernanceEvent {
        event_type: String,
        data: Vec<u8>,
    },
}

/// Bridge registry managing active bridges.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BridgeRegistry {
    pub bridges: Vec<BridgeAdapter>,
}

impl BridgeRegistry {
    /// Register a new bridge adapter.
    pub fn register(
        &mut self,
        bridge: BridgeAdapter,
        registrar_level: PrecedenceLevel,
    ) -> Result<(), String> {
        if (registrar_level as u8) > (bridge.required_level as u8) {
            return Err("Insufficient authority to register bridge".into());
        }
        if self.bridges.iter().any(|b| b.id == bridge.id) {
            return Err("Bridge already registered".into());
        }
        self.bridges.push(bridge);
        Ok(())
    }

    /// Validate a bridge message meets the adapter's requirements.
    pub fn validate_message(&self, msg: &BridgeMessage) -> Result<(), String> {
        let bridge = self
            .bridges
            .iter()
            .find(|b| b.id == msg.bridge_id)
            .ok_or("Bridge not found")?;

        if !bridge.active {
            return Err("Bridge is not active".into());
        }

        if msg.confirmations < bridge.required_confirmations {
            return Err(format!(
                "Insufficient confirmations: {} < required {}",
                msg.confirmations, bridge.required_confirmations
            ));
        }

        // Validate transfer amounts.
        if let BridgeMessageType::InboundTransfer { amount, .. }
        | BridgeMessageType::OutboundTransfer { amount, .. } = &msg.message_type
        {
            if *amount > bridge.max_transfer {
                return Err(format!(
                    "Transfer amount {} exceeds bridge max {}",
                    amount, bridge.max_transfer
                ));
            }
        }

        Ok(())
    }

    /// Get active bridges.
    pub fn active_bridges(&self) -> Vec<&BridgeAdapter> {
        self.bridges.iter().filter(|b| b.active).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_bridge() -> BridgeAdapter {
        BridgeAdapter {
            id: [1u8; 32],
            name: "test-bridge".into(),
            chain_type: ExternalChainType::Evm { chain_id: 1 },
            required_level: PrecedenceLevel::Meaning,
            active: true,
            max_transfer: TensionValue::from_integer(1_000_000),
            required_confirmations: 12,
        }
    }

    #[test]
    fn test_bridge_registration() {
        let mut registry = BridgeRegistry::default();
        registry
            .register(test_bridge(), PrecedenceLevel::Meaning)
            .unwrap();
        assert_eq!(registry.active_bridges().len(), 1);
    }

    #[test]
    fn test_bridge_authority_check() {
        let mut registry = BridgeRegistry::default();
        let result = registry.register(test_bridge(), PrecedenceLevel::Optimization);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_validation() {
        let mut registry = BridgeRegistry::default();
        registry
            .register(test_bridge(), PrecedenceLevel::Meaning)
            .unwrap();

        let msg = BridgeMessage {
            source_chain: [2u8; 32],
            dest_chain: [3u8; 32],
            bridge_id: [1u8; 32],
            message_type: BridgeMessageType::InboundTransfer {
                recipient: [4u8; 32],
                amount: TensionValue::from_integer(1000),
                external_tx_hash: vec![0xAB; 32],
            },
            source_proof: vec![],
            source_height: 100,
            confirmations: 15,
        };

        assert!(registry.validate_message(&msg).is_ok());
    }

    #[test]
    fn test_insufficient_confirmations() {
        let mut registry = BridgeRegistry::default();
        registry
            .register(test_bridge(), PrecedenceLevel::Meaning)
            .unwrap();

        let msg = BridgeMessage {
            source_chain: [2u8; 32],
            dest_chain: [3u8; 32],
            bridge_id: [1u8; 32],
            message_type: BridgeMessageType::InboundTransfer {
                recipient: [4u8; 32],
                amount: TensionValue::from_integer(1000),
                external_tx_hash: vec![],
            },
            source_proof: vec![],
            source_height: 100,
            confirmations: 5, // Less than required 12.
        };

        assert!(registry.validate_message(&msg).is_err());
    }

    #[test]
    fn test_transfer_exceeds_limit() {
        let mut registry = BridgeRegistry::default();
        registry
            .register(test_bridge(), PrecedenceLevel::Meaning)
            .unwrap();

        let msg = BridgeMessage {
            source_chain: [2u8; 32],
            dest_chain: [3u8; 32],
            bridge_id: [1u8; 32],
            message_type: BridgeMessageType::InboundTransfer {
                recipient: [4u8; 32],
                amount: TensionValue::from_integer(999_999_999), // Way over max.
                external_tx_hash: vec![],
            },
            source_proof: vec![],
            source_height: 100,
            confirmations: 15,
        };

        assert!(registry.validate_message(&msg).is_err());
    }
}
