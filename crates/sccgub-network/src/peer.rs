use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use sccgub_types::Hash;

/// Peer registry for validator network.
/// Tracks known peers, their heights, and connection state.
#[derive(Debug, Clone, Default)]
pub struct PeerRegistry {
    pub peers: HashMap<Hash, PeerInfo>,
}

/// Information about a network peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub validator_id: Hash,
    pub address: String,
    pub current_height: u64,
    pub finalized_height: u64,
    pub protocol_version: u32,
    pub last_seen_ms: u64,
    pub state: PeerState,
}

/// Connection state of a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerState {
    /// Known but not yet connected.
    Discovered,
    /// Active connection.
    Connected,
    /// Connection lost, attempting reconnect.
    Disconnected,
    /// Banned (slashed or misbehaving).
    Banned,
}

/// Minimum peer diversity requirements (eclipse attack defense).
pub mod diversity {
    /// Minimum number of distinct connected peers before accepting blocks.
    pub const MIN_CONNECTED_PEERS: usize = 3;
    /// Maximum fraction of peers from the same /16 subnet (0-100%).
    pub const MAX_SAME_SUBNET_PCT: u32 = 50;
}

/// Maximum peers tracked (prevents memory DoS from peer flooding).
pub const MAX_PEERS: usize = 1_000;

impl PeerRegistry {
    /// Register or update a peer. Rejects new peers if registry is full.
    pub fn upsert(&mut self, info: PeerInfo) -> Result<(), String> {
        // Check capacity before insert for new peers.
        let is_update = self.peers.contains_key(&info.validator_id);
        if !is_update && self.peers.len() >= MAX_PEERS {
            return Err(format!(
                "Peer registry full ({}/{})",
                self.peers.len(),
                MAX_PEERS
            ));
        }
        self.peers.insert(info.validator_id, info);
        Ok(())
    }

    /// Get active (connected) peer count.
    pub fn active_count(&self) -> usize {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .count()
    }

    /// Get the peer with the highest known block height.
    pub fn highest_peer(&self) -> Option<&PeerInfo> {
        self.peers
            .values()
            .filter(|p| p.state == PeerState::Connected)
            .max_by_key(|p| p.current_height)
    }

    /// Ban a peer (e.g., after slashing).
    pub fn ban(&mut self, validator_id: &Hash) {
        if let Some(peer) = self.peers.get_mut(validator_id) {
            peer.state = PeerState::Banned;
        }
    }

    /// Check if we're behind any peer (need sync).
    pub fn needs_sync(&self, our_height: u64) -> bool {
        self.peers
            .values()
            .any(|p| p.state == PeerState::Connected && p.current_height > our_height)
    }

    /// Check if peer diversity requirements are met (eclipse attack defense).
    /// Returns Ok if sufficient distinct peers from diverse network locations.
    pub fn check_diversity(&self) -> Result<(), String> {
        let connected = self.active_count();
        if connected < diversity::MIN_CONNECTED_PEERS {
            return Err(format!(
                "Insufficient peer diversity: {} connected, need >= {}",
                connected,
                diversity::MIN_CONNECTED_PEERS
            ));
        }

        // Check subnet diversity: count peers per /16 prefix.
        let mut subnet_counts: HashMap<String, usize> = HashMap::new();
        for peer in self.peers.values() {
            if peer.state != PeerState::Connected {
                continue;
            }
            // Extract /16 subnet from address (first two octets).
            let subnet = peer
                .address
                .split(':')
                .next()
                .unwrap_or("")
                .split('.')
                .take(2)
                .collect::<Vec<_>>()
                .join(".");
            *subnet_counts.entry(subnet).or_insert(0) += 1;
        }

        for (subnet, count) in &subnet_counts {
            let pct = (*count as u32) * 100 / connected as u32;
            if pct > diversity::MAX_SAME_SUBNET_PCT {
                return Err(format!(
                    "Subnet {} has {}% of peers (max {}%)",
                    subnet,
                    pct,
                    diversity::MAX_SAME_SUBNET_PCT
                ));
            }
        }

        Ok(())
    }

    /// Get peers sorted by height descending (for sync source selection).
    pub fn sync_candidates(&self, our_height: u64) -> Vec<&PeerInfo> {
        let mut candidates: Vec<&PeerInfo> = self
            .peers
            .values()
            .filter(|p| p.state == PeerState::Connected && p.current_height > our_height)
            .collect();
        candidates.sort_by(|a, b| b.current_height.cmp(&a.current_height));
        candidates
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer(id: u8, height: u64) -> PeerInfo {
        PeerInfo {
            validator_id: [id; 32],
            address: format!("127.0.0.{}:9000", id),
            current_height: height,
            finalized_height: height.saturating_sub(2),
            protocol_version: 1,
            last_seen_ms: 0,
            state: PeerState::Connected,
        }
    }

    #[test]
    fn test_peer_registry() {
        let mut registry = PeerRegistry::default();
        registry.upsert(test_peer(1, 100)).unwrap();
        registry.upsert(test_peer(2, 200)).unwrap();
        registry.upsert(test_peer(3, 150)).unwrap();

        assert_eq!(registry.active_count(), 3);
        assert_eq!(registry.highest_peer().unwrap().current_height, 200);
    }

    #[test]
    fn test_needs_sync() {
        let mut registry = PeerRegistry::default();
        registry.upsert(test_peer(1, 100)).unwrap();
        registry.upsert(test_peer(2, 200)).unwrap();

        assert!(registry.needs_sync(50));
        assert!(!registry.needs_sync(300));
    }

    #[test]
    fn test_sync_candidates() {
        let mut registry = PeerRegistry::default();
        registry.upsert(test_peer(1, 100)).unwrap();
        registry.upsert(test_peer(2, 200)).unwrap();
        registry.upsert(test_peer(3, 150)).unwrap();

        let candidates = registry.sync_candidates(120);
        assert_eq!(candidates.len(), 2); // Peers at 200 and 150, not 100.
        assert_eq!(candidates[0].current_height, 200); // Sorted descending.
    }

    #[test]
    fn test_ban_peer() {
        let mut registry = PeerRegistry::default();
        registry.upsert(test_peer(1, 100)).unwrap();
        assert_eq!(registry.active_count(), 1);

        registry.ban(&[1u8; 32]);
        assert_eq!(registry.active_count(), 0);
    }
}
