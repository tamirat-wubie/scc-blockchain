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

impl PeerRegistry {
    /// Register or update a peer.
    pub fn upsert(&mut self, info: PeerInfo) {
        self.peers.insert(info.validator_id, info);
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
        registry.upsert(test_peer(1, 100));
        registry.upsert(test_peer(2, 200));
        registry.upsert(test_peer(3, 150));

        assert_eq!(registry.active_count(), 3);
        assert_eq!(registry.highest_peer().unwrap().current_height, 200);
    }

    #[test]
    fn test_needs_sync() {
        let mut registry = PeerRegistry::default();
        registry.upsert(test_peer(1, 100));
        registry.upsert(test_peer(2, 200));

        assert!(registry.needs_sync(50));
        assert!(!registry.needs_sync(300));
    }

    #[test]
    fn test_sync_candidates() {
        let mut registry = PeerRegistry::default();
        registry.upsert(test_peer(1, 100));
        registry.upsert(test_peer(2, 200));
        registry.upsert(test_peer(3, 150));

        let candidates = registry.sync_candidates(120);
        assert_eq!(candidates.len(), 2); // Peers at 200 and 150, not 100.
        assert_eq!(candidates[0].current_height, 200); // Sorted descending.
    }

    #[test]
    fn test_ban_peer() {
        let mut registry = PeerRegistry::default();
        registry.upsert(test_peer(1, 100));
        assert_eq!(registry.active_count(), 1);

        registry.ban(&[1u8; 32]);
        assert_eq!(registry.active_count(), 0);
    }
}
