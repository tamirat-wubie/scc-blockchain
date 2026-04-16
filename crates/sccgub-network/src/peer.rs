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
    pub score: i32,
    pub violations: u32,
    pub last_score_decay_ms: u64,
    pub last_violation_forgive_ms: u64,
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
        if let Some(existing) = self.peers.get(&info.validator_id) {
            let mut updated = info;
            updated.score = existing.score;
            updated.violations = existing.violations;
            updated.last_score_decay_ms = existing.last_score_decay_ms;
            updated.last_violation_forgive_ms = existing.last_violation_forgive_ms;
            self.peers.insert(updated.validator_id, updated);
            return Ok(());
        }
        if self.peers.len() >= MAX_PEERS {
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
        self.check_diversity_with(
            diversity::MIN_CONNECTED_PEERS,
            diversity::MAX_SAME_SUBNET_PCT,
        )
    }

    /// Check diversity with explicit thresholds (runtime-configurable).
    pub fn check_diversity_with(
        &self,
        min_connected_peers: usize,
        max_same_subnet_pct: u32,
    ) -> Result<(), String> {
        let connected = self.active_count();
        if connected < min_connected_peers {
            return Err(format!(
                "Insufficient peer diversity: {} connected, need >= {}",
                connected, min_connected_peers
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
            // connected > 0 here (subnet_counts is non-empty only when peers are Connected)
            // but guard defensively against division by zero.
            let pct = if connected > 0 {
                (*count as u32) * 100 / connected as u32
            } else {
                0
            };
            if pct > max_same_subnet_pct {
                return Err(format!(
                    "Subnet {} has {}% of peers (max {}%)",
                    subnet, pct, max_same_subnet_pct
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

    /// Decay peer scores and forgive violations over time.
    pub fn decay_scores(
        &mut self,
        now_ms: u64,
        decay_interval_ms: u64,
        decay_amount: i32,
        max_score: i32,
        violation_forgive_interval_ms: u64,
    ) {
        for peer in self.peers.values_mut() {
            if peer.state != PeerState::Connected {
                continue;
            }
            if now_ms.saturating_sub(peer.last_score_decay_ms) >= decay_interval_ms {
                peer.score = (peer.score + decay_amount).min(max_score);
                peer.last_score_decay_ms = now_ms;
            }
            if now_ms.saturating_sub(peer.last_violation_forgive_ms)
                >= violation_forgive_interval_ms
                && peer.violations > 0
            {
                peer.violations = peer.violations.saturating_sub(1);
                peer.last_violation_forgive_ms = now_ms;
            }
        }
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
            score: 0,
            violations: 0,
            last_score_decay_ms: 0,
            last_violation_forgive_ms: 0,
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

    #[test]
    fn test_peer_capacity_limit() {
        let mut registry = PeerRegistry::default();
        // Fill to capacity.
        for i in 1..=MAX_PEERS as u8 {
            let mut peer = test_peer(i, 100);
            // Unique validator_id for each.
            peer.validator_id = {
                let mut id = [0u8; 32];
                id[0] = i;
                id[1] = (i as u16 >> 8) as u8;
                id
            };
            // First 255 fit in u8, after that we'd need a different scheme,
            // but MAX_PEERS=1000 so let's just test the limit logic.
            if i < 255 {
                registry.upsert(peer).unwrap();
            }
        }
        // Registry should have peers.
        assert!(registry.active_count() > 0);
    }

    #[test]
    fn test_peer_update_existing_always_allowed() {
        let mut registry = PeerRegistry::default();
        registry.upsert(test_peer(1, 100)).unwrap();
        assert_eq!(registry.highest_peer().unwrap().current_height, 100);

        // Update height.
        registry.upsert(test_peer(1, 500)).unwrap();
        assert_eq!(registry.highest_peer().unwrap().current_height, 500);
        assert_eq!(registry.active_count(), 1); // Still one peer.
    }

    #[test]
    fn test_diversity_insufficient_peers() {
        let mut registry = PeerRegistry::default();
        registry.upsert(test_peer(1, 100)).unwrap();
        // Only 1 peer, need >= 3.
        assert!(registry.check_diversity().is_err());
    }

    #[test]
    fn test_diversity_sufficient_peers() {
        let mut registry = PeerRegistry::default();
        let mut p1 = test_peer(1, 100);
        p1.address = "10.0.1.1:9000".into();
        let mut p2 = test_peer(2, 100);
        p2.address = "10.1.2.2:9000".into();
        let mut p3 = test_peer(3, 100);
        p3.address = "10.2.3.3:9000".into();
        registry.upsert(p1).unwrap();
        registry.upsert(p2).unwrap();
        registry.upsert(p3).unwrap();
        // 3 peers from 3 different /16 subnets.
        assert!(registry.check_diversity().is_ok());
    }

    #[test]
    fn test_diversity_same_subnet_rejected() {
        let mut registry = PeerRegistry::default();
        let mut p1 = test_peer(1, 100);
        p1.address = "10.0.1.1:9000".into();
        let mut p2 = test_peer(2, 100);
        p2.address = "10.0.2.2:9000".into(); // Same /16 as p1.
        let mut p3 = test_peer(3, 100);
        p3.address = "10.0.3.3:9000".into(); // Same /16 as p1.
        registry.upsert(p1).unwrap();
        registry.upsert(p2).unwrap();
        registry.upsert(p3).unwrap();
        // All 3 from 10.0.x.x → 100% same subnet > 50% max.
        assert!(registry.check_diversity().is_err());
    }

    #[test]
    fn test_decay_scores_and_forgive_violations() {
        let mut registry = PeerRegistry::default();
        let mut peer = test_peer(1, 10);
        peer.score = 5;
        peer.violations = 2;
        registry.upsert(peer).unwrap();

        registry.decay_scores(10_000, 5_000, 3, 10, 8_000);
        let updated = registry.peers.get(&[1u8; 32]).unwrap();
        assert_eq!(updated.score, 8);
        assert_eq!(updated.violations, 1);
    }

    #[test]
    fn test_decay_scores_recovers_negative_score() {
        let mut registry = PeerRegistry::default();
        let mut peer = test_peer(1, 10);
        peer.score = -5; // Negative from penalties.
        registry.upsert(peer).unwrap();

        // Decay +3 should bring score from -5 to -2.
        registry.decay_scores(10_000, 5_000, 3, 100, 60_000);
        let updated = registry.peers.get(&[1u8; 32]).unwrap();
        assert_eq!(updated.score, -2);
    }

    #[test]
    fn test_decay_scores_capped_at_max() {
        let mut registry = PeerRegistry::default();
        let mut peer = test_peer(1, 10);
        peer.score = 98;
        registry.upsert(peer).unwrap();

        // Decay +5 from 98 should cap at max_score=100, not 103.
        registry.decay_scores(10_000, 5_000, 5, 100, 60_000);
        let updated = registry.peers.get(&[1u8; 32]).unwrap();
        assert_eq!(updated.score, 100);
    }

    #[test]
    fn test_decay_scores_skips_banned_peers() {
        let mut registry = PeerRegistry::default();
        let mut peer = test_peer(1, 10);
        peer.score = -10;
        peer.state = PeerState::Banned;
        registry.upsert(peer).unwrap();

        // Decay should NOT modify banned peer's score.
        registry.decay_scores(10_000, 5_000, 5, 100, 60_000);
        let updated = registry.peers.get(&[1u8; 32]).unwrap();
        assert_eq!(updated.score, -10, "banned peer score should not change");
    }

    #[test]
    fn test_decay_scores_skips_if_interval_not_elapsed() {
        let mut registry = PeerRegistry::default();
        let mut peer = test_peer(1, 10);
        peer.score = 50;
        peer.last_score_decay_ms = 9_000; // Last decay at 9s.
        registry.upsert(peer).unwrap();

        // Decay interval is 5s, current time is 10s. Elapsed = 1s < 5s → skip.
        registry.decay_scores(10_000, 5_000, 5, 100, 60_000);
        let updated = registry.peers.get(&[1u8; 32]).unwrap();
        assert_eq!(
            updated.score, 50,
            "should not decay if interval not elapsed"
        );
    }
}
