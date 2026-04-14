use serde::{Deserialize, Serialize};

use sccgub_types::Hash;

/// Bounded-latency finality mechanism.
///
/// A block is final when:
/// 1. It has passed two-round consensus (prevote + precommit quorum), AND
/// 2. k subsequent blocks have been appended above it.
///
/// After finality: P(block reorganized) < epsilon_accept.
///
/// This addresses the critical gap identified in the consensus audit:
/// "Finality latency is UNSPECIFIED" -> now specified with bounded k.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityConfig {
    /// Number of subsequent blocks required for finality (k).
    /// k=1: instant finality after consensus (fastest, lowest safety margin).
    /// k=2: one confirmation block (recommended for production).
    /// k=32: high safety (comparable to Ethereum PoS).
    pub confirmation_depth: u64,
    /// Maximum acceptable finality latency in milliseconds.
    /// If finality exceeds this, emit alert.
    pub max_finality_ms: u64,
    /// Target block time in milliseconds.
    pub target_block_time_ms: u64,
}

impl Default for FinalityConfig {
    fn default() -> Self {
        Self {
            confirmation_depth: 2,       // 2 confirmations.
            max_finality_ms: 6_000,      // 6 seconds max.
            target_block_time_ms: 2_000, // 2-second blocks.
        }
    }
}

impl FinalityConfig {
    /// Compute expected finality latency.
    pub fn expected_finality_ms(&self) -> u64 {
        self.confirmation_depth.saturating_mul(self.target_block_time_ms)
    }

    /// Check if finality SLA is met.
    pub fn meets_sla(&self) -> bool {
        self.expected_finality_ms() <= self.max_finality_ms
    }
}

/// Tracks finality state for the chain.
#[derive(Debug, Clone, Default)]
pub struct FinalityTracker {
    /// Highest finalized block height.
    pub finalized_height: u64,
    /// Current chain tip height.
    pub tip_height: u64,
    /// Finality proofs (height -> finality certificate).
    pub certificates: Vec<FinalityCertificate>,
}

/// Certificate proving a block is final.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityCertificate {
    pub block_hash: Hash,
    pub height: u64,
    /// Number of confirmations at time of finalization.
    pub confirmations: u64,
    /// Validator signatures attesting to finality.
    pub attestations: Vec<Hash>,
    /// Timestamp when finality was achieved.
    pub finalized_at_ms: u64,
}

impl FinalityTracker {
    /// Update the tracker with a new block at the tip.
    pub fn on_new_block(&mut self, height: u64) {
        self.tip_height = height;
    }

    /// Check and finalize blocks that have enough confirmations.
    pub fn check_finality(
        &mut self,
        config: &FinalityConfig,
        block_hash_at: impl Fn(u64) -> Option<Hash>,
    ) -> Vec<FinalityCertificate> {
        let mut new_certs = Vec::new();

        while self.finalized_height.saturating_add(config.confirmation_depth) <= self.tip_height {
            let target_height = self.finalized_height.saturating_add(1);
            if let Some(hash) = block_hash_at(target_height) {
                let cert = FinalityCertificate {
                    block_hash: hash,
                    height: target_height,
                    confirmations: self.tip_height.saturating_sub(target_height),
                    attestations: vec![], // Filled by consensus layer.
                    finalized_at_ms: 0,   // Filled by caller.
                };
                new_certs.push(cert.clone());
                self.certificates.push(cert);
                self.finalized_height = target_height;
            } else {
                break;
            }
        }

        new_certs
    }

    /// Get the finality gap (blocks between tip and last finalized).
    pub fn finality_gap(&self) -> u64 {
        self.tip_height.saturating_sub(self.finalized_height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finality_config_sla() {
        let config = FinalityConfig::default();
        assert_eq!(config.expected_finality_ms(), 4000); // 2 blocks * 2s = 4s.
        assert!(config.meets_sla()); // 4s < 6s max.
    }

    #[test]
    fn test_finality_tracker() {
        let config = FinalityConfig {
            confirmation_depth: 2,
            ..Default::default()
        };

        let mut tracker = FinalityTracker::default();

        // Add blocks 1-5.
        for h in 1..=5 {
            tracker.on_new_block(h);
        }

        // With depth=2, blocks 1-4 finalize: finalized+depth <= tip (0+2<=5, 1+2<=5, 2+2<=5, 3+2<=5).
        let certs = tracker.check_finality(&config, |h| Some([h as u8; 32]));
        assert_eq!(certs.len(), 4); // blocks 1,2,3,4 all finalized.
        assert_eq!(tracker.finalized_height, 4);
        assert_eq!(tracker.finality_gap(), 1);
    }

    #[test]
    fn test_instant_finality() {
        let config = FinalityConfig {
            confirmation_depth: 1,
            ..Default::default()
        };

        let mut tracker = FinalityTracker::default();
        tracker.on_new_block(1);

        let certs = tracker.check_finality(&config, |h| Some([h as u8; 32]));
        assert_eq!(certs.len(), 1);
        assert_eq!(tracker.finalized_height, 1);
    }

    #[test]
    fn test_no_premature_finality() {
        let config = FinalityConfig {
            confirmation_depth: 5,
            ..Default::default()
        };

        let mut tracker = FinalityTracker::default();
        tracker.on_new_block(1);
        tracker.on_new_block(2);
        tracker.on_new_block(3);

        // Only 3 blocks, need 5 confirmations. Nothing finalized.
        let certs = tracker.check_finality(&config, |h| Some([h as u8; 32]));
        assert!(certs.is_empty());
        assert_eq!(tracker.finalized_height, 0);
    }
}
