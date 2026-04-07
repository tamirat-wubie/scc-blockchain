use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use sccgub_types::Hash;

/// Network partition detection and recovery protocol.
///
/// Detection: block height diverges > threshold between validator groups.
/// Recovery:
///   1. Identify canonical group (supermajority by validator count).
///   2. Minority group rolls back to last common block.
///   3. Minority rejoins and syncs from canonical chain.
///   4. Validators in minority that produced conflicting blocks are slashed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionConfig {
    /// Block height divergence threshold to detect partition.
    pub divergence_threshold: u64,
    /// Maximum blocks to look back for common ancestor.
    pub max_rollback_depth: u64,
}

impl Default for PartitionConfig {
    fn default() -> Self {
        Self {
            divergence_threshold: 10,
            max_rollback_depth: 100,
        }
    }
}

/// State of the partition detector.
#[derive(Debug, Clone, Default)]
pub struct PartitionDetector {
    /// Last known block height per validator.
    pub validator_heights: HashMap<Hash, u64>,
}

/// Result of partition detection.
#[derive(Debug, Clone)]
pub enum PartitionStatus {
    /// All validators are within acceptable divergence.
    Healthy { min_height: u64, max_height: u64 },
    /// Partition detected: validators are split into groups.
    Partitioned {
        groups: Vec<ValidatorGroup>,
        canonical_group_index: usize,
    },
}

/// A group of validators that agree on the same chain state.
#[derive(Debug, Clone)]
pub struct ValidatorGroup {
    pub validators: Vec<Hash>,
    pub max_height: u64,
    pub block_hash_at_max: Option<Hash>,
}

impl PartitionDetector {
    /// Update a validator's reported height.
    pub fn report_height(&mut self, validator: Hash, height: u64) {
        self.validator_heights.insert(validator, height);
    }

    /// Detect if a partition exists.
    pub fn detect(&self, config: &PartitionConfig) -> PartitionStatus {
        if self.validator_heights.is_empty() {
            return PartitionStatus::Healthy {
                min_height: 0,
                max_height: 0,
            };
        }

        let min = *self.validator_heights.values().min().unwrap();
        let max = *self.validator_heights.values().max().unwrap();

        if max - min <= config.divergence_threshold {
            return PartitionStatus::Healthy {
                min_height: min,
                max_height: max,
            };
        }

        // Partition detected. Group validators by height range.
        // Simple heuristic: split at the midpoint.
        let midpoint = (min + max) / 2;

        let mut group_low = ValidatorGroup {
            validators: Vec::new(),
            max_height: 0,
            block_hash_at_max: None,
        };
        let mut group_high = ValidatorGroup {
            validators: Vec::new(),
            max_height: 0,
            block_hash_at_max: None,
        };

        for (&validator, &height) in &self.validator_heights {
            if height <= midpoint {
                group_low.validators.push(validator);
                group_low.max_height = group_low.max_height.max(height);
            } else {
                group_high.validators.push(validator);
                group_high.max_height = group_high.max_height.max(height);
            }
        }

        // Canonical group = the one with more validators (supermajority).
        let groups = vec![group_low, group_high];
        let canonical = if groups[0].validators.len() >= groups[1].validators.len() {
            0
        } else {
            1
        };

        PartitionStatus::Partitioned {
            groups,
            canonical_group_index: canonical,
        }
    }
}

/// Recovery action to take after partition detection.
#[derive(Debug, Clone)]
pub enum RecoveryAction {
    /// No action needed.
    None,
    /// Minority validators must rollback to common ancestor and resync.
    Rollback {
        minority_validators: Vec<Hash>,
        rollback_to_height: u64,
    },
    /// Partition too deep — requires manual operator intervention.
    ManualIntervention {
        reason: String,
        minority_validators: Vec<Hash>,
        canonical_validators: Vec<Hash>,
    },
}

/// Determine recovery action from partition status.
pub fn plan_recovery(
    status: &PartitionStatus,
    config: &PartitionConfig,
    current_finalized_height: u64,
) -> RecoveryAction {
    match status {
        PartitionStatus::Healthy { .. } => RecoveryAction::None,
        PartitionStatus::Partitioned {
            groups,
            canonical_group_index,
        } => {
            let canonical = &groups[*canonical_group_index];
            let minority_idx = 1 - canonical_group_index;
            let minority = &groups[minority_idx];

            // Gap: absolute difference between groups (minority may be ahead or behind).
            let gap = canonical
                .max_height
                .max(minority.max_height)
                .saturating_sub(canonical.max_height.min(minority.max_height));

            if gap > config.max_rollback_depth {
                RecoveryAction::ManualIntervention {
                    reason: format!(
                        "Partition gap {} exceeds max rollback depth {}",
                        gap, config.max_rollback_depth
                    ),
                    minority_validators: minority.validators.clone(),
                    canonical_validators: canonical.validators.clone(),
                }
            } else {
                RecoveryAction::Rollback {
                    minority_validators: minority.validators.clone(),
                    rollback_to_height: current_finalized_height,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_healthy_network() {
        let config = PartitionConfig::default();
        let mut detector = PartitionDetector::default();

        for i in 1..=5u8 {
            detector.report_height([i; 32], 100);
        }

        match detector.detect(&config) {
            PartitionStatus::Healthy {
                min_height,
                max_height,
            } => {
                assert_eq!(min_height, 100);
                assert_eq!(max_height, 100);
            }
            _ => panic!("Expected healthy"),
        }
    }

    #[test]
    fn test_partition_detected() {
        let config = PartitionConfig {
            divergence_threshold: 5,
            ..Default::default()
        };
        let mut detector = PartitionDetector::default();

        // Group 1: heights 100-102.
        detector.report_height([1u8; 32], 100);
        detector.report_height([2u8; 32], 101);
        detector.report_height([3u8; 32], 102);

        // Group 2: heights 120-122 (diverged by 20).
        detector.report_height([4u8; 32], 120);
        detector.report_height([5u8; 32], 122);

        match detector.detect(&config) {
            PartitionStatus::Partitioned {
                groups,
                canonical_group_index,
            } => {
                assert_eq!(groups.len(), 2);
                // Group with more validators is canonical.
                assert_eq!(groups[canonical_group_index].validators.len(), 3);
            }
            _ => panic!("Expected partition"),
        }
    }

    #[test]
    fn test_recovery_rollback() {
        let config = PartitionConfig::default();

        let status = PartitionStatus::Partitioned {
            groups: vec![
                ValidatorGroup {
                    validators: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
                    max_height: 100,
                    block_hash_at_max: None,
                },
                ValidatorGroup {
                    validators: vec![[4u8; 32], [5u8; 32]],
                    max_height: 120,
                    block_hash_at_max: None,
                },
            ],
            canonical_group_index: 0, // Larger group.
        };

        let action = plan_recovery(&status, &config, 95);
        match action {
            RecoveryAction::Rollback {
                minority_validators,
                rollback_to_height,
            } => {
                assert_eq!(minority_validators.len(), 2);
                assert_eq!(rollback_to_height, 95);
            }
            _ => panic!("Expected Rollback"),
        }
    }

    #[test]
    fn test_manual_intervention_needed() {
        let config = PartitionConfig {
            max_rollback_depth: 10,
            ..Default::default()
        };

        let status = PartitionStatus::Partitioned {
            groups: vec![
                ValidatorGroup {
                    validators: vec![[1u8; 32], [2u8; 32], [3u8; 32]],
                    max_height: 100,
                    block_hash_at_max: None,
                },
                ValidatorGroup {
                    validators: vec![[4u8; 32]],
                    max_height: 200, // Gap = 100, exceeds max_rollback_depth=10.
                    block_hash_at_max: None,
                },
            ],
            canonical_group_index: 0,
        };

        let action = plan_recovery(&status, &config, 90);
        match action {
            RecoveryAction::ManualIntervention { .. } => {}
            _ => panic!("Expected ManualIntervention"),
        }
    }
}
