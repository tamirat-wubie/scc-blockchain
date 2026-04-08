use sccgub_types::tension::TensionValue;
use sccgub_types::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Adversarial containment per Phi-squared-A.
/// Hostile nodes are contained, not expelled.
/// Per spec Section 11.3: HostilityIndex = delta_negative / (delta_positive + epsilon).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainmentState {
    pub nodes: HashMap<NodeId, NodeBehaviorProfile>,
    /// Threshold above which containment is activated.
    pub hostility_threshold: TensionValue,
    /// Small epsilon to avoid division by zero.
    pub epsilon: TensionValue,
}

impl Default for ContainmentState {
    fn default() -> Self {
        Self {
            nodes: HashMap::new(),
            hostility_threshold: TensionValue::from_integer(2),
            epsilon: TensionValue(1), // minimal non-zero
        }
    }
}

/// Behavioral profile for a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeBehaviorProfile {
    pub node_id: NodeId,
    /// Total positive (stabilizing) state deltas contributed.
    pub positive_delta: TensionValue,
    /// Total negative (destabilizing) state deltas contributed.
    pub negative_delta: TensionValue,
    /// Current containment level.
    pub containment: ContainmentLevel,
    /// Number of invalid transitions submitted.
    pub invalid_count: u64,
    /// Number of valid transitions submitted.
    pub valid_count: u64,
}

impl NodeBehaviorProfile {
    pub fn new(node_id: NodeId) -> Self {
        Self {
            node_id,
            positive_delta: TensionValue::ZERO,
            negative_delta: TensionValue::ZERO,
            containment: ContainmentLevel::None,
            invalid_count: 0,
            valid_count: 0,
        }
    }

    /// Compute the hostility index: negative / (positive + epsilon).
    /// Uses split-multiply to prevent overflow.
    pub fn hostility_index(&self, epsilon: TensionValue) -> TensionValue {
        let denominator = self.positive_delta + epsilon;
        if denominator.raw() <= 0 {
            return TensionValue::ZERO;
        }
        let d = denominator.raw();
        // Split-multiply: (n / d) * SCALE + (n % d) * SCALE / d
        let n = self.negative_delta.raw();
        let whole = (n / d).saturating_mul(TensionValue::SCALE);
        let frac = (n % d).saturating_mul(TensionValue::SCALE) / d;
        TensionValue(whole.saturating_add(frac))
    }
}

/// Containment levels applied to hostile nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainmentLevel {
    /// No restrictions.
    None,
    /// Reduced transaction throughput.
    ReducedThroughput { max_txs_per_block: u32 },
    /// Increased proof requirements.
    IncreasedProofRequirements,
    /// Quarantine — no new transitions accepted, monitor only.
    Quarantine { blocks_remaining: u64 },
}

/// Maximum tracked nodes in containment state (prevents Sybil memory DoS).
pub const MAX_TRACKED_NODES: usize = 10_000;

impl ContainmentState {
    /// Record a valid transition from a node.
    pub fn record_valid(&mut self, node_id: NodeId, delta: TensionValue) {
        // Cap: reject tracking new nodes if at capacity (updates to existing nodes always allowed).
        if !self.nodes.contains_key(&node_id) && self.nodes.len() >= MAX_TRACKED_NODES {
            return;
        }
        let profile = self
            .nodes
            .entry(node_id)
            .or_insert_with(|| NodeBehaviorProfile::new(node_id));
        profile.positive_delta = profile.positive_delta + delta;
        profile.valid_count = profile.valid_count.saturating_add(1);
    }

    /// Record an invalid/destabilizing transition from a node.
    pub fn record_invalid(&mut self, node_id: NodeId, delta: TensionValue) {
        if !self.nodes.contains_key(&node_id) && self.nodes.len() >= MAX_TRACKED_NODES {
            return;
        }
        let profile = self
            .nodes
            .entry(node_id)
            .or_insert_with(|| NodeBehaviorProfile::new(node_id));
        profile.negative_delta = profile.negative_delta + delta;
        profile.invalid_count = profile.invalid_count.saturating_add(1);
    }

    /// Evaluate all nodes and apply/release containment.
    pub fn evaluate(&mut self) {
        let threshold = self.hostility_threshold;
        let epsilon = self.epsilon;

        for profile in self.nodes.values_mut() {
            let hostility = profile.hostility_index(epsilon);

            // Release threshold: half the activation threshold.
            let release_threshold = TensionValue(threshold.raw() / 2);

            if hostility > threshold {
                // Escalate containment. Reset quarantine timer if still hostile.
                profile.containment = match profile.containment {
                    ContainmentLevel::None => ContainmentLevel::ReducedThroughput {
                        max_txs_per_block: 1,
                    },
                    ContainmentLevel::ReducedThroughput { .. } => {
                        ContainmentLevel::IncreasedProofRequirements
                    }
                    ContainmentLevel::IncreasedProofRequirements => ContainmentLevel::Quarantine {
                        blocks_remaining: 100,
                    },
                    ContainmentLevel::Quarantine { .. } => {
                        // Reset quarantine timer — still hostile.
                        ContainmentLevel::Quarantine {
                            blocks_remaining: 100,
                        }
                    }
                };
            } else if hostility <= release_threshold
                && profile.containment != ContainmentLevel::None
            {
                // De-escalate one level (gradual release, not instant).
                profile.containment = match profile.containment {
                    ContainmentLevel::Quarantine { .. } => {
                        ContainmentLevel::IncreasedProofRequirements
                    }
                    ContainmentLevel::IncreasedProofRequirements => {
                        ContainmentLevel::ReducedThroughput {
                            max_txs_per_block: 5,
                        }
                    }
                    ContainmentLevel::ReducedThroughput { .. } => ContainmentLevel::None,
                    ContainmentLevel::None => ContainmentLevel::None,
                };
            }
        }
    }

    /// Check if a node is allowed to submit transactions.
    pub fn is_allowed(&self, node_id: &NodeId) -> bool {
        match self.nodes.get(node_id) {
            None => true,
            Some(profile) => !matches!(profile.containment, ContainmentLevel::Quarantine { .. }),
        }
    }

    /// Decrement quarantine counters and decay negative delta over time.
    pub fn tick_block(&mut self) {
        for profile in self.nodes.values_mut() {
            // Decay negative_delta by 1% per block (positive behavior over time reduces hostility).
            let decay = TensionValue(profile.negative_delta.raw() / 100);
            profile.negative_delta = profile.negative_delta - decay;

            if let ContainmentLevel::Quarantine { blocks_remaining } = &mut profile.containment {
                if *blocks_remaining > 0 {
                    *blocks_remaining -= 1;
                }
                if *blocks_remaining == 0 {
                    profile.containment = ContainmentLevel::ReducedThroughput {
                        max_txs_per_block: 1,
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostility_index() {
        let mut profile = NodeBehaviorProfile::new([1u8; 32]);
        profile.positive_delta = TensionValue::from_integer(10);
        profile.negative_delta = TensionValue::from_integer(30);

        let idx = profile.hostility_index(TensionValue(1));
        // 30 / (10 + epsilon) ≈ 3.0
        assert!(idx > TensionValue::from_integer(2));
    }

    #[test]
    fn test_containment_escalation() {
        let mut state = ContainmentState::default();
        let node = [1u8; 32];

        // Lots of invalid, few valid.
        state.record_invalid(node, TensionValue::from_integer(100));
        state.record_valid(node, TensionValue::from_integer(1));

        state.evaluate();
        let profile = &state.nodes[&node];
        assert!(
            !matches!(profile.containment, ContainmentLevel::None),
            "Node with high hostility should be contained"
        );
    }

    #[test]
    fn test_quarantine_blocks_submission() {
        let mut state = ContainmentState::default();
        let node = [1u8; 32];

        state.nodes.insert(
            node,
            NodeBehaviorProfile {
                node_id: node,
                positive_delta: TensionValue::ZERO,
                negative_delta: TensionValue::from_integer(100),
                containment: ContainmentLevel::Quarantine {
                    blocks_remaining: 10,
                },
                invalid_count: 50,
                valid_count: 0,
            },
        );

        assert!(!state.is_allowed(&node));
    }

    #[test]
    fn test_good_node_no_containment() {
        let mut state = ContainmentState::default();
        let node = [1u8; 32];

        state.record_valid(node, TensionValue::from_integer(100));
        state.record_valid(node, TensionValue::from_integer(50));

        state.evaluate();
        assert!(state.is_allowed(&node));
        assert_eq!(state.nodes[&node].containment, ContainmentLevel::None);
    }
}
