use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::{AgentId, ConstraintId, Hash, NormId, RuleId};
use crate::tension::TensionValue;

/// Governance precedence levels — lower number = absolute priority.
/// GENESIS > SAFETY > MEANING > EMOTION > OPTIMIZATION
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum PrecedenceLevel {
    Genesis = 0,
    Safety = 1,
    Meaning = 2,
    Emotion = 3,
    Optimization = 4,
}

impl PrecedenceLevel {
    /// Check if this level has authority over another.
    pub fn overrides(self, other: Self) -> bool {
        (self as u8) < (other as u8)
    }
}

/// Full governance state of the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceState {
    pub active_norms: HashMap<NormId, Norm>,
    pub constraint_catalog: HashSet<ConstraintId>,
    pub rule_catalog: HashSet<RuleId>,
    pub authority_map: HashMap<AgentId, AuthorityLevel>,
    pub emergency_mode: bool,
    pub finality_mode: FinalityMode,
}

impl Default for GovernanceState {
    fn default() -> Self {
        Self {
            active_norms: HashMap::new(),
            constraint_catalog: HashSet::new(),
            rule_catalog: HashSet::new(),
            authority_map: HashMap::new(),
            emergency_mode: false,
            finality_mode: FinalityMode::Deterministic,
        }
    }
}

/// Finality mode — immutable after genesis (v2.1 FIX-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FinalityMode {
    /// Exactly one authorized proposer per round. No competing blocks.
    Deterministic,
    /// Multiple proposers possible. Fork-choice by lower tension. Quorum required.
    /// quorum_threshold must be >= 1 (validated at genesis).
    BftCertified { quorum_threshold: u32 },
}

impl FinalityMode {
    /// Validate finality mode parameters.
    pub fn validate(&self) -> Result<(), String> {
        if let FinalityMode::BftCertified { quorum_threshold } = self {
            if *quorum_threshold == 0 {
                return Err("BFT quorum_threshold must be >= 1".into());
            }
        }
        Ok(())
    }
}

/// Authority level for an agent in governance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorityLevel {
    pub precedence: PrecedenceLevel,
    pub can_propose_norms: bool,
    pub can_validate: bool,
    pub can_govern: bool,
}

/// A behavioral norm that evolves via discrete replicator dynamics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Norm {
    pub id: NormId,
    pub name: String,
    pub description: String,
    pub precedence: PrecedenceLevel,
    pub population_share: TensionValue,
    pub fitness: TensionValue,
    pub enforcement_cost: TensionValue,
    pub active: bool,
    pub created_at_height: u64,
}

/// Snapshot of governance state included in each block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceSnapshot {
    pub state_hash: Hash,
    pub active_norm_count: u32,
    pub emergency_mode: bool,
    pub finality_mode: FinalityMode,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_precedence_override() {
        assert!(PrecedenceLevel::Genesis.overrides(PrecedenceLevel::Safety));
        assert!(PrecedenceLevel::Safety.overrides(PrecedenceLevel::Meaning));
        assert!(!PrecedenceLevel::Optimization.overrides(PrecedenceLevel::Genesis));
    }
}
