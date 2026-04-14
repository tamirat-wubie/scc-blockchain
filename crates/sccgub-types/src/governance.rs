use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};

use crate::tension::TensionValue;
use crate::{AgentId, ConstraintId, Hash, NormId, RuleId};

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

impl std::fmt::Display for PrecedenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Genesis => write!(f, "Genesis"),
            Self::Safety => write!(f, "Safety"),
            Self::Meaning => write!(f, "Meaning"),
            Self::Emotion => write!(f, "Emotion"),
            Self::Optimization => write!(f, "Optimization"),
        }
    }
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
    pub constraint_catalog: BTreeSet<ConstraintId>,
    pub rule_catalog: BTreeSet<RuleId>,
    pub authority_map: HashMap<AgentId, AuthorityLevel>,
    pub emergency_mode: bool,
    pub finality_mode: FinalityMode,
}

impl Default for GovernanceState {
    fn default() -> Self {
        Self {
            active_norms: HashMap::new(),
            constraint_catalog: BTreeSet::new(),
            rule_catalog: BTreeSet::new(),
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
    #[serde(default)]
    pub governance_limits: GovernanceLimitsSnapshot,
    #[serde(default)]
    pub finality_config: FinalityConfigSnapshot,
}

/// Snapshot of governance anti-concentration limits included in each block.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernanceLimitsSnapshot {
    pub max_actions_per_agent_pct: u32,
    pub safety_change_min_signers: u32,
    pub genesis_change_min_signers: u32,
    pub max_consecutive_proposals: u32,
    pub max_authority_term_epochs: u64,
    pub authority_cooldown_epochs: u64,
}

impl Default for GovernanceLimitsSnapshot {
    fn default() -> Self {
        Self {
            max_actions_per_agent_pct: 33,
            safety_change_min_signers: 3,
            genesis_change_min_signers: 5,
            max_consecutive_proposals: 3,
            max_authority_term_epochs: 100,
            authority_cooldown_epochs: 10,
        }
    }
}

/// Snapshot of finality configuration included in each block.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct FinalityConfigSnapshot {
    pub confirmation_depth: u64,
    pub max_finality_ms: u64,
    pub target_block_time_ms: u64,
}

impl Default for FinalityConfigSnapshot {
    fn default() -> Self {
        Self {
            confirmation_depth: 2,
            max_finality_ms: 6_000,
            target_block_time_ms: 2_000,
        }
    }
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
