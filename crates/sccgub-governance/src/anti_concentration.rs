use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use sccgub_types::governance::PrecedenceLevel;
use sccgub_types::AgentId;

/// Governance anti-concentration module.
/// Prevents any single entity from accumulating unchecked governance power.
///
/// This addresses the primary fracture risk: a chain built around proof-of-governance
/// can be captured if governance authority concentrates. These mechanisms ensure
/// structural distribution of power.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceLimits {
    /// Maximum percentage of governance actions any single agent can perform per epoch.
    pub max_actions_per_agent_pct: u32,
    /// Minimum number of distinct validators required for SAFETY-level changes.
    pub safety_change_min_signers: u32,
    /// Minimum number of distinct validators required for GENESIS-level changes.
    pub genesis_change_min_signers: u32,
    /// Maximum consecutive blocks any single validator can propose.
    pub max_consecutive_proposals: u32,
    /// Term limit: maximum epochs a single agent can hold SAFETY or higher authority.
    pub max_authority_term_epochs: u64,
    /// Cooldown epochs after term limit before the same agent can regain authority.
    pub authority_cooldown_epochs: u64,
}

impl Default for GovernanceLimits {
    fn default() -> Self {
        Self {
            max_actions_per_agent_pct: 33,  // No agent > 33% of governance actions.
            safety_change_min_signers: 3,   // SAFETY changes need 3+ signers.
            genesis_change_min_signers: 5,  // GENESIS changes need 5+ signers.
            max_consecutive_proposals: 3,   // Max 3 blocks in a row from same validator.
            max_authority_term_epochs: 100, // Term limit: 100 epochs.
            authority_cooldown_epochs: 10,  // 10-epoch cooldown after term expires.
        }
    }
}

/// Tracks governance power distribution across agents.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct GovernancePowerTracker {
    /// Actions per agent in the current epoch.
    pub actions_this_epoch: HashMap<AgentId, u32>,
    /// Total actions this epoch.
    pub total_actions_epoch: u32,
    /// Consecutive block proposals per validator.
    pub consecutive_proposals: HashMap<AgentId, u32>,
    /// Last proposer (for consecutive tracking).
    pub last_proposer: Option<AgentId>,
    /// Authority grant epoch per agent (for term limits).
    pub authority_granted_at: HashMap<AgentId, u64>,
    /// Agents in cooldown (cannot hold authority until cooldown expires).
    pub cooldown_until: HashMap<AgentId, u64>,
}

impl GovernancePowerTracker {
    /// Check if an agent is allowed to perform a governance action.
    pub fn check_action(&self, agent: &AgentId, limits: &GovernanceLimits) -> Result<(), String> {
        // Check percentage cap.
        if self.total_actions_epoch > 0 {
            let agent_actions = self.actions_this_epoch.get(agent).copied().unwrap_or(0);
            let pct = (agent_actions as u64 * 100) / self.total_actions_epoch as u64;
            if pct >= limits.max_actions_per_agent_pct as u64 {
                return Err(format!(
                    "Agent {} has performed {}% of governance actions (max {}%)",
                    hex::encode(agent),
                    pct,
                    limits.max_actions_per_agent_pct
                ));
            }
        }
        Ok(())
    }

    /// Record a governance action by an agent.
    pub fn record_action(&mut self, agent: &AgentId) {
        let entry = self.actions_this_epoch.entry(*agent).or_insert(0);
        *entry = entry.saturating_add(1);
        self.total_actions_epoch = self.total_actions_epoch.saturating_add(1);
    }

    /// Check if a validator can propose the next block.
    pub fn check_proposal(
        &self,
        validator: &AgentId,
        limits: &GovernanceLimits,
    ) -> Result<(), String> {
        if let Some(last) = &self.last_proposer {
            if last == validator {
                let consecutive = self
                    .consecutive_proposals
                    .get(validator)
                    .copied()
                    .unwrap_or(0);
                if consecutive >= limits.max_consecutive_proposals {
                    return Err(format!(
                        "Validator {} has proposed {} consecutive blocks (max {})",
                        hex::encode(validator),
                        consecutive,
                        limits.max_consecutive_proposals
                    ));
                }
            }
        }
        Ok(())
    }

    /// Record a block proposal.
    pub fn record_proposal(&mut self, validator: &AgentId) {
        if self.last_proposer.as_ref() == Some(validator) {
            *self.consecutive_proposals.entry(*validator).or_insert(0) += 1;
        } else {
            self.consecutive_proposals.clear();
            self.consecutive_proposals.insert(*validator, 1);
            self.last_proposer = Some(*validator);
        }
    }

    /// Check if an agent can hold authority at a given level.
    pub fn check_authority_term(
        &self,
        agent: &AgentId,
        current_epoch: u64,
        limits: &GovernanceLimits,
    ) -> Result<(), String> {
        // Check cooldown.
        if let Some(&cooldown_end) = self.cooldown_until.get(agent) {
            if current_epoch < cooldown_end {
                return Err(format!(
                    "Agent {} is in authority cooldown until epoch {}",
                    hex::encode(agent),
                    cooldown_end
                ));
            }
        }

        // Check term limit.
        if let Some(&granted_at) = self.authority_granted_at.get(agent) {
            if current_epoch - granted_at > limits.max_authority_term_epochs {
                return Err(format!(
                    "Agent {} has exceeded authority term limit ({} epochs)",
                    hex::encode(agent),
                    limits.max_authority_term_epochs
                ));
            }
        }

        Ok(())
    }

    /// Grant authority to an agent (records the epoch for term tracking).
    pub fn grant_authority(&mut self, agent: &AgentId, epoch: u64) {
        self.authority_granted_at.insert(*agent, epoch);
    }

    /// Revoke authority and start cooldown.
    pub fn revoke_authority(
        &mut self,
        agent: &AgentId,
        current_epoch: u64,
        limits: &GovernanceLimits,
    ) {
        self.authority_granted_at.remove(agent);
        self.cooldown_until
            .insert(*agent, current_epoch + limits.authority_cooldown_epochs);
    }

    /// Check if a SAFETY or GENESIS level change has enough distinct signers.
    pub fn check_multi_sig(
        signers: &[AgentId],
        level: PrecedenceLevel,
        limits: &GovernanceLimits,
    ) -> Result<(), String> {
        let unique: std::collections::HashSet<&AgentId> = signers.iter().collect();
        let required = match level {
            PrecedenceLevel::Genesis => limits.genesis_change_min_signers,
            PrecedenceLevel::Safety => limits.safety_change_min_signers,
            _ => 1,
        };
        if (unique.len() as u32) < required {
            return Err(format!(
                "{:?}-level change requires {} distinct signers, got {}",
                level,
                required,
                unique.len()
            ));
        }
        Ok(())
    }

    /// Reset epoch counters (called at epoch boundary).
    pub fn reset_epoch(&mut self) {
        self.actions_this_epoch.clear();
        self.total_actions_epoch = 0;
    }

    /// Compute a governance concentration score (0.0 = perfectly distributed, 1.0 = fully concentrated).
    pub fn concentration_score(&self) -> f64 {
        if self.total_actions_epoch == 0 || self.actions_this_epoch.is_empty() {
            return 0.0;
        }
        let n = self.actions_this_epoch.len() as f64;
        let total = self.total_actions_epoch as f64;
        // Herfindahl-Hirschman Index normalized to [0, 1].
        let hhi: f64 = self
            .actions_this_epoch
            .values()
            .map(|&count| {
                let share = count as f64 / total;
                share * share
            })
            .sum();
        // HHI ranges from 1/n (perfect distribution) to 1.0 (monopoly).
        // Normalize: (HHI - 1/n) / (1 - 1/n).
        let min_hhi = 1.0 / n;
        if (1.0 - min_hhi).abs() < f64::EPSILON {
            return 0.0;
        }
        ((hhi - min_hhi) / (1.0 - min_hhi)).clamp(0.0, 1.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_cap() {
        let limits = GovernanceLimits {
            max_actions_per_agent_pct: 50,
            ..Default::default()
        };
        let mut tracker = GovernancePowerTracker::default();
        let agent = [1u8; 32];

        // 3 actions by agent out of 5 total = 60% > 50% cap.
        for _ in 0..3 {
            tracker.record_action(&agent);
        }
        tracker.record_action(&[2u8; 32]);
        tracker.record_action(&[3u8; 32]);

        assert!(tracker.check_action(&agent, &limits).is_err());
    }

    #[test]
    fn test_consecutive_proposals() {
        let limits = GovernanceLimits::default();
        let mut tracker = GovernancePowerTracker::default();
        let validator = [1u8; 32];

        for _ in 0..3 {
            tracker.record_proposal(&validator);
        }
        // 3rd is OK (max is 3), but 4th should fail.
        assert!(tracker.check_proposal(&validator, &limits).is_err());
    }

    #[test]
    fn test_consecutive_reset_on_different_proposer() {
        let limits = GovernanceLimits::default();
        let mut tracker = GovernancePowerTracker::default();

        tracker.record_proposal(&[1u8; 32]);
        tracker.record_proposal(&[1u8; 32]);
        tracker.record_proposal(&[2u8; 32]); // Different proposer resets count.
        tracker.record_proposal(&[1u8; 32]); // Back to 1, starts fresh.

        assert!(tracker.check_proposal(&[1u8; 32], &limits).is_ok());
    }

    #[test]
    fn test_term_limit() {
        let limits = GovernanceLimits {
            max_authority_term_epochs: 10,
            authority_cooldown_epochs: 5,
            ..Default::default()
        };
        let mut tracker = GovernancePowerTracker::default();
        let agent = [1u8; 32];

        tracker.grant_authority(&agent, 0);

        // Within term: OK.
        assert!(tracker.check_authority_term(&agent, 5, &limits).is_ok());

        // Exceeded term.
        assert!(tracker.check_authority_term(&agent, 15, &limits).is_err());

        // Revoke and check cooldown.
        tracker.revoke_authority(&agent, 15, &limits);
        assert!(tracker.check_authority_term(&agent, 16, &limits).is_err()); // In cooldown.
        assert!(tracker.check_authority_term(&agent, 25, &limits).is_ok()); // Cooldown expired.
    }

    #[test]
    fn test_multi_sig_requirement() {
        let limits = GovernanceLimits::default();

        // SAFETY needs 3 signers.
        let signers = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        assert!(GovernancePowerTracker::check_multi_sig(
            &signers,
            PrecedenceLevel::Safety,
            &limits
        )
        .is_ok());

        // Only 2 signers should fail.
        let signers = vec![[1u8; 32], [2u8; 32]];
        assert!(GovernancePowerTracker::check_multi_sig(
            &signers,
            PrecedenceLevel::Safety,
            &limits
        )
        .is_err());

        // Duplicate signers don't count.
        let signers = vec![[1u8; 32], [1u8; 32], [1u8; 32]];
        assert!(GovernancePowerTracker::check_multi_sig(
            &signers,
            PrecedenceLevel::Safety,
            &limits
        )
        .is_err());
    }

    #[test]
    fn test_concentration_score() {
        let mut tracker = GovernancePowerTracker::default();

        // Perfectly distributed: 3 agents, 1 action each.
        tracker.record_action(&[1u8; 32]);
        tracker.record_action(&[2u8; 32]);
        tracker.record_action(&[3u8; 32]);
        assert!(tracker.concentration_score() < 0.01);

        // Highly concentrated: 1 agent dominates.
        let mut concentrated = GovernancePowerTracker::default();
        for _ in 0..97 {
            concentrated.record_action(&[1u8; 32]);
        }
        concentrated.record_action(&[2u8; 32]);
        concentrated.record_action(&[3u8; 32]);
        concentrated.record_action(&[4u8; 32]);
        assert!(concentrated.concentration_score() > 0.8);
    }
}
