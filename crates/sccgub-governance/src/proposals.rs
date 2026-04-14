use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use sccgub_types::governance::{Norm, PrecedenceLevel};
use sccgub_types::tension::TensionValue;
use sccgub_types::{AgentId, Hash, NormId};

/// Governance proposal lifecycle.
/// Proposals follow: Submitted -> Voting -> Accepted/Rejected -> Timelocked -> Activated.
///
/// Timelocks enforce a mandatory delay between acceptance and activation,
/// giving the community time to review and potentially veto changes.
/// Constitutional proposals (Safety+) have longer timelocks than ordinary ones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceProposal {
    pub id: Hash,
    pub proposer: AgentId,
    pub kind: ProposalKind,
    pub status: ProposalStatus,
    pub submitted_at: u64,
    pub votes_for: u32,
    pub votes_against: u32,
    /// Minimum governance level required to vote on this proposal.
    pub required_level: PrecedenceLevel,
    /// Block height at which voting closes.
    pub voting_deadline: u64,
    /// Set of agents who have already voted (prevents duplicate voting).
    pub voters: BTreeSet<AgentId>,
    /// Block height at which the timelock expires (activation becomes possible).
    /// Set when proposal is accepted. Activation before this height is rejected.
    pub timelock_until: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalKind {
    /// Add a new norm to the registry.
    AddNorm {
        name: String,
        description: String,
        initial_fitness: TensionValue,
        enforcement_cost: TensionValue,
    },
    /// Deactivate an existing norm.
    DeactivateNorm { norm_id: NormId },
    /// Modify a chain parameter (requires SAFETY precedence).
    ModifyParameter { key: String, value: String },
    /// Activate emergency mode (requires SAFETY precedence).
    ActivateEmergency,
    /// Deactivate emergency mode (requires SAFETY precedence).
    DeactivateEmergency,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    Submitted,
    Voting,
    Accepted,
    Rejected,
    /// Timelock active — waiting for mandatory delay before activation.
    Timelocked,
    Activated,
    Expired,
}

/// Timelock durations (in blocks) by proposal class.
/// Constitutional changes (Safety-level) require longer timelocks.
pub mod timelocks {
    /// Ordinary proposals (norm changes, parameter tweaks): 50 blocks.
    pub const ORDINARY: u64 = 50;
    /// Constitutional proposals (safety parameters, emergency): 200 blocks.
    pub const CONSTITUTIONAL: u64 = 200;
}

/// Settlement finality classification for financial operations.
/// Each class represents a different level of commitment certainty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementFinality {
    /// Soft finality: block accepted but not yet confirmed by depth.
    /// Suitable for low-value transfers, notifications.
    Soft,
    /// Economic finality: block confirmed by k subsequent blocks.
    /// Cost of revert exceeds value at stake. Suitable for most payments.
    Economic,
    /// Legal finality: block finalized with safety certificate.
    /// Suitable for regulated finance, compliance-critical operations.
    Legal,
}

impl SettlementFinality {
    /// Minimum confirmation depth required for each finality class.
    pub fn required_depth(&self) -> u64 {
        match self {
            Self::Soft => 0,     // Accepted in block.
            Self::Economic => 2, // 2 confirmations.
            Self::Legal => 6,    // 6 confirmations + safety certificate.
        }
    }
}

/// Maximum proposals in the registry (prevents proposal-flooding DoS).
pub const MAX_PROPOSALS: usize = 10_000;

/// Proposal registry managing the lifecycle of governance proposals.
/// Uses a HashMap index for O(1) proposal lookup by ID.
#[derive(Debug, Clone, Default)]
pub struct ProposalRegistry {
    pub proposals: Vec<GovernanceProposal>,
    index: std::collections::HashMap<Hash, usize>,
}

impl ProposalRegistry {
    /// Submit a new proposal. Returns the proposal ID.
    pub fn submit(
        &mut self,
        proposer: AgentId,
        proposer_level: PrecedenceLevel,
        kind: ProposalKind,
        current_height: u64,
        voting_period: u64,
    ) -> Result<Hash, String> {
        // Capacity check.
        if self.proposals.len() >= MAX_PROPOSALS {
            return Err("Proposal registry full".into());
        }
        // Check proposer has sufficient authority.
        let required = match &kind {
            ProposalKind::AddNorm { .. } | ProposalKind::DeactivateNorm { .. } => {
                PrecedenceLevel::Meaning
            }
            ProposalKind::ModifyParameter { .. }
            | ProposalKind::ActivateEmergency
            | ProposalKind::DeactivateEmergency => PrecedenceLevel::Safety,
        };

        if (proposer_level as u8) > (required as u8) {
            return Err(format!(
                "Insufficient authority: have {:?}, need {:?}",
                proposer_level, required
            ));
        }

        let id = sccgub_crypto::hash::blake3_hash(&sccgub_crypto::canonical::canonical_bytes(&(
            &proposer,
            &kind,
            current_height,
        )));

        self.proposals.push(GovernanceProposal {
            id,
            proposer,
            kind,
            status: ProposalStatus::Voting,
            submitted_at: current_height,
            votes_for: 0,
            votes_against: 0,
            required_level: required,
            voting_deadline: current_height + voting_period,
            voters: BTreeSet::new(),
            timelock_until: 0, // Set when accepted.
        });
        self.index.insert(id, self.proposals.len() - 1);

        Ok(id)
    }

    /// Cast a vote on a proposal. Each agent can only vote once.
    pub fn vote(
        &mut self,
        proposal_id: &Hash,
        voter: AgentId,
        voter_level: PrecedenceLevel,
        approve: bool,
        current_height: u64,
    ) -> Result<(), String> {
        let idx = *self.index.get(proposal_id).ok_or("Proposal not found")?;
        let proposal = &mut self.proposals[idx];

        if proposal.status != ProposalStatus::Voting {
            return Err("Proposal is not in voting state".into());
        }

        if current_height > proposal.voting_deadline {
            return Err("Voting period has ended".into());
        }

        if (voter_level as u8) > (proposal.required_level as u8) {
            return Err("Voter lacks required governance level".into());
        }

        if !proposal.voters.insert(voter) {
            return Err("Agent has already voted on this proposal".into());
        }

        if approve {
            proposal.votes_for = proposal.votes_for.saturating_add(1);
        } else {
            proposal.votes_against = proposal.votes_against.saturating_add(1);
        }

        Ok(())
    }

    /// Finalize proposals whose voting period has ended.
    /// Accepted proposals enter a mandatory timelock period before activation.
    /// Constitutional proposals (Safety-level) have longer timelocks.
    pub fn finalize(&mut self, current_height: u64) -> Vec<GovernanceProposal> {
        let mut accepted = Vec::new();

        for proposal in &mut self.proposals {
            if proposal.status != ProposalStatus::Voting {
                continue;
            }
            if current_height <= proposal.voting_deadline {
                continue;
            }

            if proposal.votes_for > proposal.votes_against {
                // Determine timelock duration based on proposal class.
                let timelock_duration = match &proposal.kind {
                    ProposalKind::ModifyParameter { .. }
                    | ProposalKind::ActivateEmergency
                    | ProposalKind::DeactivateEmergency => timelocks::CONSTITUTIONAL,
                    _ => timelocks::ORDINARY,
                };
                proposal.timelock_until = current_height + timelock_duration;
                proposal.status = ProposalStatus::Timelocked;
                accepted.push(proposal.clone());
            } else {
                proposal.status = ProposalStatus::Rejected;
            }
        }

        accepted
    }

    /// Activate a timelocked proposal after its delay has expired.
    /// Returns the norm to register (if AddNorm).
    pub fn activate(
        &mut self,
        proposal_id: &Hash,
        current_height: u64,
    ) -> Result<Option<Norm>, String> {
        let idx = *self.index.get(proposal_id).ok_or("Proposal not found")?;
        let proposal = &mut self.proposals[idx];

        if proposal.status != ProposalStatus::Timelocked {
            return Err("Proposal must be Timelocked before activation".into());
        }

        if current_height < proposal.timelock_until {
            return Err(format!(
                "Timelock active until block {}. Current: {}",
                proposal.timelock_until, current_height
            ));
        }

        proposal.status = ProposalStatus::Activated;

        match &proposal.kind {
            ProposalKind::AddNorm {
                name,
                description,
                initial_fitness,
                enforcement_cost,
            } => {
                let norm = Norm {
                    id: proposal.id,
                    name: name.clone(),
                    description: description.clone(),
                    precedence: proposal.required_level,
                    population_share: TensionValue(TensionValue::SCALE / 10), // 10% initial share.
                    fitness: *initial_fitness,
                    enforcement_cost: *enforcement_cost,
                    active: true,
                    created_at_height: proposal.submitted_at,
                };
                Ok(Some(norm))
            }
            _ => Ok(None),
        }
    }

    /// Get active proposals count.
    pub fn active_count(&self) -> usize {
        self.proposals
            .iter()
            .filter(|p| p.status == ProposalStatus::Voting)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proposal_lifecycle() {
        let mut registry = ProposalRegistry::default();

        // Submit a norm proposal.
        let id = registry
            .submit(
                [1u8; 32],
                PrecedenceLevel::Meaning,
                ProposalKind::AddNorm {
                    name: "TestNorm".into(),
                    description: "A test norm".into(),
                    initial_fitness: TensionValue::from_integer(5),
                    enforcement_cost: TensionValue::from_integer(1),
                },
                100,
                10, // voting period
            )
            .unwrap();

        assert_eq!(registry.active_count(), 1);

        // Vote.
        registry
            .vote(&id, [1u8; 32], PrecedenceLevel::Meaning, true, 105)
            .unwrap();
        registry
            .vote(&id, [2u8; 32], PrecedenceLevel::Meaning, true, 106)
            .unwrap();
        registry
            .vote(&id, [3u8; 32], PrecedenceLevel::Meaning, false, 107)
            .unwrap();

        // Finalize after voting period — enters timelock.
        let accepted = registry.finalize(111);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].votes_for, 2);
        assert_eq!(accepted[0].votes_against, 1);
        assert_eq!(accepted[0].status, ProposalStatus::Timelocked);

        // Cannot activate during timelock.
        let result = registry.activate(&id, 120);
        assert!(result.is_err());

        // Activate after timelock expires (ordinary = 50 blocks).
        let norm = registry.activate(&id, 111 + timelocks::ORDINARY).unwrap();
        assert!(norm.is_some());
        let norm = norm.unwrap();
        assert_eq!(norm.name, "TestNorm");
        assert!(norm.active);
    }

    #[test]
    fn test_constitutional_timelock_longer() {
        let mut registry = ProposalRegistry::default();

        let id = registry
            .submit(
                [1u8; 32],
                PrecedenceLevel::Safety,
                ProposalKind::ActivateEmergency,
                100,
                5,
            )
            .unwrap();

        registry
            .vote(&id, [1u8; 32], PrecedenceLevel::Safety, true, 102)
            .unwrap();

        let accepted = registry.finalize(106);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].timelock_until, 106 + timelocks::CONSTITUTIONAL);

        // Cannot activate too early.
        assert!(registry.activate(&id, 200).is_err());
        // Can activate after constitutional timelock.
        assert!(registry
            .activate(&id, 106 + timelocks::CONSTITUTIONAL)
            .is_ok());
    }

    #[test]
    fn test_insufficient_authority_rejected() {
        let mut registry = ProposalRegistry::default();
        let result = registry.submit(
            [1u8; 32],
            PrecedenceLevel::Optimization, // Too low for norms.
            ProposalKind::AddNorm {
                name: "X".into(),
                description: "Y".into(),
                initial_fitness: TensionValue::from_integer(1),
                enforcement_cost: TensionValue::ZERO,
            },
            0,
            10,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_voting_after_deadline_rejected() {
        let mut registry = ProposalRegistry::default();
        let id = registry
            .submit(
                [1u8; 32],
                PrecedenceLevel::Meaning,
                ProposalKind::AddNorm {
                    name: "X".into(),
                    description: "Y".into(),
                    initial_fitness: TensionValue::from_integer(1),
                    enforcement_cost: TensionValue::ZERO,
                },
                100,
                5,
            )
            .unwrap();

        // Vote after deadline (height 106 > deadline 105).
        let result = registry.vote(&id, [2u8; 32], PrecedenceLevel::Meaning, true, 106);
        assert!(result.is_err());
    }

    #[test]
    fn test_rejected_proposal() {
        let mut registry = ProposalRegistry::default();
        let id = registry
            .submit(
                [1u8; 32],
                PrecedenceLevel::Meaning,
                ProposalKind::AddNorm {
                    name: "X".into(),
                    description: "Y".into(),
                    initial_fitness: TensionValue::from_integer(1),
                    enforcement_cost: TensionValue::ZERO,
                },
                100,
                5,
            )
            .unwrap();

        // More against than for.
        registry
            .vote(&id, [1u8; 32], PrecedenceLevel::Meaning, false, 102)
            .unwrap();
        registry
            .vote(&id, [2u8; 32], PrecedenceLevel::Meaning, false, 103)
            .unwrap();
        registry
            .vote(&id, [3u8; 32], PrecedenceLevel::Meaning, true, 104)
            .unwrap();

        let accepted = registry.finalize(106);
        assert!(accepted.is_empty());
        assert_eq!(registry.proposals[0].status, ProposalStatus::Rejected);
    }

    #[test]
    fn test_settlement_finality_depths() {
        assert_eq!(SettlementFinality::Soft.required_depth(), 0);
        assert_eq!(SettlementFinality::Economic.required_depth(), 2);
        assert_eq!(SettlementFinality::Legal.required_depth(), 6);
    }
}
