use serde::{Deserialize, Serialize};

use sccgub_types::governance::{Norm, PrecedenceLevel};
use sccgub_types::tension::TensionValue;
use sccgub_types::{AgentId, Hash, NormId};

/// Governance proposal lifecycle.
/// Proposals follow: Submitted -> Voting -> Accepted/Rejected -> Activated.
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
    Activated,
    Expired,
}

/// Proposal registry managing the lifecycle of governance proposals.
#[derive(Debug, Clone, Default)]
pub struct ProposalRegistry {
    pub proposals: Vec<GovernanceProposal>,
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

        let id = sccgub_crypto::hash::blake3_hash(
            &serde_json::to_vec(&(&proposer, &kind, current_height)).unwrap_or_default(),
        );

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
        });

        Ok(id)
    }

    /// Cast a vote on a proposal.
    pub fn vote(
        &mut self,
        proposal_id: &Hash,
        voter_level: PrecedenceLevel,
        approve: bool,
        current_height: u64,
    ) -> Result<(), String> {
        let proposal = self
            .proposals
            .iter_mut()
            .find(|p| p.id == *proposal_id)
            .ok_or("Proposal not found")?;

        if proposal.status != ProposalStatus::Voting {
            return Err("Proposal is not in voting state".into());
        }

        if current_height > proposal.voting_deadline {
            return Err("Voting period has ended".into());
        }

        if (voter_level as u8) > (proposal.required_level as u8) {
            return Err("Voter lacks required governance level".into());
        }

        if approve {
            proposal.votes_for = proposal.votes_for.saturating_add(1);
        } else {
            proposal.votes_against = proposal.votes_against.saturating_add(1);
        }

        Ok(())
    }

    /// Finalize proposals whose voting period has ended.
    /// Returns list of accepted proposals ready for activation.
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
                proposal.status = ProposalStatus::Accepted;
                accepted.push(proposal.clone());
            } else {
                proposal.status = ProposalStatus::Rejected;
            }
        }

        accepted
    }

    /// Activate an accepted proposal. Returns the norm to register (if AddNorm).
    pub fn activate(&mut self, proposal_id: &Hash) -> Result<Option<Norm>, String> {
        let proposal = self
            .proposals
            .iter_mut()
            .find(|p| p.id == *proposal_id)
            .ok_or("Proposal not found")?;

        if proposal.status != ProposalStatus::Accepted {
            return Err("Proposal must be Accepted before activation".into());
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
        registry.vote(&id, PrecedenceLevel::Meaning, true, 105).unwrap();
        registry.vote(&id, PrecedenceLevel::Meaning, true, 106).unwrap();
        registry.vote(&id, PrecedenceLevel::Meaning, false, 107).unwrap();

        // Finalize after voting period.
        let accepted = registry.finalize(111);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].votes_for, 2);
        assert_eq!(accepted[0].votes_against, 1);

        // Activate.
        let norm = registry.activate(&id).unwrap();
        assert!(norm.is_some());
        let norm = norm.unwrap();
        assert_eq!(norm.name, "TestNorm");
        assert!(norm.active);
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
        let result = registry.vote(&id, PrecedenceLevel::Meaning, true, 106);
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
        registry.vote(&id, PrecedenceLevel::Meaning, false, 102).unwrap();
        registry.vote(&id, PrecedenceLevel::Meaning, false, 103).unwrap();
        registry.vote(&id, PrecedenceLevel::Meaning, true, 104).unwrap();

        let accepted = registry.finalize(106);
        assert!(accepted.is_empty());
        assert_eq!(registry.proposals[0].status, ProposalStatus::Rejected);
    }
}
