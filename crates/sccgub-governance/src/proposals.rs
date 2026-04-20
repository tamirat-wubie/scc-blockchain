use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use sccgub_types::consensus_params::ConsensusParams;
use sccgub_types::constitutional_ceilings::ConstitutionalCeilings;
use sccgub_types::governance::{Norm, PrecedenceLevel};
use sccgub_types::tension::TensionValue;
use sccgub_types::typed_params::{ConsensusParamField, ConsensusParamValue};
use sccgub_types::{AgentId, Hash, NormId};

/// Governance proposal lifecycle.
/// Actual flow: Voting -> Timelocked/Rejected -> Activated.
///
/// Note: `Submitted`, `Accepted`, and `Expired` are reserved variants that
/// exist for forward compatibility but are not set by any current code path.
/// `submit()` creates proposals directly in `Voting` status.
/// `finalize()` transitions winning proposals directly to `Timelocked`.
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
    /// PATCH_05 §25 typed `ConsensusParams` modification (requires SAFETY
    /// precedence). Supersedes the string-based `ModifyParameter` path
    /// for consensus-critical params: the typed `(field, new_value)` pair
    /// is compile-time type-checked, submission-time ceiling-validated via
    /// `validate_consensus_params_proposal`, and re-validated at activation
    /// per PATCH_05 §25.4 `INV-TYPED-PARAM-CEILING`.
    ///
    /// The `activation_height` declares when the change takes effect if
    /// the proposal survives voting + timelock. Separates governance
    /// timelock from live-state cut-over per §25.3.
    ModifyConsensusParam {
        field: ConsensusParamField,
        new_value: ConsensusParamValue,
        activation_height: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// Reserved: initial submission state (not currently used; submit() sets Voting directly).
    Submitted,
    Voting,
    /// Reserved: post-vote acceptance state (not currently used; finalize() sets Timelocked directly).
    Accepted,
    Rejected,
    /// Timelock active — waiting for mandatory delay before activation.
    Timelocked,
    Activated,
    /// Reserved: TTL-based expiration (not currently implemented).
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
            | ProposalKind::DeactivateEmergency
            | ProposalKind::ModifyConsensusParam { .. } => PrecedenceLevel::Safety,
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

        // INVARIANT: proposals is append-only (items change status but are never
        // removed). The index HashMap stores the Vec position at insertion time.
        // All subsequent `self.proposals[idx]` accesses are safe because the Vec
        // never shrinks. If this invariant is ever broken, replace `[idx]` with
        // `.get(idx).ok_or(...)` throughout.
        self.proposals.push(GovernanceProposal {
            id,
            proposer,
            kind,
            status: ProposalStatus::Voting,
            submitted_at: current_height,
            votes_for: 0,
            votes_against: 0,
            required_level: required,
            // saturating_add per DCA FRACTURE-V084-04: prevents u64 overflow
            // when current_height is near u64::MAX.
            voting_deadline: current_height.saturating_add(voting_period),
            voters: BTreeSet::new(),
            timelock_until: 0, // Set when accepted.
        });
        self.index.insert(id, self.proposals.len() - 1);

        Ok(id)
    }

    /// PATCH_05 §25 + PATCH_10 §38 + v0.8.4 FRACTURE-V084-02 closure:
    /// the ONLY supported path for submitting a typed `ModifyConsensusParam`
    /// proposal.
    ///
    /// Composes `validate_typed_param_proposal` (ceiling + in-struct bounds +
    /// activation-height cap) with `submit()`. The typed variant is always
    /// rejected at submission if the proposal would violate a constitutional
    /// ceiling or the activation-height cap (FRACTURE-V084-04), so
    /// known-invalid proposals never occupy a registry slot.
    ///
    /// Direct `submit()` of `ProposalKind::ModifyConsensusParam` is *technically*
    /// permitted (required for replay paths that must accept proposals as
    /// previously accepted by the chain, without re-running validation under
    /// possibly-different current state). Production submission paths MUST
    /// use this method; replay paths that bypass it document why explicitly.
    ///
    /// Returns `(proposal_id, hypothetical_params)`. The hypothetical params
    /// are returned so the caller can record them alongside the proposal and
    /// re-validate at activation per §25.4 `INV-TYPED-PARAM-CEILING`.
    #[allow(clippy::too_many_arguments)]
    pub fn submit_typed_consensus_param_proposal(
        &mut self,
        proposer: AgentId,
        proposer_level: PrecedenceLevel,
        current_params: &ConsensusParams,
        current_ceilings: &ConstitutionalCeilings,
        field: ConsensusParamField,
        new_value: ConsensusParamValue,
        activation_height: u64,
        current_height: u64,
        voting_period: u64,
    ) -> Result<(Hash, ConsensusParams), String> {
        // Pre-submission ceiling + bounds + cap validation.
        let hypothetical = crate::patch_04::validate_typed_param_proposal(
            current_params,
            current_ceilings,
            field,
            new_value,
            activation_height,
            current_height,
        )
        .map_err(|e| format!("typed ModifyConsensusParam rejected: {}", e))?;
        // If validated, enter the registry via the normal submit path.
        let id = self.submit(
            proposer,
            proposer_level,
            ProposalKind::ModifyConsensusParam {
                field,
                new_value,
                activation_height,
            },
            current_height,
            voting_period,
        )?;
        Ok((id, hypothetical))
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
                    | ProposalKind::DeactivateEmergency
                    | ProposalKind::ModifyConsensusParam { .. } => timelocks::CONSTITUTIONAL,
                    _ => timelocks::ORDINARY,
                };
                // saturating_add per DCA FRACTURE-V084-04: prevents u64 overflow
                // when current_height is near u64::MAX.
                proposal.timelock_until = current_height.saturating_add(timelock_duration);
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

    #[test]
    fn test_duplicate_voting_rejected() {
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
                10,
            )
            .unwrap();

        // First vote succeeds.
        registry
            .vote(&id, [1u8; 32], PrecedenceLevel::Meaning, true, 102)
            .unwrap();
        // Same voter again → should be rejected.
        let result = registry.vote(&id, [1u8; 32], PrecedenceLevel::Meaning, true, 103);
        assert!(result.is_err(), "duplicate vote should fail");
        assert!(result.unwrap_err().contains("already voted"));
    }

    #[test]
    fn test_deactivate_norm_proposal_lifecycle() {
        let mut registry = ProposalRegistry::default();
        let norm_id = [42u8; 32];

        let id = registry
            .submit(
                [1u8; 32],
                PrecedenceLevel::Meaning,
                ProposalKind::DeactivateNorm { norm_id },
                100,
                5,
            )
            .unwrap();

        registry
            .vote(&id, [1u8; 32], PrecedenceLevel::Meaning, true, 102)
            .unwrap();

        let accepted = registry.finalize(106);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].status, ProposalStatus::Timelocked);

        // Activate after timelock.
        let result = registry.activate(&id, 106 + timelocks::ORDINARY);
        assert!(result.is_ok());
        // DeactivateNorm does not produce a norm, so result is Ok(None).
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn test_vote_on_nonexistent_proposal_fails() {
        let mut registry = ProposalRegistry::default();
        let fake_id = [99u8; 32];
        let result = registry.vote(&fake_id, [1u8; 32], PrecedenceLevel::Meaning, true, 10);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not found"));
    }

    // ── PATCH_05 §25 + PATCH_10 v0.8.4 wiring tests ───────────────

    /// `ProposalKind::ModifyConsensusParam` requires Safety-level precedence,
    /// matching the sibling Safety-class variants (`ModifyParameter`,
    /// `ActivateEmergency`, `DeactivateEmergency`). A Meaning-level proposer
    /// is rejected at submit.
    #[test]
    fn patch_10_modify_consensus_param_requires_safety_precedence() {
        let mut registry = ProposalRegistry::default();
        let result = registry.submit(
            [1u8; 32],
            PrecedenceLevel::Meaning,
            ProposalKind::ModifyConsensusParam {
                field: ConsensusParamField::MaxProofDepth,
                new_value: ConsensusParamValue::U32(300),
                activation_height: 500,
            },
            100,
            10,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient authority"));
    }

    /// Safety-level proposer can submit a `ModifyConsensusParam` proposal.
    /// Returns a proposal ID; the proposal enters `Voting` state.
    #[test]
    fn patch_10_modify_consensus_param_safety_submits() {
        let mut registry = ProposalRegistry::default();
        let id = registry
            .submit(
                [1u8; 32],
                PrecedenceLevel::Safety,
                ProposalKind::ModifyConsensusParam {
                    field: ConsensusParamField::MaxProofDepth,
                    new_value: ConsensusParamValue::U32(300),
                    activation_height: 500,
                },
                100,
                10,
            )
            .unwrap();
        assert_eq!(registry.active_count(), 1);
        assert_eq!(registry.proposals[0].id, id);
        assert_eq!(registry.proposals[0].status, ProposalStatus::Voting);
    }

    /// `ModifyConsensusParam` is Constitutional-class: the finalize path
    /// assigns it the 200-block CONSTITUTIONAL timelock, not the 50-block
    /// ORDINARY timelock. This matches `ModifyParameter` sibling behavior.
    #[test]
    fn patch_10_modify_consensus_param_uses_constitutional_timelock() {
        let mut registry = ProposalRegistry::default();
        let id = registry
            .submit(
                [1u8; 32],
                PrecedenceLevel::Safety,
                ProposalKind::ModifyConsensusParam {
                    field: ConsensusParamField::MaxProofDepth,
                    new_value: ConsensusParamValue::U32(300),
                    activation_height: 500,
                },
                100,
                10,
            )
            .unwrap();
        registry
            .vote(&id, [1u8; 32], PrecedenceLevel::Safety, true, 105)
            .unwrap();
        let accepted = registry.finalize(111);
        assert_eq!(accepted.len(), 1);
        assert_eq!(accepted[0].status, ProposalStatus::Timelocked);
        // Constitutional timelock = 200 blocks from finalize height 111 = 311.
        assert_eq!(accepted[0].timelock_until, 111 + timelocks::CONSTITUTIONAL);
    }

    /// `activate()` returns `Ok(None)` for `ModifyConsensusParam` — the
    /// proposal's status flips to `Activated` but no norm is produced.
    /// The caller (node crate) is expected to read the activated proposal's
    /// kind and apply the typed param change to live `ConsensusParams` at
    /// `activation_height`.
    #[test]
    fn patch_10_modify_consensus_param_activates_without_norm() {
        let mut registry = ProposalRegistry::default();
        let id = registry
            .submit(
                [1u8; 32],
                PrecedenceLevel::Safety,
                ProposalKind::ModifyConsensusParam {
                    field: ConsensusParamField::MaxProofDepth,
                    new_value: ConsensusParamValue::U32(300),
                    activation_height: 1000,
                },
                100,
                10,
            )
            .unwrap();
        registry
            .vote(&id, [1u8; 32], PrecedenceLevel::Safety, true, 105)
            .unwrap();
        registry.finalize(111);
        // Activate after the CONSTITUTIONAL timelock expires.
        let norm = registry
            .activate(&id, 111 + timelocks::CONSTITUTIONAL)
            .unwrap();
        assert!(norm.is_none());
        assert_eq!(registry.proposals[0].status, ProposalStatus::Activated);
        // The proposal's kind is preserved for the node crate to read on apply.
        match &registry.proposals[0].kind {
            ProposalKind::ModifyConsensusParam {
                field,
                new_value,
                activation_height,
            } => {
                assert_eq!(*field, ConsensusParamField::MaxProofDepth);
                assert_eq!(*new_value, ConsensusParamValue::U32(300));
                assert_eq!(*activation_height, 1000);
            }
            _ => panic!("expected ModifyConsensusParam kind"),
        }
    }

    /// Sanity: `ProposalKind::ModifyConsensusParam` round-trips through
    /// serde (JSON via serde_json here, but bincode round-trip is already
    /// exercised by `sccgub-types::typed_params::tests`) — required for
    /// proposal persistence and cross-node propagation. JSON is a
    /// sufficient proxy because the bincode round-trip holds iff the
    /// serde derives are present; JSON also exercises the variant tag
    /// and field-name serialization consistency.
    #[test]
    fn patch_10_modify_consensus_param_serde_roundtrip() {
        let original = ProposalKind::ModifyConsensusParam {
            field: ConsensusParamField::MaxForgeryVetoesPerBlockParam,
            new_value: ConsensusParamValue::U32(6),
            activation_height: 12345,
        };
        let text = serde_json::to_string(&original).unwrap();
        let back: ProposalKind = serde_json::from_str(&text).unwrap();
        match back {
            ProposalKind::ModifyConsensusParam {
                field,
                new_value,
                activation_height,
            } => {
                assert_eq!(field, ConsensusParamField::MaxForgeryVetoesPerBlockParam);
                assert_eq!(new_value, ConsensusParamValue::U32(6));
                assert_eq!(activation_height, 12345);
            }
            _ => panic!("wrong variant after roundtrip"),
        }
    }
}
