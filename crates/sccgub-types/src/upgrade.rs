//! Patch-06 §34 live-upgrade protocol.
//!
//! Before Patch-06, v3→v4 and v4→v5 transitions were performed via a
//! genesis flag. To upgrade a live chain every validator had to stop,
//! reconfigure, and restart simultaneously — an operational impossibility
//! at production scale.
//!
//! §34 introduces the `UpgradeProposal` activation-height pattern. A
//! Governance-level `UpgradeProposal` names a `target_chain_version`, an
//! `activation_height`, and a content-addressed `upgrade_spec_hash`. The
//! chain accumulates the admitted proposal, operators upgrade binaries
//! during the waiting window, and the version flips atomically at the
//! declared height.
//!
//! This module declares the **wire types and admission predicates**.
//! The binary registry, operator tooling, and the actual runtime
//! activation path are deferred to Patch-07; in Patch-06 the chain
//! version check is a declarative predicate that the block-import path
//! consults.

use serde::{Deserialize, Serialize};

use crate::validator_set::{Ed25519PublicKey, Ed25519Signature};
use crate::Hash;

/// Domain separator for §34.2 upgrade-proposal signatures.
pub const UPGRADE_PROPOSAL_DOMAIN_SEPARATOR: &[u8] = b"sccgub-upgrade-proposal-v5";

/// Default minimum lead time (in blocks) between `submitted_at` and
/// `activation_height`. §34.2 Rule 1. Overridable via constitutional
/// ceiling in Patch-07.
pub const DEFAULT_MIN_UPGRADE_LEAD_TIME: u64 = 14_400;

/// §34.2 governance proposal declaring a chain-version upgrade at a
/// future block height.
///
/// Canonical bincode field order: `proposal_id, target_chain_version,
/// activation_height, upgrade_spec_hash, submitted_at, quorum_signatures`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeProposal {
    pub proposal_id: Hash,
    pub target_chain_version: u32,
    pub activation_height: u64,
    pub upgrade_spec_hash: Hash,
    pub submitted_at: u64,
    pub quorum_signatures: Vec<(Ed25519PublicKey, Ed25519Signature)>,
}

impl UpgradeProposal {
    /// Canonical bytes signed by each quorum participant and folded into
    /// `proposal_id`. Excludes `quorum_signatures` to keep `proposal_id`
    /// invariant under signature-set canonicalization.
    pub fn canonical_proposal_bytes(
        target_chain_version: u32,
        activation_height: u64,
        upgrade_spec_hash: &Hash,
        submitted_at: u64,
    ) -> Vec<u8> {
        bincode::serialize(&(
            target_chain_version,
            activation_height,
            upgrade_spec_hash,
            submitted_at,
        ))
        .expect("UpgradeProposal canonical_proposal_bytes serialization is infallible")
    }

    /// Compute `proposal_id = BLAKE3(domain || canonical_bytes)`.
    pub fn compute_proposal_id(
        target_chain_version: u32,
        activation_height: u64,
        upgrade_spec_hash: &Hash,
        submitted_at: u64,
    ) -> Hash {
        let bytes = Self::canonical_proposal_bytes(
            target_chain_version,
            activation_height,
            upgrade_spec_hash,
            submitted_at,
        );
        let mut hasher = blake3::Hasher::new();
        hasher.update(UPGRADE_PROPOSAL_DOMAIN_SEPARATOR);
        hasher.update(&bytes);
        *hasher.finalize().as_bytes()
    }

    /// True iff `proposal_id` matches the recomputed hash of the canonical
    /// payload.
    pub fn proposal_id_is_consistent(&self) -> bool {
        self.proposal_id
            == Self::compute_proposal_id(
                self.target_chain_version,
                self.activation_height,
                &self.upgrade_spec_hash,
                self.submitted_at,
            )
    }

    /// Bytes to sign / verify_strict for attestation.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let canonical = Self::canonical_proposal_bytes(
            self.target_chain_version,
            self.activation_height,
            &self.upgrade_spec_hash,
            self.submitted_at,
        );
        let mut out = Vec::with_capacity(UPGRADE_PROPOSAL_DOMAIN_SEPARATOR.len() + canonical.len());
        out.extend_from_slice(UPGRADE_PROPOSAL_DOMAIN_SEPARATOR);
        out.extend_from_slice(&canonical);
        out
    }
}

/// §34.4 record of a successful chain-version transition. Appended to
/// `system/chain_version_history` at the activation height. Read-only
/// after write; retained forever (not prunable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainVersionTransition {
    pub activation_height: u64,
    pub from_version: u32,
    pub to_version: u32,
    pub upgrade_spec_hash: Hash,
    pub proposal_id: Hash,
}

impl ChainVersionTransition {
    pub const TRIE_KEY: &'static [u8] = b"system/chain_version_history";
}

/// §34.2 admission-predicate result. Pure structural validation; does
/// NOT verify signatures (the governance crate does that under its
/// existing quorum-tally path).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpgradeProposalRejection {
    #[error(
        "activation_height {activation_height} too soon; requires >= submitted_at + {min_lead} \
         (= {required})"
    )]
    LeadTimeTooShort {
        activation_height: u64,
        submitted_at: u64,
        min_lead: u64,
        required: u64,
    },
    #[error("target_chain_version {target} must equal current_chain_version {current} + 1")]
    NonAdjacentVersion { target: u32, current: u32 },
    #[error("proposal_id inconsistent with canonical payload")]
    ProposalIdInconsistent,
}

/// §34.2 rules 1–2 structural check. Rule 3 (quorum) lives in the
/// governance crate; rule 4 (binary recognition) is operator-side.
pub fn validate_upgrade_proposal_structure(
    proposal: &UpgradeProposal,
    current_chain_version: u32,
    min_lead_time: u64,
) -> Result<(), UpgradeProposalRejection> {
    if !proposal.proposal_id_is_consistent() {
        return Err(UpgradeProposalRejection::ProposalIdInconsistent);
    }
    if proposal.target_chain_version != current_chain_version + 1 {
        return Err(UpgradeProposalRejection::NonAdjacentVersion {
            target: proposal.target_chain_version,
            current: current_chain_version,
        });
    }
    let required = proposal.submitted_at.saturating_add(min_lead_time);
    if proposal.activation_height < required {
        return Err(UpgradeProposalRejection::LeadTimeTooShort {
            activation_height: proposal.activation_height,
            submitted_at: proposal.submitted_at,
            min_lead: min_lead_time,
            required,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proposal(
        target: u32,
        activation: u64,
        submitted: u64,
        spec_hash: Hash,
    ) -> UpgradeProposal {
        UpgradeProposal {
            proposal_id: UpgradeProposal::compute_proposal_id(
                target, activation, &spec_hash, submitted,
            ),
            target_chain_version: target,
            activation_height: activation,
            upgrade_spec_hash: spec_hash,
            submitted_at: submitted,
            quorum_signatures: vec![],
        }
    }

    #[test]
    fn patch_06_upgrade_proposal_id_is_consistent() {
        let p = make_proposal(5, 20_000, 100, [0x11; 32]);
        assert!(p.proposal_id_is_consistent());
    }

    #[test]
    fn patch_06_accepts_valid_upgrade_proposal() {
        let p = make_proposal(5, 20_000, 100, [0x11; 32]);
        validate_upgrade_proposal_structure(&p, 4, 14_400).unwrap();
    }

    #[test]
    fn patch_06_rejects_non_adjacent_version() {
        // Trying to skip v4 → v6 directly.
        let p = make_proposal(6, 20_000, 100, [0x11; 32]);
        let r = validate_upgrade_proposal_structure(&p, 4, 14_400);
        assert!(matches!(
            r,
            Err(UpgradeProposalRejection::NonAdjacentVersion { .. })
        ));
    }

    #[test]
    fn patch_06_rejects_insufficient_lead_time() {
        // 50-block lead; requires 14_400.
        let p = make_proposal(5, 150, 100, [0x11; 32]);
        let r = validate_upgrade_proposal_structure(&p, 4, 14_400);
        assert!(matches!(
            r,
            Err(UpgradeProposalRejection::LeadTimeTooShort { .. })
        ));
    }

    #[test]
    fn patch_06_rejects_proposal_with_bad_id() {
        let mut p = make_proposal(5, 20_000, 100, [0x11; 32]);
        p.proposal_id = [0xFF; 32];
        let r = validate_upgrade_proposal_structure(&p, 4, 14_400);
        assert!(matches!(
            r,
            Err(UpgradeProposalRejection::ProposalIdInconsistent)
        ));
    }

    #[test]
    fn patch_06_signing_bytes_include_domain_separator() {
        let p = make_proposal(5, 20_000, 100, [0x11; 32]);
        assert!(p
            .signing_bytes()
            .starts_with(UPGRADE_PROPOSAL_DOMAIN_SEPARATOR));
    }

    #[test]
    fn patch_06_domain_separator_matches_spec() {
        assert_eq!(
            UPGRADE_PROPOSAL_DOMAIN_SEPARATOR,
            b"sccgub-upgrade-proposal-v5"
        );
    }

    #[test]
    fn patch_06_chain_version_transition_trie_key_in_system_namespace() {
        assert!(ChainVersionTransition::TRIE_KEY.starts_with(b"system/"));
    }

    #[test]
    fn patch_06_default_lead_time_constant() {
        assert_eq!(DEFAULT_MIN_UPGRADE_LEAD_TIME, 14_400);
    }
}
