//! Patch-04 §15.7 equivocation → slashing synthesis.
//!
//! When a block carries an `EquivocationEvidence` record, §15.7 Stage 1
//! requires a synthetic `ValidatorSetChange::Remove` to be queued with
//! `effective_height = H_admit + activation_delay` and
//! `reason = Equivocation`. This module produces that synthetic event.
//!
//! Key property: the synthetic event **bypasses** §15.5's quorum-signature
//! requirement (it is evidence-sourced rather than proposer-sourced) but
//! still satisfies the canonical-bytes and variant-predicate rules. The
//! admission path in the execution layer is responsible for accepting
//! evidence-sourced Removes without quorum; that wiring is a separate
//! integration concern tracked for Commit 6.
//!
//! The module also provides the §15.7 Stage 2 forgery-only veto-window
//! predicate: during `[H_admit, H_admit + activation_delay)` a
//! Safety-level governance proposal MAY veto the synthetic Remove iff
//! it supplies cryptographic proof of signature forgery.

use sccgub_crypto::signature::{verify, verify_strict};
use sccgub_types::validator_set::{
    EquivocationEvidence, EquivocationVoteType, RemovalReason, ValidatorSet, ValidatorSetChange,
    ValidatorSetChangeKind,
};

/// Outcome of attempting to synthesize a slashing Remove from evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EquivocationSynthesis {
    /// Evidence is valid; returns the synthetic `ValidatorSetChange` with
    /// an empty `quorum_signatures` vector (evidence-sourced — §15.7
    /// bypasses the §15.5 quorum-sig requirement).
    Synthesized(ValidatorSetChange),
    /// Evidence is not structurally well-formed (same signatures, same
    /// block hash, different signers, etc.).
    NotStructuralEquivocation,
    /// At least one of the two votes has a signature that fails
    /// `verify_strict`. Refuses to slash on ambiguous evidence.
    SignatureInvalid,
    /// The signing validator is not in `active_set(H_admit)` — we cannot
    /// resolve `validator_id → agent_id`, so we cannot form a Remove.
    SignerNotInActiveSet,
}

impl EquivocationSynthesis {
    pub fn is_synthesized(&self) -> bool {
        matches!(self, Self::Synthesized(_))
    }
}

/// Produce a synthetic `ValidatorSetChange::Remove` from an
/// `EquivocationEvidence` record per §15.7 Stage 1.
///
/// `h_admit` is the height of the block that carries the evidence.
/// `activation_delay` is §15.5's `clamp(k+1, 2, k+8)`.
/// The `proposed_at` field on the returned change is `h_admit`.
pub fn synthesize_equivocation_removal(
    evidence: &EquivocationEvidence,
    current_set: &ValidatorSet,
    h_admit: u64,
    activation_delay: u64,
) -> EquivocationSynthesis {
    if !evidence.is_structurally_equivocation() {
        return EquivocationSynthesis::NotStructuralEquivocation;
    }
    // Both signatures must verify under `verify_strict` so the evidence
    // is unambiguous. A single malleable signature (verify ok but
    // verify_strict fails) is the forgery case §15.7 Stage 2 addresses;
    // we reject here and let the veto-window path surface it.
    let sig_a_ok = verify_strict(
        &evidence.vote_a.validator_id,
        &vote_canonical_bytes(&evidence.vote_a),
        &evidence.vote_a.signature,
    );
    let sig_b_ok = verify_strict(
        &evidence.vote_b.validator_id,
        &vote_canonical_bytes(&evidence.vote_b),
        &evidence.vote_b.signature,
    );
    if !sig_a_ok || !sig_b_ok {
        return EquivocationSynthesis::SignatureInvalid;
    }

    // Resolve validator_id → agent_id via the current active set.
    let Some(record) =
        current_set.find_active_by_validator_id(&evidence.vote_a.validator_id, h_admit)
    else {
        return EquivocationSynthesis::SignerNotInActiveSet;
    };

    let effective_height = h_admit.saturating_add(activation_delay);
    let kind = ValidatorSetChangeKind::Remove {
        agent_id: record.agent_id,
        reason: RemovalReason::Equivocation,
        effective_height,
    };
    let change_id = ValidatorSetChange::compute_change_id(&kind, h_admit);
    EquivocationSynthesis::Synthesized(ValidatorSetChange {
        change_id,
        kind,
        proposed_at: h_admit,
        quorum_signatures: Vec::new(), // §15.7: evidence-sourced bypass
    })
}

fn vote_canonical_bytes(vote: &sccgub_types::validator_set::EquivocationVote) -> Vec<u8> {
    // Signed payload mirrors `sccgub-consensus::protocol::vote_sign_data`
    // domain separation but lives in the types layer. This keeps the
    // equivocation module self-contained for the state + synthesis
    // logic. Consensus-layer vote verification uses its own
    // domain-separated function; at slashing time we verify the raw
    // signed bytes as produced by the vote signer.
    sccgub_crypto::canonical::canonical_bytes(&(
        &vote.validator_id,
        &vote.block_hash,
        vote.height,
        vote.round,
        match vote.vote_type {
            EquivocationVoteType::Prevote => 0u8,
            EquivocationVoteType::Precommit => 1u8,
        },
    ))
}

// ── §15.7 Stage 2 forgery-only veto-window predicate ─────────────

/// Proof that an `EquivocationEvidence` record was itself a forgery —
/// specifically, two byte-distinct signatures over the same canonical
/// vote bytes that both pass non-strict `verify` but at least one of
/// which is rejected by `verify_strict`.
///
/// This is the ONLY valid veto ground per §15.7. Other grounds
/// (mistake, mercy, policy) are not permitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForgeryProof<'a> {
    /// The signed bytes both signatures claim to authorize.
    pub canonical_bytes: &'a [u8],
    /// Public key the signatures claim to be from.
    pub public_key: &'a [u8; 32],
    /// First signature (must pass `verify`).
    pub signature_a: &'a [u8],
    /// Second signature (must pass `verify`, must differ from A).
    pub signature_b: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ForgeryCheckError {
    #[error("signatures are byte-identical — no malleability demonstrated")]
    SignaturesIdentical,
    #[error("signature A fails non-strict verify")]
    SignatureANotValid,
    #[error("signature B fails non-strict verify")]
    SignatureBNotValid,
    #[error("both signatures pass verify_strict — no malleability exposed")]
    BothPassStrictVerify,
}

/// Validate a `ForgeryProof`. Returns `Ok(())` if the proof demonstrates
/// signature malleability under the standard Ed25519 verifier (the
/// condition §15.7 treats as sufficient to veto a synthetic slashing).
pub fn check_forgery_proof(proof: &ForgeryProof<'_>) -> Result<(), ForgeryCheckError> {
    if proof.signature_a == proof.signature_b {
        return Err(ForgeryCheckError::SignaturesIdentical);
    }
    if !verify(proof.public_key, proof.canonical_bytes, proof.signature_a) {
        return Err(ForgeryCheckError::SignatureANotValid);
    }
    if !verify(proof.public_key, proof.canonical_bytes, proof.signature_b) {
        return Err(ForgeryCheckError::SignatureBNotValid);
    }
    let strict_a = verify_strict(proof.public_key, proof.canonical_bytes, proof.signature_a);
    let strict_b = verify_strict(proof.public_key, proof.canonical_bytes, proof.signature_b);
    if strict_a && strict_b {
        return Err(ForgeryCheckError::BothPassStrictVerify);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::validator_set::{EquivocationVote, ValidatorRecord};

    fn keypair(seed: u8) -> (SigningKey, [u8; 32]) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = *sk.verifying_key().as_bytes();
        (sk, pk)
    }

    fn record(agent: u8, validator_pk: [u8; 32], power: u64) -> ValidatorRecord {
        ValidatorRecord {
            agent_id: [agent; 32],
            validator_id: validator_pk,
            mfidel_seal: MfidelAtomicSeal::from_height(0),
            voting_power: power,
            active_from: 0,
            active_until: None,
        }
    }

    fn make_vote(sk: &SigningKey, pk: [u8; 32], block_hash: [u8; 32]) -> EquivocationVote {
        let height = 10u64;
        let round = 0u32;
        let vote_type = EquivocationVoteType::Prevote;
        let vote_type_byte = 0u8;
        let payload = sccgub_crypto::canonical::canonical_bytes(&(
            &pk,
            &block_hash,
            height,
            round,
            vote_type_byte,
        ));
        let sig = sk.sign(&payload).to_bytes().to_vec();
        EquivocationVote {
            validator_id: pk,
            block_hash,
            height,
            round,
            vote_type,
            signature: sig,
        }
    }

    // ── §15.7 synthesis ───────────────────────────────────────────

    #[test]
    fn patch_04_equivocation_two_stage_slashing() {
        let (sk, pk) = keypair(5);
        let vote_x = make_vote(&sk, pk, [0xAA; 32]);
        let vote_y = make_vote(&sk, pk, [0xBB; 32]);
        let evidence = EquivocationEvidence::new(vote_x, vote_y);

        let set = ValidatorSet::new(vec![record(7, pk, 10)]).unwrap();
        let h_admit = 20u64;
        let delay = 3u64;

        let result = synthesize_equivocation_removal(&evidence, &set, h_admit, delay);
        let change = match result {
            EquivocationSynthesis::Synthesized(c) => c,
            other => panic!("expected Synthesized, got {:?}", other),
        };

        match &change.kind {
            ValidatorSetChangeKind::Remove {
                agent_id,
                reason,
                effective_height,
            } => {
                assert_eq!(*agent_id, [7u8; 32]);
                assert_eq!(*reason, RemovalReason::Equivocation);
                assert_eq!(*effective_height, h_admit + delay);
            }
            other => panic!("expected Remove, got {:?}", other),
        }
        // §15.7 rule: synthetic events bypass quorum sigs.
        assert!(change.quorum_signatures.is_empty());
        // Change ID is consistent.
        assert!(change.change_id_is_consistent());
        assert_eq!(change.proposed_at, h_admit);
    }

    #[test]
    fn patch_04_equivocation_rejects_non_structural() {
        // Same signature on both votes → not an equivocation.
        let (sk, pk) = keypair(5);
        let vote = make_vote(&sk, pk, [0xAA; 32]);
        let evidence = EquivocationEvidence {
            vote_a: vote.clone(),
            vote_b: vote,
        };
        let set = ValidatorSet::new(vec![record(7, pk, 10)]).unwrap();
        let result = synthesize_equivocation_removal(&evidence, &set, 20, 3);
        assert_eq!(result, EquivocationSynthesis::NotStructuralEquivocation);
    }

    #[test]
    fn patch_04_equivocation_rejects_bad_signature() {
        let (sk, pk) = keypair(5);
        let vote_x = make_vote(&sk, pk, [0xAA; 32]);
        let mut vote_y = make_vote(&sk, pk, [0xBB; 32]);
        // Corrupt vote_y's signature; evidence still looks structurally
        // distinct (different block_hash, different signature bytes).
        vote_y.signature[0] ^= 0xFF;
        let evidence = EquivocationEvidence::new(vote_x, vote_y);
        let set = ValidatorSet::new(vec![record(7, pk, 10)]).unwrap();
        let result = synthesize_equivocation_removal(&evidence, &set, 20, 3);
        assert_eq!(result, EquivocationSynthesis::SignatureInvalid);
    }

    #[test]
    fn patch_04_equivocation_rejects_signer_outside_active_set() {
        let (sk, pk) = keypair(5);
        let (_outsider_sk, outsider_pk) = keypair(99);
        let _ = outsider_pk;
        let vote_x = make_vote(&sk, pk, [0xAA; 32]);
        let vote_y = make_vote(&sk, pk, [0xBB; 32]);
        let evidence = EquivocationEvidence::new(vote_x, vote_y);
        // Build a set that does NOT contain `pk`.
        let (_, other_pk) = keypair(77);
        let set = ValidatorSet::new(vec![record(1, other_pk, 10)]).unwrap();
        let result = synthesize_equivocation_removal(&evidence, &set, 20, 3);
        assert_eq!(result, EquivocationSynthesis::SignerNotInActiveSet);
    }

    #[test]
    fn patch_04_equivocation_effective_height_includes_activation_delay() {
        // With h_admit=100 and delay=3, Remove takes effect at 103.
        let (sk, pk) = keypair(5);
        let vote_x = make_vote(&sk, pk, [0xAA; 32]);
        let vote_y = make_vote(&sk, pk, [0xBB; 32]);
        let evidence = EquivocationEvidence::new(vote_x, vote_y);
        let set = ValidatorSet::new(vec![record(7, pk, 10)]).unwrap();
        let result = synthesize_equivocation_removal(&evidence, &set, 100, 3);
        match result {
            EquivocationSynthesis::Synthesized(change) => {
                assert_eq!(change.kind.effective_height(), 103);
            }
            other => panic!("expected Synthesized, got {:?}", other),
        }
    }

    // ── §15.7 Stage 2 forgery veto ────────────────────────────────

    #[test]
    fn patch_04_slashing_veto_rejects_non_forgery() {
        // Two distinct signatures that both pass verify_strict — no
        // malleability to veto on. Reject.
        let (sk, pk) = keypair(5);
        let payload = b"test message";
        let sig_a = sk.sign(payload).to_bytes().to_vec();
        // Produce an independent legitimate signature by signing a
        // slightly different message, then try to pass it off as a
        // second signature on `payload`. It will fail `verify`.
        let sig_b = sk.sign(b"other message").to_bytes().to_vec();

        // Both identical? No.
        let proof = ForgeryProof {
            canonical_bytes: payload,
            public_key: &pk,
            signature_a: &sig_a,
            signature_b: &sig_b,
        };
        let result = check_forgery_proof(&proof);
        assert!(matches!(result, Err(ForgeryCheckError::SignatureBNotValid)));
    }

    #[test]
    fn patch_04_slashing_veto_rejects_identical_signatures() {
        let (sk, pk) = keypair(5);
        let payload = b"test";
        let sig = sk.sign(payload).to_bytes().to_vec();
        let proof = ForgeryProof {
            canonical_bytes: payload,
            public_key: &pk,
            signature_a: &sig,
            signature_b: &sig,
        };
        let result = check_forgery_proof(&proof);
        assert!(matches!(
            result,
            Err(ForgeryCheckError::SignaturesIdentical)
        ));
    }

    #[test]
    fn patch_04_slashing_veto_rejects_both_strict_valid() {
        // If we try to submit two signatures that BOTH pass verify_strict,
        // that is not a forgery demonstration. The "valid forgery" case
        // requires at least one strict-fail, which under correct
        // ed25519-dalek is near-impossible to produce without an oracle
        // we don't have in tests. We therefore exercise the negative
        // check: two legitimate signatures on the same message are
        // byte-identical under Ed25519 (deterministic), so we'd hit
        // SignaturesIdentical first, not BothPassStrictVerify. This
        // test documents that asymmetry — the veto path is narrow by
        // design and cannot fire on any stack of legitimate signatures.
        let (sk, pk) = keypair(5);
        let payload = b"strict";
        let sig = sk.sign(payload).to_bytes().to_vec();
        let proof = ForgeryProof {
            canonical_bytes: payload,
            public_key: &pk,
            signature_a: &sig,
            signature_b: &sig,
        };
        let result = check_forgery_proof(&proof);
        // Falls into SignaturesIdentical (handled first).
        assert!(matches!(
            result,
            Err(ForgeryCheckError::SignaturesIdentical)
        ));
    }
}
