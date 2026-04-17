//! Execution-layer validation for `ValidatorSetChange` events (Patch-04 §15.5).
//!
//! Called from phase 12 (Feedback) when a block carries validator-set
//! changes. Enforces every §15.5 admission predicate except activation
//! delay (which is a §15.5 rule 1 enforced per-event at block-admission
//! time against `H_admit + activation_delay`):
//!
//! - change_id matches the canonical hash of `(kind, proposed_at)`.
//! - quorum_signatures is deduped and canonically sorted.
//! - every signer is in `active_set(H_admit)` under the CURRENT set
//!   (critical: quorum is evaluated against the set as-of H_admit, NEVER
//!   against the post-change set — this prevents a post-change majority
//!   from self-admitting).
//! - every signature verifies under `verify_strict`.
//! - the sum of signer voting_power reaches `quorum_power(H_admit)`.

use sccgub_crypto::signature::verify_strict;
use sccgub_types::validator_set::{ValidatorSet, ValidatorSetChange};

/// Patch-04 §15.5 `activation_delay = clamp(k + 1, 2, k + 8)` where
/// `k` is `confirmation_depth`. Exported so callers (execution admission
/// path, future consensus wiring) compute it identically.
pub fn activation_delay(confirmation_depth: u64) -> u64 {
    let lower = 2u64;
    let raw = confirmation_depth.saturating_add(1);
    let upper = confirmation_depth.saturating_add(8);
    raw.clamp(lower, upper)
}

/// Outcome of validating a single `ValidatorSetChange` event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidatorSetChangeValidation {
    /// Event is admissible under §15.5.
    Valid,
    /// Event is inadmissible; `reason` is the first failing predicate
    /// encountered in spec order.
    Invalid(ValidatorSetChangeRejection),
}

impl ValidatorSetChangeValidation {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidatorSetChangeRejection {
    #[error(
        "effective_height {effective} < H_admit {admit} + activation_delay {delay} \
         (raw {raw})"
    )]
    ActivationTooSoon {
        effective: u64,
        admit: u64,
        delay: u64,
        raw: u64,
    },
    #[error("change_id does not match canonical hash of (kind, proposed_at)")]
    ChangeIdMismatch,
    #[error("quorum_signatures contains duplicate signer")]
    DuplicateSigner,
    #[error("signer {signer:?} is not in active_set(H_admit)")]
    SignerNotInActiveSet { signer: [u8; 32] },
    #[error("signature by {signer:?} fails verify_strict")]
    SignatureInvalid { signer: [u8; 32] },
    #[error("signer voting power sum {got} < quorum threshold {need}")]
    QuorumNotReached { got: u128, need: u128 },
}

/// Validate a single `ValidatorSetChange` event admitted at `H_admit`
/// against the CURRENT validator set (the set as of `H_admit`, NOT the
/// set after the change takes effect). Quorum is computed under §15.3
/// against `active_set(H_admit)`.
pub fn validate_validator_set_change(
    change: &ValidatorSetChange,
    current_set: &ValidatorSet,
    h_admit: u64,
    confirmation_depth: u64,
) -> ValidatorSetChangeValidation {
    // §15.5 rule 1: activation-delay floor.
    let effective = change.kind.effective_height();
    let delay = activation_delay(confirmation_depth);
    let raw_lower = h_admit.saturating_add(delay);
    if effective < raw_lower {
        return ValidatorSetChangeValidation::Invalid(
            ValidatorSetChangeRejection::ActivationTooSoon {
                effective,
                admit: h_admit,
                delay,
                raw: raw_lower,
            },
        );
    }

    // §15.5 rule 5: change_id consistency.
    if !change.change_id_is_consistent() {
        return ValidatorSetChangeValidation::Invalid(
            ValidatorSetChangeRejection::ChangeIdMismatch,
        );
    }

    // Duplicate-signer check (implicit precondition of the §15.4 canonical
    // sort + duplicate ban).
    let mut seen: Vec<[u8; 32]> = change.quorum_signatures.iter().map(|(pk, _)| *pk).collect();
    seen.sort();
    for w in seen.windows(2) {
        if w[0] == w[1] {
            return ValidatorSetChangeValidation::Invalid(
                ValidatorSetChangeRejection::DuplicateSigner,
            );
        }
    }

    // §15.5 rules 2, 4: every signer is in active_set(H_admit) and each
    // signature verifies under `verify_strict`. Quorum (§15.5 rule 3) is
    // tallied on the fly so the rejection surfaces the closest-to-quorum
    // state on partial success.
    let payload = ValidatorSetChange::canonical_change_bytes(&change.kind, change.proposed_at);
    let mut signer_power: u128 = 0;
    for (signer_pk, sig) in &change.quorum_signatures {
        let Some(record) = current_set.find_active_by_validator_id(signer_pk, h_admit) else {
            return ValidatorSetChangeValidation::Invalid(
                ValidatorSetChangeRejection::SignerNotInActiveSet { signer: *signer_pk },
            );
        };
        if !verify_strict(signer_pk, &payload, sig) {
            return ValidatorSetChangeValidation::Invalid(
                ValidatorSetChangeRejection::SignatureInvalid { signer: *signer_pk },
            );
        }
        signer_power = signer_power.saturating_add(record.voting_power as u128);
    }

    // §15.5 rule 3: quorum reached against active_set(H_admit).
    let needed = current_set.quorum_power_at(h_admit);
    if signer_power < needed {
        return ValidatorSetChangeValidation::Invalid(
            ValidatorSetChangeRejection::QuorumNotReached {
                got: signer_power,
                need: needed,
            },
        );
    }

    ValidatorSetChangeValidation::Valid
}

/// Validate every `ValidatorSetChange` event in a block. Returns on the
/// first invalid event (block-level validation is all-or-nothing).
/// Caller is responsible for enforcing the §17.2
/// `max_validator_set_changes_per_block` ceiling separately.
pub fn validate_all_validator_set_changes(
    changes: &[ValidatorSetChange],
    current_set: &ValidatorSet,
    h_admit: u64,
    confirmation_depth: u64,
) -> ValidatorSetChangeValidation {
    for change in changes {
        let result =
            validate_validator_set_change(change, current_set, h_admit, confirmation_depth);
        if !result.is_valid() {
            return result;
        }
    }
    ValidatorSetChangeValidation::Valid
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use sccgub_crypto::signature::sign;
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::validator_set::{RemovalReason, ValidatorRecord, ValidatorSetChangeKind};

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

    /// Build a 3-validator active set with known signing keys and equal power.
    fn three_validator_set() -> (ValidatorSet, Vec<(SigningKey, [u8; 32])>) {
        let v0 = keypair(10);
        let v1 = keypair(11);
        let v2 = keypair(12);
        let set = ValidatorSet::new(vec![
            record(0, v0.1, 30),
            record(1, v1.1, 30),
            record(2, v2.1, 40),
        ])
        .unwrap();
        (set, vec![v0, v1, v2])
    }

    fn sign_change(
        kind: &ValidatorSetChangeKind,
        proposed_at: u64,
        signers: &[(SigningKey, [u8; 32])],
    ) -> ValidatorSetChange {
        let change_id = ValidatorSetChange::compute_change_id(kind, proposed_at);
        let payload = ValidatorSetChange::canonical_change_bytes(kind, proposed_at);
        let mut sigs: Vec<([u8; 32], Vec<u8>)> = signers
            .iter()
            .map(|(sk, pk)| (*pk, sign(sk, &payload)))
            .collect();
        sigs.sort_by_key(|pair| pair.0);
        ValidatorSetChange {
            change_id,
            kind: kind.clone(),
            proposed_at,
            quorum_signatures: sigs,
        }
    }

    #[test]
    fn patch_04_activation_delay_clamp() {
        // k=0 → raw=1, clamped to floor 2
        assert_eq!(activation_delay(0), 2);
        // k=1 → raw=2, no clamping needed
        assert_eq!(activation_delay(1), 2);
        // k=2 (default confirmation_depth) → raw=3
        assert_eq!(activation_delay(2), 3);
        // k=6 → raw=7, upper bound is k+8=14 so no clamp
        assert_eq!(activation_delay(6), 7);
        // Large k: clamp never lifts; upper = k+8 >= k+1 always
        assert_eq!(activation_delay(100), 101);
        // u64::MAX wrap protection
        assert_eq!(activation_delay(u64::MAX), u64::MAX);
    }

    #[test]
    fn patch_04_validator_set_change_admitted_under_current_quorum() {
        let (set, validators) = three_validator_set();
        // Kind: Remove validator 2 at effective_height 13 (H_admit 10 + delay 3).
        let kind = ValidatorSetChangeKind::Remove {
            agent_id: [2; 32],
            reason: RemovalReason::Governance,
            effective_height: 13,
        };
        // Sign with validators 0, 1, 2 → total power 100, quorum = 67.
        let change = sign_change(&kind, 10, &validators);
        let res = validate_validator_set_change(&change, &set, 10, 2);
        assert!(res.is_valid(), "expected Valid, got {:?}", res);
    }

    #[test]
    fn patch_04_validator_set_change_rejected_under_quorum_below_threshold() {
        let (set, validators) = three_validator_set();
        let kind = ValidatorSetChangeKind::Remove {
            agent_id: [2; 32],
            reason: RemovalReason::Voluntary,
            effective_height: 13,
        };
        // Sign with only validator 0 (power 30) → below quorum of 67.
        let change = sign_change(&kind, 10, &validators[..1]);
        let res = validate_validator_set_change(&change, &set, 10, 2);
        assert!(matches!(
            res,
            ValidatorSetChangeValidation::Invalid(
                ValidatorSetChangeRejection::QuorumNotReached { .. }
            )
        ));
    }

    #[test]
    fn patch_04_validator_set_change_rejected_if_signer_outside_current_set() {
        let (set, validators) = three_validator_set();
        let outsider = keypair(99);
        let kind = ValidatorSetChangeKind::Remove {
            agent_id: [2; 32],
            reason: RemovalReason::Voluntary,
            effective_height: 13,
        };
        // Swap validator 2 for the outsider; quorum still looks like 100 power
        // but the outsider is not in the set.
        let signers: Vec<(SigningKey, [u8; 32])> = vec![
            validators[0].clone(),
            validators[1].clone(),
            outsider.clone(),
        ];
        let change = sign_change(&kind, 10, &signers);
        let res = validate_validator_set_change(&change, &set, 10, 2);
        assert!(matches!(
            res,
            ValidatorSetChangeValidation::Invalid(
                ValidatorSetChangeRejection::SignerNotInActiveSet { .. }
            )
        ));
    }

    #[test]
    fn patch_04_validator_set_change_rejected_if_signature_invalid() {
        let (set, validators) = three_validator_set();
        let kind = ValidatorSetChangeKind::Remove {
            agent_id: [2; 32],
            reason: RemovalReason::Voluntary,
            effective_height: 13,
        };
        let mut change = sign_change(&kind, 10, &validators);
        // Corrupt validator 0's signature.
        change.quorum_signatures[0].1[10] ^= 0xFF;
        let res = validate_validator_set_change(&change, &set, 10, 2);
        assert!(matches!(
            res,
            ValidatorSetChangeValidation::Invalid(
                ValidatorSetChangeRejection::SignatureInvalid { .. }
            )
        ));
    }

    #[test]
    fn patch_04_validator_set_change_rejected_if_change_id_tampered() {
        let (set, validators) = three_validator_set();
        let kind = ValidatorSetChangeKind::Remove {
            agent_id: [2; 32],
            reason: RemovalReason::Voluntary,
            effective_height: 13,
        };
        let mut change = sign_change(&kind, 10, &validators);
        change.change_id = [0xAA; 32];
        let res = validate_validator_set_change(&change, &set, 10, 2);
        assert!(matches!(
            res,
            ValidatorSetChangeValidation::Invalid(ValidatorSetChangeRejection::ChangeIdMismatch)
        ));
    }

    #[test]
    fn patch_04_validator_set_change_rejected_if_activation_too_soon() {
        let (set, validators) = three_validator_set();
        // Admission at H=10 with confirmation_depth=2 → min effective = 13.
        // effective=12 must be rejected.
        let kind = ValidatorSetChangeKind::Remove {
            agent_id: [2; 32],
            reason: RemovalReason::Voluntary,
            effective_height: 12,
        };
        let change = sign_change(&kind, 10, &validators);
        let res = validate_validator_set_change(&change, &set, 10, 2);
        assert!(matches!(
            res,
            ValidatorSetChangeValidation::Invalid(
                ValidatorSetChangeRejection::ActivationTooSoon { .. }
            )
        ));
    }

    #[test]
    fn patch_04_validator_set_change_rejected_against_post_change_set() {
        // The capture-prevention test from PATCH_04.md §15.5: a
        // post-change majority cannot self-admit.
        //
        // Scenario: set A = {v0, v1, v2} (power 30/30/40), quorum = 67.
        // Attacker is trying to Add a new validator v3 (power 100), and
        // sign the change only with v3 itself. Under §15.5 the quorum
        // is computed against set A (pre-change), not set A + {v3}.
        let (set_a, _) = three_validator_set();
        let v3 = keypair(99);
        let new_record = ValidatorRecord {
            agent_id: [3; 32],
            validator_id: v3.1,
            mfidel_seal: MfidelAtomicSeal::from_height(0),
            voting_power: 100,
            active_from: 13,
            active_until: None,
        };
        let kind = ValidatorSetChangeKind::Add(new_record);
        // Only v3 signs. v3 is NOT in set_a.
        let change = sign_change(&kind, 10, std::slice::from_ref(&v3));
        let res = validate_validator_set_change(&change, &set_a, 10, 2);
        // Fails because v3 is not in active_set(H_admit) (not yet admitted).
        assert!(matches!(
            res,
            ValidatorSetChangeValidation::Invalid(
                ValidatorSetChangeRejection::SignerNotInActiveSet { .. }
            )
        ));
    }

    #[test]
    fn patch_04_validator_set_change_duplicate_signer_rejected() {
        let (set, validators) = three_validator_set();
        let kind = ValidatorSetChangeKind::Remove {
            agent_id: [2; 32],
            reason: RemovalReason::Voluntary,
            effective_height: 13,
        };
        let mut change = sign_change(&kind, 10, &validators);
        // Force a duplicate signer by copying an entry.
        let dup = change.quorum_signatures[0].clone();
        change.quorum_signatures.push(dup);
        let res = validate_validator_set_change(&change, &set, 10, 2);
        assert!(matches!(
            res,
            ValidatorSetChangeValidation::Invalid(ValidatorSetChangeRejection::DuplicateSigner)
        ));
    }

    #[test]
    fn patch_04_validate_all_returns_first_invalid() {
        let (set, validators) = three_validator_set();
        let ok_kind = ValidatorSetChangeKind::Remove {
            agent_id: [2; 32],
            reason: RemovalReason::Voluntary,
            effective_height: 13,
        };
        let bad_kind = ValidatorSetChangeKind::Remove {
            agent_id: [1; 32],
            reason: RemovalReason::Voluntary,
            effective_height: 12, // too soon
        };
        let batch = vec![
            sign_change(&ok_kind, 10, &validators),
            sign_change(&bad_kind, 10, &validators),
        ];
        let res = validate_all_validator_set_changes(&batch, &set, 10, 2);
        assert!(matches!(
            res,
            ValidatorSetChangeValidation::Invalid(
                ValidatorSetChangeRejection::ActivationTooSoon { .. }
            )
        ));
    }

    #[test]
    fn patch_04_validate_all_empty_batch_is_valid() {
        let (set, _) = three_validator_set();
        let res = validate_all_validator_set_changes(&[], &set, 10, 2);
        assert!(res.is_valid());
    }
}
