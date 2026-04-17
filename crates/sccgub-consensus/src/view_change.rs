//! Patch-04 §16 view-change protocol.
//!
//! The pre-Patch-04 two-round BFT specified prevote/precommit admission
//! but not round advancement. A silent leader halted liveness
//! indefinitely. §16 fixes that by adding:
//!
//! - exponential round timeouts (§16.1): `T(r) = min(base * 2^r, cap)`
//! - deterministic leader selection (§16.2): `leader(h, r) =
//!   active_set[BLAKE3(prior_block_hash || h || r) mod |active_set|]`
//! - a `NewRound` message (§16.3) that signals a wish to enter round
//!   `r+1`
//! - round advancement (§16.4): 2f+1 voting-power worth of `NewRound`
//!   messages, all verified under `verify_strict`, are required to move
//!   from `r` to `r+1`
//!
//! This module is pure and uses only `BTreeMap` / `BTreeSet` in
//! consensus-critical paths — see the crate-level
//! `#![deny(clippy::iter_over_hash_type)]` pragma that enforces this.
//!
//! All wall-clock reads are local-only. Consensus outcomes depend on
//! received messages, not on local time.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use sccgub_crypto::signature::verify_strict;
use sccgub_types::validator_set::{Ed25519PublicKey, Ed25519Signature, ValidatorSet};
use sccgub_types::Hash;
use sccgub_types::ZERO_HASH;

/// §16.3 `NewRound` message — a signed signal that the signer is ready
/// to enter `round + 1` at `height`.
///
/// Canonical bincode field order: `height, round, last_prevote, signer,
/// signature`. `canonical_newround_bytes` covers
/// `bincode(height, round, last_prevote, signer)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewRoundMessage {
    pub height: u64,
    pub round: u32,
    pub last_prevote: Option<Hash>,
    pub signer: Ed25519PublicKey,
    pub signature: Ed25519Signature,
}

impl NewRoundMessage {
    /// Canonical signed payload for §16.3.
    pub fn canonical_bytes(
        height: u64,
        round: u32,
        last_prevote: &Option<Hash>,
        signer: &Ed25519PublicKey,
    ) -> Vec<u8> {
        bincode::serialize(&(height, round, last_prevote, signer))
            .expect("NewRound canonical_bytes serialization is infallible")
    }

    /// Payload bytes for this message (for re-verification).
    pub fn payload_bytes(&self) -> Vec<u8> {
        Self::canonical_bytes(self.height, self.round, &self.last_prevote, &self.signer)
    }
}

/// §16.1 round timeout with exponential backoff and a saturating cap.
///
/// `T(r) = min(base_ms * 2^r, cap_ms)`. Saturation protects against
/// overflow at large round numbers; at saturation the timeout stops
/// growing and stays at `cap_ms`.
pub fn round_timeout_ms(base_ms: u32, cap_ms: u32, round: u32) -> u32 {
    let base = base_ms as u64;
    let shift = round.min(31);
    let raw = base.saturating_mul(1u64 << shift);
    raw.min(cap_ms as u64) as u32
}

/// §16.2 leader selection.
///
/// `leader(h, r) = active_set[BLAKE3(prior || h.le || r.le) mod n]` where:
///
/// - `prior` is `block[h-1].block_id` for `h >= 2`, and `ZERO_HASH` for
///   `h == 1` (first post-genesis block, PATCH_04.md §16.2).
/// - `h.le` is little-endian u64 (8 bytes).
/// - `r.le` is little-endian u32 (4 bytes).
/// - The BLAKE3 output is treated as a big-endian u256; the modulo is
///   u256 % (active_set size as u256).
///
/// Returns `None` if the active set at `height` is empty (the chain has
/// no validators to lead — a fatal configuration, not something the
/// consensus protocol is expected to recover from).
pub fn select_leader<'a>(
    set: &'a ValidatorSet,
    height: u64,
    round: u32,
    prior_block_hash: &Hash,
) -> Option<&'a sccgub_types::validator_set::ValidatorRecord> {
    let active = set.active_at(height);
    if active.is_empty() {
        return None;
    }
    // Compute `BLAKE3(prior || h.le || r.le)` — pure, deterministic.
    let mut data = Vec::with_capacity(32 + 8 + 4);
    data.extend_from_slice(prior_block_hash);
    data.extend_from_slice(&height.to_le_bytes());
    data.extend_from_slice(&round.to_le_bytes());
    let digest = blake3::hash(&data);

    // Interpret digest as big-endian u256, mod n. n is small (<= §17.2
    // ceiling of 128) so we can reduce 32 bytes mod n with u128
    // arithmetic — still exact because n fits easily in u64.
    let n = active.len() as u128;
    // Reduce 32 bytes iteratively: (acc * 256 + byte) % n.
    let mut acc: u128 = 0;
    for b in digest.as_bytes() {
        acc = ((acc << 8) | (*b as u128)) % n;
    }
    let idx = acc as usize;
    Some(active[idx])
}

/// `prior_block_hash` value at height `h` per §16.2.
///
/// For `h == 1` (first post-genesis block) the sentinel is `ZERO_HASH`.
/// For `h >= 2` the caller supplies the concrete parent block_id; this
/// helper exists to keep the height=1 convention in one place.
pub fn prior_block_hash_for_height(h: u64, parent_block_id: &Hash) -> Hash {
    if h <= 1 {
        ZERO_HASH
    } else {
        *parent_block_id
    }
}

/// §16.4 round-advancement decision state.
///
/// A validator advances from round `r` to round `r+1` at height `h` iff:
///
/// 1. It has received `NewRound` messages from a subset of
///    `active_set(h)` whose voting-power sum reaches
///    `quorum_power(h)`, AND
/// 2. Every referenced `NewRound` has `height == h && round == r+1`, AND
/// 3. Every signature verifies under `verify_strict`, AND
/// 4. Every signer is in `active_set(h)` with `signer == validator_id`.
///
/// The state machine is a pure function: messages in, decision out. No
/// timers, no I/O. Callers are responsible for driving the timeout
/// clock (§16.5) and forwarding received `NewRound` messages here.
#[derive(Debug, Clone, Default)]
pub struct RoundAdvance {
    /// Admitted `NewRound` messages keyed by signer for canonical order.
    /// `BTreeMap` is mandatory — iteration order directly informs the
    /// power-sum check and must be deterministic across implementations.
    admitted: BTreeMap<Ed25519PublicKey, NewRoundMessage>,
}

/// Reason a `NewRound` message was rejected (§16.4 predicates).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NewRoundRejection {
    #[error("message height {got} != target height {want}")]
    HeightMismatch { got: u64, want: u64 },
    #[error("message round {got} != expected target round {want}")]
    RoundMismatch { got: u32, want: u32 },
    #[error("signer {signer:?} is not in active_set(height)")]
    SignerNotInActiveSet { signer: Ed25519PublicKey },
    #[error("signature by {signer:?} fails verify_strict")]
    SignatureInvalid { signer: Ed25519PublicKey },
    #[error("duplicate NewRound message from signer {signer:?}")]
    DuplicateSigner { signer: Ed25519PublicKey },
}

impl RoundAdvance {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of admitted messages.
    pub fn admitted_count(&self) -> usize {
        self.admitted.len()
    }

    /// Sum of voting power of admitted signers, computed against the
    /// active set at the message's target height.
    pub fn admitted_power(&self, set: &ValidatorSet, height: u64) -> u128 {
        let mut sum: u128 = 0;
        for signer in self.admitted.keys() {
            if let Some(record) = set.find_active_by_validator_id(signer, height) {
                sum = sum.saturating_add(record.voting_power as u128);
            }
        }
        sum
    }

    /// True once `admitted_power >= quorum_power(height)`.
    pub fn has_quorum(&self, set: &ValidatorSet, height: u64) -> bool {
        self.admitted_power(set, height) >= set.quorum_power_at(height)
    }

    /// Sorted view of admitted messages for inspection / test assertions.
    /// Returned as an iterator to keep `RoundAdvance`'s internal map
    /// private and preserve the BTreeMap discipline.
    pub fn admitted_iter(
        &self,
    ) -> impl Iterator<Item = (&Ed25519PublicKey, &NewRoundMessage)> {
        self.admitted.iter()
    }

    /// Admit a `NewRound` message aimed at round `target_round` at
    /// height `target_height`.
    ///
    /// `active_set` is used for both membership and signature-verifier
    /// lookup. Returns `Ok(())` on admission, `Err(reason)` otherwise.
    /// Rejected messages do not mutate `self`.
    pub fn admit(
        &mut self,
        msg: NewRoundMessage,
        set: &ValidatorSet,
        target_height: u64,
        target_round: u32,
    ) -> Result<(), NewRoundRejection> {
        if msg.height != target_height {
            return Err(NewRoundRejection::HeightMismatch {
                got: msg.height,
                want: target_height,
            });
        }
        if msg.round != target_round {
            return Err(NewRoundRejection::RoundMismatch {
                got: msg.round,
                want: target_round,
            });
        }
        if set
            .find_active_by_validator_id(&msg.signer, target_height)
            .is_none()
        {
            return Err(NewRoundRejection::SignerNotInActiveSet { signer: msg.signer });
        }
        let payload = msg.payload_bytes();
        if !verify_strict(&msg.signer, &payload, &msg.signature) {
            return Err(NewRoundRejection::SignatureInvalid { signer: msg.signer });
        }
        if self.admitted.contains_key(&msg.signer) {
            return Err(NewRoundRejection::DuplicateSigner { signer: msg.signer });
        }
        self.admitted.insert(msg.signer, msg);
        Ok(())
    }
}

/// Set of unique admitted signers, for §16.4 rule 4 enforcement across
/// multiple rounds. Stored as `BTreeSet` to keep iteration deterministic.
pub type AdmittedSigners = BTreeSet<Ed25519PublicKey>;

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use sccgub_crypto::signature::sign;
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::validator_set::ValidatorRecord;

    fn keypair(seed: u8) -> (SigningKey, Ed25519PublicKey) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pk = *sk.verifying_key().as_bytes();
        (sk, pk)
    }

    fn record(agent: u8, validator_pk: Ed25519PublicKey, power: u64) -> ValidatorRecord {
        ValidatorRecord {
            agent_id: [agent; 32],
            validator_id: validator_pk,
            mfidel_seal: MfidelAtomicSeal::from_height(0),
            voting_power: power,
            active_from: 0,
            active_until: None,
        }
    }

    fn three_validators() -> (ValidatorSet, Vec<(SigningKey, Ed25519PublicKey)>) {
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

    fn signed_new_round(
        sk: &SigningKey,
        pk: Ed25519PublicKey,
        height: u64,
        round: u32,
        last_prevote: Option<Hash>,
    ) -> NewRoundMessage {
        let payload = NewRoundMessage::canonical_bytes(height, round, &last_prevote, &pk);
        let sig = sign(sk, &payload);
        NewRoundMessage {
            height,
            round,
            last_prevote,
            signer: pk,
            signature: sig,
        }
    }

    // ── §16.1 timeout ──────────────────────────────────────────────

    #[test]
    fn patch_04_timeout_backoff_capped() {
        let base = 1_000u32;
        let cap = 60_000u32;
        assert_eq!(round_timeout_ms(base, cap, 0), 1_000);
        assert_eq!(round_timeout_ms(base, cap, 1), 2_000);
        assert_eq!(round_timeout_ms(base, cap, 2), 4_000);
        assert_eq!(round_timeout_ms(base, cap, 3), 8_000);
        assert_eq!(round_timeout_ms(base, cap, 4), 16_000);
        assert_eq!(round_timeout_ms(base, cap, 5), 32_000);
        // 2^6 * 1000 = 64_000 > cap 60_000 → capped.
        assert_eq!(round_timeout_ms(base, cap, 6), cap);
        assert_eq!(round_timeout_ms(base, cap, 10), cap);
        // Saturation at large rounds: no overflow, still capped.
        assert_eq!(round_timeout_ms(base, cap, 31), cap);
        assert_eq!(round_timeout_ms(base, cap, u32::MAX), cap);
    }

    // ── §16.2 leader selection ────────────────────────────────────

    #[test]
    fn patch_04_leader_selection_deterministic() {
        // Same inputs → same leader across repeated calls.
        let (set, _) = three_validators();
        let prior = [0x11u8; 32];
        let l1 = select_leader(&set, 5, 0, &prior).map(|r| r.agent_id);
        let l2 = select_leader(&set, 5, 0, &prior).map(|r| r.agent_id);
        assert_eq!(l1, l2);
    }

    #[test]
    fn patch_04_leader_includes_prior_block_hash() {
        // Changing prior_block_hash changes leader (with high probability).
        // Pick a specific pair where the outcome differs.
        let (set, _) = three_validators();
        let a = select_leader(&set, 5, 0, &[0x11u8; 32]).unwrap().agent_id;
        // Scan a few priors to find one yielding a different leader.
        let mut found_different = false;
        for i in 0..32u8 {
            let prior = [i; 32];
            let b = select_leader(&set, 5, 0, &prior).unwrap().agent_id;
            if b != a {
                found_different = true;
                break;
            }
        }
        assert!(
            found_different,
            "leader never changes with prior_block_hash — folding is cosmetic"
        );
    }

    #[test]
    fn patch_04_leader_rotation_across_10_rounds() {
        let (set, _) = three_validators();
        let prior = [0x42u8; 32];
        let mut seen = BTreeSet::new();
        for r in 0..10u32 {
            let l = select_leader(&set, 7, r, &prior).unwrap().agent_id;
            seen.insert(l);
        }
        // With 3 validators and 10 rounds, leader selection should hit
        // all three at least once (probability of missing any with
        // uniform-ish hash output is ~ (2/3)^10 ≈ 1.7%, low enough for
        // this to be a meaningful regression test).
        assert_eq!(
            seen.len(),
            3,
            "leader rotation across 10 rounds missed some validators: {:?}",
            seen
        );
    }

    #[test]
    fn patch_04_leader_block1_zero_hash_prior() {
        assert_eq!(prior_block_hash_for_height(1, &[0x99u8; 32]), ZERO_HASH);
    }

    #[test]
    fn patch_04_leader_block_n_uses_parent() {
        let parent = [0x99u8; 32];
        assert_eq!(prior_block_hash_for_height(2, &parent), parent);
        assert_eq!(prior_block_hash_for_height(100, &parent), parent);
    }

    #[test]
    fn patch_04_leader_empty_active_set_none() {
        let set = ValidatorSet::new(vec![]).unwrap();
        let l = select_leader(&set, 1, 0, &ZERO_HASH);
        assert!(l.is_none());
    }

    // ── §16.3 NewRound canonical bytes ────────────────────────────

    #[test]
    fn patch_04_newround_canonical_bytes() {
        let (sk, pk) = keypair(7);
        let msg = signed_new_round(&sk, pk, 10, 3, Some([0xAA; 32]));
        let bytes = bincode::serialize(&msg).unwrap();
        let back: NewRoundMessage = bincode::deserialize(&bytes).unwrap();
        assert_eq!(msg, back);
    }

    // ── §16.4 round advancement ───────────────────────────────────

    #[test]
    fn patch_04_round_advancement_quorum() {
        let (set, validators) = three_validators();
        // Target: advance to round 1 at height 5.
        let mut adv = RoundAdvance::new();
        // Admit v0 (power 30) + v1 (power 30). Quorum = floor(2*100/3)+1 = 67.
        // 60 < 67 → not yet quorum.
        for (sk, pk) in &validators[..2] {
            let msg = signed_new_round(sk, *pk, 5, 1, None);
            adv.admit(msg, &set, 5, 1).unwrap();
        }
        assert!(!adv.has_quorum(&set, 5));

        // Admit v2 (power 40). Total 100 ≥ 67 → quorum.
        let (sk, pk) = &validators[2];
        let msg = signed_new_round(sk, *pk, 5, 1, None);
        adv.admit(msg, &set, 5, 1).unwrap();
        assert!(adv.has_quorum(&set, 5));
    }

    #[test]
    fn patch_04_round_advancement_rejects_wrong_height() {
        let (set, validators) = three_validators();
        let mut adv = RoundAdvance::new();
        let (sk, pk) = &validators[0];
        let msg = signed_new_round(sk, *pk, 99, 1, None);
        let err = adv.admit(msg, &set, 5, 1);
        assert!(matches!(err, Err(NewRoundRejection::HeightMismatch { .. })));
    }

    #[test]
    fn patch_04_round_advancement_rejects_wrong_round() {
        let (set, validators) = three_validators();
        let mut adv = RoundAdvance::new();
        let (sk, pk) = &validators[0];
        let msg = signed_new_round(sk, *pk, 5, 9, None);
        let err = adv.admit(msg, &set, 5, 1);
        assert!(matches!(err, Err(NewRoundRejection::RoundMismatch { .. })));
    }

    #[test]
    fn patch_04_round_advancement_rejects_outsider() {
        let (set, _) = three_validators();
        let mut adv = RoundAdvance::new();
        let (sk_out, pk_out) = keypair(99);
        let msg = signed_new_round(&sk_out, pk_out, 5, 1, None);
        let err = adv.admit(msg, &set, 5, 1);
        assert!(matches!(
            err,
            Err(NewRoundRejection::SignerNotInActiveSet { .. })
        ));
    }

    #[test]
    fn patch_04_round_advancement_rejects_bad_signature() {
        let (set, validators) = three_validators();
        let mut adv = RoundAdvance::new();
        let (sk, pk) = &validators[0];
        let mut msg = signed_new_round(sk, *pk, 5, 1, None);
        msg.signature[0] ^= 0xFF;
        let err = adv.admit(msg, &set, 5, 1);
        assert!(matches!(err, Err(NewRoundRejection::SignatureInvalid { .. })));
    }

    #[test]
    fn patch_04_round_advancement_rejects_duplicate_signer() {
        let (set, validators) = three_validators();
        let mut adv = RoundAdvance::new();
        let (sk, pk) = &validators[0];
        adv.admit(signed_new_round(sk, *pk, 5, 1, None), &set, 5, 1)
            .unwrap();
        let err = adv.admit(signed_new_round(sk, *pk, 5, 1, None), &set, 5, 1);
        assert!(matches!(err, Err(NewRoundRejection::DuplicateSigner { .. })));
    }

    #[test]
    fn patch_04_round_advancement_under_partition_simulation() {
        // Simulate a partition where only v0 and v2 (power 30 + 40 = 70)
        // can reach consensus. Quorum is 67, so they can advance;
        // v1 (partitioned away) is not required.
        let (set, validators) = three_validators();
        let mut adv = RoundAdvance::new();
        for idx in [0, 2] {
            let (sk, pk) = &validators[idx];
            adv.admit(signed_new_round(sk, *pk, 5, 1, None), &set, 5, 1)
                .unwrap();
        }
        assert!(
            adv.has_quorum(&set, 5),
            "v0+v2 (30+40=70) should reach quorum of 67 without v1"
        );
    }

    #[test]
    fn patch_04_round_advancement_below_quorum_under_partition() {
        // Same setup, but only v0 (power 30) participates — below quorum.
        let (set, validators) = three_validators();
        let mut adv = RoundAdvance::new();
        let (sk, pk) = &validators[0];
        adv.admit(signed_new_round(sk, *pk, 5, 1, None), &set, 5, 1)
            .unwrap();
        assert!(
            !adv.has_quorum(&set, 5),
            "single validator with power 30 must not reach quorum of 67"
        );
    }
}
