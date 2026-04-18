//! Patch-05 §20 tension-history ring buffer for the median-over-window
//! fee oracle.
//!
//! The v4 fee oracle (`effective_fee_median` in `sccgub-types::economics`)
//! needs a window of the last W block tensions to compute the median.
//! This module stores that window on-chain under
//! `system/tension_history`, populated at block commit time.
//!
//! The buffer is capped at `W_max = max_median_tension_window_ceiling`
//! (64 by default) so chain-history iteration costs stay bounded even
//! when governance raises W. The oracle consults only the most recent
//! `median_tension_window` samples from the stored buffer.
//!
//! Canonical bincode: `Vec<TensionValue>` sorted by insertion order
//! (oldest first, most recent last). This gives a total ordering over
//! the state root that replay can reproduce bit-for-bit.

use sccgub_types::tension::TensionValue;
use sccgub_types::transition::{StateDelta, StateWrite};

use crate::world::ManagedWorldState;

/// Canonical trie key: `system/tension_history`.
pub const TENSION_HISTORY_TRIE_KEY: &[u8] = b"system/tension_history";

/// Maximum number of prior-block tensions retained in the ring.
/// Matches `ConstitutionalCeilings::max_median_tension_window_ceiling`
/// so the state never needs to grow past what the oracle could ever
/// consume.
pub const TENSION_HISTORY_MAX_LEN: usize = 64;

/// Read the current tension history (most-recent-last).
/// Returns `Ok(Vec::new())` when the key is not yet committed
/// (pre-v4 chains).
pub fn tension_history_from_trie(state: &ManagedWorldState) -> Result<Vec<TensionValue>, String> {
    match state.get(&TENSION_HISTORY_TRIE_KEY.to_vec()) {
        Some(bytes) => {
            bincode::deserialize(bytes).map_err(|e| format!("tension_history deserialize: {}", e))
        }
        None => Ok(Vec::new()),
    }
}

/// Commit the tension-history buffer to state.
/// `buffer` must be sorted oldest-first, most-recent-last, and have
/// length `<= TENSION_HISTORY_MAX_LEN`.
pub fn commit_tension_history(state: &mut ManagedWorldState, buffer: &[TensionValue]) {
    debug_assert!(
        buffer.len() <= TENSION_HISTORY_MAX_LEN,
        "tension history over cap: {} > {}",
        buffer.len(),
        TENSION_HISTORY_MAX_LEN
    );
    let bytes = bincode::serialize(buffer).expect("tension_history serialization is infallible");
    state.apply_delta(&StateDelta {
        writes: vec![StateWrite {
            address: TENSION_HISTORY_TRIE_KEY.to_vec(),
            value: bytes,
        }],
        deletes: vec![],
    });
}

/// Append `new_tension` to the history buffer and trim to
/// `TENSION_HISTORY_MAX_LEN`. Called at block commit time by the chain
/// applier once the block's post-apply tension has been computed.
/// Returns the new buffer (for immediate re-use by the fee oracle in
/// the following block's CPoG validation).
pub fn append_and_trim(
    state: &mut ManagedWorldState,
    new_tension: TensionValue,
) -> Result<Vec<TensionValue>, String> {
    let mut buf = tension_history_from_trie(state)?;
    buf.push(new_tension);
    // Drop oldest entries until length fits the cap.
    while buf.len() > TENSION_HISTORY_MAX_LEN {
        buf.remove(0);
    }
    commit_tension_history(state, &buf);
    Ok(buf)
}

/// Return the most-recent `window` entries from the history buffer as
/// a slice-owned `Vec<TensionValue>`. Passed to
/// `EconomicState::effective_fee_median` as the prior-tensions window.
/// If the buffer holds fewer than `window` entries, the full buffer is
/// returned (§20.1 warming-window behavior).
pub fn window(buffer: &[TensionValue], window: usize) -> Vec<TensionValue> {
    if buffer.len() <= window {
        buffer.to_vec()
    } else {
        buffer[buffer.len() - window..].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(n: i64) -> TensionValue {
        TensionValue::from_integer(n)
    }

    #[test]
    fn patch_05_tension_history_trie_key_in_system_namespace() {
        assert!(TENSION_HISTORY_TRIE_KEY.starts_with(b"system/"));
    }

    #[test]
    fn patch_05_tension_history_empty_on_fresh_state() {
        let state = ManagedWorldState::new();
        let history = tension_history_from_trie(&state).unwrap();
        assert!(history.is_empty());
    }

    #[test]
    fn patch_05_tension_history_commit_read_roundtrip() {
        let mut state = ManagedWorldState::new();
        let buf = vec![t(10), t(20), t(30)];
        commit_tension_history(&mut state, &buf);
        let back = tension_history_from_trie(&state).unwrap();
        assert_eq!(back, buf);
    }

    #[test]
    fn patch_05_append_and_trim_below_cap_appends() {
        let mut state = ManagedWorldState::new();
        let a = append_and_trim(&mut state, t(10)).unwrap();
        assert_eq!(a, vec![t(10)]);
        let b = append_and_trim(&mut state, t(20)).unwrap();
        assert_eq!(b, vec![t(10), t(20)]);
        let c = append_and_trim(&mut state, t(30)).unwrap();
        assert_eq!(c, vec![t(10), t(20), t(30)]);
    }

    #[test]
    fn patch_05_append_and_trim_at_cap_drops_oldest() {
        let mut state = ManagedWorldState::new();
        // Fill to cap.
        for i in 0..(TENSION_HISTORY_MAX_LEN as i64) {
            append_and_trim(&mut state, t(i)).unwrap();
        }
        let at_cap = tension_history_from_trie(&state).unwrap();
        assert_eq!(at_cap.len(), TENSION_HISTORY_MAX_LEN);
        assert_eq!(at_cap[0], t(0));
        assert_eq!(
            at_cap[TENSION_HISTORY_MAX_LEN - 1],
            t((TENSION_HISTORY_MAX_LEN - 1) as i64)
        );

        // One more entry: oldest drops.
        let next = t(999);
        let trimmed = append_and_trim(&mut state, next).unwrap();
        assert_eq!(trimmed.len(), TENSION_HISTORY_MAX_LEN);
        assert_eq!(trimmed[0], t(1)); // t(0) dropped
        assert_eq!(trimmed[TENSION_HISTORY_MAX_LEN - 1], next);
    }

    #[test]
    fn patch_05_window_smaller_than_buffer_returns_tail() {
        let buf = vec![t(1), t(2), t(3), t(4), t(5)];
        let w = window(&buf, 3);
        assert_eq!(w, vec![t(3), t(4), t(5)]);
    }

    #[test]
    fn patch_05_window_larger_than_buffer_returns_all() {
        let buf = vec![t(1), t(2), t(3)];
        let w = window(&buf, 7);
        assert_eq!(w, vec![t(1), t(2), t(3)]);
    }

    #[test]
    fn patch_05_window_equal_to_buffer_returns_full() {
        let buf = vec![t(1), t(2), t(3)];
        let w = window(&buf, 3);
        assert_eq!(w, vec![t(1), t(2), t(3)]);
    }

    #[test]
    fn patch_05_window_on_empty_buffer_is_empty() {
        let buf: Vec<TensionValue> = vec![];
        let w = window(&buf, 7);
        assert!(w.is_empty());
    }

    #[test]
    fn patch_05_append_replay_determinism() {
        // Two independent runs appending the same sequence must produce
        // bit-identical state roots.
        fn run() -> sccgub_types::Hash {
            let mut state = ManagedWorldState::new();
            for i in 0..20 {
                append_and_trim(&mut state, t(i * 7 + 3)).unwrap();
            }
            state.state_root()
        }
        assert_eq!(run(), run());
    }

    #[test]
    fn patch_05_history_cap_matches_ceiling() {
        // Regression guard: state-layer cap must match the ConstitutionalCeilings
        // default so the state never holds more than the oracle could consume.
        let ceilings = sccgub_types::constitutional_ceilings::ConstitutionalCeilings::default();
        assert_eq!(
            TENSION_HISTORY_MAX_LEN as u32,
            ceilings.max_median_tension_window_ceiling
        );
    }
}
