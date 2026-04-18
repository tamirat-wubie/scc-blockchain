//! `ChainStateView` — read-only handle to chain log per PATCH_08.md
//! §B.1.
//!
//! The verifier requires three pieces of information about a chain to
//! check the moat:
//!
//! 1. The genesis `ConstitutionalCeilings` — the moat-defining
//!    baseline values.
//! 2. The full `chain_version_history` — every
//!    `ChainVersionTransition` from genesis to current tip.
//! 3. The ceilings record at any specific block height — used to
//!    confirm that at every transition the ceilings still match the
//!    genesis baseline.
//!
//! `ChainStateView` is a trait so the verifier can be backed by:
//!
//! - A live full node (operator's local mode — implemented in
//!   `sccgub-node` via a thin adapter, **outside this crate**).
//! - A snapshot file (institutional auditor's offline mode —
//!   binary-snapshot reading is **deferred to Patch-09** per
//!   `PATCH_08.md` §C.4 follow-up).
//! - A merkle-proof bundle (light-client mode — also deferred).
//! - A JSON fixture (used in tests and as the v1 CLI input format —
//!   `JsonChainStateFixture` below).
//!
//! Per PATCH_08.md §C.2, this crate ships no implementation that
//! pulls in `sccgub-state`/`-node`; those bindings live elsewhere
//! and depend on this crate, not the other way around.

use serde::{Deserialize, Serialize};

use sccgub_types::constitutional_ceilings::ConstitutionalCeilings;
use sccgub_types::upgrade::ChainVersionTransition;
use sccgub_types::Hash;

/// Errors `ChainStateView` implementors may return when the chain log
/// is unreadable, corrupted, or missing required entries.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainStateError {
    /// The genesis ceilings record could not be located.
    #[error("genesis ceilings missing: {0}")]
    GenesisCeilingsMissing(String),
    /// The genesis ceilings record was found but failed to deserialize.
    #[error("genesis ceilings malformed: {0}")]
    GenesisCeilingsMalformed(String),
    /// A `ChainVersionTransition` referenced a height for which the
    /// state view has no ceilings record.
    #[error("ceilings missing at height {height}: {reason}")]
    CeilingsMissingAtHeight {
        /// Block height where the read was attempted.
        height: u64,
        /// Underlying reason (snapshot incomplete, key not found,
        /// etc.).
        reason: String,
    },
    /// I/O or backend error not specific to a single height.
    #[error("chain state I/O error: {0}")]
    Io(String),
}

/// Read-only view over a chain's state required by the verifier.
///
/// Implementations supply the three reads. The verifier is the only
/// caller and uses these reads in a single pass.
pub trait ChainStateView {
    /// The genesis block hash (returned for completeness; the verifier
    /// does not currently use it but operator/CLI output does).
    fn genesis_block_hash(&self) -> Hash;

    /// The `ConstitutionalCeilings` as committed at genesis. Must be
    /// read from the genesis-block state, NOT from any later snapshot
    /// that might reflect post-genesis writes (per PATCH_08 §B.1).
    fn genesis_constitutional_ceilings(&self) -> Result<ConstitutionalCeilings, ChainStateError>;

    /// Every `ChainVersionTransition` record from genesis to current
    /// tip, ordered ascending by `activation_height`. Empty iff the
    /// chain is genesis-only.
    fn chain_version_history(&self) -> Result<Vec<ChainVersionTransition>, ChainStateError>;

    /// The ceilings record as committed at block `height`. The
    /// verifier reads this at each transition's `activation_height`
    /// (and `activation_height - 1` when applicable per PATCH_08
    /// §B.5) to confirm the ceilings still match the genesis
    /// baseline at every transition.
    fn ceilings_at_height(&self, height: u64) -> Result<ConstitutionalCeilings, ChainStateError>;
}

// ─── JsonChainStateFixture ───────────────────────────────────────────
//
// CLI v1 input format. Real binary-snapshot reading is deferred to
// Patch-09 (per PATCH_08.md §C.4). The JSON form is convenient for
// fixtures, deterministic conformance testing, and pilot-adopter
// dry-runs against synthetic chain histories.

/// A `ChainStateView` backed by an in-memory JSON-shaped fixture.
///
/// Designed for tests, the CLI v1 `--chain-state <path>` mode, and
/// the conformance harness. Implementors of binary-snapshot mode
/// (Patch-09) need not use this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonChainStateFixture {
    /// Genesis block hash (32-byte hex string at JSON layer).
    pub genesis_block_hash: Hash,
    /// Ceilings as committed at genesis.
    pub genesis_ceilings: ConstitutionalCeilings,
    /// Every chain-version transition from genesis to tip, ascending
    /// by `activation_height`.
    pub chain_version_history: Vec<ChainVersionTransition>,
    /// `(height, ceilings)` pairs giving the ceilings record at each
    /// queried height. The verifier queries each transition's
    /// activation height (and the height immediately before it). A
    /// fixture missing one of those heights surfaces as
    /// `CeilingsMissingAtHeight`.
    pub ceilings_by_height: Vec<(u64, ConstitutionalCeilings)>,
}

impl JsonChainStateFixture {
    /// Construct a "happy path" fixture where every height in the
    /// history retains the genesis ceilings exactly. Useful for tests
    /// of the `Ok(())` path and as a baseline for adversarial
    /// mutations.
    pub fn genesis_preserved(
        genesis_block_hash: Hash,
        genesis_ceilings: ConstitutionalCeilings,
        history: Vec<ChainVersionTransition>,
    ) -> Self {
        let mut by_height = Vec::new();
        for t in &history {
            // Pre-transition height (when activation_height > 0) and
            // the activation height itself both need entries.
            if t.activation_height > 0 {
                by_height.push((t.activation_height - 1, genesis_ceilings.clone()));
            }
            by_height.push((t.activation_height, genesis_ceilings.clone()));
        }
        Self {
            genesis_block_hash,
            genesis_ceilings,
            chain_version_history: history,
            ceilings_by_height: by_height,
        }
    }
}

impl ChainStateView for JsonChainStateFixture {
    fn genesis_block_hash(&self) -> Hash {
        self.genesis_block_hash
    }

    fn genesis_constitutional_ceilings(&self) -> Result<ConstitutionalCeilings, ChainStateError> {
        Ok(self.genesis_ceilings.clone())
    }

    fn chain_version_history(&self) -> Result<Vec<ChainVersionTransition>, ChainStateError> {
        Ok(self.chain_version_history.clone())
    }

    fn ceilings_at_height(&self, height: u64) -> Result<ConstitutionalCeilings, ChainStateError> {
        for (h, c) in &self.ceilings_by_height {
            if *h == height {
                return Ok(c.clone());
            }
        }
        Err(ChainStateError::CeilingsMissingAtHeight {
            height,
            reason: format!("no ceilings record in fixture for height {}", height),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_transition(activation: u64, to_v: u32) -> ChainVersionTransition {
        ChainVersionTransition {
            activation_height: activation,
            from_version: to_v - 1,
            to_version: to_v,
            upgrade_spec_hash: [0xAA; 32],
            proposal_id: [0xBB; 32],
        }
    }

    #[test]
    fn patch_08_genesis_preserved_includes_pre_and_post_heights() {
        let c = ConstitutionalCeilings::default();
        let h = vec![dummy_transition(100, 5), dummy_transition(200, 6)];
        let f = JsonChainStateFixture::genesis_preserved([0xCC; 32], c.clone(), h);
        // Should contain heights 99, 100, 199, 200.
        let heights: Vec<u64> = f.ceilings_by_height.iter().map(|(h, _)| *h).collect();
        assert!(heights.contains(&99));
        assert!(heights.contains(&100));
        assert!(heights.contains(&199));
        assert!(heights.contains(&200));
    }

    #[test]
    fn patch_08_genesis_preserved_returns_genesis_ceilings_at_every_queried_height() {
        let c = ConstitutionalCeilings::default();
        let h = vec![dummy_transition(50, 5)];
        let f = JsonChainStateFixture::genesis_preserved([0; 32], c.clone(), h);
        assert_eq!(f.ceilings_at_height(49).unwrap(), c);
        assert_eq!(f.ceilings_at_height(50).unwrap(), c);
    }

    #[test]
    fn patch_08_ceilings_missing_at_unrequested_height() {
        let c = ConstitutionalCeilings::default();
        let h = vec![dummy_transition(100, 5)];
        let f = JsonChainStateFixture::genesis_preserved([0; 32], c, h);
        let r = f.ceilings_at_height(500);
        assert!(matches!(
            r,
            Err(ChainStateError::CeilingsMissingAtHeight { height: 500, .. })
        ));
    }

    #[test]
    fn patch_08_empty_history_fixture_well_formed() {
        let c = ConstitutionalCeilings::default();
        let f = JsonChainStateFixture::genesis_preserved([0; 32], c.clone(), vec![]);
        assert_eq!(f.chain_version_history().unwrap().len(), 0);
        assert_eq!(f.genesis_constitutional_ceilings().unwrap(), c);
    }

    #[test]
    fn patch_08_fixture_serde_roundtrip() {
        let c = ConstitutionalCeilings::default();
        let h = vec![dummy_transition(100, 5)];
        let f = JsonChainStateFixture::genesis_preserved([0xDE; 32], c, h);
        let json = serde_json::to_string(&f).unwrap();
        let back: JsonChainStateFixture = serde_json::from_str(&json).unwrap();
        assert_eq!(back.genesis_block_hash, [0xDE; 32]);
    }

    #[test]
    fn patch_08_genesis_block_hash_returned() {
        let c = ConstitutionalCeilings::default();
        let f = JsonChainStateFixture::genesis_preserved([0x42; 32], c, vec![]);
        assert_eq!(f.genesis_block_hash(), [0x42; 32]);
    }
}
