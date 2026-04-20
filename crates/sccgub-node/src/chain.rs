//! Purpose: Chain state machine, block production/import, governance application.
//! Governance scope: Consensus/treasury/governance/finality state transitions.
//! Dependencies: sccgub_execution, sccgub_state, sccgub_consensus, sccgub_governance.
//! Invariants: deterministic replay, governed parameter application, fail-closed validation.

use sccgub_crypto::canonical::{canonical_bytes, canonical_hash};
use sccgub_crypto::hash::{blake3_hash, blake3_hash_concat};
use sccgub_crypto::keys::generate_keypair;
use sccgub_crypto::merkle::merkle_root_of_bytes;
use sccgub_crypto::signature::sign;
use sccgub_execution::cpog::{validate_cpog, CpogResult};
use sccgub_execution::gas::BlockGasMeter;
use sccgub_execution::validate::validate_transition_metered;
use sccgub_state::balances::BalanceLedger;
use sccgub_state::treasury::{
    commit_treasury_state, default_block_reward, treasury_from_trie, Treasury,
};
use sccgub_state::world::{commit_consensus_params, consensus_params_from_trie, ManagedWorldState};
use sccgub_types::agent::ValidatorAuthority;
use sccgub_types::block::{
    is_supported_block_version, Block, BlockBody, BlockHeader, CURRENT_BLOCK_VERSION,
};
use sccgub_types::causal::{CausalEdge, CausalGraphDelta, CausalVertex};
use sccgub_types::consensus_params::ConsensusParams;
use sccgub_types::economics::EconomicState;
use sccgub_types::governance::{
    FinalityConfigSnapshot, FinalityMode, GovernanceLimitsSnapshot, GovernanceSnapshot,
    GovernanceState,
};
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::proof::{CausalProof, PhiTraversalLog};
use sccgub_types::receipt::CausalReceipt;
use sccgub_types::tension::TensionValue;
use sccgub_types::timestamp::CausalTimestamp;
use sccgub_types::transition::SymbolicTransition;
use sccgub_types::{Hash, MerkleRoot, ZERO_HASH};
use std::collections::BTreeSet;
use std::time::{SystemTime, UNIX_EPOCH};

use sccgub_consensus::finality::{FinalityConfig, FinalityTracker};
use sccgub_consensus::protocol::EquivocationProof;
use sccgub_consensus::safety::SafetyCertificate;
use sccgub_consensus::slashing::SlashingEngine;
use sccgub_governance::anti_concentration::{GovernanceLimits, GovernancePowerTracker};

use crate::mempool::Mempool;

fn initialize_genesis_state(
    block_version: u32,
    validator_public_key: &[u8; 32],
    consensus_params: ConsensusParams,
    finality_mode: FinalityMode,
) -> (ManagedWorldState, BalanceLedger) {
    let mut state = ManagedWorldState::with_consensus_params(consensus_params);
    state.state.governance_state = GovernanceState {
        finality_mode,
        ..GovernanceState::default()
    };
    commit_consensus_params(&mut state);

    let mut balances = BalanceLedger::new();
    let validator_spend_account =
        sccgub_state::apply::validator_spend_account(block_version, validator_public_key);
    sccgub_state::apply::apply_genesis_mint(&mut state, &mut balances, &validator_spend_account);
    state.set_height(0);

    (state, balances)
}

fn load_genesis_consensus_params(genesis: &Block) -> Result<ConsensusParams, ImportError> {
    match genesis.body.genesis_consensus_params.as_ref() {
        Some(bytes) => ConsensusParams::from_canonical_bytes(bytes)
            .map_err(ImportError::GenesisConsensusParams),
        None => Ok(ConsensusParams::default()),
    }
}

/// The chain — manages blocks, state, consensus, and block production.
#[derive(Clone)]
pub struct Chain {
    pub blocks: Vec<Block>,
    pub block_version: u32,
    pub state: ManagedWorldState,
    pub mempool: Mempool,
    pub chain_id: Hash,
    pub validator_key: ed25519_dalek::SigningKey,
    pub economics: EconomicState,
    pub balances: BalanceLedger,
    pub treasury: Treasury,
    pub governance_limits: GovernanceLimits,
    pub power_tracker: GovernancePowerTracker,
    pub proposals: sccgub_governance::proposals::ProposalRegistry,
    pub finality: FinalityTracker,
    pub finality_config: FinalityConfig,
    pub slashing: SlashingEngine,
    /// Equivocation evidence records (proof + epoch).
    pub equivocation_records: Vec<(EquivocationProof, u64)>,
    /// Safety certificates from BFT finality (consensus proofs).
    pub safety_certificates: Vec<SafetyCertificate>,
    /// Active validator set for proposer rotation (optional).
    pub validator_set: Vec<ValidatorAuthority>,
    /// Event log for the most recently produced block.
    pub latest_events: sccgub_types::events::BlockEventLog,
    /// Rejected transaction receipts from the most recent block production.
    pub latest_rejected_receipts: Vec<sccgub_types::receipt::CausalReceipt>,
    /// Per-agent responsibility state (Φ²-R causal accounting).
    pub responsibility:
        std::collections::HashMap<sccgub_types::AgentId, sccgub_types::agent::ResponsibilityState>,
    /// Optional API bridge for local event-driven syncs.
    pub api_bridge: Option<crate::api_bridge::ApiBridge>,
}

impl Chain {
    /// Create a new chain with a genesis block.
    pub fn init() -> Self {
        Self::init_with_version(CURRENT_BLOCK_VERSION)
    }

    /// Create a new chain with an explicit block version.
    pub fn init_with_version(block_version: u32) -> Self {
        Self::init_with_consensus_params(block_version, ConsensusParams::default())
    }

    /// Create a new chain with an explicit finality mode at genesis.
    pub fn init_with_finality_mode(finality_mode: FinalityMode) -> Self {
        Self::init_with_consensus_params_and_finality(
            CURRENT_BLOCK_VERSION,
            ConsensusParams::default(),
            finality_mode,
        )
    }

    fn init_with_consensus_params(block_version: u32, consensus_params: ConsensusParams) -> Self {
        Self::init_with_consensus_params_and_finality(
            block_version,
            consensus_params,
            FinalityMode::Deterministic,
        )
    }

    fn init_with_consensus_params_and_finality(
        block_version: u32,
        consensus_params: ConsensusParams,
        finality_mode: FinalityMode,
    ) -> Self {
        assert!(
            is_supported_block_version(block_version),
            "unsupported block version {}",
            block_version
        );

        let validator_key = generate_keypair();
        let pk = *validator_key.verifying_key().as_bytes();
        // validator_id = public_key directly (Position A).
        // This enables real Ed25519 verification at import without a registry.
        // Key rotation requires a Constitutional governance proposal.
        let validator_id = pk;
        let chain_id = blake3_hash(b"sccgub-genesis-chain");

        let genesis_consensus_params = consensus_params.to_canonical_bytes();
        let (state, balances) = initialize_genesis_state(
            block_version,
            &validator_id,
            consensus_params,
            finality_mode,
        );
        let genesis = build_genesis_block(
            chain_id,
            validator_id,
            block_version,
            &validator_key,
            state.state_root(),
            balances.balance_root(),
            Some(genesis_consensus_params),
        );

        // Initialize slashing engine with validator stake.
        let mut slashing = SlashingEngine::new(Default::default());
        slashing.set_stake(validator_id, TensionValue::from_integer(100_000));

        let mut chain = Chain {
            blocks: vec![genesis],
            block_version,
            state,
            mempool: Mempool::new(10_000),
            chain_id,
            validator_key,
            economics: EconomicState::default(),
            balances,
            treasury: Treasury::new(),
            governance_limits: GovernanceLimits::default(),
            power_tracker: GovernancePowerTracker::default(),
            proposals: sccgub_governance::proposals::ProposalRegistry::default(),
            finality: FinalityTracker::default(),
            finality_config: FinalityConfig::default(),
            slashing,
            equivocation_records: Vec::new(),
            safety_certificates: Vec::new(),
            validator_set: Vec::new(),
            latest_events: sccgub_types::events::BlockEventLog::new(),
            latest_rejected_receipts: Vec::new(),
            responsibility: std::collections::HashMap::new(),
            api_bridge: None,
        };

        chain.state.set_height(0);
        chain
    }

    /// Reconstruct chain from blocks (e.g., loaded from disk or received from peer).
    ///
    /// This is a HOT TRUST BOUNDARY. Every block must pass full CPoG validation
    /// against the state derived from its predecessors. Block 0 must carry a
    /// valid producer signature, and every subsequent block likewise.
    ///
    /// Returns Err on any validation failure. Callers must NOT proceed with a
    /// partially-validated chain.
    pub fn from_blocks(blocks: Vec<Block>) -> Result<Self, ImportError> {
        if blocks.is_empty() {
            return Err(ImportError::Empty);
        }

        let validator_key = generate_keypair();
        let chain_id = blocks[0].header.chain_id;

        // --- Genesis block (height 0) validation ---
        let genesis = &blocks[0];
        if genesis.header.height != 0 {
            return Err(ImportError::FirstBlockNotGenesis);
        }
        let block_version = genesis.header.version;
        verify_producer_signature(genesis).map_err(ImportError::GenesisSignature)?;
        let genesis_consensus_params = load_genesis_consensus_params(genesis)?;

        // CPoG on genesis against empty state.
        let mut empty_state =
            ManagedWorldState::with_consensus_params(genesis_consensus_params.clone());
        empty_state.state.governance_state = GovernanceState {
            finality_mode: FinalityMode::Deterministic,
            ..GovernanceState::default()
        };
        match validate_cpog(genesis, &empty_state, &sccgub_types::ZERO_HASH) {
            CpogResult::Valid => {}
            CpogResult::Invalid { errors } => return Err(ImportError::Cpog { height: 0, errors }),
        }

        let (mut state, mut balances) = initialize_genesis_state(
            block_version,
            &genesis.header.validator_id,
            genesis_consensus_params,
            FinalityMode::Deterministic,
        );
        match &genesis.body.genesis_consensus_params {
            Some(_) => {
                let expected_state_root = state.state_root();
                if genesis.header.state_root != expected_state_root {
                    return Err(ImportError::GenesisStateMismatch {
                        detail: format!(
                            "header={}, reconstructed={}",
                            hex::encode(genesis.header.state_root),
                            hex::encode(expected_state_root),
                        ),
                    });
                }
                let expected_balance_root = balances.balance_root();
                if genesis.header.balance_root != expected_balance_root {
                    return Err(ImportError::GenesisStateMismatch {
                        detail: format!(
                            "balance header={}, reconstructed={}",
                            hex::encode(genesis.header.balance_root),
                            hex::encode(expected_balance_root),
                        ),
                    });
                }
            }
            None => {
                if genesis.header.state_root != ZERO_HASH
                    || genesis.header.balance_root != ZERO_HASH
                {
                    return Err(ImportError::MissingGenesisConsensusParams);
                }
            }
        }
        let mut treasury = Treasury::new();
        state.set_height(0);
        let mut governance_limits = GovernanceLimits::default();
        let mut finality_config = FinalityConfig::default();
        let mut proposals = sccgub_governance::proposals::ProposalRegistry::default();

        // --- Subsequent blocks: full CPoG validation against running state ---
        for (i, block) in blocks.iter().enumerate().skip(1) {
            // 1. Producer signature.
            verify_producer_signature(block).map_err(|e| ImportError::ProducerSignature {
                height: block.header.height,
                reason: e,
            })?;

            // 2. Chain ID consistency.
            if block.header.chain_id != chain_id {
                return Err(ImportError::ChainIdMismatch {
                    height: block.header.height,
                });
            }
            if block.header.version != block_version {
                return Err(ImportError::VersionMismatch {
                    height: block.header.height,
                    expected: block_version,
                    found: block.header.version,
                });
            }

            // 3. CPoG: parent linkage, Mfidel seal, tension, all roots, state replay,
            //    13-phase Phi traversal. This is the integrity gate.
            let parent_id = blocks[i - 1].header.block_id;
            match validate_cpog(block, &state, &parent_id) {
                CpogResult::Valid => {}
                CpogResult::Invalid { errors } => {
                    return Err(ImportError::Cpog {
                        height: block.header.height,
                        errors,
                    });
                }
            }

            // 4. Validate nonces atomically BEFORE mutating balances/state.
            //    If any tx has an invalid nonce the ledger stays untouched.
            state
                .validate_nonces(&block.body.transitions)
                .map_err(|detail| ImportError::NonceViolation {
                    height: block.header.height,
                    detail,
                })?;

            // 5. Apply economics and transitions (safe — nonces already verified).
            let gas_price = EconomicState::default().effective_fee(
                state.state.tension_field.total,
                state.state.tension_field.budget.current_budget,
            );
            sccgub_state::apply::apply_block_economics(
                &mut state,
                &mut balances,
                &mut treasury,
                &block.body.transitions,
                &block.receipts,
                block_version,
                &block.header.validator_id,
                gas_price,
                default_block_reward(),
            )
            .map_err(|detail| ImportError::EconomicsViolation {
                height: block.header.height,
                detail: format!("Economics replay failed: {}", detail),
            })?;
            sccgub_state::apply::apply_block_transitions(
                &mut state,
                &mut balances,
                &block.body.transitions,
            );
            if block.header.height % 100 == 0 {
                treasury.advance_epoch();
                commit_treasury_state(&mut state, &treasury);
            }
            state.set_height(block.header.height);

            // Apply governance activations during replay (restart-safe).
            // from_blocks has no validator_set, so validator changes are no-ops.
            // For ModifyConsensusParam: per FRACTURE-V084-R01 closure, replay
            // MUST apply the mutation to consensus_params (and persist via
            // commit_consensus_params) so the cold-replayed state_root
            // matches the live-head state_root. An earlier draft made this
            // a no-op on the claim that replay reconstructs params from
            // genesis — that was wrong: post-genesis activations MUST apply
            // during replay or state roots diverge.
            let replay_ceilings =
                sccgub_state::constitutional_ceilings_state::constitutional_ceilings_from_trie(
                    &state,
                )
                .ok()
                .flatten();
            let mut replay_mutated_consensus_params = false;
            {
                let state_mut = &mut state;
                let governance_state_mut = &mut state_mut.state.governance_state;
                let consensus_params_mut = &mut state_mut.consensus_params;
                replay_governance_from_transitions(
                    &block.body.transitions,
                    block.header.height,
                    &mut proposals,
                    governance_state_mut,
                    &mut governance_limits,
                    &mut finality_config,
                    &mut |_key, _value| Ok(()), // No validator set in replay context
                    &mut |field, new_value, _activation_height| {
                        let hypothetical = sccgub_types::typed_params::apply_typed_param(
                            consensus_params_mut,
                            field,
                            new_value,
                        )
                        .map_err(|e| format!("replay typed param apply: {}", e))?;
                        if let Some(ref ceilings) = replay_ceilings {
                            ceilings
                                .validate(&hypothetical)
                                .map_err(|e| format!("replay ceiling re-check: {}", e))?;
                        }
                        hypothetical
                            .validate()
                            .map_err(|e| format!("replay in-struct re-check: {}", e))?;
                        *consensus_params_mut = hypothetical;
                        replay_mutated_consensus_params = true;
                        Ok(())
                    },
                );
            }
            if replay_mutated_consensus_params {
                sccgub_state::world::commit_consensus_params(&mut state);
            }
        }

        if let Some(last) = blocks.last() {
            governance_limits = governance_limits_from_snapshot(&last.governance.governance_limits);
            finality_config = finality_config_from_snapshot(&last.governance.finality_config);
        }

        // Rebuild finality tracker.
        let mut finality = FinalityTracker::default();
        if let Some(last) = blocks.last() {
            finality.on_new_block(last.header.height);
            if matches!(
                state.state.governance_state.finality_mode,
                FinalityMode::Deterministic
            ) {
                finality.check_finality(&finality_config, |h| {
                    blocks.get(h as usize).map(|b| b.header.block_id)
                });
            }
        }

        Ok(Chain {
            blocks,
            block_version,
            state,
            mempool: Mempool::new(10_000),
            chain_id,
            validator_key,
            economics: EconomicState::default(),
            balances,
            treasury,
            governance_limits,
            power_tracker: GovernancePowerTracker::default(),
            proposals,
            finality,
            finality_config,
            slashing: SlashingEngine::new(Default::default()),
            equivocation_records: Vec::new(),
            safety_certificates: Vec::new(),
            validator_set: Vec::new(),
            latest_events: sccgub_types::events::BlockEventLog::new(),
            latest_rejected_receipts: Vec::new(),
            responsibility: std::collections::HashMap::new(),
            api_bridge: None,
        })
    }

    /// Reconstruct chain from blocks using a validated snapshot boundary to
    /// reduce replay work on boot.
    pub fn from_blocks_with_snapshot(
        blocks: Vec<Block>,
        snapshot: &crate::persistence::StateSnapshot,
        store: Option<std::sync::Arc<dyn sccgub_state::store::StateStore>>,
    ) -> Result<Self, ImportError> {
        if blocks.is_empty() {
            return Err(ImportError::Empty);
        }

        let snapshot_index =
            usize::try_from(snapshot.height).map_err(|_| ImportError::SnapshotMismatch {
                height: snapshot.height,
                detail: "snapshot height does not fit in usize".into(),
            })?;
        let Some(boundary_block) = blocks.get(snapshot_index) else {
            return Err(ImportError::SnapshotMismatch {
                height: snapshot.height,
                detail: "snapshot height is beyond the block log".into(),
            });
        };

        if boundary_block.header.height != snapshot.height {
            return Err(ImportError::SnapshotMismatch {
                height: snapshot.height,
                detail: format!(
                    "boundary block height mismatch: block log has {}",
                    boundary_block.header.height
                ),
            });
        }
        if snapshot.state_root != boundary_block.header.state_root {
            return Err(ImportError::SnapshotMismatch {
                height: snapshot.height,
                detail: format!(
                    "state root mismatch: snapshot={} block={}",
                    hex::encode(snapshot.state_root),
                    hex::encode(boundary_block.header.state_root)
                ),
            });
        }

        let mut snapshot_balances = BalanceLedger::new();
        for (agent_id, raw_balance) in &snapshot.balances {
            snapshot_balances.import_balance(*agent_id, TensionValue(*raw_balance));
        }
        let snapshot_balance_root = snapshot_balances.balance_root();
        if snapshot_balance_root != boundary_block.header.balance_root {
            return Err(ImportError::SnapshotMismatch {
                height: snapshot.height,
                detail: format!(
                    "balance root mismatch: snapshot={} block={}",
                    hex::encode(snapshot_balance_root),
                    hex::encode(boundary_block.header.balance_root)
                ),
            });
        }

        let mut chain = Self::from_blocks(blocks[..=snapshot_index].to_vec())?;
        match store {
            Some(durable_store) => chain
                .restore_from_snapshot_with_store(snapshot, durable_store)
                .map_err(|detail| ImportError::SnapshotMismatch {
                    height: snapshot.height,
                    detail,
                })?,
            None => chain.restore_from_snapshot(snapshot).map_err(|detail| {
                ImportError::SnapshotMismatch {
                    height: snapshot.height,
                    detail,
                }
            })?,
        }

        for block in blocks.iter().skip(snapshot_index + 1) {
            chain.import_block(block.clone()).map_err(|detail| {
                ImportError::PostSnapshotReplay {
                    height: block.header.height,
                    detail,
                }
            })?;
        }

        Ok(chain)
    }

    /// Set the active validator set (used for proposer rotation).
    pub fn set_validator_set(&mut self, mut validators: Vec<ValidatorAuthority>) {
        validators.sort_by_key(|v| v.node_id);
        self.validator_set = validators;
    }

    /// Attach an API bridge for local event-driven syncs.
    pub fn set_api_bridge(&mut self, bridge: crate::api_bridge::ApiBridge) {
        self.api_bridge = Some(bridge);
    }

    /// Execute a slashing penalty: debit the validator's real balance and burn
    /// the penalty to the treasury. This connects the SlashingEngine's internal
    /// stake tracking to the actual on-chain balance ledger.
    ///
    /// Returns the actual penalty applied (capped at available balance).
    pub fn execute_slashing_penalty(
        &mut self,
        validator_id: &[u8; 32],
        penalty: TensionValue,
    ) -> TensionValue {
        // Debit from real balance (capped at available).
        let available = self.balances.balance_of(validator_id);
        let actual_penalty = if penalty.raw() > available.raw() {
            available
        } else {
            penalty
        };
        if actual_penalty.raw() > 0 {
            if let Err(e) = self.balances.debit(validator_id, actual_penalty) {
                tracing::error!(
                    "Slashing debit failed for {}: {}",
                    hex::encode(validator_id),
                    e
                );
                return TensionValue::ZERO;
            }
            // Burn the slashed amount (removed from circulating supply).
            self.treasury.collect_fee(actual_penalty);
            if let Err(e) = self.treasury.burn(actual_penalty) {
                tracing::error!("Slashing burn failed: {}", e);
            }
        }
        actual_penalty
    }

    /// Maximum retained equivocation records across all epochs.
    ///
    /// N-55: Slashing has already been applied by the time evidence reaches
    /// this ledger, so records are purely an audit trail.  Capping prevents
    /// a crafted-evidence flood from blowing up every snapshot and every
    /// api_bridge sync.
    const MAX_EQUIVOCATION_RECORDS: usize = 8_192;

    /// Record equivocation evidence (deduplicated by proof fields + epoch).
    pub fn record_equivocation(&mut self, proof: EquivocationProof, epoch: u64) {
        let (block_a, block_b) = if proof.block_hash_a <= proof.block_hash_b {
            (proof.block_hash_a, proof.block_hash_b)
        } else {
            (proof.block_hash_b, proof.block_hash_a)
        };
        let duplicate = self
            .equivocation_records
            .iter()
            .any(|(existing, existing_epoch)| {
                *existing_epoch == epoch
                    && existing.validator_id == proof.validator_id
                    && existing.height == proof.height
                    && existing.round == proof.round
                    && existing.vote_type == proof.vote_type
                    && {
                        let (existing_a, existing_b) =
                            if existing.block_hash_a <= existing.block_hash_b {
                                (existing.block_hash_a, existing.block_hash_b)
                            } else {
                                (existing.block_hash_b, existing.block_hash_a)
                            };
                        existing_a == block_a && existing_b == block_b
                    }
            });

        if !duplicate {
            let mut normalized = proof;
            normalized.block_hash_a = block_a;
            normalized.block_hash_b = block_b;
            self.equivocation_records.push((normalized, epoch));
            // N-55: Keep only the most recent MAX_EQUIVOCATION_RECORDS entries
            // across all epochs.  Oldest (earliest-epoch) records are dropped
            // first.  The order of `equivocation_records` is insertion order,
            // which is also roughly epoch order, so truncating the head is a
            // safe FIFO eviction.
            if self.equivocation_records.len() > Self::MAX_EQUIVOCATION_RECORDS {
                let excess = self.equivocation_records.len() - Self::MAX_EQUIVOCATION_RECORDS;
                self.equivocation_records.drain(..excess);
            }
        }
    }

    /// Maximum retained safety certificates.
    ///
    /// N-55: Certificates are only needed for recent finality decisions;
    /// historical certs serve as an audit trail but do not gate consensus.
    /// Without a cap, each finalized block appends one entry indefinitely,
    /// bloating every snapshot and api_bridge sync.
    const MAX_SAFETY_CERTIFICATES: usize = 10_000;

    /// Record a safety certificate (deduplicated by height/block/round).
    pub fn record_safety_certificate(&mut self, cert: SafetyCertificate) {
        let exists = self.safety_certificates.iter().any(|existing| {
            existing.height == cert.height
                && existing.block_hash == cert.block_hash
                && existing.round == cert.round
        });
        if exists {
            return;
        }
        let height = cert.height;
        let block_hash = cert.block_hash;
        self.safety_certificates.push(cert);
        // N-55: Keep only the most recent MAX_SAFETY_CERTIFICATES by height.
        // Sort-by-height then truncate is deterministic; existing semantics
        // (max height → finalized_height) remain intact because we keep the
        // highest-height entries.
        if self.safety_certificates.len() > Self::MAX_SAFETY_CERTIFICATES {
            self.safety_certificates
                .sort_by_key(|c| (c.height, c.round, c.block_hash));
            let excess = self.safety_certificates.len() - Self::MAX_SAFETY_CERTIFICATES;
            self.safety_certificates.drain(..excess);
        }
        if matches!(
            self.state.state.governance_state.finality_mode,
            FinalityMode::BftCertified { .. }
        ) && height > self.finality.finalized_height
        {
            self.finality.finalized_height = height;
            self.latest_events
                .emit(sccgub_types::events::ChainEvent::BlockFinalized {
                    block_height: height,
                    block_hash,
                    finality_class: "bft".into(),
                });
        }
    }

    /// Restore safety certificates from storage without emitting events.
    pub fn restore_safety_certificates(&mut self, certs: Vec<SafetyCertificate>) {
        if certs.is_empty() {
            return;
        }
        let mut seen = BTreeSet::new();
        let mut merged = Vec::new();
        for cert in self.safety_certificates.iter().cloned().chain(certs) {
            let key = (cert.height, cert.round, cert.block_hash);
            if seen.insert(key) {
                merged.push(cert);
            }
        }
        self.safety_certificates = merged;
        if matches!(
            self.state.state.governance_state.finality_mode,
            FinalityMode::BftCertified { .. }
        ) {
            if let Some(max_height) = self.safety_certificates.iter().map(|c| c.height).max() {
                if max_height > self.finality.finalized_height {
                    self.finality.finalized_height = max_height;
                }
            }
        }
    }

    fn sync_api_bridge(&self, pending_txs: Vec<SymbolicTransition>) {
        let Some(bridge) = &self.api_bridge else {
            return;
        };
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if !bridge.should_sync(now_ms()) {
            return;
        }

        let bridge = bridge.clone();
        let blocks = self.blocks.clone();
        let state = self.state.clone();
        let chain_id = self.chain_id;
        let finalized_height = self.finality.finalized_height;
        let slashing_events = self.slashing.events.clone();
        let slashing_stakes: Vec<(Hash, i128)> = self
            .slashing
            .stakes
            .iter()
            .map(|(k, v)| (*k, v.raw()))
            .collect();
        let slashing_removed = self.slashing.removed.clone();
        let equivocation_records = self.equivocation_records.clone();
        let safety_certificates = self.safety_certificates.clone();

        handle.spawn(async move {
            let mut app = bridge.app_state.write().await;
            app.blocks = blocks;
            app.state = state;
            app.chain_id = chain_id;
            app.finalized_height = finalized_height;
            app.slashing_events = slashing_events;
            app.slashing_stakes = slashing_stakes;
            app.slashing_removed = slashing_removed;
            app.equivocation_records = equivocation_records;
            app.safety_certificates = safety_certificates;
            app.pending_txs = pending_txs.clone();
            // N-50: Merge pending tx IDs into seen set (don't replace — that
            // would discard rejection history and re-open replay windows).
            for tx in &pending_txs {
                if app.seen_tx_ids.insert(tx.tx_id) {
                    app.seen_tx_order.push_back(tx.tx_id);
                }
            }
        });
    }

    fn maybe_sync_api_bridge(&self, pending_txs: Vec<SymbolicTransition>) {
        if self.api_bridge.is_some() {
            self.sync_api_bridge(pending_txs);
        }
    }

    fn local_validator_id(&self) -> Hash {
        *self.validator_key.verifying_key().as_bytes()
    }

    /// Check whether this node is the designated proposer for a height.
    pub fn is_proposer_for_height(&self, height: u64) -> bool {
        if self.validator_set.is_empty() {
            return true;
        }
        let proposer =
            sccgub_governance::validator::round_robin_proposer(&self.validator_set, height);
        match proposer {
            Some(authority) => authority.node_id == self.local_validator_id(),
            None => false,
        }
    }

    /// Validate an externally produced block without mutating state.
    ///
    /// `consensus_round` is only available on the live proposal path. Imported
    /// blocks do not currently persist their proposal round in the header, so
    /// replay/import validation can only enforce that the producer belongs to
    /// the active validator set.
    pub fn validate_candidate_block_for_round(
        &self,
        block: &Block,
        consensus_round: Option<u32>,
    ) -> Result<(), String> {
        let parent = self.blocks.last().ok_or("No blocks in chain")?;
        let expected_height = parent.header.height.saturating_add(1);
        if block.header.height != expected_height {
            return Err(format!(
                "Block height mismatch: expected {}, got {}",
                expected_height, block.header.height
            ));
        }
        if block.header.parent_id != parent.header.block_id {
            return Err("Parent hash mismatch".into());
        }
        if block.header.chain_id != self.chain_id {
            return Err("Chain ID mismatch".into());
        }
        // Patch-06 §34.6: INV-UPGRADE-ATOMICITY. If the chain has
        // committed ChainVersionTransition records (i.e., one or more
        // UpgradeProposals have activated), the block's declared version
        // must match the version active at its height per the
        // transition history. For pre-upgrade chains the history is
        // empty and this collapses to the single-version check below.
        let transitions =
            sccgub_state::chain_version_history_state::chain_version_history_from_trie(&self.state)
                .unwrap_or_default();
        if !transitions.is_empty() {
            use sccgub_execution::chain_version_check::{
                verify_block_version_alignment, ChainVersionCheck,
            };
            match verify_block_version_alignment(
                block.header.height,
                block.header.version,
                self.block_version,
                &transitions,
            ) {
                ChainVersionCheck::Aligned => {}
                ChainVersionCheck::Misaligned(rej) => {
                    return Err(format!("Block version out of alignment: {}", rej));
                }
            }
        } else if block.header.version != self.block_version {
            return Err("Block version mismatch".into());
        }
        if !self.validator_set.is_empty() {
            if let Some(round) = consensus_round {
                let expected = sccgub_governance::validator::round_robin_proposer(
                    &self.validator_set,
                    block.header.height.saturating_add(round as u64),
                )
                .ok_or("No active proposer for height")?;
                if expected.node_id != block.header.validator_id {
                    return Err(format!(
                        "Proposer mismatch: expected {}, got {}",
                        hex::encode(expected.node_id),
                        hex::encode(block.header.validator_id)
                    ));
                }
            } else if !self
                .validator_set
                .iter()
                .any(|authority| authority.node_id == block.header.validator_id)
            {
                return Err(format!(
                    "Block proposer not in authorized set: {}",
                    hex::encode(block.header.validator_id)
                ));
            }
        }
        verify_producer_signature(block)?;

        match validate_cpog(block, &self.state, &parent.header.block_id) {
            CpogResult::Valid => Ok(()),
            CpogResult::Invalid { errors } => {
                Err(format!("CPoG validation failed: {}", errors.join("; ")))
            }
        }
    }

    /// Validate a candidate block when the proposal round is not available.
    pub fn validate_candidate_block(&self, block: &Block) -> Result<(), String> {
        self.validate_candidate_block_for_round(block, None)
    }

    /// Import an externally produced block (validated and applied).
    /// Fork choice: should we switch to a competing chain?
    #[allow(dead_code)] // Infrastructure for network fork resolution.
    ///
    /// Patch-06 §32 fork-choice rule: prefer the chain with the highest
    /// score, where
    ///
    /// ```text
    /// score(tip) = (finalized_depth, cumulative_voting_power, tie_break_hash)
    /// ```
    ///
    /// compared lexicographically. Higher wins. The tie-break hash
    /// (tip `block_id` as a big-endian integer) guarantees a total order
    /// so two honest nodes on the same candidate set always agree on the
    /// winner (INV-FORK-CHOICE-DETERMINISM).
    ///
    /// BFT-mode safety: if either chain is in non-deterministic BFT
    /// finality mode and finalized depths are tied, we keep the current
    /// chain. This preserves the pre-Patch-06 incumbency rule as a
    /// belt-and-braces guard against reorg over finalized blocks. A
    /// future commit will replace this with
    /// `sccgub_consensus::fork_choice::is_safe_reorg` once common-
    /// ancestor height is tracked at the Chain level.
    ///
    /// Returns true if `other` should replace the current chain.
    pub fn should_switch_to(&self, other: &Chain) -> bool {
        // Different chain — never switch.
        if other.chain_id != self.chain_id {
            return false;
        }

        // BFT-mode safety valve: both chains in deterministic finality
        // mode, otherwise we defer to the §32 score but skip on ties.
        let both_deterministic = matches!(
            self.state.state.governance_state.finality_mode,
            FinalityMode::Deterministic
        ) && matches!(
            other.state.state.governance_state.finality_mode,
            FinalityMode::Deterministic
        );

        // Build §32 tips. `cumulative_voting_power` is approximated by
        // block height — each committed block represents ≥ ⅔ of active
        // voting power under BFT finality, so height is a faithful
        // proxy for "cumulative signed work" without walking every
        // precommit set. When a more precise accounting is needed, this
        // becomes a per-block counter commit-folded into block.header.
        let self_tip = sccgub_consensus::fork_choice::ChainTip {
            block_id: self
                .blocks
                .last()
                .map(|b| b.header.block_id)
                .unwrap_or(sccgub_types::ZERO_HASH),
            height: self.height(),
            finalized_depth: self.finality.finalized_height,
            cumulative_voting_power: self.height(),
        };
        let other_tip = sccgub_consensus::fork_choice::ChainTip {
            block_id: other
                .blocks
                .last()
                .map(|b| b.header.block_id)
                .unwrap_or(sccgub_types::ZERO_HASH),
            height: other.height(),
            finalized_depth: other.finality.finalized_height,
            cumulative_voting_power: other.height(),
        };

        use std::cmp::Ordering;
        match other_tip.score_cmp(&self_tip) {
            Ordering::Greater => {
                // §32.3 safety: in BFT mode never reorg once finality is
                // tied, preserving the pre-Patch-06 incumbency rule.
                if !both_deterministic && self_tip.finalized_depth == other_tip.finalized_depth {
                    return false;
                }
                true
            }
            Ordering::Equal | Ordering::Less => false,
        }
    }

    pub fn import_block(&mut self, block: Block) -> Result<(), String> {
        self.validate_candidate_block(&block)?;

        // Validate nonces atomically BEFORE mutating balances/state.
        // If any tx has an invalid nonce the ledger stays untouched.
        self.state
            .validate_nonces(&block.body.transitions)
            .map_err(|e| format!("Nonce violation: {}", e))?;

        let gas_price = self.economics.effective_fee(
            self.state.state.tension_field.total,
            self.state.state.tension_field.budget.current_budget,
        );
        sccgub_state::apply::apply_block_economics(
            &mut self.state,
            &mut self.balances,
            &mut self.treasury,
            &block.body.transitions,
            &block.receipts,
            self.block_version,
            &block.header.validator_id,
            gas_price,
            default_block_reward(),
        )
        .map_err(|e| format!("Economics replay failed: {}", e))?;
        sccgub_state::apply::apply_block_transitions(
            &mut self.state,
            &mut self.balances,
            &block.body.transitions,
        );
        if block.header.height.is_multiple_of(100) {
            self.treasury.advance_epoch();
            commit_treasury_state(&mut self.state, &self.treasury);
        }
        // Patch-05 §20: for v4 blocks, record the post-apply tension in
        // the rolling history buffer so the next block's median fee
        // oracle can consult the last W samples. Non-fatal: if storage
        // write fails, the block is still committed (subsequent v4
        // blocks would then fall back to the warming-window shorter
        // slice, at worst charging base_fee until the buffer refills).
        if block.header.version >= sccgub_types::block::PATCH_05_BLOCK_VERSION {
            if let Err(e) = sccgub_state::tension_history::append_and_trim(
                &mut self.state,
                block.header.tension_after,
            ) {
                tracing::warn!(
                    "tension_history append failed at height {}: {}",
                    block.header.height,
                    e
                );
            }
        }
        self.state.set_height(block.header.height);

        // Mark included tx IDs as confirmed in mempool.
        let confirmed: Vec<_> = block.body.transitions.iter().map(|tx| tx.tx_id).collect();
        self.mempool.mark_confirmed(&confirmed);

        // Record proposer for anti-concentration tracking.
        self.power_tracker
            .record_proposal(&block.header.validator_id);
        if block.header.height.is_multiple_of(100) {
            self.power_tracker.reset_epoch();
            self.economics.reset_epoch();
        }

        // Update finality tracker.
        self.finality.on_new_block(block.header.height);
        if matches!(
            self.state.state.governance_state.finality_mode,
            FinalityMode::Deterministic
        ) {
            let blocks_ref = &self.blocks;
            self.finality.check_finality(&self.finality_config, |h| {
                blocks_ref.get(h as usize).map(|b| b.header.block_id)
            });
        }

        // Record validator presence (resets absence counter).
        self.slashing.record_presence(&block.header.validator_id);

        // E-2: Replay governance transitions (proposals, votes, activation).
        // This must match the governance replay in produce_block and from_blocks.
        let height = block.header.height;
        self.replay_governance_transitions(&block.body.transitions, height);

        self.blocks.push(block);
        self.maybe_sync_api_bridge(self.mempool.pending_snapshot());
        Ok(())
    }

    /// Replay governance side-effects from block transitions.
    /// Called by produce_block, import_block, and from_blocks.
    fn replay_governance_transitions(
        &mut self,
        transitions: &[sccgub_types::transition::SymbolicTransition],
        height: u64,
    ) {
        // PATCH_10 §25.4 INV-TYPED-PARAM-CEILING second half: read ceilings
        // as-of activation height (they are genesis-write-once so this is
        // equivalent to submission-time ceilings, but we snapshot explicitly
        // for spec fidelity — if a future hard-fork changes ceilings, this
        // path re-validates correctly).
        let ceilings_snapshot =
            sccgub_state::constitutional_ceilings_state::constitutional_ceilings_from_trie(
                &self.state,
            )
            .ok()
            .flatten();

        // FRACTURE-V084-R01 persistence flag: set by the closure on
        // successful consensus_params mutation. Read after the
        // split-borrow scope ends so we can re-borrow `&mut self.state`
        // for the trie commit.
        let mut mutated_consensus_params = false;

        // Split disjoint mutable borrows: ManagedWorldState has disjoint fields
        // `state` (the WorldState containing governance_state) and
        // `consensus_params`. The compiler permits splitting them into two
        // non-overlapping mutable references.
        {
            let state_mut = &mut self.state;
            let governance_state_mut = &mut state_mut.state.governance_state;
            let consensus_params_mut = &mut state_mut.consensus_params;
            let vs = &mut self.validator_set;

            replay_governance_from_transitions(
                transitions,
                height,
                &mut self.proposals,
                governance_state_mut,
                &mut self.governance_limits,
                &mut self.finality_config,
                &mut |key, value| apply_validator_change(vs, key, value),
                &mut |field, new_value, _activation_height| {
                    // Re-validate against the ceilings as-of activation height.
                    let hypothetical = sccgub_types::typed_params::apply_typed_param(
                        consensus_params_mut,
                        field,
                        new_value,
                    )
                    .map_err(|e| format!("live typed param apply: {}", e))?;
                    if let Some(ref ceilings) = ceilings_snapshot {
                        ceilings
                            .validate(&hypothetical)
                            .map_err(|e| format!("live ceiling re-check: {}", e))?;
                    }
                    // In-struct bounds re-check (catches confirmation_depth == 0, etc.).
                    hypothetical
                        .validate()
                        .map_err(|e| format!("live in-struct re-check: {}", e))?;
                    // All re-validations passed; commit the mutation to live state.
                    *consensus_params_mut = hypothetical;
                    mutated_consensus_params = true;
                    Ok(())
                },
            );
        } // Drop split borrows of self.state here so we can re-borrow below.

        // FRACTURE-V084-R01 closure: persist the in-memory mutation to the
        // state trie under ConsensusParams::TRIE_KEY. Without this, the
        // post-activation state_root does not reflect the new params,
        // breaking block-producer/validator determinism and cold-replay
        // convergence. Idempotent when nothing mutated (guarded by flag).
        if mutated_consensus_params {
            sccgub_state::world::commit_consensus_params(&mut self.state);
        }
    }

    /// Submit a transition to the mempool.
    /// Returns Err if the agent is quarantined or the tx is a duplicate.
    pub fn submit_transition(&mut self, tx: SymbolicTransition) -> Result<(), String> {
        self.mempool.add(tx)?;
        self.maybe_sync_api_bridge(self.mempool.pending_snapshot());
        Ok(())
    }

    /// Build a candidate block without mutating the live chain state.
    /// Used by the p2p proposer loop to avoid committing pre-consensus.
    pub fn build_candidate_block(&self) -> Result<Block, String> {
        let mut scratch = self.clone();
        let block = scratch.produce_block()?.clone();
        Ok(block)
    }

    /// Build a candidate block without the proposer check.
    /// Used by tests and the network layer when the actual proposer
    /// may differ from the local validator (multi-validator mode).
    #[allow(dead_code)]
    pub fn build_candidate_block_unchecked(&self) -> Result<Block, String> {
        let mut scratch = self.clone();
        // Temporarily clear the validator set so produce_block
        // skips the proposer check (single-validator fallback).
        let saved = std::mem::take(&mut scratch.validator_set);
        let block = scratch.produce_block()?.clone();
        // Validator set is on the scratch copy, no need to restore.
        let _ = saved;
        Ok(block)
    }

    /// Produce a new block from mempool transactions.
    /// Speculatively applies state to compute post-transition state root.
    /// Enforces anti-concentration limits on consecutive proposals.
    pub fn produce_block(&mut self) -> Result<&Block, String> {
        let parent = self.blocks.last().ok_or("No blocks in chain")?;
        let parent_id = parent.header.block_id;
        let height = parent.header.height.saturating_add(1);

        // Anti-concentration: check consecutive proposal limit.
        // validator_id = public_key directly (Position A).
        let validator_id_for_check: [u8; 32] = *self.validator_key.verifying_key().as_bytes();
        if !self.is_proposer_for_height(height) {
            return Err(format!(
                "Not proposer for height {} (validator {})",
                height,
                hex::encode(validator_id_for_check)
            ));
        }
        if let Err(e) = self
            .power_tracker
            .check_proposal(&validator_id_for_check, &self.governance_limits)
        {
            return Err(format!("Anti-concentration: {}", e));
        }

        // Collect validated transitions from mempool.
        let transitions = self.mempool.drain_validated(&self.state);

        // Gas-metered admission: validate each tx with gas accounting,
        // enforce per-block gas limit, and reject txs that cannot pay their
        // fee plus payload effects against the evolving in-block balance view.
        let mut block_gas = BlockGasMeter::new(self.state.consensus_params.default_block_gas_limit);
        let mut filter_state = self.state.clone();
        let mut filter_balances = self.balances.clone();
        let mut accepted_transitions = Vec::new();
        let mut metered_receipts = Vec::new();
        let mut rejected_receipts = Vec::new();

        let prior_tension = self
            .blocks
            .last()
            .map(|b| b.header.tension_after)
            .unwrap_or(TensionValue::ZERO);
        let budget = self.state.state.tension_field.budget.current_budget;
        let gas_price = self.economics.effective_fee(prior_tension, budget);

        for tx in transitions {
            // Pre-filter: nonce must be valid (READ-ONLY check).
            {
                let last = filter_state
                    .agent_nonces
                    .get(&tx.actor.agent_id)
                    .copied()
                    .unwrap_or(0);
                let expected = last.checked_add(1);
                if tx.nonce == 0 || (expected != Some(tx.nonce)) {
                    // N-17: produce reject receipt instead of silent continue.
                    rejected_receipts.push(make_prefilter_reject_receipt(
                        &tx,
                        self.state.state_root(),
                        &format!(
                            "Nonce sequence violation: got {} for agent {}",
                            tx.nonce,
                            hex::encode(tx.actor.agent_id)
                        ),
                    ));
                    continue;
                }
            }

            // Gas-metered validation — produces a typed receipt for every tx.
            let (receipt, gas_used) = validate_transition_metered(
                &tx,
                &filter_state,
                filter_state.consensus_params.default_tx_gas_limit,
            );

            // Only include if the block gas limit allows it.
            if !block_gas.can_fit(gas_used) {
                break; // Block is full.
            }

            if receipt.verdict.is_accepted() {
                let fee = TensionValue((gas_used as i128).saturating_mul(gas_price.raw()));
                let fee_payer = match sccgub_state::apply::resolve_fee_payer(
                    self.block_version,
                    &filter_balances,
                    &tx,
                    fee,
                ) {
                    Ok(payer) => payer,
                    Err(e) => {
                        rejected_receipts.push(make_metered_reject_receipt(
                            receipt,
                            &format!("Fee solvency check failed: {}", e),
                        ));
                        continue;
                    }
                };

                let mut post_tx_balances = filter_balances.clone();
                if fee.raw() > 0 {
                    if let Err(e) = post_tx_balances.debit(&fee_payer, fee) {
                        rejected_receipts.push(make_metered_reject_receipt(
                            receipt,
                            &format!("Fee debit failed: {}", e),
                        ));
                        continue;
                    }
                }

                if let sccgub_types::transition::OperationPayload::AssetTransfer {
                    from,
                    to,
                    amount,
                } = &tx.payload
                {
                    if let Err(e) = post_tx_balances.transfer(from, to, TensionValue(*amount)) {
                        rejected_receipts.push(make_metered_reject_receipt(
                            receipt,
                            &format!("Transfer solvency check failed: {}", e),
                        ));
                        continue;
                    }
                }

                block_gas.record_tx(gas_used);
                filter_balances = post_tx_balances;
                if let Err(e) = filter_state.check_nonce(&tx.actor.agent_id, tx.nonce) {
                    // E-4: nonce drift is a consensus invariant violation.
                    // Reject the tx instead of silently accepting.
                    tracing::error!("Nonce filter drift during block production: {}", e);
                    rejected_receipts.push(make_prefilter_reject_receipt(
                        &tx,
                        self.state.state_root(),
                        &format!("Nonce drift: {}", e),
                    ));
                    continue;
                }

                accepted_transitions.push(tx);
                metered_receipts.push(receipt);
            } else {
                // Rejected txs get receipts too — on-chain evidence of consideration.
                // Users can query the receipt to see why their tx was rejected.
                rejected_receipts.push(receipt);
            }
        }
        let transitions = accepted_transitions;

        let mut speculative_state = self.state.clone();
        let mut speculative_balances = self.balances.clone();
        let mut speculative_treasury = self.treasury.clone();

        // Defense-in-depth: validate nonces atomically BEFORE mutating the
        // speculative state. The pre-filter loop above should have caught any
        // nonce drift, so a failure here is an invariant violation — but we
        // still want to avoid leaving a half-mutated speculative ledger if it
        // ever fires.
        if let Err(e) = speculative_state.validate_nonces(&transitions) {
            tracing::error!("Nonce invariant violation in block production: {}", e);
        }

        let economics_outcome = sccgub_state::apply::apply_block_economics(
            &mut speculative_state,
            &mut speculative_balances,
            &mut speculative_treasury,
            &transitions,
            &metered_receipts,
            self.block_version,
            &validator_id_for_check,
            gas_price,
            default_block_reward(),
        )
        .map_err(|e| format!("Economics invariant violation: {}", e))?;
        let per_tx_deltas = sccgub_state::apply::apply_block_transitions(
            &mut speculative_state,
            &mut speculative_balances,
            &transitions,
        );
        if height % 100 == 0 {
            speculative_treasury.advance_epoch();
            commit_treasury_state(&mut speculative_state, &speculative_treasury);
        }
        speculative_state.set_height(height);

        // N-9: wire per-tx deltas into receipt what_actual before sealing.
        let actual_deltas = sccgub_state::apply::combine_receipt_deltas(
            &economics_outcome.tx_deltas,
            &per_tx_deltas,
        )
        .map_err(|e| format!("Receipt delta merge failed: {}", e))?;
        for (receipt, delta) in metered_receipts.iter_mut().zip(actual_deltas.iter()) {
            receipt.wh_binding.what_actual = delta.clone();
        }

        // Seal receipts with the post-apply state root (atomic finalization).
        // This is the ONLY place where post_state_root is set — after state is committed.
        // Sealing failure is an invariant violation: accepted receipts must always be
        // sealable. Propagate the error rather than producing a block with unsealed receipts.
        let post_root = speculative_state.state_root();
        for receipt in &mut metered_receipts {
            sccgub_execution::validate::seal_receipt_post_state(receipt, post_root).map_err(
                |e| {
                    format!(
                        "Invariant: failed to seal receipt {}: {}",
                        hex::encode(receipt.tx_id),
                        e
                    )
                },
            )?;
        }

        // Use same canonical derivation as validator_id_for_check (line 178).
        let validator_id = validator_id_for_check;

        // Compute balance root via canonical BalanceLedger method.
        let balance_root = speculative_balances.balance_root();

        let block = build_block(BlockBuildParams {
            chain_id: self.chain_id,
            height,
            parent_id,
            parent_timestamp: &parent.header.timestamp,
            validator_id,
            version: self.block_version,
            validator_key: &self.validator_key,
            transitions,
            receipts: metered_receipts,
            state: &speculative_state,
            balance_root,
            governance_limits: governance_limits_snapshot_from(&self.governance_limits),
            finality_config: finality_config_snapshot_from(&self.finality_config),
        });

        // Validate via CPoG against pre-transition state (governance checks).
        let result = validate_cpog(&block, &self.state, &parent_id);
        match result {
            CpogResult::Valid => {
                // Mark included tx IDs as confirmed in mempool.
                let confirmed: Vec<_> = block.body.transitions.iter().map(|tx| tx.tx_id).collect();
                self.mempool.mark_confirmed(&confirmed);

                // Tick containment counters (quarantine decay).
                self.mempool.containment.tick_block();

                // Record proposal for anti-concentration tracking.
                self.power_tracker.record_proposal(&validator_id_for_check);

                // Commit speculative state, balances, and treasury.
                self.state = speculative_state;
                self.balances = speculative_balances;
                self.treasury = speculative_treasury;
                self.economics.record_fee(economics_outcome.total_fees);
                self.economics
                    .distribute_reward(economics_outcome.actual_reward);

                self.blocks.push(block);
                let tip_idx = self.blocks.len() - 1;
                self.maybe_sync_api_bridge(self.mempool.pending_snapshot());

                // Apply governance transitions via shared method (single source of truth).
                {
                    let txs: Vec<_> = self.blocks[tip_idx].body.transitions.clone();
                    self.replay_governance_transitions(&txs, height);
                }

                // N-7: Record governance actions for anti-concentration tracking.
                for tx in &self.blocks[tip_idx].body.transitions {
                    if matches!(
                        tx.intent.kind,
                        sccgub_types::transition::TransitionKind::GovernanceUpdate
                            | sccgub_types::transition::TransitionKind::NormProposal
                            | sccgub_types::transition::TransitionKind::ConstraintAddition
                    ) {
                        self.power_tracker.record_action(&tx.actor.agent_id);
                    }
                }
                // Reset epoch counters every 100 blocks.
                if height % 100 == 0 {
                    self.power_tracker.reset_epoch();
                    self.economics.reset_epoch();
                }

                // Update finality tracker.
                let prev_finalized_height = self.finality.finalized_height;
                self.finality.on_new_block(height);
                if matches!(
                    self.state.state.governance_state.finality_mode,
                    FinalityMode::Deterministic
                ) {
                    let blocks_ref = &self.blocks;
                    let _new_finals = self.finality.check_finality(&self.finality_config, |h| {
                        blocks_ref.get(h as usize).map(|b| b.header.block_id)
                    });
                }

                // Record validator presence (resets absence counter).
                self.slashing.record_presence(&validator_id_for_check);

                // Emit chain events for this block.
                let mut events = sccgub_types::events::BlockEventLog::new();

                // Emit events for each accepted transition.
                for tx in &self.blocks[tip_idx].body.transitions {
                    match &tx.payload {
                        sccgub_types::transition::OperationPayload::Write { key, .. } => {
                            events.emit(sccgub_types::events::ChainEvent::StateWrite {
                                tx_id: tx.tx_id,
                                key: key.clone(),
                                actor: tx.actor.agent_id,
                            });
                        }
                        sccgub_types::transition::OperationPayload::AssetTransfer {
                            from,
                            to,
                            amount,
                        } => {
                            events.emit(sccgub_types::events::ChainEvent::Transfer {
                                tx_id: tx.tx_id,
                                from: *from,
                                to: *to,
                                amount: TensionValue(*amount),
                                purpose: tx.intent.declared_purpose.clone(),
                            });
                        }
                        _ => {}
                    }
                }

                // Emit fee and reward events.
                for ((tx, receipt), (payer, fee)) in self.blocks[tip_idx]
                    .body
                    .transitions
                    .iter()
                    .zip(self.blocks[tip_idx].receipts.iter())
                    .zip(
                        economics_outcome
                            .tx_fee_payers
                            .iter()
                            .zip(economics_outcome.tx_fees.iter()),
                    )
                {
                    if fee.raw() <= 0 {
                        continue;
                    }
                    events.emit(sccgub_types::events::ChainEvent::FeeCharged {
                        tx_id: tx.tx_id,
                        payer: *payer,
                        amount: *fee,
                        gas_used: receipt.resource_used.compute_steps,
                    });
                }
                if economics_outcome.actual_reward.raw() > 0 {
                    events.emit(sccgub_types::events::ChainEvent::RewardDistributed {
                        block_height: height,
                        validator: validator_id_for_check,
                        amount: economics_outcome.actual_reward,
                    });
                }

                // B-8: Only emit finality event when finalized height actually advances.
                if self.finality.finalized_height > prev_finalized_height {
                    events.emit(sccgub_types::events::ChainEvent::BlockFinalized {
                        block_height: self.finality.finalized_height,
                        block_hash: self
                            .blocks
                            .get(self.finality.finalized_height as usize)
                            .map(|b| b.header.block_id)
                            .unwrap_or([0u8; 32]),
                        finality_class: "economic".into(),
                    });
                }

                self.latest_events = events;
                self.latest_rejected_receipts = rejected_receipts;

                // N-6: Responsibility tracking — record contributions
                // for each accepted transition in this block.
                for tx in &self.blocks[tip_idx].body.transitions {
                    let agent_resp = self.responsibility.entry(tx.actor.agent_id).or_default();
                    sccgub_governance::responsibility::record_positive(
                        agent_resp,
                        tx.tx_id,
                        TensionValue::from_integer(1),
                        height,
                    );
                }
                // Apply temporal decay on all tracked agents at block boundary.
                for resp in self.responsibility.values_mut() {
                    sccgub_governance::responsibility::apply_decay(resp, height);
                }

                Ok(&self.blocks[tip_idx])
            }
            CpogResult::Invalid { errors } => {
                Err(format!("CPoG validation failed: {}", errors.join("; ")))
            }
        }
    }

    /// Set the validator key (e.g., loaded from disk).
    pub fn set_validator_key(&mut self, key: ed25519_dalek::SigningKey) {
        self.validator_key = key;
    }

    /// Get the last finalized block height.
    #[allow(dead_code)]
    pub fn finalized_height(&self) -> u64 {
        self.finality.finalized_height
    }

    /// Get the finality gap (blocks between tip and last finalized).
    #[allow(dead_code)]
    pub fn finality_gap(&self) -> u64 {
        self.finality.finality_gap()
    }

    /// Create a state snapshot at the current height.
    /// Captures all consensus-critical state including treasury and finality.
    pub fn create_snapshot(&self) -> crate::persistence::StateSnapshot {
        crate::persistence::StateSnapshot {
            height: self.state.state.height,
            state_root: self.state.state_root(),
            trie_entries: self
                .state
                .trie
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            agent_nonces: self
                .state
                .agent_nonces
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            balances: self
                .balances
                .balances
                .iter()
                .map(|(k, v)| (*k, v.raw()))
                .collect(),
            treasury_pending_raw: self.treasury.pending_fees.raw(),
            treasury_collected_raw: self.treasury.total_fees_collected.raw(),
            treasury_distributed_raw: self.treasury.total_rewards_distributed.raw(),
            treasury_burned_raw: self.treasury.total_burned.raw(),
            treasury_epoch: self.treasury.epoch,
            finalized_height: self.finality.finalized_height,
            slashing_events: self.slashing.events.clone(),
            slashing_stakes: self
                .slashing
                .stakes
                .iter()
                .map(|(k, v)| (*k, v.raw()))
                .collect(),
            slashing_removed: self.slashing.removed.clone(),
            slashing_absence: self
                .slashing
                .absence_counter
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect(),
            equivocation_records: self.equivocation_records.clone(),
            safety_certificates: self.safety_certificates.clone(),
            validator_set: self.validator_set.clone(),
            governance_limits: self.governance_limits.clone(),
            finality_config: self.finality_config.clone(),
            finality_mode: self.state.state.governance_state.finality_mode,
            proposals: self.proposals.proposals.clone(),
        }
    }

    /// Restore chain state from a snapshot (fast load — no block replay needed).
    ///
    /// N-53: After rebuilding the trie from `snapshot.trie_entries`, the
    /// re-computed trie root is verified against `snapshot.state_root`.  A
    /// tampered snapshot file with mutated entries but unchanged root field
    /// would otherwise silently produce a forked post-state.
    pub fn restore_from_snapshot(
        &mut self,
        snapshot: &crate::persistence::StateSnapshot,
    ) -> Result<(), String> {
        // Clear and rebuild trie.
        self.state = ManagedWorldState::new();
        self.state.state.governance_state = GovernanceState {
            finality_mode: snapshot.finality_mode,
            ..GovernanceState::default()
        };
        for (key, value) in &snapshot.trie_entries {
            self.state.trie.insert(key.clone(), value.clone());
        }

        // N-53: Verify the re-computed trie root matches the snapshot's
        // self-reported root before trusting any derived state.  This defeats
        // snapshot-tampering attacks where an attacker mutates `trie_entries`
        // while leaving `state_root` unchanged.
        let computed_root = self.state.trie.root();
        if computed_root != snapshot.state_root {
            return Err(format!(
                "Snapshot trie root mismatch: recomputed {} vs snapshot-reported {}",
                hex::encode(computed_root),
                hex::encode(snapshot.state_root)
            ));
        }

        self.state.consensus_params = consensus_params_from_trie(&self.state)
            .unwrap_or(None)
            .unwrap_or_default();
        for (agent_id, nonce) in &snapshot.agent_nonces {
            self.state.agent_nonces.insert(*agent_id, *nonce);
        }
        self.state.set_height(snapshot.height);

        // Restore balances.
        self.balances = BalanceLedger::new();
        for (agent_id, raw_balance) in &snapshot.balances {
            self.balances
                .import_balance(*agent_id, TensionValue(*raw_balance));
        }

        // Restore treasury from the trie when available, with snapshot-field
        // fallback for older snapshots created before treasury keys were committed.
        self.treasury = treasury_from_trie(&self.state).unwrap_or(Treasury {
            pending_fees: TensionValue(snapshot.treasury_pending_raw),
            total_fees_collected: TensionValue(snapshot.treasury_collected_raw),
            total_rewards_distributed: TensionValue(snapshot.treasury_distributed_raw),
            total_burned: TensionValue(snapshot.treasury_burned_raw),
            epoch: snapshot.treasury_epoch,
            epoch_fees: TensionValue::ZERO,
            epoch_rewards: TensionValue::ZERO,
        });

        // Restore finality.
        self.finality = FinalityTracker::default();
        self.finality.on_new_block(snapshot.height);
        self.finality.finalized_height = snapshot.finalized_height;

        // Restore slashing state.
        let mut slashing = SlashingEngine::new(Default::default());
        for (validator, raw_stake) in &snapshot.slashing_stakes {
            slashing.set_stake(*validator, TensionValue(*raw_stake));
        }
        slashing.events = snapshot.slashing_events.clone();
        slashing.removed = snapshot.slashing_removed.clone();
        slashing.absence_counter = snapshot
            .slashing_absence
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect();
        self.slashing = slashing;
        self.equivocation_records = snapshot.equivocation_records.clone();
        self.safety_certificates = snapshot.safety_certificates.clone();
        self.validator_set = snapshot.validator_set.clone();
        self.governance_limits = snapshot.governance_limits.clone();
        self.finality_config = snapshot.finality_config.clone();
        // E-3: Restore in-flight governance proposals from snapshot.
        self.proposals.proposals = snapshot.proposals.clone();
        Ok(())
    }

    pub fn restore_from_snapshot_with_store(
        &mut self,
        snapshot: &crate::persistence::StateSnapshot,
        store: std::sync::Arc<dyn sccgub_state::store::StateStore>,
    ) -> Result<(), String> {
        self.restore_from_snapshot(snapshot)?;
        self.state.bind_store(store)
    }

    /// Get the latest block.
    pub fn latest_block(&self) -> Option<&Block> {
        self.blocks.last()
    }

    /// Get block by height.
    #[allow(dead_code)]
    pub fn block_at(&self, height: u64) -> Option<&Block> {
        self.blocks.get(height as usize)
    }

    /// Chain height.
    pub fn height(&self) -> u64 {
        self.blocks.last().map_or(0, |b| b.header.height)
    }
}

fn apply_validator_change(
    validator_set: &mut Vec<sccgub_types::agent::ValidatorAuthority>,
    key: &str,
    value: &str,
) -> Result<(), String> {
    if key == "validators.add" {
        let pk_hex = value.trim();
        let pk_bytes =
            hex::decode(pk_hex).map_err(|e| format!("Invalid validator pubkey hex: {}", e))?;
        if pk_bytes.len() != 32 {
            return Err("Validator pubkey must be 32 bytes".into());
        }
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&pk_bytes);
        if !validator_set.iter().any(|v| v.node_id == node_id) {
            validator_set.push(sccgub_types::agent::ValidatorAuthority {
                node_id,
                governance_level: sccgub_types::governance::PrecedenceLevel::Meaning,
                norm_compliance: sccgub_types::tension::TensionValue::from_integer(1),
                causal_reliability: sccgub_types::tension::TensionValue::from_integer(1),
                active: true,
            });
            validator_set.sort_by_key(|v| v.node_id);
            tracing::info!("Governance: added validator {}", pk_hex);
        }
        return Ok(());
    }
    if key == "validators.remove" {
        let pk_hex = value.trim();
        let pk_bytes =
            hex::decode(pk_hex).map_err(|e| format!("Invalid validator pubkey hex: {}", e))?;
        if pk_bytes.len() != 32 {
            return Err("Validator pubkey must be 32 bytes".into());
        }
        let mut node_id = [0u8; 32];
        node_id.copy_from_slice(&pk_bytes);
        let before = validator_set.len();
        validator_set.retain(|v| v.node_id != node_id);
        if validator_set.len() < before {
            tracing::info!("Governance: removed validator {}", pk_hex);
        }
        return Ok(());
    }
    Err(format!("Unknown validator change key: {}", key))
}

fn governance_limits_snapshot_from(limits: &GovernanceLimits) -> GovernanceLimitsSnapshot {
    GovernanceLimitsSnapshot {
        max_actions_per_agent_pct: limits.max_actions_per_agent_pct,
        safety_change_min_signers: limits.safety_change_min_signers,
        genesis_change_min_signers: limits.genesis_change_min_signers,
        max_consecutive_proposals: limits.max_consecutive_proposals,
        max_authority_term_epochs: limits.max_authority_term_epochs,
        authority_cooldown_epochs: limits.authority_cooldown_epochs,
    }
}

fn finality_config_snapshot_from(config: &FinalityConfig) -> FinalityConfigSnapshot {
    FinalityConfigSnapshot {
        confirmation_depth: config.confirmation_depth,
        max_finality_ms: config.max_finality_ms,
        target_block_time_ms: config.target_block_time_ms,
    }
}

fn governance_limits_from_snapshot(snapshot: &GovernanceLimitsSnapshot) -> GovernanceLimits {
    GovernanceLimits {
        max_actions_per_agent_pct: snapshot.max_actions_per_agent_pct,
        safety_change_min_signers: snapshot.safety_change_min_signers,
        genesis_change_min_signers: snapshot.genesis_change_min_signers,
        max_consecutive_proposals: snapshot.max_consecutive_proposals,
        max_authority_term_epochs: snapshot.max_authority_term_epochs,
        authority_cooldown_epochs: snapshot.authority_cooldown_epochs,
    }
}

fn finality_config_from_snapshot(snapshot: &FinalityConfigSnapshot) -> FinalityConfig {
    FinalityConfig {
        confirmation_depth: snapshot.confirmation_depth,
        max_finality_ms: snapshot.max_finality_ms,
        target_block_time_ms: snapshot.target_block_time_ms,
    }
}

fn apply_governance_parameter_static(
    governance_limits: &mut GovernanceLimits,
    finality_config: &mut FinalityConfig,
    finality_mode: &mut FinalityMode,
    key: &str,
    value: &str,
) -> Result<(), String> {
    match key {
        "governance.max_consecutive_proposals" => {
            let parsed = value
                .parse::<u32>()
                .map_err(|_| "max_consecutive_proposals must be u32".to_string())?;
            if parsed == 0 {
                return Err("max_consecutive_proposals must be >= 1".into());
            }
            governance_limits.max_consecutive_proposals = parsed;
            Ok(())
        }
        "governance.max_actions_per_agent_pct" => {
            let parsed = value
                .parse::<u32>()
                .map_err(|_| "max_actions_per_agent_pct must be u32".to_string())?;
            if !(1..=100).contains(&parsed) {
                return Err("max_actions_per_agent_pct must be 1..=100".into());
            }
            governance_limits.max_actions_per_agent_pct = parsed;
            Ok(())
        }
        "governance.safety_change_min_signers" => {
            let parsed = value
                .parse::<u32>()
                .map_err(|_| "safety_change_min_signers must be u32".to_string())?;
            if parsed == 0 {
                return Err("safety_change_min_signers must be >= 1".into());
            }
            governance_limits.safety_change_min_signers = parsed;
            Ok(())
        }
        "governance.genesis_change_min_signers" => {
            let parsed = value
                .parse::<u32>()
                .map_err(|_| "genesis_change_min_signers must be u32".to_string())?;
            if parsed == 0 {
                return Err("genesis_change_min_signers must be >= 1".into());
            }
            governance_limits.genesis_change_min_signers = parsed;
            Ok(())
        }
        "governance.max_authority_term_epochs" => {
            let parsed = value
                .parse::<u64>()
                .map_err(|_| "max_authority_term_epochs must be u64".to_string())?;
            if parsed == 0 {
                return Err("max_authority_term_epochs must be >= 1".into());
            }
            governance_limits.max_authority_term_epochs = parsed;
            Ok(())
        }
        "governance.authority_cooldown_epochs" => {
            let parsed = value
                .parse::<u64>()
                .map_err(|_| "authority_cooldown_epochs must be u64".to_string())?;
            if parsed > 1_000 {
                return Err("authority_cooldown_epochs must be <= 1000".into());
            }
            governance_limits.authority_cooldown_epochs = parsed;
            Ok(())
        }
        "finality.confirmation_depth" => {
            let parsed = value
                .parse::<u64>()
                .map_err(|_| "confirmation_depth must be u64".to_string())?;
            if parsed == 0 {
                return Err("confirmation_depth must be >= 1".into());
            }
            finality_config.confirmation_depth = parsed;
            Ok(())
        }
        "finality.max_finality_ms" => {
            let parsed = value
                .parse::<u64>()
                .map_err(|_| "max_finality_ms must be u64".to_string())?;
            if parsed == 0 || parsed > 300_000 {
                return Err("max_finality_ms must be 1..300000".into());
            }
            finality_config.max_finality_ms = parsed;
            Ok(())
        }
        "finality.target_block_time_ms" => {
            let parsed = value
                .parse::<u64>()
                .map_err(|_| "target_block_time_ms must be u64".to_string())?;
            if parsed == 0 {
                return Err("target_block_time_ms must be >= 1".into());
            }
            finality_config.target_block_time_ms = parsed;
            Ok(())
        }
        "finality.mode" => {
            *finality_mode = parse_finality_mode(value)?;
            Ok(())
        }
        _ => Err(format!("Unknown governance parameter key: {}", key)),
    }
}

pub fn parse_finality_mode(value: &str) -> Result<FinalityMode, String> {
    let trimmed = value.trim().to_ascii_lowercase();
    if trimmed == "deterministic" {
        return Ok(FinalityMode::Deterministic);
    }
    if let Some(quorum) = trimmed.strip_prefix("bft:") {
        let parsed = quorum
            .parse::<u32>()
            .map_err(|_| "finality.mode bft quorum must be u32".to_string())?;
        if parsed == 0 {
            return Err("finality.mode bft quorum must be >= 1".into());
        }
        return Ok(FinalityMode::BftCertified {
            quorum_threshold: parsed,
        });
    }
    Err("finality.mode must be 'deterministic' or 'bft:<quorum>'".into())
}

fn replay_governance_from_transitions<F, G>(
    transitions: &[SymbolicTransition],
    height: u64,
    proposals: &mut sccgub_governance::proposals::ProposalRegistry,
    governance_state: &mut GovernanceState,
    governance_limits: &mut GovernanceLimits,
    finality_config: &mut FinalityConfig,
    apply_validator_change: &mut F,
    apply_consensus_params_change: &mut G,
) where
    F: FnMut(&str, &str) -> Result<(), String>,
    G: FnMut(
        sccgub_types::typed_params::ConsensusParamField,
        sccgub_types::typed_params::ConsensusParamValue,
        u64, // activation_height
    ) -> Result<(), String>,
{
    for tx in transitions {
        if let sccgub_types::transition::OperationPayload::ProposeNorm { name, description } =
            &tx.payload
        {
            if let Err(e) = proposals.submit(
                tx.actor.agent_id,
                tx.actor.governance_level,
                sccgub_governance::proposals::ProposalKind::AddNorm {
                    name: name.clone(),
                    description: description.clone(),
                    initial_fitness: TensionValue::from_integer(5),
                    enforcement_cost: TensionValue::from_integer(1),
                },
                height,
                5,
            ) {
                tracing::warn!("Replay proposal submit failed: {}", e);
            }
        }
        if tx.intent.kind == sccgub_types::transition::TransitionKind::GovernanceUpdate {
            if let sccgub_types::transition::OperationPayload::Write { key, value } = &tx.payload {
                if key.starts_with(b"norms/governance/params/propose") {
                    if let Some((param_key, param_value)) = parse_governance_param_write(value) {
                        if let Err(e) = proposals.submit(
                            tx.actor.agent_id,
                            tx.actor.governance_level,
                            sccgub_governance::proposals::ProposalKind::ModifyParameter {
                                key: param_key,
                                value: param_value,
                            },
                            height,
                            5,
                        ) {
                            tracing::warn!("Replay parameter proposal failed: {}", e);
                        }
                    }
                }
                if key.starts_with(b"governance/proposals/")
                    || key.starts_with(b"norms/governance/proposals/")
                {
                    if let Ok(proposal_id) = <[u8; 32]>::try_from(&value[..]) {
                        if let Err(e) = proposals.vote(
                            &proposal_id,
                            tx.actor.agent_id,
                            tx.actor.governance_level,
                            true,
                            height,
                        ) {
                            tracing::warn!(
                                "Replay governance vote failed for proposal {}: {}",
                                hex::encode(&proposal_id[..4]),
                                e
                            );
                        }
                    }
                }
            }
        }
    }

    let _accepted = proposals.finalize(height);
    for proposal in proposals.proposals.clone() {
        if proposal.status == sccgub_governance::proposals::ProposalStatus::Timelocked
            && height >= proposal.timelock_until
        {
            match proposals.activate(&proposal.id, height) {
                Ok(Some(norm)) => {
                    governance_state.active_norms.insert(norm.id, norm);
                }
                Ok(None) => match proposal.kind {
                    sccgub_governance::proposals::ProposalKind::DeactivateNorm { norm_id } => {
                        if let Some(mut norm) = governance_state.active_norms.get(&norm_id).cloned()
                        {
                            norm.active = false;
                            governance_state.active_norms.insert(norm_id, norm);
                        }
                    }
                    sccgub_governance::proposals::ProposalKind::ModifyParameter {
                        ref key,
                        ref value,
                    } => {
                        if key.starts_with("validators.") {
                            if let Err(e) = apply_validator_change(key, value) {
                                tracing::warn!("Validator parameter update rejected: {}", e);
                            }
                        } else if let Err(e) = apply_governance_parameter_static(
                            governance_limits,
                            finality_config,
                            &mut governance_state.finality_mode,
                            key,
                            value,
                        ) {
                            tracing::warn!("Governance parameter update rejected: {}", e);
                        }
                    }
                    sccgub_governance::proposals::ProposalKind::ActivateEmergency => {
                        governance_state.emergency_mode = true;
                    }
                    sccgub_governance::proposals::ProposalKind::DeactivateEmergency => {
                        governance_state.emergency_mode = false;
                    }
                    sccgub_governance::proposals::ProposalKind::AddNorm { .. } => {}
                    sccgub_governance::proposals::ProposalKind::ModifyConsensusParam {
                        ref field,
                        ref new_value,
                        activation_height,
                    } => {
                        // PATCH_10 §25 + v0.8.4 FRACTURE-V084-01/F-03 closure:
                        // Apply the typed param mutation at timelock expiry.
                        // The caller-supplied closure is responsible for:
                        //   (a) re-validating against ceilings-as-of-activation
                        //       (PATCH_05 §25.4 INV-TYPED-PARAM-CEILING second half)
                        //   (b) mutating live ConsensusParams if re-validation passes
                        // Failure is logged, not panicking — submission-time
                        // validation should have caught all invalid proposals
                        // (FRACTURE-V084-02 closure in submit_typed_consensus_param_proposal),
                        // so a failure here indicates a ceiling change between
                        // submission and activation (extremely rare; requires a
                        // hard-fork between the two events).
                        //
                        // NOTE for v0.8.4 scope: `activation_height` is an
                        // advisory scheduling hint. The mutation currently applies
                        // at `timelock_until` regardless of `activation_height`
                        // value. Strict separation of `timelock_until` from
                        // `activation_height` per §25.3 requires tracking Activated
                        // proposals pending their declared application height;
                        // that refactor is deferred. The validator's
                        // MAX_ACTIVATION_HEIGHT_OFFSET cap still constrains
                        // `activation_height` to a reviewable range.
                        if let Err(e) =
                            apply_consensus_params_change(*field, *new_value, activation_height)
                        {
                            tracing::warn!(
                                "ModifyConsensusParam activation at height {} rejected: {}",
                                height,
                                e
                            );
                        }
                    }
                },
                Err(e) => {
                    tracing::warn!("Proposal activation failed: {}", e);
                }
            }
        }
    }
}

fn parse_governance_param_write(value: &[u8]) -> Option<(String, String)> {
    let decoded = std::str::from_utf8(value).ok()?;
    let mut parts = decoded.splitn(2, '=');
    let key = parts.next()?.trim();
    let value = parts.next()?.trim();
    if key.is_empty() || value.is_empty() {
        return None;
    }
    Some((key.to_string(), value.to_string()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_millis(0))
        .as_millis() as u64
}

/// Errors that can occur during chain import. Every variant is fatal —
/// there is no "partial import" mode.
#[derive(Debug)]
pub enum ImportError {
    Empty,
    FirstBlockNotGenesis,
    MissingGenesisConsensusParams,
    GenesisConsensusParams(String),
    GenesisStateMismatch {
        detail: String,
    },
    GenesisSignature(String),
    ProducerSignature {
        height: u64,
        reason: String,
    },
    ChainIdMismatch {
        height: u64,
    },
    VersionMismatch {
        height: u64,
        expected: u32,
        found: u32,
    },
    Cpog {
        height: u64,
        errors: Vec<String>,
    },
    EconomicsViolation {
        height: u64,
        detail: String,
    },
    NonceViolation {
        height: u64,
        detail: String,
    },
    SnapshotMismatch {
        height: u64,
        detail: String,
    },
    PostSnapshotReplay {
        height: u64,
        detail: String,
    },
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "cannot import an empty block list"),
            Self::FirstBlockNotGenesis => write!(f, "first block is not genesis"),
            Self::MissingGenesisConsensusParams => write!(
                f,
                "genesis block is missing embedded consensus params for a non-legacy state root"
            ),
            Self::GenesisConsensusParams(reason) => {
                write!(f, "invalid embedded genesis consensus params: {}", reason)
            }
            Self::GenesisStateMismatch { detail } => {
                write!(f, "genesis state reconstruction mismatch: {}", detail)
            }
            Self::GenesisSignature(e) => write!(f, "genesis signature invalid: {}", e),
            Self::ProducerSignature { height, reason } => {
                write!(f, "producer sig invalid at height {}: {}", height, reason)
            }
            Self::ChainIdMismatch { height } => {
                write!(f, "chain_id mismatch at height {}", height)
            }
            Self::VersionMismatch {
                height,
                expected,
                found,
            } => write!(
                f,
                "block version mismatch at height {}: expected {}, found {}",
                height, expected, found
            ),
            Self::Cpog { height, errors } => {
                write!(f, "CPoG failed at height {}: {}", height, errors.join("; "))
            }
            Self::EconomicsViolation { height, detail } => {
                write!(
                    f,
                    "economics replay failed at height {}: {}",
                    height, detail
                )
            }
            Self::NonceViolation { height, detail } => {
                write!(f, "nonce violation at height {}: {}", height, detail)
            }
            Self::SnapshotMismatch { height, detail } => {
                write!(f, "snapshot mismatch at height {}: {}", height, detail)
            }
            Self::PostSnapshotReplay { height, detail } => {
                write!(
                    f,
                    "post-snapshot replay failed at height {}: {}",
                    height, detail
                )
            }
        }
    }
}

impl std::error::Error for ImportError {}

/// Build a lightweight reject receipt for pre-filter rejections (N-17).
/// These receipts don't go through the gas meter because the pre-filter
/// runs before metered validation. Gas used is 0.
fn make_prefilter_reject_receipt(
    tx: &sccgub_types::transition::SymbolicTransition,
    state_root: [u8; 32],
    reason: &str,
) -> sccgub_types::receipt::CausalReceipt {
    sccgub_types::receipt::CausalReceipt {
        tx_id: tx.tx_id,
        verdict: sccgub_types::receipt::Verdict::Reject {
            reason: reason.to_string(),
        },
        pre_state_root: state_root,
        post_state_root: state_root,
        read_set: vec![],
        write_set: vec![],
        causes: vec![],
        resource_used: sccgub_types::receipt::ResourceUsage::default(),
        emitted_events: vec![],
        wh_binding: sccgub_types::transition::WHBindingResolved {
            intent: tx.wh_binding_intent.clone(),
            what_actual: sccgub_types::transition::StateDelta::default(),
            whether: sccgub_types::transition::ValidationResult::Invalid {
                reason: reason.to_string(),
            },
        },
        phi_phase_reached: 0,
        tension_delta: TensionValue::ZERO,
    }
}

fn make_metered_reject_receipt(mut receipt: CausalReceipt, reason: &str) -> CausalReceipt {
    receipt.verdict = sccgub_types::receipt::Verdict::Reject {
        reason: reason.to_string(),
    };
    receipt.post_state_root = receipt.pre_state_root;
    receipt.write_set.clear();
    receipt.emitted_events.clear();
    receipt.wh_binding.what_actual = sccgub_types::transition::StateDelta::default();
    receipt.wh_binding.whether = sccgub_types::transition::ValidationResult::Invalid {
        reason: reason.to_string(),
    };
    receipt
}

/// The canonical signing payload for a block. Both producers and verifiers
/// MUST construct the payload via this function. Any change to the payload
/// shape is a hard fork.
fn block_signing_payload(header: &BlockHeader, proof: &CausalProof) -> [u8; 32] {
    let mut proof_for_signing = proof.clone();
    proof_for_signing.validator_signature = Vec::new();
    let bytes = canonical_bytes(&(header, &proof_for_signing));
    blake3_hash(&bytes)
}

/// Verify the producer's Ed25519 signature on a block.
///
/// validator_id = Ed25519 public key directly (Position A).
/// Signature is over block_signing_payload(header, proof).
/// No registry needed — the public key IS the validator identity.
fn verify_producer_signature(block: &Block) -> Result<(), String> {
    let sig = &block.proof.validator_signature;
    if sig.len() < 64 {
        return Err(format!(
            "producer signature missing or too short ({} bytes)",
            sig.len()
        ));
    }

    let public_key = block.header.validator_id;
    if public_key == [0u8; 32] {
        return Err("validator_id (public key) is zero".into());
    }

    let payload_hash = block_signing_payload(&block.header, &block.proof);

    if !sccgub_crypto::signature::verify(&public_key, &payload_hash, sig) {
        return Err("Ed25519 producer signature verification failed".into());
    }

    Ok(())
}

fn build_genesis_block(
    chain_id: Hash,
    validator_id: Hash,
    version: u32,
    validator_key: &ed25519_dalek::SigningKey,
    state_root: Hash,
    balance_root: Hash,
    genesis_consensus_params: Option<Vec<u8>>,
) -> Block {
    let timestamp = CausalTimestamp::genesis();
    let seal = MfidelAtomicSeal::from_height(0);
    let governance = GovernanceSnapshot {
        state_hash: ZERO_HASH,
        active_norm_count: 0,
        emergency_mode: false,
        finality_mode: FinalityMode::Deterministic,
        governance_limits: GovernanceLimitsSnapshot::default(),
        finality_config: FinalityConfigSnapshot::default(),
    };

    let header_data = sccgub_crypto::canonical::canonical_bytes(&("genesis", &chain_id));
    let block_id = blake3_hash(&header_data);

    let header = BlockHeader {
        chain_id,
        block_id,
        parent_id: ZERO_HASH,
        height: 0,
        timestamp,
        state_root,
        transition_root: ZERO_HASH,
        receipt_root: ZERO_HASH,
        causal_root: ZERO_HASH,
        proof_root: ZERO_HASH,
        governance_hash: canonical_hash(&governance),
        tension_before: TensionValue::ZERO,
        tension_after: TensionValue::ZERO,
        mfidel_seal: seal,
        balance_root,
        validator_id,
        version,
        round_history_root: ZERO_HASH,
    };

    // Build proof without signature, then sign the (header, proof) pair.
    let mut proof = CausalProof {
        block_height: 0,
        transitions_proven: vec![],
        phi_traversal_log: PhiTraversalLog::new(),
        governance_snapshot_hash: header.governance_hash,
        tension_before: TensionValue::ZERO,
        tension_after: TensionValue::ZERO,
        constraint_results: vec![],
        recursion_depth: 0,
        validator_signature: vec![],
        causal_hash: blake3_hash(b"genesis-proof"),
    };
    // Sign via shared helper — matches verify_producer_signature exactly.
    let signing_hash = block_signing_payload(&header, &proof);
    proof.validator_signature = sign(validator_key, &signing_hash);

    Block {
        header,
        body: BlockBody {
            transitions: vec![],
            transition_count: 0,
            total_tension_delta: TensionValue::ZERO,
            constraint_satisfaction: vec![],
            genesis_consensus_params,
            validator_set_changes: None,
            equivocation_evidence: None,
        },
        receipts: vec![],
        causal_delta: CausalGraphDelta::default(),
        proof,
        governance,
    }
}

struct BlockBuildParams<'a> {
    chain_id: Hash,
    height: u64,
    parent_id: Hash,
    parent_timestamp: &'a CausalTimestamp,
    validator_id: Hash,
    version: u32,
    validator_key: &'a ed25519_dalek::SigningKey,
    transitions: Vec<SymbolicTransition>,
    receipts: Vec<CausalReceipt>,
    state: &'a ManagedWorldState,
    balance_root: Hash,
    governance_limits: GovernanceLimitsSnapshot,
    finality_config: FinalityConfigSnapshot,
}

fn build_block(params: BlockBuildParams<'_>) -> Block {
    let BlockBuildParams {
        chain_id,
        height,
        parent_id,
        parent_timestamp,
        validator_id,
        version,
        validator_key,
        transitions,
        receipts,
        state,
        balance_root,
        governance_limits,
        finality_config,
    } = params;
    let wall_hint = sccgub_types::timestamp::CausalTimestamp::now_secs();
    let timestamp =
        parent_timestamp.successor(validator_id, canonical_hash(parent_timestamp), wall_hint);
    let seal = MfidelAtomicSeal::from_height(height);

    let tx_bytes: Vec<&[u8]> = transitions.iter().map(|tx| tx.tx_id.as_slice()).collect();
    let transition_root = merkle_root_of_bytes(&tx_bytes);

    let governance = GovernanceSnapshot {
        state_hash: blake3_hash(&sccgub_crypto::canonical::canonical_bytes(
            &state.state.governance_state,
        )),
        active_norm_count: state
            .state
            .governance_state
            .active_norms
            .len()
            .min(u32::MAX as usize) as u32,
        emergency_mode: state.state.governance_state.emergency_mode,
        finality_mode: state.state.governance_state.finality_mode,
        governance_limits,
        finality_config,
    };

    let tension_before = state.state.tension_field.total;

    // Build causal graph delta.
    let block_vertex = CausalVertex::Block(blake3_hash(
        &sccgub_crypto::canonical::canonical_bytes(&(chain_id, height)),
    ));
    let mut causal_vertices = vec![block_vertex.clone()];
    let mut causal_edges = Vec::new();

    // Build causal edges for each transition.
    for tx in &transitions {
        let tx_vertex = CausalVertex::Transition(tx.tx_id);
        let actor_vertex = CausalVertex::Actor(tx.actor.agent_id);
        causal_vertices.push(tx_vertex.clone());

        causal_edges.push(CausalEdge::ContainedBy {
            source: tx_vertex.clone(),
            target: block_vertex.clone(),
        });
        causal_edges.push(CausalEdge::AuthorizedBy {
            source: tx_vertex.clone(),
            target: actor_vertex,
        });
        for ancestor_id in &tx.causal_chain {
            causal_edges.push(CausalEdge::CausedBy {
                source: tx_vertex.clone(),
                target: CausalVertex::Transition(*ancestor_id),
            });
        }
    }

    let causal_root: MerkleRoot = if causal_edges.is_empty() {
        ZERO_HASH
    } else {
        // Serialize each edge to get unique hashes (not dummy bytes).
        let edge_bytes: Vec<Vec<u8>> = causal_edges.iter().map(canonical_bytes).collect();
        let edge_refs: Vec<&[u8]> = edge_bytes.iter().map(|b| b.as_slice()).collect();
        merkle_root_of_bytes(&edge_refs)
    };

    // Hash canonical receipt content (not just tx_id) for full receipt binding.
    let receipt_bytes: Vec<Vec<u8>> = receipts.iter().map(canonical_bytes).collect();
    let receipt_refs: Vec<&[u8]> = receipt_bytes.iter().map(|b| b.as_slice()).collect();
    let receipt_root = merkle_root_of_bytes(&receipt_refs);

    let gov_hash = canonical_hash(&governance);

    // Build header with ZERO_HASH for block_id, then hash the full header to get block_id.
    let mut header = BlockHeader {
        chain_id,
        block_id: ZERO_HASH, // Placeholder — computed below.
        parent_id,
        height,
        timestamp,
        state_root: state.state_root(),
        transition_root,
        receipt_root,
        causal_root,
        proof_root: ZERO_HASH,
        governance_hash: gov_hash,
        tension_before,
        tension_after: tension_before,
        mfidel_seal: seal,
        balance_root,
        validator_id,
        version,
        round_history_root: ZERO_HASH,
    };
    // block_id = Hash(full header with block_id=ZERO) — commits to all header fields.
    let header_bytes = canonical_bytes(&header);
    header.block_id = blake3_hash(&header_bytes);

    // Build proof without signature, then sign (header, proof) pair.
    let mut proof = CausalProof {
        block_height: height,
        transitions_proven: vec![],
        phi_traversal_log: PhiTraversalLog::default(),
        governance_snapshot_hash: header.governance_hash,
        tension_before,
        tension_after: tension_before,
        constraint_results: vec![],
        recursion_depth: 0,
        validator_signature: vec![],
        causal_hash: blake3_hash_concat(&[&parent_id, &transition_root]),
    };
    let signing_hash = block_signing_payload(&header, &proof);
    proof.validator_signature = sign(validator_key, &signing_hash);

    let transition_count = transitions.len().min(u32::MAX as usize) as u32;
    Block {
        header,
        body: BlockBody {
            transitions,
            transition_count,
            total_tension_delta: TensionValue::ZERO,
            constraint_satisfaction: vec![],
            genesis_consensus_params: None,
            validator_set_changes: None,
            equivocation_evidence: None,
        },
        receipts,
        causal_delta: CausalGraphDelta {
            new_vertices: causal_vertices,
            new_edges: causal_edges,
            causal_root,
        },
        proof,
        governance,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sccgub_types::governance::PrecedenceLevel;

    #[test]
    fn test_chain_init_produces_genesis() {
        let chain = Chain::init();
        assert_eq!(chain.height(), 0);
        assert!(chain.latest_block().is_some());
        let genesis = chain.latest_block().unwrap();
        assert_eq!(genesis.header.height, 0);
        assert_eq!(genesis.header.parent_id, ZERO_HASH);
        assert_eq!(genesis.header.version, CURRENT_BLOCK_VERSION);
        assert!(chain.balances.total_supply().raw() > 0);
    }

    #[test]
    fn test_chain_genesis_embeds_consensus_params() {
        let chain = Chain::init();
        let genesis = chain.latest_block().expect("genesis block must exist");
        let embedded = genesis
            .body
            .genesis_consensus_params
            .as_ref()
            .expect("new genesis must embed consensus params");
        let parsed =
            ConsensusParams::from_canonical_bytes(embedded).expect("embedded params must parse");

        assert_eq!(parsed, chain.state.consensus_params);
        assert_eq!(
            chain.state.get(&ConsensusParams::TRIE_KEY.to_vec()),
            Some(embedded)
        );
        assert_eq!(genesis.header.state_root, chain.state.state_root());
        assert_eq!(genesis.header.balance_root, chain.balances.balance_root());
    }

    #[test]
    fn test_chain_from_blocks_replays_genesis_consensus_params() {
        let params = ConsensusParams {
            default_tx_gas_limit: 1_234,
            default_block_gas_limit: 9_876,
            max_state_entry_size: 2_048,
            ..ConsensusParams::default()
        };
        let chain = Chain::init_with_consensus_params(CURRENT_BLOCK_VERSION, params.clone());
        let embedded = params.to_canonical_bytes();

        let replayed = Chain::from_blocks(chain.blocks.clone())
            .expect("from_blocks should load embedded consensus params");

        assert_eq!(replayed.state.consensus_params, params);
        assert_eq!(replayed.state.state_root(), chain.state.state_root());
        assert_eq!(
            replayed.state.get(&ConsensusParams::TRIE_KEY.to_vec()),
            Some(&embedded)
        );
        assert_eq!(
            replayed
                .latest_block()
                .unwrap()
                .body
                .genesis_consensus_params,
            chain.latest_block().unwrap().body.genesis_consensus_params
        );
    }

    #[test]
    fn test_chain_snapshot_restores_consensus_params_from_trie() {
        let params = ConsensusParams {
            max_proof_depth: 99,
            default_tx_gas_limit: 2_222,
            ..ConsensusParams::default()
        };
        let chain = Chain::init_with_consensus_params(CURRENT_BLOCK_VERSION, params.clone());
        let snapshot = chain.create_snapshot();
        let embedded = params.to_canonical_bytes();

        let mut restored = Chain::init();
        restored.restore_from_snapshot(&snapshot).unwrap();

        assert_eq!(restored.state.consensus_params, params);
        assert_eq!(restored.state.state_root(), chain.state.state_root());
        assert_eq!(
            restored.state.get(&ConsensusParams::TRIE_KEY.to_vec()),
            Some(&embedded)
        );
        assert_eq!(
            restored.balances.total_supply(),
            chain.balances.total_supply()
        );
    }

    #[test]
    fn test_from_blocks_rejects_stripped_embedded_genesis_consensus_params() {
        let chain = Chain::init();
        let mut stripped = chain.blocks.clone();
        stripped[0].body.genesis_consensus_params = None;

        match Chain::from_blocks(stripped) {
            Err(ImportError::MissingGenesisConsensusParams) => {}
            Err(other) => panic!("expected missing genesis consensus params, got {}", other),
            Ok(_) => panic!("import must fail when embedded genesis params are stripped"),
        }
    }

    #[test]
    fn test_chain_produce_empty_block() {
        let mut chain = Chain::init();
        let result = chain.produce_block();
        assert!(
            result.is_ok(),
            "Empty block should succeed: {:?}",
            result.err()
        );
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn test_build_candidate_block_does_not_mutate_chain() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;
        let start_height = chain.height();
        let block = chain.build_candidate_block().unwrap();
        assert_eq!(chain.height(), start_height);
        assert_eq!(block.header.height, start_height + 1);
    }

    #[test]
    fn test_proposer_rotation_allows_expected_validator() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;
        let local = *chain.validator_key.verifying_key().as_bytes();
        let validators = vec![
            ValidatorAuthority {
                node_id: [0u8; 32],
                governance_level: PrecedenceLevel::Safety,
                norm_compliance: TensionValue::from_integer(1),
                causal_reliability: TensionValue::from_integer(1),
                active: true,
            },
            ValidatorAuthority {
                node_id: local,
                governance_level: PrecedenceLevel::Safety,
                norm_compliance: TensionValue::from_integer(1),
                causal_reliability: TensionValue::from_integer(1),
                active: true,
            },
        ];
        chain.set_validator_set(validators);

        assert!(chain.is_proposer_for_height(1));
        assert!(!chain.is_proposer_for_height(2));
    }

    #[test]
    fn test_produce_block_rejects_non_proposer() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;
        let validators = vec![ValidatorAuthority {
            node_id: [1u8; 32],
            governance_level: PrecedenceLevel::Safety,
            norm_compliance: TensionValue::from_integer(1),
            causal_reliability: TensionValue::from_integer(1),
            active: true,
        }];
        chain.set_validator_set(validators);

        let result = chain.produce_block();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_candidate_block_rejects_wrong_proposer() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;
        let local = *chain.validator_key.verifying_key().as_bytes();
        let validators = vec![
            ValidatorAuthority {
                node_id: local,
                governance_level: PrecedenceLevel::Safety,
                norm_compliance: TensionValue::from_integer(1),
                causal_reliability: TensionValue::from_integer(1),
                active: true,
            },
            ValidatorAuthority {
                node_id: [255u8; 32],
                governance_level: PrecedenceLevel::Safety,
                norm_compliance: TensionValue::from_integer(1),
                causal_reliability: TensionValue::from_integer(1),
                active: true,
            },
        ];
        chain.set_validator_set(validators);

        let parent = chain.latest_block().unwrap();
        let balance_root = chain.balances.balance_root();
        let block = build_block(BlockBuildParams {
            chain_id: chain.chain_id,
            height: parent.header.height + 1,
            parent_id: parent.header.block_id,
            parent_timestamp: &parent.header.timestamp,
            validator_id: local,
            version: chain.block_version,
            validator_key: &chain.validator_key,
            transitions: Vec::new(),
            receipts: Vec::new(),
            state: &chain.state,
            balance_root,
            governance_limits: governance_limits_snapshot_from(&chain.governance_limits),
            finality_config: finality_config_snapshot_from(&chain.finality_config),
        });

        let err = chain
            .validate_candidate_block_for_round(&block, Some(0))
            .unwrap_err();
        assert!(
            err.contains("Proposer mismatch"),
            "Expected proposer mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn test_chain_produce_multiple_blocks() {
        let mut chain = Chain::init();
        // Single-node mode: raise consecutive proposal limit for testing.
        chain.governance_limits.max_consecutive_proposals = 100;
        for i in 1..=5 {
            let result = chain.produce_block();
            assert!(result.is_ok(), "Block {} failed: {:?}", i, result.err());
        }
        assert_eq!(chain.height(), 5);
        assert_eq!(chain.blocks.len(), 6); // genesis + 5.
    }

    #[test]
    fn test_chain_supply_conserved_across_blocks() {
        let mut chain = Chain::init();
        let initial_supply = chain.balances.total_supply();
        for _ in 0..3 {
            chain.produce_block().unwrap();
        }
        // No fees collected for empty blocks → treasury distributes 0 → supply unchanged.
        assert_eq!(chain.balances.total_supply(), initial_supply);
    }

    #[test]
    fn test_chain_snapshot_roundtrip() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;
        chain.governance_limits.max_actions_per_agent_pct = 25;
        chain.finality_config.confirmation_depth = 4;
        chain.produce_block().unwrap();
        chain.produce_block().unwrap();

        let snapshot = chain.create_snapshot();
        let original_root = chain.state.state_root();
        let original_supply = chain.balances.total_supply();
        let original_limits = chain.governance_limits.clone();
        let original_finality = chain.finality_config.clone();

        let mut chain2 = Chain::init();
        chain2.restore_from_snapshot(&snapshot).unwrap();

        assert_eq!(chain2.state.state_root(), original_root);
        assert_eq!(chain2.balances.total_supply(), original_supply);
        assert_eq!(
            chain2.governance_limits.max_actions_per_agent_pct,
            original_limits.max_actions_per_agent_pct
        );
        assert_eq!(
            chain2.finality_config.confirmation_depth,
            original_finality.confirmation_depth
        );
    }

    #[test]
    fn test_restore_from_snapshot_rejects_tampered_trie_entries() {
        // N-53: Mutating `trie_entries` without updating `state_root` must be
        // rejected so that a malicious snapshot file cannot silently fork state.
        let mut chain = Chain::init();
        chain.produce_block().unwrap();
        chain.produce_block().unwrap();

        let mut snapshot = chain.create_snapshot();
        // Inject a bogus key/value into the trie entries while leaving the
        // snapshot's self-reported `state_root` unchanged.
        snapshot
            .trie_entries
            .push((b"malicious/backdoor".to_vec(), b"evil".to_vec()));

        let mut victim = Chain::init();
        let result = victim.restore_from_snapshot(&snapshot);
        assert!(
            result.is_err(),
            "tampered snapshot must be rejected, got Ok"
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("trie root mismatch"),
            "expected root-mismatch error, got: {}",
            err
        );
    }

    #[test]
    fn test_restore_from_snapshot_rejects_mutated_entry_value() {
        // N-53: Mutating an existing trie entry's value (e.g., forging a
        // balance) must be caught by the recomputed-root check.
        let mut chain = Chain::init();
        chain.produce_block().unwrap();

        let mut snapshot = chain.create_snapshot();
        // Flip at least one byte of the first trie entry's value.
        if let Some((_, value)) = snapshot.trie_entries.first_mut() {
            if value.is_empty() {
                value.push(0xFF);
            } else {
                value[0] = value[0].wrapping_add(1);
            }
        } else {
            // No entries to tamper — just append a bogus one to force divergence.
            snapshot
                .trie_entries
                .push((b"system/tamper".to_vec(), b"x".to_vec()));
        }

        let mut victim = Chain::init();
        let result = victim.restore_from_snapshot(&snapshot);
        assert!(result.is_err(), "mutated value must be rejected");
    }

    #[test]
    fn test_chain_snapshot_restore_matches_tip_roots() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;
        for _ in 0..3 {
            chain.produce_block().unwrap();
        }

        let snapshot = chain.create_snapshot();
        let tip = chain.latest_block().expect("tip block");
        assert_eq!(snapshot.height, tip.header.height);
        assert_eq!(snapshot.state_root, tip.header.state_root);

        let mut ledger = BalanceLedger::new();
        for (agent_id, raw_balance) in &snapshot.balances {
            ledger.import_balance(*agent_id, TensionValue(*raw_balance));
        }
        let snapshot_balance_root = ledger.balance_root();
        assert_eq!(snapshot_balance_root, tip.header.balance_root);

        let mut replayed = Chain::from_blocks(chain.blocks.clone())
            .expect("from_blocks should succeed for valid chain");
        replayed.restore_from_snapshot(&snapshot).unwrap();
        assert_eq!(replayed.state.state_root(), tip.header.state_root);
        assert_eq!(replayed.balances.balance_root(), tip.header.balance_root);
    }

    #[test]
    fn test_chain_from_blocks_with_snapshot_matches_full_replay() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;
        for _ in 0..2 {
            chain.produce_block().unwrap();
        }

        let snapshot = chain.create_snapshot();
        for _ in 0..2 {
            chain.produce_block().unwrap();
        }
        let replayed =
            Chain::from_blocks(chain.blocks.clone()).expect("full replay should succeed");
        let accelerated = Chain::from_blocks_with_snapshot(chain.blocks.clone(), &snapshot, None)
            .expect("snapshot replay should succeed");

        assert_eq!(accelerated.state.state_root(), replayed.state.state_root());
        assert_eq!(
            accelerated.balances.balance_root(),
            replayed.balances.balance_root()
        );
        assert_eq!(
            accelerated.finality.finalized_height,
            replayed.finality.finalized_height
        );
    }

    #[test]
    fn test_chain_from_blocks_with_snapshot_rejects_root_mismatch() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;
        chain.produce_block().unwrap();

        let mut snapshot = chain.create_snapshot();
        snapshot.state_root = [9u8; 32];

        match Chain::from_blocks_with_snapshot(chain.blocks.clone(), &snapshot, None) {
            Err(ImportError::SnapshotMismatch { height, .. }) => assert_eq!(height, 1),
            Err(other) => panic!("expected snapshot mismatch, got {}", other),
            Ok(_) => panic!("expected snapshot mismatch, got success"),
        }
    }

    #[test]
    fn test_chain_snapshot_restores_finality_mode() {
        let chain = Chain::init_with_finality_mode(FinalityMode::BftCertified {
            quorum_threshold: 2,
        });
        let snapshot = chain.create_snapshot();

        let mut restored = Chain::init();
        restored.restore_from_snapshot(&snapshot).unwrap();

        assert_eq!(
            restored.state.state.governance_state.finality_mode,
            chain.state.state.governance_state.finality_mode
        );
    }

    #[test]
    fn test_chain_from_blocks_replay() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;
        chain.produce_block().unwrap();
        chain.produce_block().unwrap();

        let blocks = chain.blocks.clone();
        let original_root = chain.state.state_root();

        let replayed =
            Chain::from_blocks(blocks).expect("from_blocks should succeed for valid chain");
        assert_eq!(replayed.state.state_root(), original_root);
        assert_eq!(replayed.height(), 2);
    }

    #[test]
    fn test_chain_replays_fee_and_reward_state_from_blocks() {
        use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
        use sccgub_types::governance::PrecedenceLevel;
        use sccgub_types::mfidel::MfidelAtomicSeal;
        use sccgub_types::timestamp::CausalTimestamp;
        use sccgub_types::transition::*;
        use std::collections::BTreeSet;

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;

        let actor_key = chain.validator_key.clone();
        let actor_pk = *actor_key.verifying_key().as_bytes();
        let actor_seal = MfidelAtomicSeal::from_height(0);
        let actor_id = sccgub_state::apply::validator_spend_account(chain.block_version, &actor_pk);

        let target = b"data/economics/replay".to_vec();
        let mut tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: AgentIdentity {
                agent_id: actor_id,
                public_key: actor_pk,
                mfidel_seal: actor_seal,
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: BTreeSet::new(),
                responsibility: ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::StateWrite,
                target: target.clone(),
                declared_purpose: "economics replay test".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: target.clone(),
                value: b"charged".to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: actor_id,
                when: CausalTimestamp::genesis(),
                r#where: target.clone(),
                why: CausalJustification {
                    invoking_rule: [1u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "economics replay test".into(),
            },
            nonce: 1,
            signature: vec![],
        };

        let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
        tx.tx_id = blake3_hash(&canonical);
        tx.signature = sccgub_crypto::signature::sign(&actor_key, &canonical);

        chain.submit_transition(tx).expect("submit should succeed");

        let block = chain
            .produce_block()
            .expect("block production should succeed")
            .clone();
        assert_eq!(block.body.transitions.len(), 1, "tx must be included");
        assert_eq!(block.receipts.len(), 1, "accepted tx must have a receipt");

        let fee = TensionValue(
            (block.receipts[0].resource_used.compute_steps as i128)
                .saturating_mul(chain.economics.base_fee.raw()),
        );
        let expected_reward = default_block_reward();
        let reward_account =
            sccgub_state::apply::validator_spend_account(chain.block_version, &actor_pk);
        assert!(fee.raw() > 0, "accepted tx must pay a positive fee");
        assert_eq!(chain.treasury.total_fees_collected, fee);
        assert_eq!(chain.treasury.total_rewards_distributed, expected_reward);
        assert_eq!(
            chain.balances.balance_of(&reward_account),
            TensionValue::from_integer(1_000_000) - fee + expected_reward,
            "canonical validator spend account must reflect fee debit plus fixed reward"
        );

        let replayed =
            Chain::from_blocks(chain.blocks.clone()).expect("from_blocks should replay economics");
        assert_eq!(replayed.state.state_root(), chain.state.state_root());
        assert_eq!(
            replayed.treasury.total_fees_collected,
            chain.treasury.total_fees_collected
        );
        assert_eq!(
            replayed.treasury.total_rewards_distributed,
            chain.treasury.total_rewards_distributed
        );
        assert_eq!(
            replayed.balances.balance_of(&reward_account),
            chain.balances.balance_of(&reward_account)
        );
    }

    #[test]
    fn test_state_store_bind_persists_trie_root() {
        use crate::config::StorageConfig;
        use sccgub_state::store::StateStore;
        use sccgub_state::trie::StateTrie;
        use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
        use sccgub_types::governance::PrecedenceLevel;
        use sccgub_types::mfidel::MfidelAtomicSeal;
        use sccgub_types::timestamp::CausalTimestamp;
        use sccgub_types::transition::*;
        use std::collections::BTreeSet;
        use std::path::PathBuf;
        use std::sync::Arc;

        let dir =
            std::env::temp_dir().join(format!("sccgub_state_store_bind_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = crate::persistence::ChainStore::new(&dir).expect("store init");
        let storage = StorageConfig {
            data_dir: PathBuf::from(&dir),
            snapshot_restore_enabled: true,
            state_store_enabled: true,
            state_store_authoritative: false,
            state_store_dir: PathBuf::from("state_db"),
        };
        let state_store = store.open_state_store(&storage).expect("open state store");
        let state_store_arc = Arc::new(state_store.clone()) as Arc<dyn StateStore>;

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;
        chain
            .state
            .bind_store(state_store_arc.clone())
            .expect("bind store");

        let actor_key = chain.validator_key.clone();
        let actor_pk = *actor_key.verifying_key().as_bytes();
        let actor_seal = MfidelAtomicSeal::from_height(0);
        let actor_id = sccgub_state::apply::validator_spend_account(chain.block_version, &actor_pk);

        let target = b"data/state_store/bind".to_vec();
        let mut tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: AgentIdentity {
                agent_id: actor_id,
                public_key: actor_pk,
                mfidel_seal: actor_seal,
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: BTreeSet::new(),
                responsibility: ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::StateWrite,
                target: target.clone(),
                declared_purpose: "state store bind test".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: target.clone(),
                value: b"durable".to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: actor_id,
                when: CausalTimestamp::genesis(),
                r#where: target.clone(),
                why: CausalJustification {
                    invoking_rule: [1u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "state store bind test".into(),
            },
            nonce: 1,
            signature: vec![],
        };

        let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
        tx.tx_id = blake3_hash(&canonical);
        tx.signature = sccgub_crypto::signature::sign(&actor_key, &canonical);

        chain.submit_transition(tx).expect("submit should succeed");
        chain
            .produce_block()
            .expect("block production should succeed");

        chain.state.flush_store().expect("flush store");

        let durable_trie = StateTrie::with_store(state_store_arc).expect("load durable trie");
        assert_eq!(
            durable_trie.root_readonly(),
            chain.state.state_root(),
            "durable trie root must match chain state root"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_state_store_snapshot_restore_matches_root() {
        use crate::config::StorageConfig;
        use sccgub_state::store::StateStore;
        use sccgub_state::trie::StateTrie;
        use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
        use sccgub_types::governance::PrecedenceLevel;
        use sccgub_types::mfidel::MfidelAtomicSeal;
        use sccgub_types::timestamp::CausalTimestamp;
        use sccgub_types::transition::*;
        use std::collections::BTreeSet;
        use std::path::PathBuf;
        use std::sync::Arc;

        let dir =
            std::env::temp_dir().join(format!("sccgub_state_snapshot_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = crate::persistence::ChainStore::new(&dir).expect("store init");
        let storage = StorageConfig {
            data_dir: PathBuf::from(&dir),
            snapshot_restore_enabled: true,
            state_store_enabled: true,
            state_store_authoritative: false,
            state_store_dir: PathBuf::from("state_db"),
        };
        let state_store = store.open_state_store(&storage).expect("open state store");
        let state_store_arc = Arc::new(state_store.clone()) as Arc<dyn StateStore>;

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;
        chain
            .state
            .bind_store(state_store_arc.clone())
            .expect("bind store");

        let actor_key = chain.validator_key.clone();
        let actor_pk = *actor_key.verifying_key().as_bytes();
        let actor_seal = MfidelAtomicSeal::from_height(0);
        let actor_id = sccgub_state::apply::validator_spend_account(chain.block_version, &actor_pk);

        for idx in 0..3 {
            let target = format!("data/state_store/snapshot/{}", idx).into_bytes();
            let mut tx = SymbolicTransition {
                tx_id: [0u8; 32],
                actor: AgentIdentity {
                    agent_id: actor_id,
                    public_key: actor_pk,
                    mfidel_seal: actor_seal.clone(),
                    registration_block: 0,
                    governance_level: PrecedenceLevel::Meaning,
                    norm_set: BTreeSet::new(),
                    responsibility: ResponsibilityState::default(),
                },
                intent: TransitionIntent {
                    kind: TransitionKind::StateWrite,
                    target: target.clone(),
                    declared_purpose: "state store snapshot test".into(),
                },
                preconditions: vec![],
                postconditions: vec![],
                payload: OperationPayload::Write {
                    key: target.clone(),
                    value: b"durable".to_vec(),
                },
                causal_chain: vec![],
                wh_binding_intent: WHBindingIntent {
                    who: actor_id,
                    when: CausalTimestamp::genesis(),
                    r#where: target.clone(),
                    why: CausalJustification {
                        invoking_rule: [1u8; 32],
                        precedence_level: PrecedenceLevel::Meaning,
                        causal_ancestors: vec![],
                        constraint_proof: vec![],
                    },
                    how: TransitionMechanism::DirectStateWrite,
                    which: BTreeSet::new(),
                    what_declared: "state store snapshot test".into(),
                },
                nonce: (idx + 1) as u128,
                signature: vec![],
            };

            let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
            tx.tx_id = blake3_hash(&canonical);
            tx.signature = sccgub_crypto::signature::sign(&actor_key, &canonical);

            chain.submit_transition(tx).expect("submit should succeed");
            chain
                .produce_block()
                .expect("block production should succeed");
        }

        chain.state.flush_store().expect("flush store");

        let snapshot = chain.create_snapshot();
        store.save_snapshot(&snapshot).expect("snapshot save");

        let mut restored = Chain::init();
        let durable_trie = StateTrie::with_store(state_store_arc.clone()).expect("load store");
        restored.state.trie = durable_trie;
        restored
            .restore_from_snapshot_with_store(&snapshot, state_store_arc)
            .expect("restore snapshot with store");

        assert_eq!(
            restored.state.state_root(),
            chain.state.state_root(),
            "restored state root must match snapshot root"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_chain_from_blocks_replays_governance_parameters() {
        use sccgub_governance::proposals::ProposalKind;
        use sccgub_types::governance::PrecedenceLevel;

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 400;
        let proposer = chain.latest_block().unwrap().header.validator_id;

        let proposal_id = chain
            .proposals
            .submit(
                proposer,
                PrecedenceLevel::Safety,
                ProposalKind::ModifyParameter {
                    key: "finality.confirmation_depth".into(),
                    value: "5".into(),
                },
                chain.height(),
                5,
            )
            .unwrap();
        chain
            .proposals
            .vote(
                &proposal_id,
                proposer,
                PrecedenceLevel::Safety,
                true,
                chain.height(),
            )
            .unwrap();

        for _ in 0..210 {
            chain.produce_block().unwrap();
        }
        assert_eq!(chain.finality_config.confirmation_depth, 5);

        let replayed =
            Chain::from_blocks(chain.blocks.clone()).expect("from_blocks should succeed");
        assert_eq!(replayed.finality_config.confirmation_depth, 5);
    }

    #[test]
    fn test_v1_chain_accepts_transfer_from_signer_public_key_account() {
        use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
        use sccgub_types::governance::PrecedenceLevel;
        use sccgub_types::mfidel::MfidelAtomicSeal;
        use sccgub_types::timestamp::CausalTimestamp;
        use sccgub_types::transition::*;
        use std::collections::BTreeSet;

        let mut chain = Chain::init_with_version(sccgub_types::block::LEGACY_BLOCK_VERSION);
        chain.governance_limits.max_consecutive_proposals = 100;

        let sender_pk = *chain.validator_key.verifying_key().as_bytes();
        let sender_seal = MfidelAtomicSeal::from_height(0);
        let sender_id = blake3_hash_concat(&[
            &sender_pk,
            &sccgub_crypto::canonical::canonical_bytes(&sender_seal),
        ]);
        let recipient_key = generate_keypair();
        let recipient_pk = *recipient_key.verifying_key().as_bytes();
        let recipient_seal = MfidelAtomicSeal::from_height(1);
        let recipient_id = blake3_hash_concat(&[
            &recipient_pk,
            &sccgub_crypto::canonical::canonical_bytes(&recipient_seal),
        ]);
        let transfer_amount = TensionValue::from_integer(25);
        let sender_before = chain.balances.balance_of(&sender_pk);

        let mut tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: AgentIdentity {
                agent_id: sender_id,
                public_key: sender_pk,
                mfidel_seal: sender_seal,
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: BTreeSet::new(),
                responsibility: ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::AssetTransfer,
                target: sccgub_types::namespace::balance_key(&sender_pk),
                declared_purpose: "compat transfer".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::AssetTransfer {
                from: sender_pk,
                to: recipient_id,
                amount: transfer_amount.raw(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: sender_id,
                when: CausalTimestamp::genesis(),
                r#where: sccgub_types::namespace::balance_key(&sender_pk),
                why: CausalJustification {
                    invoking_rule: [1u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "compat transfer".into(),
            },
            nonce: 1,
            signature: vec![],
        };

        let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
        tx.tx_id = blake3_hash(&canonical);
        tx.signature = sccgub_crypto::signature::sign(&chain.validator_key, &canonical);

        chain.submit_transition(tx).expect("submit should succeed");
        let block = chain
            .produce_block()
            .expect("block production should succeed")
            .clone();

        assert_eq!(block.body.transitions.len(), 1, "transfer must be accepted");
        assert_eq!(
            chain.balances.balance_of(&recipient_id),
            transfer_amount,
            "recipient must receive transfer amount"
        );
        assert!(
            chain.balances.balance_of(&sender_pk) < sender_before,
            "sender compatibility account must be debited by transfer plus fee"
        );
    }

    #[test]
    fn test_v2_chain_funds_validator_agent_account() {
        let chain = Chain::init();
        let validator_pk = *chain.validator_key.verifying_key().as_bytes();
        let canonical_account =
            sccgub_state::apply::validator_spend_account(chain.block_version, &validator_pk);

        assert_eq!(
            chain.balances.balance_of(&canonical_account),
            TensionValue::from_integer(1_000_000)
        );
        assert_eq!(
            chain.balances.balance_of(&validator_pk),
            TensionValue::ZERO,
            "v2 must not leave genesis funds on the signer compatibility account"
        );
    }

    #[test]
    fn test_from_blocks_rejects_mixed_block_versions() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;
        chain
            .produce_block()
            .expect("block production should succeed");

        let mut mixed = chain.blocks.clone();
        mixed[1].header.version = sccgub_types::block::LEGACY_BLOCK_VERSION;
        let signing_hash = block_signing_payload(&mixed[1].header, &mixed[1].proof);
        mixed[1].proof.validator_signature = sign(&chain.validator_key, &signing_hash);

        match Chain::from_blocks(mixed) {
            Err(ImportError::VersionMismatch {
                expected, found, ..
            }) => {
                assert_eq!(expected, CURRENT_BLOCK_VERSION);
                assert_eq!(found, sccgub_types::block::LEGACY_BLOCK_VERSION);
            }
            Err(other) => panic!("expected version mismatch, got {}", other),
            Ok(_) => panic!("mixed-version chain must be rejected"),
        }
    }

    #[test]
    fn test_chain_finality_advances() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;
        for _ in 0..5 {
            chain.produce_block().unwrap();
        }
        assert!(chain.finality.finalized_height >= 3);
    }

    #[test]
    fn test_chain_emits_events_after_finality() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;

        // Produce enough blocks for finality to advance (default depth=2).
        for _ in 0..4 {
            chain.produce_block().unwrap();
        }

        // After 4 blocks, finality should have advanced, producing BlockFinalized events.
        let events = &chain.latest_events;
        assert!(
            events.event_count() > 0,
            "Block production with finality must emit events, got 0"
        );

        let finality_events: Vec<_> = events
            .events
            .iter()
            .filter(|e| matches!(e, sccgub_types::events::ChainEvent::BlockFinalized { .. }))
            .collect();
        assert!(
            !finality_events.is_empty(),
            "Must have at least one BlockFinalized event"
        );
    }

    #[test]
    fn test_chain_treasury_snapshot_roundtrip() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;

        // Produce blocks to accumulate some treasury state.
        for _ in 0..3 {
            chain.produce_block().unwrap();
        }

        let snapshot = chain.create_snapshot();

        // Verify treasury fields are captured.
        // Treasury starts at zero and may have epoch data.
        assert_eq!(snapshot.treasury_epoch, chain.treasury.epoch);
        assert_eq!(snapshot.finalized_height, chain.finality.finalized_height);

        // Restore and verify.
        let mut chain2 = Chain::init();
        chain2.restore_from_snapshot(&snapshot).unwrap();
        assert_eq!(chain2.treasury.epoch, chain.treasury.epoch);
        assert_eq!(
            chain2.treasury.pending_fees.raw(),
            chain.treasury.pending_fees.raw()
        );
        assert_eq!(
            chain2.finality.finalized_height,
            chain.finality.finalized_height
        );
    }

    #[test]
    fn test_scce_constraint_persists_through_empty_block() {
        // Smoke test: planting a constraint doesn't get clobbered by block production.
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;

        let key = sccgub_execution::scce::constraint_key(b"test/symbol", b"c0").unwrap();
        chain.state.trie.insert(key.clone(), b"false".to_vec());

        let result = chain.produce_block();
        assert!(result.is_ok());

        assert!(
            chain.state.trie.get(&key).is_some(),
            "Constraint must persist in state trie after block production"
        );
    }

    #[test]
    fn test_scce_rejects_tx_targeting_constrained_symbol() {
        // REAL integration test: proves the SCCE walker is wired into
        // the production path. If propagate_constraints were replaced with
        // `return consistent: true`, this test would fail.
        //
        // Flow: admit_check (mempool) → gas loop → validate_transition_metered
        //       → validate_transition → phi_check_single_tx → phase_constraint
        //       → scce_validate → propagate_constraints → UNSAT → reject receipt
        use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
        use sccgub_types::governance::PrecedenceLevel;
        use sccgub_types::mfidel::MfidelAtomicSeal;
        use sccgub_types::timestamp::CausalTimestamp;
        use sccgub_types::transition::*;
        use std::collections::BTreeSet;

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;

        // 1. Plant an unsatisfiable constraint at "test/constrained".
        let constraint =
            sccgub_execution::scce::constraint_key(b"test/constrained", b"c0").unwrap();
        chain.state.trie.insert(constraint, b"false".to_vec());

        // 2. Build a properly signed transaction targeting that symbol.
        let pk = *chain.validator_key.verifying_key().as_bytes();
        let seal = MfidelAtomicSeal::from_height(1);
        let agent_id =
            blake3_hash_concat(&[&pk, &sccgub_crypto::canonical::canonical_bytes(&seal)]);
        let agent = AgentIdentity {
            agent_id,
            public_key: pk,
            mfidel_seal: seal,
            registration_block: 0,
            governance_level: PrecedenceLevel::Meaning,
            norm_set: BTreeSet::new(),
            responsibility: ResponsibilityState::default(),
        };

        let target = b"test/constrained".to_vec();
        let mut tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: agent,
            intent: TransitionIntent {
                kind: TransitionKind::StateWrite,
                target: target.clone(),
                declared_purpose: "SCCE e2e test".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: target.clone(),
                value: b"should_be_rejected".to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: agent_id,
                when: CausalTimestamp::genesis(),
                r#where: target,
                why: CausalJustification {
                    invoking_rule: [1u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "SCCE e2e test".into(),
            },
            nonce: 1,
            signature: vec![],
        };

        // Sign properly.
        let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
        tx.tx_id = blake3_hash(&canonical);
        tx.signature = sccgub_crypto::signature::sign(&chain.validator_key, &canonical);

        // 3. Submit to mempool.
        chain.submit_transition(tx).expect("submit should succeed");
        assert_eq!(chain.mempool.len(), 1, "tx must be in mempool");

        // 4. Produce a block. The tx passes admit_check (lightweight) but is
        //    REJECTED by the gas loop: validate_transition_metered →
        //    validate_transition → phi_check_single_tx → phase_constraint →
        //    scce_validate → propagate_constraints → UNSAT → reject receipt.
        let block = chain
            .produce_block()
            .expect("block production should succeed");

        // 5. Assert: the block has ZERO transactions because the
        //    constrained tx was rejected during gas-loop validation.
        assert_eq!(
            block.body.transitions.len(),
            0,
            "Constrained tx must be filtered out by SCCE. If this fails, \
             the SCCE walker is not wired into the production path."
        );

        // 6. Verify the state was NOT mutated by the rejected tx.
        assert!(
            chain
                .state
                .trie
                .get(&b"test/constrained".to_vec())
                .is_none()
                || chain.state.trie.get(&b"test/constrained".to_vec())
                    != Some(&b"should_be_rejected".to_vec()),
            "Rejected tx must not mutate state"
        );

        // 7. N-3 closure: the rejected tx must have produced a reject receipt.
        // Before the mempool → admit_check refactor, this tx would have been
        // silently dropped at drain_validated time with no receipt. Now it passes
        // admit_check, enters the gas loop, and is rejected with a receipt.
        assert!(
            !chain.latest_rejected_receipts.is_empty(),
            "N-3: SCCE-rejected tx must produce a reject receipt in the gas loop"
        );
        let reject = &chain.latest_rejected_receipts[0];
        assert!(!reject.verdict.is_accepted(), "Receipt must be a rejection");
    }

    #[test]
    fn test_proposal_wired_into_chain_lifecycle() {
        use sccgub_governance::proposals::{ProposalKind, ProposalStatus};
        use sccgub_types::governance::PrecedenceLevel;

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 200;

        let proposer = chain.latest_block().unwrap().header.validator_id;

        // Submit a norm proposal.
        let proposal_id = chain
            .proposals
            .submit(
                proposer,
                PrecedenceLevel::Meaning,
                ProposalKind::AddNorm {
                    name: "test-norm".into(),
                    description: "A test norm".into(),
                    initial_fitness: TensionValue::from_integer(5),
                    enforcement_cost: TensionValue::from_integer(1),
                },
                chain.height(),
                5, // 5-block voting period
            )
            .unwrap();

        // Vote for it.
        chain
            .proposals
            .vote(
                &proposal_id,
                proposer,
                PrecedenceLevel::Meaning,
                true,
                chain.height(),
            )
            .unwrap();

        // Produce blocks through voting period (5 blocks) + timelock (50 blocks).
        for _ in 0..60 {
            chain.produce_block().unwrap();
        }

        // The proposal should have been finalized, timelocked, and activated.
        let proposal = chain
            .proposals
            .proposals
            .iter()
            .find(|p| p.id == proposal_id)
            .unwrap();
        assert_eq!(
            proposal.status,
            ProposalStatus::Activated,
            "Proposal should be activated after voting + timelock"
        );

        // The norm should be in the governance state.
        assert!(
            chain
                .state
                .state
                .governance_state
                .active_norms
                .contains_key(&proposal_id),
            "Activated norm must be in governance state"
        );
    }

    #[test]
    fn test_governance_emergency_toggle_activation() {
        use sccgub_governance::proposals::ProposalKind;
        use sccgub_types::governance::PrecedenceLevel;

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 500;
        let proposer = chain.latest_block().unwrap().header.validator_id;

        let activate_id = chain
            .proposals
            .submit(
                proposer,
                PrecedenceLevel::Safety,
                ProposalKind::ActivateEmergency,
                chain.height(),
                5,
            )
            .unwrap();
        chain
            .proposals
            .vote(
                &activate_id,
                proposer,
                PrecedenceLevel::Safety,
                true,
                chain.height(),
            )
            .unwrap();

        for _ in 0..210 {
            chain.produce_block().unwrap();
        }
        assert!(chain.state.state.governance_state.emergency_mode);

        let deactivate_id = chain
            .proposals
            .submit(
                proposer,
                PrecedenceLevel::Safety,
                ProposalKind::DeactivateEmergency,
                chain.height(),
                5,
            )
            .unwrap();
        chain
            .proposals
            .vote(
                &deactivate_id,
                proposer,
                PrecedenceLevel::Safety,
                true,
                chain.height(),
            )
            .unwrap();

        for _ in 0..210 {
            chain.produce_block().unwrap();
        }
        assert!(!chain.state.state.governance_state.emergency_mode);
    }

    #[test]
    fn test_governance_parameter_update_activation() {
        use sccgub_governance::proposals::ProposalKind;
        use sccgub_types::governance::PrecedenceLevel;

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 300;
        let proposer = chain.latest_block().unwrap().header.validator_id;

        let proposal_id = chain
            .proposals
            .submit(
                proposer,
                PrecedenceLevel::Safety,
                ProposalKind::ModifyParameter {
                    key: "finality.confirmation_depth".into(),
                    value: "4".into(),
                },
                chain.height(),
                5,
            )
            .unwrap();
        chain
            .proposals
            .vote(
                &proposal_id,
                proposer,
                PrecedenceLevel::Safety,
                true,
                chain.height(),
            )
            .unwrap();

        for _ in 0..210 {
            chain.produce_block().unwrap();
        }

        assert_eq!(chain.finality_config.confirmation_depth, 4);
    }

    #[test]
    fn test_governance_parameter_updates_finality_mode() {
        use sccgub_governance::proposals::ProposalKind;
        use sccgub_types::governance::{FinalityMode, PrecedenceLevel};

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 300;
        let proposer = chain.latest_block().unwrap().header.validator_id;

        let proposal_id = chain
            .proposals
            .submit(
                proposer,
                PrecedenceLevel::Safety,
                ProposalKind::ModifyParameter {
                    key: "finality.mode".into(),
                    value: "bft:2".into(),
                },
                chain.height(),
                5,
            )
            .unwrap();
        chain
            .proposals
            .vote(
                &proposal_id,
                proposer,
                PrecedenceLevel::Safety,
                true,
                chain.height(),
            )
            .unwrap();

        for _ in 0..210 {
            chain.produce_block().unwrap();
        }

        assert_eq!(
            chain.state.state.governance_state.finality_mode,
            FinalityMode::BftCertified {
                quorum_threshold: 2
            }
        );
    }

    #[test]
    fn test_governance_parameter_update_via_transitions() {
        use sccgub_governance::proposals::ProposalStatus;
        use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
        use sccgub_types::governance::PrecedenceLevel;
        use sccgub_types::mfidel::MfidelAtomicSeal;
        use sccgub_types::timestamp::CausalTimestamp;
        use sccgub_types::transition::*;
        use std::collections::BTreeSet;

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 300;

        let pk = *chain.validator_key.verifying_key().as_bytes();
        let seal = MfidelAtomicSeal::from_height(0);
        let agent_id = blake3_hash_concat(&[&pk, &canonical_bytes(&seal)]);
        let agent = AgentIdentity {
            agent_id,
            public_key: pk,
            mfidel_seal: seal,
            registration_block: 0,
            governance_level: PrecedenceLevel::Safety,
            norm_set: BTreeSet::new(),
            responsibility: ResponsibilityState::default(),
        };

        let propose_key = b"norms/governance/params/propose".to_vec();
        let propose_value = b"finality.confirmation_depth=5".to_vec();
        let mut propose_tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: agent.clone(),
            intent: TransitionIntent {
                kind: TransitionKind::GovernanceUpdate,
                target: propose_key.clone(),
                declared_purpose: "Propose finality depth update".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: propose_key.clone(),
                value: propose_value,
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: agent_id,
                when: CausalTimestamp::genesis(),
                r#where: propose_key.clone(),
                why: CausalJustification {
                    invoking_rule: [1u8; 32],
                    precedence_level: PrecedenceLevel::Safety,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "Propose finality depth update".into(),
            },
            nonce: 1,
            signature: vec![],
        };
        let propose_canonical = sccgub_execution::validate::canonical_tx_bytes(&propose_tx);
        propose_tx.tx_id = blake3_hash(&propose_canonical);
        propose_tx.signature =
            sccgub_crypto::signature::sign(&chain.validator_key, &propose_canonical);

        chain
            .submit_transition(propose_tx)
            .expect("proposal submit should succeed");
        let proposal_block = chain
            .produce_block()
            .expect("proposal block should succeed");
        assert!(
            !proposal_block.body.transitions.is_empty(),
            "proposal transition must be included in produced block"
        );

        let proposal_id = chain
            .proposals
            .proposals
            .iter()
            .find(|proposal| {
                matches!(
                    proposal.kind,
                    sccgub_governance::proposals::ProposalKind::ModifyParameter { .. }
                )
            })
            .map(|proposal| proposal.id)
            .expect("proposal registry should contain parameter proposal");

        let vote_key = b"norms/governance/proposals/vote".to_vec();
        let mut vote_tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: agent,
            intent: TransitionIntent {
                kind: TransitionKind::GovernanceUpdate,
                target: vote_key.clone(),
                declared_purpose: "Vote for governance proposal".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: vote_key.clone(),
                value: proposal_id.to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: agent_id,
                when: CausalTimestamp::genesis(),
                r#where: vote_key.clone(),
                why: CausalJustification {
                    invoking_rule: [2u8; 32],
                    precedence_level: PrecedenceLevel::Safety,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "Vote for governance proposal".into(),
            },
            nonce: 2,
            signature: vec![],
        };
        let vote_canonical = sccgub_execution::validate::canonical_tx_bytes(&vote_tx);
        vote_tx.tx_id = blake3_hash(&vote_canonical);
        vote_tx.signature = sccgub_crypto::signature::sign(&chain.validator_key, &vote_canonical);

        chain
            .submit_transition(vote_tx)
            .expect("vote submit should succeed");
        let vote_block = chain.produce_block().expect("vote block should succeed");
        assert!(
            !vote_block.body.transitions.is_empty(),
            "vote transition must be included in produced block"
        );

        for _ in 0..210 {
            chain.produce_block().unwrap();
        }

        let proposal = chain
            .proposals
            .proposals
            .iter()
            .find(|proposal| proposal.id == proposal_id)
            .expect("proposal should remain in registry");
        assert_eq!(proposal.status, ProposalStatus::Activated);
        assert_eq!(chain.finality_config.confirmation_depth, 5);
    }

    #[test]
    fn test_governance_snapshot_reflects_live_limits_and_finality() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 123;
        chain.governance_limits.max_actions_per_agent_pct = 42;
        chain.finality_config.confirmation_depth = 7;
        chain.finality_config.max_finality_ms = 9_000;

        let block = chain.produce_block().expect("block should succeed");

        assert_eq!(
            block.governance.governance_limits.max_consecutive_proposals,
            123
        );
        assert_eq!(
            block.governance.governance_limits.max_actions_per_agent_pct,
            42
        );
        assert_eq!(block.governance.finality_config.confirmation_depth, 7);
        assert_eq!(block.governance.finality_config.max_finality_ms, 9_000);
    }

    #[test]
    fn test_phase8_rejects_payload_target_mismatch() {
        // End-to-end witness: proves Phase 8 payload consistency check
        // is wired into the production path. If check_payload_consistency
        // were replaced with `return Consistent`, this test would fail.
        use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
        use sccgub_types::governance::PrecedenceLevel;
        use sccgub_types::mfidel::MfidelAtomicSeal;
        use sccgub_types::timestamp::CausalTimestamp;
        use sccgub_types::transition::*;
        use std::collections::BTreeSet;

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;

        // Build a properly signed tx with a MISMATCHED payload:
        // kind=StateWrite, target=data/foo, but payload writes to balance/victim.
        let pk = *chain.validator_key.verifying_key().as_bytes();
        let seal = MfidelAtomicSeal::from_height(1);
        let agent_id =
            blake3_hash_concat(&[&pk, &sccgub_crypto::canonical::canonical_bytes(&seal)]);

        let target = b"data/legitimate".to_vec();
        let mut tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: AgentIdentity {
                agent_id,
                public_key: pk,
                mfidel_seal: seal,
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: BTreeSet::new(),
                responsibility: ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::StateWrite,
                target: target.clone(),
                declared_purpose: "Phase 8 e2e test".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            // THE ATTACK: payload key differs from intent.target.
            payload: OperationPayload::Write {
                key: b"balance/victim".to_vec(),
                value: b"stolen_funds".to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: agent_id,
                when: CausalTimestamp::genesis(),
                r#where: target,
                why: CausalJustification {
                    invoking_rule: [1u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "Phase 8 e2e test".into(),
            },
            nonce: 1,
            signature: vec![],
        };

        let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
        tx.tx_id = blake3_hash(&canonical);
        tx.signature = sccgub_crypto::signature::sign(&chain.validator_key, &canonical);

        chain.submit_transition(tx).expect("submit should succeed");
        let block = chain.produce_block().expect("block should succeed");

        // The tx must be FILTERED by Phase 8 payload consistency check.
        assert_eq!(
            block.body.transitions.len(),
            0,
            "Payload-mismatched tx must be filtered by Phase 8. \
             If this fails, the payload consistency check is not wired."
        );

        // N-3: Rejected receipts are captured when txs pass mempool drain
        // but fail gas-metered validation. In this test, the tx fails at
        // mempool drain (Phase 8 runs inside validate_transition), so
        // no receipt reaches the gas loop. The rejected_receipts field
        // captures gas-loop rejections specifically.
    }

    #[test]
    fn test_responsibility_tracked_across_blocks() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;

        // Produce a few blocks (empty — but responsibility tracking runs).
        for _ in 0..5 {
            chain.produce_block().unwrap();
        }

        // Validator's responsibility state should exist and have decayed.
        // (Empty blocks produce no transitions, so the validator only gets
        // decay applied, not positive contributions.)
        // But the responsibility map should be populated once any agent acts.

        // The map starts empty because no transactions have been submitted.
        // This test verifies the decay path runs without panic.
        assert!(
            chain.responsibility.is_empty()
                || chain.responsibility.values().all(|r| {
                    r.net_responsibility.raw().unsigned_abs()
                        <= TensionValue::from_integer(1000).raw().unsigned_abs()
                }),
            "Responsibility must be bounded (INV-13)"
        );
    }

    #[test]
    fn test_n9_what_actual_populated_for_write_tx() {
        // N-9 closure test: accepted Write transitions must have non-empty
        // what_actual in their receipt after block production.
        use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
        use sccgub_types::governance::PrecedenceLevel;
        use sccgub_types::mfidel::MfidelAtomicSeal;
        use sccgub_types::timestamp::CausalTimestamp;
        use sccgub_types::transition::*;
        use std::collections::BTreeSet;

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;

        // Build a properly signed Write transaction.
        let pk = *chain.validator_key.verifying_key().as_bytes();
        let seal = MfidelAtomicSeal::from_height(0);
        let agent_id = sccgub_state::apply::validator_spend_account(chain.block_version, &pk);
        let agent = AgentIdentity {
            agent_id,
            public_key: pk,
            mfidel_seal: seal,
            registration_block: 0,
            governance_level: PrecedenceLevel::Meaning,
            norm_set: BTreeSet::new(),
            responsibility: ResponsibilityState::default(),
        };

        let target = b"data/n9/test".to_vec();
        let mut tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: agent,
            intent: TransitionIntent {
                kind: TransitionKind::StateWrite,
                target: target.clone(),
                declared_purpose: "N-9 test".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: target.clone(),
                value: b"hello_n9".to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: agent_id,
                when: CausalTimestamp::genesis(),
                r#where: target,
                why: CausalJustification {
                    invoking_rule: [1u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "N-9 test".into(),
            },
            nonce: 1,
            signature: vec![],
        };

        let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
        tx.tx_id = blake3_hash(&canonical);
        tx.signature = sccgub_crypto::signature::sign(&chain.validator_key, &canonical);

        chain.submit_transition(tx).expect("submit should succeed");

        let block = chain
            .produce_block()
            .expect("block production should succeed")
            .clone();
        let rejects: Vec<_> = chain
            .latest_rejected_receipts
            .iter()
            .map(|r| format!("{:?}", r.verdict))
            .collect();

        // The block should have exactly 1 accepted transition.
        assert_eq!(
            block.body.transitions.len(),
            1,
            "Write tx must be accepted (rejects: {:?})",
            rejects
        );

        // N-9: The receipt's what_actual must contain the actual writes.
        assert_eq!(block.receipts.len(), 1);
        let receipt = &block.receipts[0];
        assert!(
            receipt.verdict.is_accepted(),
            "Write tx receipt must be accepted"
        );
        assert!(
            !receipt.wh_binding.what_actual.writes.is_empty(),
            "N-9: what_actual.writes must be populated for accepted Write tx"
        );
        let payload_write = receipt
            .wh_binding
            .what_actual
            .writes
            .iter()
            .find(|write| write.address == b"data/n9/test".to_vec())
            .expect("N-9: what_actual must include the payload write alongside economics writes");
        assert_eq!(
            payload_write.value,
            b"hello_n9".to_vec(),
            "N-9: what_actual must record the actual write value"
        );
    }

    #[test]
    fn test_execute_slashing_penalty_debits_balance() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;

        let pk = *chain.validator_key.verifying_key().as_bytes();
        let spend_account = sccgub_state::apply::validator_spend_account(chain.block_version, &pk);
        let initial_balance = chain.balances.balance_of(&spend_account);
        assert!(
            initial_balance.raw() > 0,
            "Validator must have genesis balance"
        );

        // Execute a slashing penalty of 100 tokens.
        let penalty = TensionValue::from_integer(100);
        let actual = chain.execute_slashing_penalty(&spend_account, penalty);
        assert_eq!(actual, penalty, "Full penalty should be applied");

        let after = chain.balances.balance_of(&spend_account);
        assert_eq!(
            after,
            initial_balance - penalty,
            "Balance must decrease by penalty amount"
        );
    }

    #[test]
    fn test_execute_slashing_penalty_capped_at_balance() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;

        let pk = *chain.validator_key.verifying_key().as_bytes();
        let spend_account = sccgub_state::apply::validator_spend_account(chain.block_version, &pk);
        let initial_balance = chain.balances.balance_of(&spend_account);

        // Request penalty larger than balance.
        let huge_penalty = initial_balance + TensionValue::from_integer(999_999);
        let actual = chain.execute_slashing_penalty(&spend_account, huge_penalty);
        assert_eq!(
            actual, initial_balance,
            "Penalty must be capped at available balance"
        );

        let after = chain.balances.balance_of(&spend_account);
        assert_eq!(after, TensionValue::ZERO, "Balance must be zeroed");
    }

    #[test]
    fn test_fork_choice_prefers_higher_finalized_height() {
        let mut chain_a = Chain::init();
        chain_a.governance_limits.max_consecutive_proposals = 100;
        let mut chain_b = Chain::init();
        chain_b.governance_limits.max_consecutive_proposals = 100;
        // Make chain_b same chain_id as chain_a.
        chain_b.chain_id = chain_a.chain_id;

        // Both at height 0, finalized 0. No switch.
        assert!(
            !chain_a.should_switch_to(&chain_b),
            "Equal chains: no switch"
        );

        // Advance chain_b's finalized height.
        chain_b.finality.finalized_height = 5;
        assert!(
            chain_a.should_switch_to(&chain_b),
            "Higher finalized height: should switch"
        );

        // Chain_a has higher finalized.
        chain_a.finality.finalized_height = 10;
        assert!(
            !chain_a.should_switch_to(&chain_b),
            "Lower finalized height: no switch"
        );
    }

    #[test]
    fn test_bft_fork_choice_refuses_equal_finality_switch() {
        let mut chain_a = Chain::init();
        let mut chain_b = Chain::init();
        chain_b.chain_id = chain_a.chain_id;

        chain_a.state.state.governance_state.finality_mode = FinalityMode::BftCertified {
            quorum_threshold: 2,
        };
        chain_b.state.state.governance_state.finality_mode = FinalityMode::BftCertified {
            quorum_threshold: 2,
        };
        chain_a.finality.finalized_height = 5;
        chain_b.finality.finalized_height = 5;

        assert!(
            !chain_a.should_switch_to(&chain_b),
            "BFT finality tie: should not switch"
        );
    }

    #[test]
    fn test_fork_choice_rejects_different_chain_id() {
        let chain_a = Chain::init();
        let chain_b = Chain::init(); // Different chain_id (random keys).
        assert!(
            !chain_a.should_switch_to(&chain_b),
            "Different chain_id: never switch"
        );
    }

    #[test]
    fn test_fork_choice_deterministic_equal_finality_prefers_higher_height() {
        let mut chain_a = Chain::init();
        chain_a.governance_limits.max_consecutive_proposals = 100;
        let mut chain_b = chain_a.clone();

        // Both are Deterministic mode (default). Same finalized height.
        chain_a.finality.finalized_height = 3;
        chain_b.finality.finalized_height = 3;

        // chain_b has more total blocks.
        for _ in 0..5 {
            chain_b.produce_block().unwrap();
        }
        assert!(
            chain_a.should_switch_to(&chain_b),
            "Equal finality, higher total height: should switch"
        );
        assert!(
            !chain_b.should_switch_to(&chain_a),
            "Equal finality, lower total height: should not switch"
        );
    }

    #[test]
    fn patch_06_fork_choice_uses_score_cmp_lexicographic_ordering() {
        // INV-FORK-CHOICE-DETERMINISM regression fence. Confirm that
        // Chain::should_switch_to routes through the §32
        // (finalized_depth, cumulative_voting_power, tie_break_hash)
        // ordering. Higher finalized_depth wins regardless of height,
        // matching the lexicographic rule (primary component dominates).
        let mut chain_a = Chain::init();
        chain_a.governance_limits.max_consecutive_proposals = 100;
        let mut chain_b = chain_a.clone();

        // chain_a: more blocks (bigger cumulative "work") but lower finalized depth.
        for _ in 0..10 {
            chain_a.produce_block().unwrap();
        }
        chain_a.finality.finalized_height = 2;

        // chain_b: fewer blocks but higher finalized depth. Per §32's
        // primary-component ordering, chain_b outscores chain_a — deep
        // finality beats raw block count.
        chain_b.finality.finalized_height = 5;

        assert!(
            chain_a.should_switch_to(&chain_b),
            "§32 primary component: higher finalized_depth must win over higher height"
        );
        assert!(
            !chain_b.should_switch_to(&chain_a),
            "§32 primary component: lower finalized_depth must lose"
        );
    }

    #[test]
    fn test_fork_choice_deterministic_equal_finality_equal_height_no_switch() {
        let mut chain_a = Chain::init();
        chain_a.governance_limits.max_consecutive_proposals = 100;
        let chain_b = chain_a.clone();

        // Same finality, same height → incumbency advantage.
        assert!(
            !chain_a.should_switch_to(&chain_b),
            "Equal everything: incumbency advantage, no switch"
        );
    }

    #[test]
    fn test_fork_choice_mixed_finality_mode_refuses_switch() {
        let mut chain_a = Chain::init();
        let mut chain_b = chain_a.clone();

        // chain_a is BFT, chain_b is Deterministic.
        chain_a.state.state.governance_state.finality_mode = FinalityMode::BftCertified {
            quorum_threshold: 2,
        };
        // chain_b stays Deterministic (default).
        chain_a.finality.finalized_height = 5;
        chain_b.finality.finalized_height = 5;

        // Mixed mode with tied finality: should NOT switch (at least one is BFT).
        assert!(
            !chain_a.should_switch_to(&chain_b),
            "Mixed finality mode with tied finality: no switch"
        );
    }

    /// CONSERVATION INVARIANT: total token supply must not change across
    /// block production. Tokens can move between accounts (transfers, fees,
    /// rewards) but the treasury accounting identity must hold:
    ///   balances + pending_fees + burned + distributed = genesis + collected
    #[test]
    fn test_token_conservation_across_block_production() {
        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;

        let genesis_supply = chain.balances.total_supply();
        assert!(
            genesis_supply.raw() > 0,
            "Genesis must mint a non-zero supply"
        );

        // Produce 5 blocks. The fee/reward/treasury cycle runs each block.
        // Even empty blocks exercise the economics path.
        for i in 1..=5 {
            chain.produce_block().unwrap();
            // Treasury accounting identity:
            //   balances + pending + burned = genesis + (collected - distributed)
            // Because distributed tokens go back into balances.
            let lhs = chain.balances.total_supply().raw()
                + chain.treasury.pending_fees.raw()
                + chain.treasury.total_burned.raw();
            let rhs = genesis_supply.raw() + chain.treasury.total_fees_collected.raw()
                - chain.treasury.total_rewards_distributed.raw();
            assert_eq!(
                lhs, rhs,
                "Conservation violated at block {}: balances={}, pending={}, burned={}, collected={}, distributed={}",
                i,
                chain.balances.total_supply(),
                chain.treasury.pending_fees,
                chain.treasury.total_burned,
                chain.treasury.total_fees_collected,
                chain.treasury.total_rewards_distributed,
            );
        }
    }

    /// REPLAY DETERMINISM: two chains built from identical blocks must produce
    /// identical state roots. This is the fundamental consistency property.
    #[test]
    fn test_replay_determinism_with_transactions() {
        use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
        use sccgub_types::governance::PrecedenceLevel;
        use sccgub_types::mfidel::MfidelAtomicSeal;
        use sccgub_types::timestamp::CausalTimestamp;
        use sccgub_types::transition::*;
        use std::collections::BTreeSet;

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;

        // Submit and produce a block with a real tx.
        let pk = *chain.validator_key.verifying_key().as_bytes();
        let seal = MfidelAtomicSeal::from_height(1);
        let agent_id =
            blake3_hash_concat(&[&pk, &sccgub_crypto::canonical::canonical_bytes(&seal)]);
        let mut tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor: AgentIdentity {
                agent_id,
                public_key: pk,
                mfidel_seal: seal,
                registration_block: 0,
                governance_level: PrecedenceLevel::Meaning,
                norm_set: BTreeSet::new(),
                responsibility: ResponsibilityState::default(),
            },
            intent: TransitionIntent {
                kind: TransitionKind::StateWrite,
                target: b"data/replay/test".to_vec(),
                declared_purpose: "replay test".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: b"data/replay/test".to_vec(),
                value: b"deterministic".to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: agent_id,
                when: CausalTimestamp::genesis(),
                r#where: b"data/replay/test".to_vec(),
                why: CausalJustification {
                    invoking_rule: [1u8; 32],
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "replay test".into(),
            },
            nonce: 1,
            signature: vec![],
        };
        let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
        tx.tx_id = blake3_hash(&canonical);
        tx.signature = sccgub_crypto::signature::sign(&chain.validator_key, &canonical);

        chain.submit_transition(tx).unwrap();
        chain.produce_block().unwrap();

        // Produce 2 more empty blocks.
        chain.produce_block().unwrap();
        chain.produce_block().unwrap();

        let blocks = chain.blocks.clone();
        let root_a = chain.state.state_root();

        // Replay from blocks.
        let chain_b = Chain::from_blocks(blocks).expect("replay must succeed");
        let root_b = chain_b.state.state_root();

        assert_eq!(
            root_a, root_b,
            "Replayed chain must produce identical state root"
        );
        assert_eq!(chain.height(), chain_b.height());
        assert_eq!(
            chain.balances.total_supply(),
            chain_b.balances.total_supply(),
            "Replayed chain must have identical balance supply"
        );
    }

    #[test]
    fn test_batch_nonce_multiple_txs_per_block() {
        use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
        use sccgub_types::governance::PrecedenceLevel;
        use sccgub_types::mfidel::MfidelAtomicSeal;
        use sccgub_types::timestamp::CausalTimestamp;
        use sccgub_types::transition::*;
        use std::collections::BTreeSet;

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;
        chain.mempool.containment.hostility_threshold =
            sccgub_types::tension::TensionValue::from_integer(1_000_000);

        let actor_key = chain.validator_key.clone();
        let actor_pk = *actor_key.verifying_key().as_bytes();
        let actor_id = sccgub_state::apply::validator_spend_account(chain.block_version, &actor_pk);

        // Submit 5 transactions with sequential nonces (1..=5) before producing a block.
        let tx_count = 5u128;
        for nonce in 1..=tx_count {
            let target = format!("data/batch/{}", nonce).into_bytes();
            let mut tx = SymbolicTransition {
                tx_id: [0u8; 32],
                actor: AgentIdentity {
                    agent_id: actor_id,
                    public_key: actor_pk,
                    mfidel_seal: MfidelAtomicSeal::from_height(0),
                    registration_block: 0,
                    governance_level: PrecedenceLevel::Meaning,
                    norm_set: BTreeSet::new(),
                    responsibility: ResponsibilityState::default(),
                },
                intent: TransitionIntent {
                    kind: TransitionKind::StateWrite,
                    target: target.clone(),
                    declared_purpose: format!("batch nonce test #{}", nonce),
                },
                preconditions: vec![],
                postconditions: vec![],
                payload: OperationPayload::Write {
                    key: target.clone(),
                    value: format!("val_{}", nonce).into_bytes(),
                },
                causal_chain: vec![],
                wh_binding_intent: WHBindingIntent {
                    who: actor_id,
                    when: CausalTimestamp::genesis(),
                    r#where: target,
                    why: CausalJustification {
                        invoking_rule: [1u8; 32],
                        precedence_level: PrecedenceLevel::Meaning,
                        causal_ancestors: vec![],
                        constraint_proof: vec![],
                    },
                    how: TransitionMechanism::DirectStateWrite,
                    which: BTreeSet::new(),
                    what_declared: format!("batch nonce test #{}", nonce),
                },
                nonce,
                signature: vec![],
            };

            let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
            tx.tx_id = blake3_hash(&canonical);
            tx.signature = sccgub_crypto::signature::sign(&actor_key, &canonical);

            chain
                .submit_transition(tx)
                .unwrap_or_else(|e| panic!("submit nonce {} failed: {}", nonce, e));
        }

        // All 5 txs should be included in a single block.
        let block = chain
            .produce_block()
            .expect("block production should succeed")
            .clone();

        assert_eq!(
            block.body.transitions.len(),
            tx_count as usize,
            "All {} txs with sequential nonces must be included in one block (got {})",
            tx_count,
            block.body.transitions.len()
        );
        assert_eq!(
            block.receipts.len(),
            tx_count as usize,
            "Each included tx must have a receipt"
        );
        for receipt in &block.receipts {
            assert!(
                receipt.verdict.is_accepted(),
                "All batch txs should be accepted, got: {:?}",
                receipt.verdict
            );
        }
    }

    // ── import_block tests (B-6) ─────────────────────────────────

    #[test]
    fn test_import_block_succeeds_for_valid_empty_block() {
        // Use build_candidate_block (no mutation) then import into a clone.
        let chain = Chain::init();
        let block = chain.build_candidate_block().unwrap();

        let mut importer = chain.clone();
        let result = importer.import_block(block.clone());
        assert!(
            result.is_ok(),
            "import of valid block should succeed: {:?}",
            result.err()
        );
        assert_eq!(importer.height(), 1);
        assert_eq!(
            importer.latest_block().unwrap().header.block_id,
            block.header.block_id
        );
    }

    #[test]
    fn test_import_block_rejects_wrong_height() {
        let mut producer = Chain::init();
        producer.produce_block().unwrap();
        let block_2 = producer.build_candidate_block().unwrap();

        // importer is at height 0, block_2 is for height 2 → mismatch.
        let mut importer = Chain::from_blocks(vec![producer.blocks[0].clone()]).unwrap();
        let result = importer.import_block(block_2);
        assert!(result.is_err(), "should reject height mismatch");
        let err = result.unwrap_err();
        assert!(
            err.to_lowercase().contains("height"),
            "error should mention height: {}",
            err
        );
    }

    #[test]
    fn test_import_block_rejects_wrong_parent_hash() {
        let chain = Chain::init();
        let mut block = chain.build_candidate_block().unwrap();
        block.header.parent_id = [0xFFu8; 32]; // Corrupt parent hash.

        let mut importer = chain.clone();
        let result = importer.import_block(block);
        assert!(result.is_err(), "should reject parent hash mismatch");
        let err = result.unwrap_err();
        assert!(
            err.to_lowercase().contains("parent"),
            "error should mention parent: {}",
            err
        );
    }

    #[test]
    fn test_import_block_double_import_same_block_fails() {
        let chain = Chain::init();
        let block = chain.build_candidate_block().unwrap();

        let mut importer = chain.clone();
        importer.import_block(block.clone()).unwrap();
        // Second import of same block: height now wrong (expects 2, got 1).
        let result = importer.import_block(block);
        assert!(result.is_err(), "should reject double import");
    }

    #[test]
    fn test_import_block_advances_finality() {
        let mut producer = Chain::init();
        producer.governance_limits.max_consecutive_proposals = 100;
        // Produce enough blocks for finality to advance (default confirmation_depth + 1).
        for _ in 0..5 {
            producer.produce_block().unwrap();
        }

        // Import all produced blocks into a chain cloned from genesis.
        let mut importer = Chain::from_blocks(vec![producer.blocks[0].clone()]).unwrap();
        importer.governance_limits.max_consecutive_proposals = 100;
        for block in &producer.blocks[1..] {
            importer.import_block(block.clone()).unwrap();
        }
        assert_eq!(importer.height(), producer.height());
        // Finality should match between producer and importer.
        assert_eq!(
            importer.finality.finalized_height, producer.finality.finalized_height,
            "imported chain finality should match producer"
        );
    }

    // ───────────────────────────────────────────────────────────────────
    // N-55: Bounded evidence collections (CRITICAL memory-DoS defenses).
    // ───────────────────────────────────────────────────────────────────

    #[test]
    fn test_equivocation_records_bounded_to_max() {
        use sccgub_consensus::protocol::{EquivocationProof, VoteType};

        let mut chain = Chain::init();
        let cap = Chain::MAX_EQUIVOCATION_RECORDS;
        // Insert cap + 100 distinct proofs.  Each proof must be unique along
        // at least one dedup key (we vary `height`) so they are all kept.
        for i in 0..(cap as u64 + 100) {
            let proof = EquivocationProof {
                validator_id: [1u8; 32],
                height: i,
                round: 0,
                vote_type: VoteType::Prevote,
                block_hash_a: [2u8; 32],
                block_hash_b: [3u8; 32],
            };
            chain.record_equivocation(proof, 0);
        }
        // Ledger must not exceed the cap.
        assert_eq!(chain.equivocation_records.len(), cap);
        // The oldest (lowest height) entries must have been evicted.
        let min_kept_height = chain
            .equivocation_records
            .iter()
            .map(|(p, _)| p.height)
            .min()
            .unwrap();
        assert!(
            min_kept_height >= 100,
            "lowest retained height should be >= 100, got {}",
            min_kept_height
        );
    }

    #[test]
    fn test_equivocation_records_dedup_still_works_at_cap() {
        use sccgub_consensus::protocol::{EquivocationProof, VoteType};

        let mut chain = Chain::init();
        let proof = EquivocationProof {
            validator_id: [7u8; 32],
            height: 42,
            round: 1,
            vote_type: VoteType::Precommit,
            block_hash_a: [8u8; 32],
            block_hash_b: [9u8; 32],
        };
        // Insert the same proof 10 times — dedup must keep it at 1 entry.
        for _ in 0..10 {
            chain.record_equivocation(proof.clone(), 3);
        }
        assert_eq!(chain.equivocation_records.len(), 1);
    }

    #[test]
    fn test_safety_certificates_pruned_to_max() {
        let mut chain = Chain::init();
        let cap = Chain::MAX_SAFETY_CERTIFICATES;
        // Feed cap + 50 unique certs with increasing heights.
        for i in 0..(cap as u64 + 50) {
            let cert = SafetyCertificate {
                chain_id: [0u8; 32],
                epoch: 0,
                height: i,
                block_hash: [(i % 251) as u8; 32],
                round: 0,
                precommit_signatures: vec![],
                quorum: 1,
                validator_count: 1,
            };
            chain.record_safety_certificate(cert);
        }
        assert_eq!(chain.safety_certificates.len(), cap);
        // The retained certs must be the newest (highest-height) ones.
        let min_kept_height = chain
            .safety_certificates
            .iter()
            .map(|c| c.height)
            .min()
            .unwrap();
        assert!(
            min_kept_height >= 50,
            "lowest retained safety cert height should be >= 50, got {}",
            min_kept_height
        );
    }
}
