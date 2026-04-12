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
use sccgub_state::world::{
    commit_consensus_params, consensus_params_from_trie, ManagedWorldState,
};
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
use std::time::{SystemTime, UNIX_EPOCH};

use sccgub_consensus::finality::{FinalityConfig, FinalityTracker};
use sccgub_consensus::protocol::EquivocationProof;
use sccgub_consensus::slashing::SlashingEngine;
use sccgub_governance::anti_concentration::{GovernanceLimits, GovernancePowerTracker};

use crate::mempool::Mempool;

fn initialize_genesis_state(
    block_version: u32,
    validator_public_key: &[u8; 32],
    consensus_params: ConsensusParams,
) -> (ManagedWorldState, BalanceLedger) {
    let mut state = ManagedWorldState::with_consensus_params(consensus_params);
    state.state.governance_state = GovernanceState {
        finality_mode: FinalityMode::Deterministic,
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

pub(crate) fn balance_root_from_ledger(balances: &BalanceLedger) -> Hash {
    let mut bal_entries: Vec<_> = balances.balances.iter().collect();
    bal_entries.sort_by_key(|(k, _)| *k);
    if bal_entries.is_empty() {
        ZERO_HASH
    } else {
        let mut hasher_data = Vec::new();
        for (agent_id, balance) in &bal_entries {
            hasher_data.extend_from_slice(*agent_id);
            hasher_data.extend_from_slice(&balance.raw().to_le_bytes());
        }
        blake3_hash(&hasher_data)
    }
}

fn load_genesis_consensus_params(genesis: &Block) -> Result<ConsensusParams, ImportError> {
    match genesis.body.genesis_consensus_params.as_ref() {
        Some(bytes) => {
            ConsensusParams::from_canonical_bytes(bytes).map_err(ImportError::GenesisConsensusParams)
        }
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

    fn init_with_consensus_params(block_version: u32, consensus_params: ConsensusParams) -> Self {
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
        let (state, balances) =
            initialize_genesis_state(block_version, &validator_id, consensus_params);
        let genesis = build_genesis_block(
            chain_id,
            validator_id,
            block_version,
            &validator_key,
            state.state_root(),
            balance_root_from_ledger(&balances),
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
                let expected_balance_root = balance_root_from_ledger(&balances);
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
                if genesis.header.state_root != ZERO_HASH || genesis.header.balance_root != ZERO_HASH
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

            // 4. Apply transitions to running state (after validation succeeded).
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
            for tx in &block.body.transitions {
                if let Err(e) = state.check_nonce(&tx.actor.agent_id, tx.nonce) {
                    return Err(ImportError::NonceViolation {
                        height: block.header.height,
                        detail: e,
                    });
                }
            }
            if block.header.height % 100 == 0 {
                treasury.advance_epoch();
                commit_treasury_state(&mut state, &treasury);
            }
            state.set_height(block.header.height);

            // Apply governance activations during replay (restart-safe).
            for tx in &block.body.transitions {
                if let sccgub_types::transition::OperationPayload::ProposeNorm {
                    name,
                    description,
                } = &tx.payload
                {
                    if let Err(e) = proposals.submit(
                        tx.actor.agent_id,
                        tx.actor.governance_level,
                        sccgub_governance::proposals::ProposalKind::AddNorm {
                            name: name.clone(),
                            description: description.clone(),
                            initial_fitness: sccgub_types::tension::TensionValue::from_integer(5),
                            enforcement_cost: sccgub_types::tension::TensionValue::from_integer(1),
                        },
                        block.header.height,
                        5,
                    ) {
                        tracing::warn!("Replay proposal submit failed: {}", e);
                    }
                }
                if tx.intent.kind == sccgub_types::transition::TransitionKind::GovernanceUpdate {
                    if let sccgub_types::transition::OperationPayload::Write { key, value } =
                        &tx.payload
                    {
                        if key.starts_with(b"norms/governance/params/propose") {
                            if let Some((param_key, param_value)) =
                                parse_governance_param_write(value)
                            {
                                if let Err(e) = proposals.submit(
                                    tx.actor.agent_id,
                                    tx.actor.governance_level,
                                    sccgub_governance::proposals::ProposalKind::ModifyParameter {
                                        key: param_key,
                                        value: param_value,
                                    },
                                    block.header.height,
                                    5,
                                ) {
                                    tracing::warn!("Replay parameter proposal failed: {}", e);
                                }
                            }
                        }
                        if key.starts_with(b"governance/proposals/")
                            || key.starts_with(b"norms/governance/proposals/")
                        {
                            if let Ok(proposal_id) =
                                <[u8; 32]>::try_from(&value[..])
                            {
                                let _ = proposals.vote(
                                    &proposal_id,
                                    tx.actor.agent_id,
                                    tx.actor.governance_level,
                                    true,
                                    block.header.height,
                                );
                            }
                        }
                    }
                }
            }
            let _accepted = proposals.finalize(block.header.height);
            for proposal in proposals.proposals.clone() {
                if proposal.status
                    == sccgub_governance::proposals::ProposalStatus::Timelocked
                    && block.header.height >= proposal.timelock_until
                {
                    match proposals.activate(&proposal.id, block.header.height) {
                        Ok(Some(norm)) => {
                            state
                                .state
                                .governance_state
                                .active_norms
                                .insert(norm.id, norm);
                        }
                        Ok(None) => match proposal.kind {
                            sccgub_governance::proposals::ProposalKind::DeactivateNorm {
                                norm_id,
                            } => {
                                if let Some(mut norm) =
                                    state.state.governance_state.active_norms.get(&norm_id).cloned()
                                {
                                    norm.active = false;
                                    state
                                        .state
                                        .governance_state
                                        .active_norms
                                        .insert(norm_id, norm);
                                }
                            }
                            sccgub_governance::proposals::ProposalKind::ModifyParameter {
                                ref key,
                                ref value,
                            } => {
                                if let Err(e) = apply_governance_parameter_static(
                                    &mut governance_limits,
                                    &mut finality_config,
                                    key,
                                    value,
                                ) {
                                    tracing::warn!(
                                        "Governance parameter update rejected: {}",
                                        e
                                    );
                                }
                            }
                            sccgub_governance::proposals::ProposalKind::ActivateEmergency => {
                                state.state.governance_state.emergency_mode = true;
                            }
                            sccgub_governance::proposals::ProposalKind::DeactivateEmergency => {
                                state.state.governance_state.emergency_mode = false;
                            }
                            sccgub_governance::proposals::ProposalKind::AddNorm { .. } => {}
                        },
                        Err(e) => {
                            tracing::warn!("Proposal activation failed: {}", e);
                        }
                    }
                }
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
            finality.check_finality(&finality_config, |h| {
                blocks.get(h as usize).map(|b| b.header.block_id)
            });
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
            validator_set: Vec::new(),
            latest_events: sccgub_types::events::BlockEventLog::new(),
            latest_rejected_receipts: Vec::new(),
            responsibility: std::collections::HashMap::new(),
            api_bridge: None,
        })
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

    /// Record equivocation evidence (deduplicated by proof fields + epoch).
    pub fn record_equivocation(&mut self, proof: EquivocationProof, epoch: u64) {
        let (block_a, block_b) = if proof.block_hash_a <= proof.block_hash_b {
            (proof.block_hash_a, proof.block_hash_b)
        } else {
            (proof.block_hash_b, proof.block_hash_a)
        };
        let duplicate = self.equivocation_records.iter().any(|(existing, existing_epoch)| {
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
            app.pending_txs = pending_txs.clone();
            app.seen_tx_ids = pending_txs.iter().map(|tx| tx.tx_id).collect();
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
    pub fn validate_candidate_block(&self, block: &Block) -> Result<(), String> {
        let parent = self.blocks.last().ok_or("No blocks in chain")?;
        if block.header.height != parent.header.height + 1 {
            return Err(format!(
                "Block height mismatch: expected {}, got {}",
                parent.header.height + 1,
                block.header.height
            ));
        }
        if block.header.parent_id != parent.header.block_id {
            return Err("Parent hash mismatch".into());
        }
        if block.header.chain_id != self.chain_id {
            return Err("Chain ID mismatch".into());
        }
        if block.header.version != self.block_version {
            return Err("Block version mismatch".into());
        }
        if !self.validator_set.is_empty() {
            let expected = sccgub_governance::validator::round_robin_proposer(
                &self.validator_set,
                block.header.height,
            )
            .ok_or("No active proposer for height")?;
            if expected.node_id != block.header.validator_id {
                return Err(format!(
                    "Proposer mismatch: expected {}, got {}",
                    hex::encode(expected.node_id),
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

    /// Import an externally produced block (validated and applied).
    pub fn import_block(&mut self, block: Block) -> Result<(), String> {
        self.validate_candidate_block(&block)?;

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
        for tx in &block.body.transitions {
            self.state
                .check_nonce(&tx.actor.agent_id, tx.nonce)
                .map_err(|e| format!("Nonce violation: {}", e))?;
        }
        if block.header.height % 100 == 0 {
            self.treasury.advance_epoch();
            commit_treasury_state(&mut self.state, &self.treasury);
        }
        self.state.set_height(block.header.height);

        // Mark included tx IDs as confirmed in mempool.
        let confirmed: Vec<_> = block.body.transitions.iter().map(|tx| tx.tx_id).collect();
        self.mempool.mark_confirmed(&confirmed);

        // Record proposer for anti-concentration tracking.
        self.power_tracker.record_proposal(&block.header.validator_id);
        if block.header.height % 100 == 0 {
            self.power_tracker.reset_epoch();
            self.economics.reset_epoch();
        }

        // Update finality tracker.
        self.finality.on_new_block(block.header.height);
        let blocks_ref = &self.blocks;
        self.finality.check_finality(&self.finality_config, |h| {
            blocks_ref.get(h as usize).map(|b| b.header.block_id)
        });

        // Record validator presence (resets absence counter).
        self.slashing.record_presence(&block.header.validator_id);

        self.blocks.push(block);
        self.maybe_sync_api_bridge(self.mempool.pending_snapshot());
        Ok(())
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

    /// Produce a new block from mempool transactions.
    /// Speculatively applies state to compute post-transition state root.
    /// Enforces anti-concentration limits on consecutive proposals.
    pub fn produce_block(&mut self) -> Result<&Block, String> {
        let parent = self.blocks.last().ok_or("No blocks in chain")?;
        let parent_id = parent.header.block_id;
        let height = parent.header.height + 1;

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
                if tx.nonce == 0 || tx.nonce != last + 1 {
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
                    tracing::error!("Nonce filter drift during block production: {}", e);
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
        for tx in &transitions {
            if let Err(e) = speculative_state.check_nonce(&tx.actor.agent_id, tx.nonce) {
                tracing::error!("Nonce invariant violation in block production: {}", e);
            }
        }
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
        let post_root = speculative_state.state_root();
        for receipt in &mut metered_receipts {
            if let Err(e) = sccgub_execution::validate::seal_receipt_post_state(receipt, post_root)
            {
                tracing::error!(
                    "Failed to seal receipt {}: {}",
                    hex::encode(receipt.tx_id),
                    e
                );
            }
        }

        // Use same canonical derivation as validator_id_for_check (line 178).
        let validator_id = validator_id_for_check;

        // Compute balance root: sort by agent_id for determinism, hash concatenation.
        let mut bal_entries: Vec<_> = speculative_balances.balances.iter().collect();
        bal_entries.sort_by_key(|(k, _)| *k);
        let balance_root = if bal_entries.is_empty() {
            ZERO_HASH
        } else {
            let mut hasher_data = Vec::new();
            for (agent_id, balance) in &bal_entries {
                hasher_data.extend_from_slice(*agent_id);
                hasher_data.extend_from_slice(&balance.raw().to_le_bytes());
            }
            blake3_hash(&hasher_data)
        };

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
                self.maybe_sync_api_bridge(self.mempool.pending_snapshot());

                // Apply governance transitions from block payloads (live chain).
                for tx in &self.blocks.last().unwrap().body.transitions {
                    if let sccgub_types::transition::OperationPayload::ProposeNorm {
                        name,
                        description,
                    } = &tx.payload
                    {
                        if let Err(e) = self.proposals.submit(
                            tx.actor.agent_id,
                            tx.actor.governance_level,
                            sccgub_governance::proposals::ProposalKind::AddNorm {
                                name: name.clone(),
                                description: description.clone(),
                                initial_fitness: sccgub_types::tension::TensionValue::from_integer(
                                    5,
                                ),
                                enforcement_cost: sccgub_types::tension::TensionValue::from_integer(
                                    1,
                                ),
                            },
                            height,
                            5,
                        ) {
                            tracing::warn!("Proposal submit failed: {}", e);
                        }
                    }
                    if tx.intent.kind
                        == sccgub_types::transition::TransitionKind::GovernanceUpdate
                    {
                        if let sccgub_types::transition::OperationPayload::Write { key, value } =
                            &tx.payload
                        {
                            if key.starts_with(b"norms/governance/params/propose") {
                                if let Some((param_key, param_value)) =
                                    parse_governance_param_write(value)
                                {
                                    if let Err(e) = self.proposals.submit(
                                        tx.actor.agent_id,
                                        tx.actor.governance_level,
                                        sccgub_governance::proposals::ProposalKind::ModifyParameter {
                                            key: param_key,
                                            value: param_value,
                                        },
                                        height,
                                        5,
                                    ) {
                                        tracing::warn!("Parameter proposal failed: {}", e);
                                    }
                                }
                            }
                            if key.starts_with(b"governance/proposals/")
                                || key.starts_with(b"norms/governance/proposals/")
                            {
                                if let Ok(proposal_id) = <[u8; 32]>::try_from(&value[..]) {
                                    let _ = self.proposals.vote(
                                        &proposal_id,
                                        tx.actor.agent_id,
                                        tx.actor.governance_level,
                                        true,
                                        height,
                                    );
                                }
                            }
                        }
                    }
                }

                // Finalize governance proposals whose voting period has ended.
                // Accepted proposals enter timelock, then activate after the delay.
                let _accepted = self.proposals.finalize(height);
                // Activate proposals whose timelock has expired.
                for proposal in self.proposals.proposals.clone() {
                    if proposal.status == sccgub_governance::proposals::ProposalStatus::Timelocked
                        && height >= proposal.timelock_until
                    {
                        match self.proposals.activate(&proposal.id, height) {
                            Ok(Some(norm)) => {
                                // Register the activated norm in governance state.
                                self.state
                                    .state
                                    .governance_state
                                    .active_norms
                                    .insert(norm.id, norm);
                            }
                            Ok(None) => match proposal.kind {
                                sccgub_governance::proposals::ProposalKind::DeactivateNorm {
                                    norm_id,
                                } => {
                                    if let Some(mut norm) = self
                                        .state
                                        .state
                                        .governance_state
                                        .active_norms
                                        .get(&norm_id)
                                        .cloned()
                                    {
                                        norm.active = false;
                                        self.state
                                            .state
                                            .governance_state
                                            .active_norms
                                            .insert(norm_id, norm);
                                    }
                                }
                                sccgub_governance::proposals::ProposalKind::ModifyParameter {
                                    ref key,
                                    ref value,
                                } => {
                                    if let Err(e) = self.apply_governance_parameter(key, value) {
                                        tracing::warn!(
                                            "Governance parameter update rejected: {}",
                                            e
                                        );
                                    }
                                }
                                sccgub_governance::proposals::ProposalKind::ActivateEmergency => {
                                    self.state.state.governance_state.emergency_mode = true;
                                }
                                sccgub_governance::proposals::ProposalKind::DeactivateEmergency => {
                                    self.state.state.governance_state.emergency_mode = false;
                                }
                                sccgub_governance::proposals::ProposalKind::AddNorm { .. } => {}
                            },
                            Err(e) => {
                                tracing::warn!("Proposal activation failed: {}", e);
                            }
                        }
                    }
                }

                // N-7: Record governance actions for anti-concentration tracking.
                for tx in &self.blocks.last().unwrap().body.transitions {
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
                self.finality.on_new_block(height);
                let blocks_ref = &self.blocks;
                let _new_finals = self.finality.check_finality(&self.finality_config, |h| {
                    blocks_ref.get(h as usize).map(|b| b.header.block_id)
                });

                // Record validator presence (resets absence counter).
                self.slashing.record_presence(&validator_id_for_check);

                // Emit chain events for this block.
                let mut events = sccgub_types::events::BlockEventLog::new();

                // Emit events for each accepted transition.
                for tx in &self.blocks.last().unwrap().body.transitions {
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
                for ((tx, receipt), (payer, fee)) in self
                    .blocks
                    .last()
                    .unwrap()
                    .body
                    .transitions
                    .iter()
                    .zip(self.blocks.last().unwrap().receipts.iter())
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

                // Emit finality event if new blocks were finalized.
                if self.finality.finalized_height > 0 {
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
                for tx in &self.blocks.last().unwrap().body.transitions {
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

                Ok(self.blocks.last().unwrap())
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
            governance_limits: self.governance_limits.clone(),
            finality_config: self.finality_config.clone(),
        }
    }

    /// Restore chain state from a snapshot (fast load — no block replay needed).
    pub fn restore_from_snapshot(&mut self, snapshot: &crate::persistence::StateSnapshot) {
        // Clear and rebuild trie.
        self.state = ManagedWorldState::new();
        self.state.state.governance_state = GovernanceState {
            finality_mode: FinalityMode::Deterministic,
            ..GovernanceState::default()
        };
        for (key, value) in &snapshot.trie_entries {
            self.state.trie.insert(key.clone(), value.clone());
        }
        self.state.consensus_params = consensus_params_from_trie(&self.state)
            .unwrap_or_else(|_| None)
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
        self.treasury = treasury_from_trie(&self.state).unwrap_or_else(|_| Treasury {
            pending_fees: TensionValue(snapshot.treasury_pending_raw),
            total_fees_collected: TensionValue(snapshot.treasury_collected_raw),
            total_rewards_distributed: TensionValue(snapshot.treasury_distributed_raw),
            total_burned: TensionValue(snapshot.treasury_burned_raw),
            epoch: snapshot.treasury_epoch,
            epoch_fees: TensionValue::ZERO,
            epoch_rewards: TensionValue::ZERO,
        });

        // Restore finality.
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
        self.governance_limits = snapshot.governance_limits.clone();
        self.finality_config = snapshot.finality_config.clone();
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

    fn apply_governance_parameter(&mut self, key: &str, value: &str) -> Result<(), String> {
        apply_governance_parameter_static(
            &mut self.governance_limits,
            &mut self.finality_config,
            key,
            value,
        )
    }
}

fn governance_limits_snapshot_from(
    limits: &GovernanceLimits,
) -> GovernanceLimitsSnapshot {
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
        _ => Err(format!("Unknown governance parameter key: {}", key)),
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
        active_norm_count: state.state.governance_state.active_norms.len() as u32,
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

    let transition_count = transitions.len() as u32;
    Block {
        header,
        body: BlockBody {
            transitions,
            transition_count,
            total_tension_delta: TensionValue::ZERO,
            constraint_satisfaction: vec![],
            genesis_consensus_params: None,
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
        assert_eq!(
            genesis.header.balance_root,
            balance_root_from_ledger(&chain.balances)
        );
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
            replayed.latest_block().unwrap().body.genesis_consensus_params,
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
        restored.restore_from_snapshot(&snapshot);

        assert_eq!(restored.state.consensus_params, params);
        assert_eq!(restored.state.state_root(), chain.state.state_root());
        assert_eq!(
            restored.state.get(&ConsensusParams::TRIE_KEY.to_vec()),
            Some(&embedded)
        );
        assert_eq!(restored.balances.total_supply(), chain.balances.total_supply());
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
        let balance_root = balance_root_from_ledger(&chain.balances);
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

        let err = chain.validate_candidate_block(&block).unwrap_err();
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
        chain2.restore_from_snapshot(&snapshot);

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
        let snapshot_balance_root = balance_root_from_ledger(&ledger);
        assert_eq!(snapshot_balance_root, tip.header.balance_root);

        let mut replayed = Chain::from_blocks(chain.blocks.clone())
            .expect("from_blocks should succeed for valid chain");
        replayed.restore_from_snapshot(&snapshot);
        assert_eq!(replayed.state.state_root(), tip.header.state_root);
        assert_eq!(balance_root_from_ledger(&replayed.balances), tip.header.balance_root);
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
        use std::collections::HashSet;

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
                norm_set: HashSet::new(),
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
                which: HashSet::new(),
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
        use std::collections::HashSet;

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
                norm_set: HashSet::new(),
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
                which: HashSet::new(),
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
        chain2.restore_from_snapshot(&snapshot);
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

        let key = sccgub_execution::scce::constraint_key(b"test/symbol", b"c0");
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
        use std::collections::HashSet;

        let mut chain = Chain::init();
        chain.governance_limits.max_consecutive_proposals = 100;

        // 1. Plant an unsatisfiable constraint at "test/constrained".
        let constraint = sccgub_execution::scce::constraint_key(b"test/constrained", b"c0");
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
            norm_set: HashSet::new(),
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
                which: HashSet::new(),
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
    fn test_governance_parameter_update_via_transitions() {
        use sccgub_governance::proposals::ProposalStatus;
        use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
        use sccgub_types::governance::PrecedenceLevel;
        use sccgub_types::mfidel::MfidelAtomicSeal;
        use sccgub_types::timestamp::CausalTimestamp;
        use sccgub_types::transition::*;
        use std::collections::HashSet;

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
            norm_set: HashSet::new(),
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
                which: HashSet::new(),
                what_declared: "Propose finality depth update".into(),
            },
            nonce: 1,
            signature: vec![],
        };
        let propose_canonical = sccgub_execution::validate::canonical_tx_bytes(&propose_tx);
        propose_tx.tx_id = blake3_hash(&propose_canonical);
        propose_tx.signature = sccgub_crypto::signature::sign(&chain.validator_key, &propose_canonical);

        chain.submit_transition(propose_tx).expect("proposal submit should succeed");
        let proposal_block = chain.produce_block().expect("proposal block should succeed");
        assert!(
            !proposal_block.body.transitions.is_empty(),
            "proposal transition must be included in produced block"
        );

        let proposal_id = chain
            .proposals
            .proposals
            .iter()
            .find(|proposal| matches!(proposal.kind, sccgub_governance::proposals::ProposalKind::ModifyParameter { .. }))
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
                which: HashSet::new(),
                what_declared: "Vote for governance proposal".into(),
            },
            nonce: 2,
            signature: vec![],
        };
        let vote_canonical = sccgub_execution::validate::canonical_tx_bytes(&vote_tx);
        vote_tx.tx_id = blake3_hash(&vote_canonical);
        vote_tx.signature = sccgub_crypto::signature::sign(&chain.validator_key, &vote_canonical);

        chain.submit_transition(vote_tx).expect("vote submit should succeed");
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
    fn test_phase8_rejects_payload_target_mismatch() {
        // End-to-end witness: proves Phase 8 payload consistency check
        // is wired into the production path. If check_payload_consistency
        // were replaced with `return Consistent`, this test would fail.
        use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
        use sccgub_types::governance::PrecedenceLevel;
        use sccgub_types::mfidel::MfidelAtomicSeal;
        use sccgub_types::timestamp::CausalTimestamp;
        use sccgub_types::transition::*;
        use std::collections::HashSet;

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
                norm_set: HashSet::new(),
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
                which: HashSet::new(),
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
        use std::collections::HashSet;

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
            norm_set: HashSet::new(),
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
                which: HashSet::new(),
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
}
