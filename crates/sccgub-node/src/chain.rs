use sccgub_crypto::canonical::{canonical_bytes, canonical_hash};
use sccgub_crypto::hash::{blake3_hash, blake3_hash_concat};
use sccgub_crypto::keys::generate_keypair;
use sccgub_crypto::merkle::merkle_root_of_bytes;
use sccgub_crypto::signature::sign;
use sccgub_execution::cpog::{validate_cpog, CpogResult};
use sccgub_execution::gas::{self, BlockGasMeter};
use sccgub_execution::validate::validate_transition_metered;
use sccgub_state::balances::BalanceLedger;
use sccgub_state::treasury::Treasury;
use sccgub_state::world::ManagedWorldState;
use sccgub_types::block::{Block, BlockBody, BlockHeader};
use sccgub_types::causal::{CausalEdge, CausalGraphDelta, CausalVertex};
use sccgub_types::economics::EconomicState;
use sccgub_types::governance::{FinalityMode, GovernanceSnapshot, GovernanceState};
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::proof::{CausalProof, PhiTraversalLog};
use sccgub_types::receipt::CausalReceipt;
use sccgub_types::tension::TensionValue;
use sccgub_types::timestamp::CausalTimestamp;
use sccgub_types::transition::SymbolicTransition;
use sccgub_types::{Hash, MerkleRoot, ZERO_HASH};

use sccgub_consensus::finality::{FinalityConfig, FinalityTracker};
use sccgub_consensus::slashing::SlashingEngine;
use sccgub_governance::anti_concentration::{GovernanceLimits, GovernancePowerTracker};

use crate::mempool::Mempool;

/// The chain — manages blocks, state, consensus, and block production.
pub struct Chain {
    pub blocks: Vec<Block>,
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
    /// Event log for the most recently produced block.
    pub latest_events: sccgub_types::events::BlockEventLog,
    /// Rejected transaction receipts from the most recent block production.
    pub latest_rejected_receipts: Vec<sccgub_types::receipt::CausalReceipt>,
    /// Per-agent responsibility state (Φ²-R causal accounting).
    pub responsibility:
        std::collections::HashMap<sccgub_types::AgentId, sccgub_types::agent::ResponsibilityState>,
}

impl Chain {
    /// Create a new chain with a genesis block.
    pub fn init() -> Self {
        let validator_key = generate_keypair();
        let pk = *validator_key.verifying_key().as_bytes();
        // validator_id = public_key directly (Position A).
        // This enables real Ed25519 verification at import without a registry.
        // Key rotation requires a Constitutional governance proposal.
        let validator_id = pk;
        let chain_id = blake3_hash(b"sccgub-genesis-chain");

        let mut state = ManagedWorldState::new();
        state.state.governance_state = GovernanceState {
            finality_mode: FinalityMode::Deterministic,
            ..GovernanceState::default()
        };

        let genesis = build_genesis_block(chain_id, validator_id, &validator_key);

        // Mint initial supply to the validator (genesis allocation).
        let mut balances = BalanceLedger::new();
        balances.credit(&validator_id, TensionValue::from_integer(1_000_000));

        // Write genesis balances into state trie for unified commitment.
        let balance_key = sccgub_types::namespace::balance_key(&validator_id);
        state.apply_delta(&sccgub_types::transition::StateDelta {
            writes: vec![sccgub_types::transition::StateWrite {
                address: balance_key,
                value: TensionValue::from_integer(1_000_000)
                    .raw()
                    .to_le_bytes()
                    .to_vec(),
            }],
            deletes: vec![],
        });

        // Initialize slashing engine with validator stake.
        let mut slashing = SlashingEngine::new(Default::default());
        slashing.set_stake(validator_id, TensionValue::from_integer(100_000));

        let mut chain = Chain {
            blocks: vec![genesis],
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
            latest_events: sccgub_types::events::BlockEventLog::new(),
            latest_rejected_receipts: Vec::new(),
            responsibility: std::collections::HashMap::new(),
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
        verify_producer_signature(genesis).map_err(ImportError::GenesisSignature)?;

        // CPoG on genesis against empty state.
        let empty_state = ManagedWorldState::new();
        match validate_cpog(genesis, &empty_state, &sccgub_types::ZERO_HASH) {
            CpogResult::Valid => {}
            CpogResult::Invalid { errors } => return Err(ImportError::Cpog { height: 0, errors }),
        }

        let mut state = ManagedWorldState::new();
        state.state.governance_state = GovernanceState {
            finality_mode: FinalityMode::Deterministic,
            ..GovernanceState::default()
        };

        // Replay genesis mint.
        let mut balances = BalanceLedger::new();
        balances.credit(
            &genesis.header.validator_id,
            TensionValue::from_integer(1_000_000),
        );
        let balance_key = sccgub_types::namespace::balance_key(&genesis.header.validator_id);
        state.apply_delta(&sccgub_types::transition::StateDelta {
            writes: vec![sccgub_types::transition::StateWrite {
                address: balance_key,
                value: TensionValue::from_integer(1_000_000)
                    .raw()
                    .to_le_bytes()
                    .to_vec(),
            }],
            deletes: vec![],
        });
        state.set_height(0);

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
            state.set_height(block.header.height);
        }

        // Rebuild finality tracker.
        let mut finality = FinalityTracker::default();
        let finality_config = FinalityConfig::default();
        if let Some(last) = blocks.last() {
            finality.on_new_block(last.header.height);
            finality.check_finality(&finality_config, |h| {
                blocks.get(h as usize).map(|b| b.header.block_id)
            });
        }

        Ok(Chain {
            blocks,
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
            finality,
            finality_config,
            slashing: SlashingEngine::new(Default::default()),
            latest_events: sccgub_types::events::BlockEventLog::new(),
            latest_rejected_receipts: Vec::new(),
            responsibility: std::collections::HashMap::new(),
        })
    }

    /// Submit a transition to the mempool.
    /// Returns Err if the agent is quarantined or the tx is a duplicate.
    pub fn submit_transition(&mut self, tx: SymbolicTransition) -> Result<(), String> {
        self.mempool.add(tx)
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
        if let Err(e) = self
            .power_tracker
            .check_proposal(&validator_id_for_check, &self.governance_limits)
        {
            return Err(format!("Anti-concentration: {}", e));
        }

        // Collect validated transitions from mempool.
        let transitions = self.mempool.drain_validated(&self.state);

        // Gas-metered admission: validate each tx with gas accounting,
        // enforce per-block gas limit, reject failed transfers and bad nonces.
        let mut block_gas = BlockGasMeter::default_block();
        let mut filter_state = self.state.clone();
        let filter_balances = self.balances.clone();
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
            // Pre-filter: check transfer solvency.
            if let sccgub_types::transition::OperationPayload::AssetTransfer { from, to, amount } =
                &tx.payload
            {
                let mut test_bal = filter_balances.clone();
                if test_bal.transfer(from, to, TensionValue(*amount)).is_err() {
                    continue;
                }
            }
            // Pre-filter: nonce must be valid.
            if filter_state
                .check_nonce(&tx.actor.agent_id, tx.nonce)
                .is_err()
            {
                continue;
            }

            // Gas-metered validation — produces a typed receipt for every tx.
            let (receipt, gas_used) =
                validate_transition_metered(&tx, &filter_state, gas::costs::DEFAULT_TX_LIMIT);

            // Only include if the block gas limit allows it.
            if !block_gas.can_fit(gas_used) {
                break; // Block is full.
            }

            if receipt.verdict.is_accepted() {
                block_gas.record_tx(gas_used);

                // Charge fee: gas_used * gas_price → treasury.
                let fee = TensionValue((gas_used as i128).saturating_mul(gas_price.raw()));
                self.treasury.collect_fee(fee);
                self.economics.record_fee(fee);

                accepted_transitions.push(tx);
                metered_receipts.push(receipt);
            } else {
                // Rejected txs get receipts too — on-chain evidence of consideration.
                // Users can query the receipt to see why their tx was rejected.
                rejected_receipts.push(receipt);
            }
        }
        let transitions = accepted_transitions;

        // Distribute block reward to validator (from accumulated treasury fees).
        let block_reward = TensionValue::from_integer(10); // 10 tokens per block.
        let actual_reward = self.treasury.distribute_reward(block_reward);
        if actual_reward.raw() > 0 {
            self.balances.credit(&validator_id_for_check, actual_reward);
        }

        // Apply accepted transitions using shared function (single source of truth).
        let mut speculative_state = self.state.clone();
        let mut speculative_balances = self.balances.clone();
        sccgub_state::apply::apply_block_transitions(
            &mut speculative_state,
            &mut speculative_balances,
            &transitions,
        );
        for tx in &transitions {
            if let Err(e) = speculative_state.check_nonce(&tx.actor.agent_id, tx.nonce) {
                tracing::error!("Nonce invariant violation in block production: {}", e);
            }
        }
        speculative_state.set_height(height);

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
            validator_key: &self.validator_key,
            transitions,
            receipts: metered_receipts,
            state: &speculative_state,
            balance_root,
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

                // Commit speculative state and balances.
                self.state = speculative_state;
                self.balances = speculative_balances;
                self.blocks.push(block);

                // Finalize governance proposals whose voting period has ended.
                // Accepted proposals enter timelock, then activate after the delay.
                let _accepted = self.proposals.finalize(height);
                // Activate proposals whose timelock has expired.
                for proposal in self.proposals.proposals.clone() {
                    if proposal.status == sccgub_governance::proposals::ProposalStatus::Timelocked
                        && height >= proposal.timelock_until
                    {
                        if let Ok(Some(norm)) = self.proposals.activate(&proposal.id, height) {
                            // Register the activated norm in governance state.
                            self.state
                                .state
                                .governance_state
                                .active_norms
                                .insert(norm.id, norm);
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
                if self.treasury.epoch_fees.raw() > 0 {
                    events.emit(sccgub_types::events::ChainEvent::FeeCharged {
                        tx_id: [0u8; 32], // Block-level aggregate.
                        payer: validator_id_for_check,
                        amount: self.treasury.epoch_fees,
                        gas_used: block_gas.used,
                    });
                }
                if actual_reward.raw() > 0 {
                    events.emit(sccgub_types::events::ChainEvent::RewardDistributed {
                        block_height: height,
                        validator: validator_id_for_check,
                        amount: actual_reward,
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
        for (agent_id, nonce) in &snapshot.agent_nonces {
            self.state.agent_nonces.insert(*agent_id, *nonce);
        }
        self.state.set_height(snapshot.height);

        // Restore balances.
        self.balances = BalanceLedger::new();
        for (agent_id, raw_balance) in &snapshot.balances {
            self.balances.credit(agent_id, TensionValue(*raw_balance));
        }

        // Restore treasury.
        self.treasury.pending_fees = TensionValue(snapshot.treasury_pending_raw);
        self.treasury.total_fees_collected = TensionValue(snapshot.treasury_collected_raw);
        self.treasury.total_rewards_distributed = TensionValue(snapshot.treasury_distributed_raw);
        self.treasury.total_burned = TensionValue(snapshot.treasury_burned_raw);
        self.treasury.epoch = snapshot.treasury_epoch;

        // Restore finality.
        self.finality.finalized_height = snapshot.finalized_height;
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

/// Errors that can occur during chain import. Every variant is fatal —
/// there is no "partial import" mode.
#[derive(Debug)]
pub enum ImportError {
    Empty,
    FirstBlockNotGenesis,
    GenesisSignature(String),
    ProducerSignature { height: u64, reason: String },
    ChainIdMismatch { height: u64 },
    Cpog { height: u64, errors: Vec<String> },
    NonceViolation { height: u64, detail: String },
}

impl std::fmt::Display for ImportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "cannot import an empty block list"),
            Self::FirstBlockNotGenesis => write!(f, "first block is not genesis"),
            Self::GenesisSignature(e) => write!(f, "genesis signature invalid: {}", e),
            Self::ProducerSignature { height, reason } => {
                write!(f, "producer sig invalid at height {}: {}", height, reason)
            }
            Self::ChainIdMismatch { height } => {
                write!(f, "chain_id mismatch at height {}", height)
            }
            Self::Cpog { height, errors } => {
                write!(f, "CPoG failed at height {}: {}", height, errors.join("; "))
            }
            Self::NonceViolation { height, detail } => {
                write!(f, "nonce violation at height {}: {}", height, detail)
            }
        }
    }
}

impl std::error::Error for ImportError {}

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
    validator_key: &ed25519_dalek::SigningKey,
) -> Block {
    let timestamp = CausalTimestamp::genesis();
    let seal = MfidelAtomicSeal::from_height(0);
    let governance = GovernanceSnapshot {
        state_hash: ZERO_HASH,
        active_norm_count: 0,
        emergency_mode: false,
        finality_mode: FinalityMode::Deterministic,
    };

    let header_data = sccgub_crypto::canonical::canonical_bytes(&("genesis", &chain_id));
    let block_id = blake3_hash(&header_data);

    let header = BlockHeader {
        chain_id,
        block_id,
        parent_id: ZERO_HASH,
        height: 0,
        timestamp,
        state_root: ZERO_HASH,
        transition_root: ZERO_HASH,
        receipt_root: ZERO_HASH,
        causal_root: ZERO_HASH,
        proof_root: ZERO_HASH,
        governance_hash: canonical_hash(&governance),
        tension_before: TensionValue::ZERO,
        tension_after: TensionValue::ZERO,
        mfidel_seal: seal,
        balance_root: ZERO_HASH, // No balances at genesis block creation time.
        validator_id,
        version: 1,
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
    validator_key: &'a ed25519_dalek::SigningKey,
    transitions: Vec<SymbolicTransition>,
    receipts: Vec<CausalReceipt>,
    state: &'a ManagedWorldState,
    balance_root: Hash,
}

fn build_block(params: BlockBuildParams<'_>) -> Block {
    let BlockBuildParams {
        chain_id,
        height,
        parent_id,
        parent_timestamp,
        validator_id,
        validator_key,
        transitions,
        receipts,
        state,
        balance_root,
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
        version: 1,
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

    #[test]
    fn test_chain_init_produces_genesis() {
        let chain = Chain::init();
        assert_eq!(chain.height(), 0);
        assert!(chain.latest_block().is_some());
        let genesis = chain.latest_block().unwrap();
        assert_eq!(genesis.header.height, 0);
        assert_eq!(genesis.header.parent_id, ZERO_HASH);
        assert!(chain.balances.total_supply().raw() > 0);
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
        chain.produce_block().unwrap();
        chain.produce_block().unwrap();

        let snapshot = chain.create_snapshot();
        let original_root = chain.state.state_root();
        let original_supply = chain.balances.total_supply();

        let mut chain2 = Chain::init();
        chain2.restore_from_snapshot(&snapshot);

        assert_eq!(chain2.state.state_root(), original_root);
        assert_eq!(chain2.balances.total_supply(), original_supply);
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
        // Flow: validate_transition → phi_traversal_tx → phase_constraint
        //       → scce_validate → propagate_constraints → UNSAT → reject
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

        // 4. Produce a block. The tx should be FILTERED by the SCCE
        //    constraint during drain_validated → validate_transition →
        //    phi_traversal_tx → phase_constraint → scce_validate →
        //    propagate_constraints → UNSAT.
        let block = chain
            .produce_block()
            .expect("block production should succeed");

        // 5. Assert: the block has ZERO transactions because the
        //    constrained tx was rejected during validation.
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
}
