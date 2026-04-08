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
    pub finality: FinalityTracker,
    pub finality_config: FinalityConfig,
    pub slashing: SlashingEngine,
}

impl Chain {
    /// Create a new chain with a genesis block.
    pub fn init() -> Self {
        let validator_key = generate_keypair();
        let pk = *validator_key.verifying_key().as_bytes();
        let seal = MfidelAtomicSeal::from_height(0);
        // Agent ID = Hash(pubkey ++ seal) — canonical derivation matching validate.rs.
        let validator_id = blake3_hash_concat(&[&pk, &canonical_bytes(&seal)]);
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
        let balance_key = format!("balance/{}", hex::encode(validator_id)).into_bytes();
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
            finality: FinalityTracker::default(),
            finality_config: FinalityConfig::default(),
            slashing,
        };

        chain.state.set_height(0);
        chain
    }

    /// Reconstruct a chain from loaded blocks (replay state).
    pub fn from_blocks(blocks: Vec<Block>) -> Self {
        let validator_key = generate_keypair();
        let chain_id = blocks
            .first()
            .map(|b| b.header.chain_id)
            .unwrap_or(blake3_hash(b"sccgub-genesis-chain"));

        let mut state = ManagedWorldState::new();
        state.state.governance_state = GovernanceState {
            finality_mode: FinalityMode::Deterministic,
            ..GovernanceState::default()
        };

        // Replay genesis mint + write to trie.
        let mut balances = BalanceLedger::new();
        if let Some(genesis) = blocks.first() {
            balances.credit(
                &genesis.header.validator_id,
                TensionValue::from_integer(1_000_000),
            );
            let balance_key =
                format!("balance/{}", hex::encode(genesis.header.validator_id)).into_bytes();
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
        }

        // Replay all block transitions using shared apply function (single source of truth).
        for block in &blocks {
            sccgub_state::apply::apply_block_transitions(
                &mut state,
                &mut balances,
                &block.body.transitions,
            );
            for tx in &block.body.transitions {
                if let Err(e) = state.check_nonce(&tx.actor.agent_id, tx.nonce) {
                    tracing::warn!(
                        "Nonce error during replay at height {}: {}",
                        block.header.height,
                        e
                    );
                }
            }
            state.set_height(block.header.height);
        }

        // Rebuild finality tracker from chain history.
        let mut finality = FinalityTracker::default();
        let finality_config = FinalityConfig::default();
        if let Some(last) = blocks.last() {
            finality.on_new_block(last.header.height);
            finality.check_finality(&finality_config, |h| {
                blocks.get(h as usize).map(|b| b.header.block_id)
            });
        }

        Chain {
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
            finality,
            finality_config,
            slashing: SlashingEngine::new(Default::default()),
        }
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
        let validator_id_for_check = blake3_hash_concat(&[
            self.validator_key.verifying_key().as_bytes(),
            &canonical_bytes(&MfidelAtomicSeal::from_height(0)),
        ]);
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
            }
            // Rejected txs are silently dropped from the block
            // (their receipts are not included — only accepted txs are committed).
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

                // Update finality tracker.
                self.finality.on_new_block(height);
                let blocks_ref = &self.blocks;
                let _new_finals = self.finality.check_finality(&self.finality_config, |h| {
                    blocks_ref.get(h as usize).map(|b| b.header.block_id)
                });

                // Record validator presence (resets absence counter).
                self.slashing.record_presence(&validator_id_for_check);

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

    let proof = CausalProof {
        block_height: 0,
        transitions_proven: vec![],
        phi_traversal_log: PhiTraversalLog::new(),
        governance_snapshot_hash: header.governance_hash,
        tension_before: TensionValue::ZERO,
        tension_after: TensionValue::ZERO,
        constraint_results: vec![],
        recursion_depth: 0,
        validator_signature: sign(validator_key, &header_data),
        causal_hash: blake3_hash(b"genesis-proof"),
    };

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

    let proof = CausalProof {
        block_height: height,
        transitions_proven: vec![],
        phi_traversal_log: PhiTraversalLog::default(),
        governance_snapshot_hash: header.governance_hash,
        tension_before,
        tension_after: tension_before,
        constraint_results: vec![],
        recursion_depth: 0,
        validator_signature: sign(validator_key, &header_bytes),
        causal_hash: blake3_hash_concat(&[&parent_id, &transition_root]),
    };

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
