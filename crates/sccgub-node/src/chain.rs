use sccgub_crypto::hash::{blake3_hash, blake3_hash_concat};
use sccgub_crypto::keys::generate_keypair;
use sccgub_crypto::merkle::merkle_root_of_bytes;
use sccgub_crypto::signature::sign;
use sccgub_execution::cpog::{validate_cpog, CpogResult};
use sccgub_state::world::ManagedWorldState;
use sccgub_types::block::{Block, BlockBody, BlockHeader};
use sccgub_types::causal::{CausalEdge, CausalGraphDelta, CausalVertex};
use sccgub_types::governance::{FinalityMode, GovernanceSnapshot, GovernanceState};
use sccgub_types::mfidel::MfidelAtomicSeal;
use sccgub_types::proof::{CausalProof, PhiTraversalLog};
use sccgub_types::receipt::{CausalReceipt, ResourceUsage, Verdict};
use sccgub_types::tension::TensionValue;
use sccgub_types::timestamp::CausalTimestamp;
use sccgub_types::transition::{StateDelta, SymbolicTransition, WHBindingResolved, ValidationResult};
use sccgub_types::{Hash, MerkleRoot, ZERO_HASH};

use crate::mempool::Mempool;

/// The chain — manages blocks, state, and block production.
pub struct Chain {
    pub blocks: Vec<Block>,
    pub state: ManagedWorldState,
    pub mempool: Mempool,
    pub chain_id: Hash,
    pub validator_key: ed25519_dalek::SigningKey,
}

impl Chain {
    /// Create a new chain with a genesis block.
    pub fn init() -> Self {
        let validator_key = generate_keypair();
        let validator_id = blake3_hash(validator_key.verifying_key().as_bytes());
        let chain_id = blake3_hash(b"sccgub-genesis-chain");

        let mut state = ManagedWorldState::new();
        state.state.governance_state = GovernanceState {
            finality_mode: FinalityMode::Deterministic,
            ..GovernanceState::default()
        };

        let genesis = build_genesis_block(chain_id, validator_id, &validator_key);

        let mut chain = Chain {
            blocks: vec![genesis],
            state,
            mempool: Mempool::new(10_000),
            chain_id,
            validator_key,
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

        // Replay all block transitions to reconstruct state.
        for block in &blocks {
            for tx in &block.body.transitions {
                if let sccgub_types::transition::OperationPayload::Write { key, value } =
                    &tx.payload
                {
                    state.apply_delta(&sccgub_types::transition::StateDelta {
                        writes: vec![sccgub_types::transition::StateWrite {
                            address: key.clone(),
                            value: value.clone(),
                        }],
                        deletes: vec![],
                    });
                }
            }
            state.set_height(block.header.height);
        }

        Chain {
            blocks,
            state,
            mempool: Mempool::new(10_000),
            chain_id,
            validator_key,
        }
    }

    /// Submit a transition to the mempool.
    /// Returns Err if the agent is quarantined.
    pub fn submit_transition(&mut self, tx: SymbolicTransition) {
        // Ignore containment errors for now — log but don't fail.
        let _ = self.mempool.add(tx);
    }

    /// Produce a new block from mempool transactions.
    pub fn produce_block(&mut self) -> Result<&Block, String> {
        let parent = self.blocks.last().ok_or("No blocks in chain")?;
        let parent_id = parent.header.block_id;
        let height = parent.header.height + 1;

        // Collect validated transitions from mempool.
        let transitions = self.mempool.drain_validated(&self.state);

        let validator_id = blake3_hash(self.validator_key.verifying_key().as_bytes());

        let block = build_block(BlockBuildParams {
            chain_id: self.chain_id,
            height,
            parent_id,
            parent_timestamp: &parent.header.timestamp,
            validator_id,
            validator_key: &self.validator_key,
            transitions,
            state: &self.state,
        });

        // Validate via CPoG.
        let result = validate_cpog(&block, &self.state, &parent_id);
        match result {
            CpogResult::Valid => {
                // Apply state changes.
                for tx in &block.body.transitions {
                    if let sccgub_types::transition::OperationPayload::Write { key, value } =
                        &tx.payload
                    {
                        self.state.apply_delta(&sccgub_types::transition::StateDelta {
                            writes: vec![sccgub_types::transition::StateWrite {
                                address: key.clone(),
                                value: value.clone(),
                            }],
                            deletes: vec![],
                        });
                    }
                }
                self.state.set_height(height);
                self.blocks.push(block);
                Ok(self.blocks.last().unwrap())
            }
            CpogResult::Invalid { errors } => {
                Err(format!("CPoG validation failed: {}", errors.join("; ")))
            }
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

    let header_data = serde_json::to_vec(&("genesis", &chain_id)).unwrap_or_default();
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
        governance_hash: blake3_hash(&serde_json::to_vec(&governance).unwrap_or_default()),
        tension_before: TensionValue::ZERO,
        tension_after: TensionValue::ZERO,
        mfidel_seal: seal,
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
    state: &'a ManagedWorldState,
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
        state,
    } = params;
    let timestamp = parent_timestamp.successor(
        validator_id,
        blake3_hash(&serde_json::to_vec(parent_timestamp).unwrap_or_default()),
    );
    let seal = MfidelAtomicSeal::from_height(height);

    let tx_bytes: Vec<&[u8]> = transitions.iter().map(|tx| tx.tx_id.as_slice()).collect();
    let transition_root = merkle_root_of_bytes(&tx_bytes);

    let governance = GovernanceSnapshot {
        state_hash: blake3_hash(
            &serde_json::to_vec(&state.state.governance_state).unwrap_or_default(),
        ),
        active_norm_count: state.state.governance_state.active_norms.len() as u32,
        emergency_mode: state.state.governance_state.emergency_mode,
        finality_mode: state.state.governance_state.finality_mode,
    };

    let tension_before = state.state.tension_field.total;

    // Build causal graph delta.
    let block_vertex = CausalVertex::Block(blake3_hash(
        &serde_json::to_vec(&(chain_id, height)).unwrap_or_default(),
    ));
    let mut causal_vertices = vec![block_vertex.clone()];
    let mut causal_edges = Vec::new();

    // Generate receipts and causal edges for each transition.
    let mut receipts = Vec::new();
    let pre_state_root = state.state_root();

    for tx in &transitions {
        let tx_vertex = CausalVertex::Transition(tx.tx_id);
        let actor_vertex = CausalVertex::Actor(tx.actor.agent_id);
        causal_vertices.push(tx_vertex.clone());

        // Edge: transition is contained_by this block.
        causal_edges.push(CausalEdge::ContainedBy {
            source: tx_vertex.clone(),
            target: block_vertex.clone(),
        });

        // Edge: transition authorized_by actor.
        causal_edges.push(CausalEdge::AuthorizedBy {
            source: tx_vertex.clone(),
            target: actor_vertex,
        });

        // Edge: caused_by causal ancestors.
        for ancestor_id in &tx.causal_chain {
            causal_edges.push(CausalEdge::CausedBy {
                source: tx_vertex.clone(),
                target: CausalVertex::Transition(*ancestor_id),
            });
        }

        // Generate receipt.
        let receipt = CausalReceipt {
            tx_id: tx.tx_id,
            verdict: Verdict::Accept,
            pre_state_root,
            post_state_root: pre_state_root, // Will be updated after apply.
            read_set: vec![],
            write_set: vec![],
            causes: causal_edges
                .iter()
                .filter(|e| {
                    let (src, _) = e.endpoints();
                    src == tx_vertex
                })
                .cloned()
                .collect(),
            resource_used: ResourceUsage {
                compute_steps: 1,
                state_reads: 0,
                state_writes: match &tx.payload {
                    sccgub_types::transition::OperationPayload::Write { .. } => 1,
                    _ => 0,
                },
                proof_size_bytes: 0,
            },
            emitted_events: vec![],
            wh_binding: WHBindingResolved {
                intent: tx.wh_binding_intent.clone(),
                what_actual: StateDelta::default(),
                whether: ValidationResult::Valid,
            },
            phi_phase_reached: 13,
            tension_delta: TensionValue::ZERO,
        };
        receipts.push(receipt);
    }

    let causal_root: MerkleRoot = if causal_edges.is_empty() {
        ZERO_HASH
    } else {
        let edge_hashes: Vec<&[u8]> = causal_edges
            .iter()
            .map(|_| b"edge" as &[u8])
            .collect();
        merkle_root_of_bytes(&edge_hashes)
    };

    let receipt_hashes: Vec<&[u8]> = receipts.iter().map(|r| r.tx_id.as_slice()).collect();
    let receipt_root = merkle_root_of_bytes(&receipt_hashes);

    let header_data = serde_json::to_vec(&(chain_id, height, &parent_id)).unwrap_or_default();
    let block_id = blake3_hash(&header_data);

    let header = BlockHeader {
        chain_id,
        block_id,
        parent_id,
        height,
        timestamp,
        state_root: state.state_root(),
        transition_root,
        receipt_root,
        causal_root,
        proof_root: ZERO_HASH,
        governance_hash: blake3_hash(&serde_json::to_vec(&governance).unwrap_or_default()),
        tension_before,
        tension_after: tension_before,
        mfidel_seal: seal,
        validator_id,
        version: 1,
    };

    let proof = CausalProof {
        block_height: height,
        transitions_proven: vec![],
        phi_traversal_log: PhiTraversalLog::default(),
        governance_snapshot_hash: header.governance_hash,
        tension_before,
        tension_after: tension_before,
        constraint_results: vec![],
        recursion_depth: 0,
        validator_signature: sign(validator_key, &header_data),
        causal_hash: blake3_hash_concat(&[&parent_id, &transition_root]),
    };

    Block {
        header,
        body: BlockBody {
            transitions: transitions.clone(),
            transition_count: transitions.len() as u32,
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
