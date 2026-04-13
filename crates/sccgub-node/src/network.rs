//! Purpose: P2P networking runtime for gossiping blocks/txs and syncing peers.
//! Governance scope: Network message handling, peer registry, block import boundary.
//! Dependencies: sccgub-network (messages/peer), sccgub-node::chain, tokio transport.
//! Invariants: length-delimited frames, chain_id/version checks, fail-closed imports.

use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio::time::{interval, Duration};

use sccgub_consensus::protocol::{
    vote_sign_data, ConsensusResult, ConsensusRound, EquivocationProof, Vote, VoteType,
};
use sccgub_consensus::safety::SafetyCertificate;
use sccgub_crypto::canonical::canonical_bytes;
use sccgub_crypto::signature::{sign, verify};
use sccgub_network::messages::{
    BlockProposalMessage, BlockRequestMessage, BlockResponseMessage, EquivocationEvidenceMessage,
    HeartbeatMessage, HelloMessage, NetworkMessage, TransactionGossipMessage,
};
use sccgub_network::peer::{PeerInfo, PeerRegistry, PeerState};
use sccgub_types::agent::ValidatorAuthority;
use sccgub_types::governance::{FinalityMode, PrecedenceLevel};
use sccgub_types::Hash;

use crate::chain::Chain;
use crate::config::NetworkConfig;

const FRAME_HEADER_LEN: usize = 4;
const MAX_SEED_PEERS: usize = 256;
const CONNECT_BACKOFF_MS: u64 = 5_000;
const EMPTY_HASH: Hash = [0u8; 32];

pub struct NetworkRuntime {
    chain: Arc<RwLock<Chain>>,
    app_state: Option<crate::api_bridge::ApiBridge>,
    config: NetworkConfig,
    store: Option<Arc<crate::persistence::ChainStore>>,
    snapshot_interval: u64,
    registry: Arc<Mutex<PeerRegistry>>,
    connections: Arc<Mutex<HashMap<String, mpsc::Sender<NetworkMessage>>>>,
    consensus_rounds: Arc<Mutex<HashMap<u64, RoundState>>>,
    pending_blocks: Arc<Mutex<HashMap<Hash, sccgub_types::block::Block>>>,
    equivocations: Arc<Mutex<HashSet<EquivocationKey>>>,
    rate_limits: Arc<Mutex<HashMap<String, RateState>>>,
    bandwidth: Arc<Mutex<HashMap<String, BandwidthState>>>,
    peer_seeds: Arc<Mutex<HashSet<String>>>,
    peer_connect_backoff: Arc<Mutex<HashMap<String, u64>>>,
    validator_set: Arc<RwLock<HashMap<Hash, [u8; 32]>>>,
    validator_key: ed25519_dalek::SigningKey,
    validator_id: Hash,
    chain_id: Hash,
}

/// Consensus round state — persisted to survive validator restarts.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct RoundState {
    round: ConsensusRound,
    last_round_ms: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistedRoundState {
    round: PersistedConsensusRound,
    last_round_ms: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct PersistedConsensusRound {
    chain_id: Hash,
    epoch: u64,
    block_hash: Hash,
    height: u64,
    round: u32,
    phase: sccgub_consensus::protocol::ConsensusPhase,
    prevotes: Vec<Vote>,
    precommits: Vec<Vote>,
    validator_set: Vec<ValidatorRecord>,
    quorum: u32,
    max_rounds: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct ValidatorRecord {
    validator_id: Hash,
    public_key: [u8; 32],
}

fn round_state_to_persisted(state: &RoundState) -> PersistedRoundState {
    let mut validator_set = Vec::new();
    for (validator_id, public_key) in &state.round.validator_set {
        validator_set.push(ValidatorRecord {
            validator_id: *validator_id,
            public_key: *public_key,
        });
    }
    let prevotes = state.round.prevotes.values().cloned().collect();
    let precommits = state.round.precommits.values().cloned().collect();
    PersistedRoundState {
        round: PersistedConsensusRound {
            chain_id: state.round.chain_id,
            epoch: state.round.epoch,
            block_hash: state.round.block_hash,
            height: state.round.height,
            round: state.round.round,
            phase: state.round.phase,
            prevotes,
            precommits,
            validator_set,
            quorum: state.round.quorum,
            max_rounds: state.round.max_rounds,
        },
        last_round_ms: state.last_round_ms,
    }
}

fn persisted_to_round_state(persisted: PersistedRoundState) -> RoundState {
    let mut validator_set = HashMap::new();
    for record in persisted.round.validator_set {
        validator_set.insert(record.validator_id, record.public_key);
    }
    let mut prevotes = HashMap::new();
    for vote in persisted.round.prevotes {
        prevotes.insert(vote.validator_id, vote);
    }
    let mut precommits = HashMap::new();
    for vote in persisted.round.precommits {
        precommits.insert(vote.validator_id, vote);
    }
    let validator_count = validator_set.len() as u32;
    RoundState {
        round: ConsensusRound {
            chain_id: persisted.round.chain_id,
            epoch: persisted.round.epoch,
            block_hash: persisted.round.block_hash,
            height: persisted.round.height,
            round: persisted.round.round,
            phase: persisted.round.phase,
            prevotes,
            precommits,
            validator_count,
            quorum: persisted.round.quorum,
            max_rounds: persisted.round.max_rounds,
            validator_set,
        },
        last_round_ms: persisted.last_round_ms,
    }
}

struct RateState {
    window_start_ms: u64,
    count: u32,
    violations: u32,
}

#[derive(Clone)]
struct BandwidthState {
    inbound_bytes: u64,
    outbound_bytes: u64,
    #[allow(dead_code)]
    window_start_ms: u64,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
struct EquivocationKey {
    validator_id: Hash,
    height: u64,
    round: u32,
    vote_type: u8,
    block_hash_a: Hash,
    block_hash_b: Hash,
    epoch: u64,
}

impl NetworkRuntime {
    pub async fn new(chain: Arc<RwLock<Chain>>, config: NetworkConfig) -> Result<Self, String> {
        let guard = chain.read().await;
        let validator_id = *guard.validator_key.verifying_key().as_bytes();
        let validator_key = guard.validator_key.clone();
        let chain_id = guard.chain_id;
        let chain_validators = guard.validator_set.clone();
        drop(guard);
        if !config.validators.is_empty() {
            let validators = Self::validators_from_config(&config)?;
            let mut guard = chain.write().await;
            guard.set_validator_set(validators);
        }
        let mut validator_set = validator_set_map(&config)?;
        if validator_set.is_empty() {
            for validator in chain_validators.iter().filter(|v| v.active) {
                validator_set.insert(validator.node_id, validator.node_id);
            }
            if validator_set.is_empty() {
                // Default single-proposer mode: treat the local validator as the
                // sole authorized signer when no explicit validator set is configured.
                validator_set.insert(validator_id, validator_id);
            }
        }
        let peer_seeds = config.peers.iter().cloned().collect::<HashSet<_>>();

        Ok(Self {
            chain,
            config,
            store: None,
            snapshot_interval: 0,
            registry: Arc::new(Mutex::new(PeerRegistry::default())),
            connections: Arc::new(Mutex::new(HashMap::new())),
            consensus_rounds: Arc::new(Mutex::new(HashMap::new())),
            pending_blocks: Arc::new(Mutex::new(HashMap::new())),
            equivocations: Arc::new(Mutex::new(HashSet::new())),
            rate_limits: Arc::new(Mutex::new(HashMap::new())),
            bandwidth: Arc::new(Mutex::new(HashMap::new())),
            peer_seeds: Arc::new(Mutex::new(peer_seeds)),
            peer_connect_backoff: Arc::new(Mutex::new(HashMap::new())),
            validator_set: Arc::new(RwLock::new(validator_set)),
            validator_key,
            validator_id,
            chain_id,
            app_state: None,
        })
    }

    pub fn with_api_bridge(mut self, bridge: crate::api_bridge::ApiBridge) -> Self {
        self.app_state = Some(bridge);
        self
    }

    pub fn with_persistence(
        mut self,
        store: Arc<crate::persistence::ChainStore>,
        snapshot_interval: u64,
    ) -> Self {
        self.store = Some(store);
        self.snapshot_interval = snapshot_interval;
        self
    }

    /// Persist current consensus round state to disk for crash recovery.
    async fn persist_consensus_state(&self) {
        if let Some(store) = &self.store {
            let rounds = self.consensus_rounds.lock().await;
            let serializable: std::collections::HashMap<u64, serde_json::Value> = rounds
                .iter()
                .filter_map(|(h, s)| {
                    serde_json::to_value(round_state_to_persisted(s))
                        .ok()
                        .map(|v| (*h, v))
                })
                .collect();
            drop(rounds);
            if let Err(e) = store.save_consensus_state(&serializable) {
                tracing::warn!("Failed to persist consensus state: {}", e);
            }
        }
    }

    pub async fn run(self: Arc<Self>) -> Result<(), String> {
        self.load_persisted_consensus_state().await;
        let listener_addr = format!("{}:{}", self.config.bind, self.config.port);
        let listener = TcpListener::bind(&listener_addr)
            .await
            .map_err(|e| format!("P2P bind {} failed: {}", listener_addr, e))?;
        tracing::info!("P2P listener online at {}", listener_addr);

        let runtime = self.clone();
        tokio::spawn(async move {
            runtime.accept_loop(listener).await;
        });

        let runtime = self.clone();
        tokio::spawn(async move {
            runtime.connect_peers_loop().await;
        });

        let runtime = self.clone();
        tokio::spawn(async move {
            runtime.heartbeat_loop().await;
        });

        let runtime = self.clone();
        tokio::spawn(async move {
            runtime.sync_loop().await;
        });

        let runtime = self.clone();
        tokio::spawn(async move {
            runtime.consensus_timeout_loop().await;
        });

        let runtime = self.clone();
        tokio::spawn(async move {
            runtime.validator_set_refresh_loop().await;
        });

        let runtime = self.clone();
        tokio::spawn(async move {
            runtime.proposer_loop().await;
        });

        let runtime = self.clone();
        tokio::spawn(async move {
            runtime.decay_loop().await;
        });

        Ok(())
    }

    async fn load_persisted_consensus_state(&self) {
        let Some(store) = &self.store else {
            return;
        };
        let persisted = match store.load_consensus_state() {
            Ok(state) => state,
            Err(e) => {
                tracing::warn!("Failed to load consensus state: {}", e);
                return;
            }
        };
        if persisted.is_empty() {
            return;
        }

        let expected_height = { self.chain.read().await.height().saturating_add(1) };
        let mut rounds = self.consensus_rounds.lock().await;
        let mut cleaned = false;
        for (height, value) in persisted {
            if height != expected_height {
                tracing::warn!(
                    "Ignoring persisted consensus round at height {} (expected {})",
                    height,
                    expected_height
                );
                continue;
            }
            match serde_json::from_value::<PersistedRoundState>(value) {
                Ok(state) => {
                    let mut round_state = persisted_to_round_state(state);
                    if round_state.round.block_hash != EMPTY_HASH {
                        let pending = self.pending_blocks.lock().await;
                        let has_block = pending.contains_key(&round_state.round.block_hash);
                        drop(pending);
                        if !has_block {
                            tracing::warn!(
                                "Clearing persisted round at height {}: missing pending block",
                                height
                            );
                            round_state.round.block_hash = EMPTY_HASH;
                            round_state.round.prevotes.clear();
                            round_state.round.precommits.clear();
                            round_state.round.phase =
                                sccgub_consensus::protocol::ConsensusPhase::Propose;
                            cleaned = true;
                        }
                    }
                    rounds.insert(height, round_state);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to deserialize consensus round at height {}: {}",
                        height,
                        e
                    );
                }
            }
        }
        drop(rounds);
        if cleaned {
            self.persist_consensus_state().await;
        }
    }

    pub fn validators_from_config(
        config: &NetworkConfig,
    ) -> Result<Vec<ValidatorAuthority>, String> {
        let mut validators = Vec::new();
        for entry in &config.validators {
            let bytes = hex::decode(entry.trim())
                .map_err(|e| format!("Validator key hex decode failed: {}", e))?;
            if bytes.len() != 32 {
                return Err(format!(
                    "Validator public key must be 32 bytes, got {}",
                    bytes.len()
                ));
            }
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            validators.push(ValidatorAuthority {
                node_id: id,
                governance_level: PrecedenceLevel::Safety,
                norm_compliance: sccgub_types::tension::TensionValue::from_integer(1),
                causal_reliability: sccgub_types::tension::TensionValue::from_integer(1),
                active: true,
            });
        }
        validators.sort_by_key(|v| v.node_id);
        Ok(validators)
    }

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    let addr_str = addr.to_string();
                    if !self.is_peer_allowed(&addr_str) {
                        tracing::warn!("P2P inbound peer {} rejected by allowlist", addr_str);
                        continue;
                    }
                    let runtime = self.clone();
                    tokio::spawn(async move {
                        runtime.handle_connection(stream, addr_str, true).await;
                    });
                }
                Err(e) => {
                    tracing::error!("P2P accept failed: {}", e);
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    }

    async fn connect_peers_loop(self: Arc<Self>) {
        let mut ticker = interval(Duration::from_millis(2_000));
        loop {
            ticker.tick().await;
            let peers = self.collect_peer_targets().await;
            for peer_addr in peers {
                if peer_addr == format!("{}:{}", self.config.bind, self.config.port) {
                    continue;
                }
                let known = { self.connections.lock().await.contains_key(&peer_addr) };
                if known {
                    continue;
                }
                let now = now_ms();
                let backoff_until = {
                    let backoff = self.peer_connect_backoff.lock().await;
                    backoff
                        .get(&peer_addr)
                        .copied()
                        .unwrap_or_default()
                        .saturating_add(CONNECT_BACKOFF_MS)
                };
                if now < backoff_until {
                    continue;
                }
                let runtime = self.clone();
                tokio::spawn(async move {
                    match TcpStream::connect(&peer_addr).await {
                        Ok(stream) => {
                            runtime.peer_connect_backoff.lock().await.remove(&peer_addr);
                            runtime.handle_connection(stream, peer_addr, false).await;
                        }
                        Err(e) => {
                            tracing::warn!("Failed to connect to {}: {}", peer_addr, e);
                            runtime
                                .peer_connect_backoff
                                .lock()
                                .await
                                .insert(peer_addr, now_ms());
                        }
                    }
                });
            }
        }
    }

    async fn handle_connection(
        self: Arc<Self>,
        stream: TcpStream,
        peer_addr: String,
        _inbound: bool,
    ) {
        let (mut reader, mut writer) = stream.into_split();
        let (tx, mut rx) = mpsc::channel::<NetworkMessage>(128);
        self.connections.lock().await.insert(peer_addr.clone(), tx);

        let outbound_usage = self.bandwidth.clone();
        let outbound_bridge = self.app_state.clone();
        let peer_for_writer = peer_addr.clone();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let payload = msg.to_bytes();
                if let Err(e) = write_frame(&mut writer, &payload).await {
                    tracing::warn!("P2P write to {} failed: {}", peer_for_writer, e);
                    break;
                }
                record_bandwidth(&outbound_usage, &peer_for_writer, 0, payload.len() as u64).await;
                if let Some(bridge) = &outbound_bridge {
                    bridge.record_bandwidth(0, payload.len() as u64);
                    bridge
                        .record_peer_bandwidth(&peer_for_writer, 0, payload.len() as u64)
                        .await;
                }
            }
        });

        let _ = self.send_hello(&peer_addr).await;

        loop {
            match read_frame(&mut reader).await {
                Ok(bytes) => match NetworkMessage::from_bytes(&bytes) {
                    Ok(message) => {
                        record_bandwidth(&self.bandwidth, &peer_addr, bytes.len() as u64, 0).await;
                        if let Some(bridge) = &self.app_state {
                            bridge.record_bandwidth(bytes.len() as u64, 0);
                            bridge
                                .record_peer_bandwidth(&peer_addr, bytes.len() as u64, 0)
                                .await;
                        }
                        self.sync_peer_stats(&peer_addr).await;
                        if let Err(e) = self.handle_message(message, &peer_addr).await {
                            tracing::warn!("P2P message handling failed: {}", e);
                            if e.starts_with("disconnect:") {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!("P2P decode failed: {}", e);
                        break;
                    }
                },
                Err(e) => {
                    tracing::warn!("P2P read failed from {}: {}", peer_addr, e);
                    break;
                }
            }
        }

        self.connections.lock().await.remove(&peer_addr);
        self.mark_peer_disconnected(&peer_addr).await;
    }

    async fn handle_message(&self, message: NetworkMessage, peer_addr: &str) -> Result<(), String> {
        let is_priority = matches!(
            message,
            NetworkMessage::ConsensusVote(_)
                | NetworkMessage::BlockProposal(_)
                | NetworkMessage::FinalityCertificate(_)
                | NetworkMessage::LawSync(_)
        );
        self.check_rate_limit(peer_addr, is_priority).await?;
        self.check_bandwidth_limit(peer_addr).await?;
        let result = match message {
            NetworkMessage::Hello(msg) => self.handle_hello(msg, peer_addr).await,
            NetworkMessage::Heartbeat(msg) => self.handle_heartbeat(msg, peer_addr).await,
            NetworkMessage::TransactionGossip(msg) => self.handle_tx_gossip(msg).await,
            NetworkMessage::BlockProposal(msg) => self.handle_block_proposal(msg).await,
            NetworkMessage::BlockRequest(msg) => self.handle_block_request(msg, peer_addr).await,
            NetworkMessage::BlockResponse(msg) => self.handle_block_response(msg).await,
            NetworkMessage::ConsensusVote(vote) => self.handle_consensus_vote(vote).await,
            NetworkMessage::EquivocationEvidence(msg) => {
                self.handle_equivocation_evidence(msg).await
            }
            NetworkMessage::FinalityCertificate(cert) => {
                self.handle_finality_certificate(cert).await
            }
            NetworkMessage::LawSync(msg) => self.handle_law_sync(msg).await,
        };
        if let Err(err) = &result {
            if self.should_penalize_error(err) {
                let banned = self.record_peer_violation(peer_addr).await;
                if banned {
                    return Err("disconnect: peer violation".into());
                }
            }
        }
        result
    }

    fn should_penalize_error(&self, err: &str) -> bool {
        err.contains("signature invalid")
            || err.contains("protocol version mismatch")
            || err.contains("epoch mismatch")
            || err.contains("not in authorized set")
            || err.contains("proposer_id mismatch")
    }

    async fn handle_hello(&self, msg: HelloMessage, peer_addr: &str) -> Result<(), String> {
        if msg.chain_id != self.chain_id {
            return Err("Hello chain_id mismatch".into());
        }
        if msg.protocol_version != self.config.protocol_version {
            return Err("Hello protocol version mismatch".into());
        }
        if msg.epoch != self.current_epoch().await {
            return Err("Hello epoch mismatch".into());
        }
        if !verify_hello_signature(&msg) {
            return Err("Hello signature invalid".into());
        }
        let validator_set = self.validator_set.read().await;
        if !validator_set.is_empty() && !validator_set.contains_key(&msg.validator_id) {
            return Err("Hello validator not in authorized set".into());
        }

        {
            let registry = self.registry.lock().await;
            if let Some(existing) = registry.peers.get(&msg.validator_id) {
                if existing.address != peer_addr && existing.state == PeerState::Connected {
                    return Err("Hello address mismatch for validator".into());
                }
            }
        }

        self.update_peer_seeds(peer_addr, &msg.known_peers).await;
        let info = PeerInfo {
            validator_id: msg.validator_id,
            address: peer_addr.to_string(),
            current_height: msg.current_height,
            finalized_height: msg.finalized_height,
            protocol_version: msg.protocol_version,
            last_seen_ms: now_ms(),
            score: self.config.peer_score_initial,
            violations: 0,
            last_score_decay_ms: now_ms(),
            last_violation_forgive_ms: now_ms(),
            state: PeerState::Connected,
        };
        self.registry.lock().await.upsert(info)?;
        self.sync_peer_stats(peer_addr).await;
        Ok(())
    }

    async fn handle_heartbeat(&self, msg: HeartbeatMessage, peer_addr: &str) -> Result<(), String> {
        let validator_set = self.validator_set.read().await;
        if !validator_set.is_empty() && !validator_set.contains_key(&msg.validator_id) {
            return Err("Heartbeat validator not in authorized set".into());
        }
        if msg.protocol_version != self.config.protocol_version {
            return Err("Heartbeat protocol version mismatch".into());
        }
        if msg.epoch != self.current_epoch().await {
            return Err("Heartbeat epoch mismatch".into());
        }
        let mut registry = self.registry.lock().await;
        let entry = registry.peers.get_mut(&msg.validator_id);
        if let Some(peer) = entry {
            if peer.address != peer_addr && peer.state == PeerState::Connected {
                return Err("Heartbeat address mismatch for validator".into());
            }
            peer.current_height = msg.current_height;
            peer.last_seen_ms = msg.timestamp_ms;
            peer.state = PeerState::Connected;
        } else {
            registry.upsert(PeerInfo {
                validator_id: msg.validator_id,
                address: peer_addr.to_string(),
                current_height: msg.current_height,
                finalized_height: msg.current_height.saturating_sub(2),
                protocol_version: self.config.protocol_version,
                last_seen_ms: msg.timestamp_ms,
                score: self.config.peer_score_initial,
                violations: 0,
                last_score_decay_ms: msg.timestamp_ms,
                last_violation_forgive_ms: msg.timestamp_ms,
                state: PeerState::Connected,
            })?;
        }
        self.sync_peer_stats(peer_addr).await;
        Ok(())
    }

    async fn collect_peer_targets(&self) -> Vec<String> {
        let mut targets = HashSet::new();
        {
            let seeds = self.peer_seeds.lock().await;
            for peer in seeds.iter() {
                targets.insert(peer.clone());
            }
        }

        let validator_set = self.validator_set.read().await.clone();
        let registry = self.registry.lock().await;
        for peer in registry.peers.values() {
            if peer.state == PeerState::Banned {
                continue;
            }
            if !validator_set.is_empty() && !validator_set.contains_key(&peer.validator_id) {
                continue;
            }
            targets.insert(peer.address.clone());
        }

        let mut peers: Vec<String> = targets.into_iter().collect();
        peers.sort();
        peers
    }

    async fn is_proposer_for_height(&self, height: u64) -> bool {
        let validator_set = self.validator_set.read().await;
        if validator_set.is_empty() {
            return true;
        }
        let mut validators = Vec::with_capacity(validator_set.len());
        for validator_id in validator_set.keys() {
            validators.push(ValidatorAuthority {
                node_id: *validator_id,
                governance_level: PrecedenceLevel::Safety,
                norm_compliance: sccgub_types::tension::TensionValue::from_integer(1),
                causal_reliability: sccgub_types::tension::TensionValue::from_integer(1),
                active: true,
            });
        }
        validators.sort_by_key(|v| v.node_id);
        match sccgub_governance::validator::round_robin_proposer(&validators, height) {
            Some(expected) => expected.node_id == self.validator_id,
            None => false,
        }
    }

    async fn mark_peer_disconnected(&self, peer_addr: &str) {
        let mut registry = self.registry.lock().await;
        for peer in registry.peers.values_mut() {
            if peer.address == peer_addr && peer.state == PeerState::Connected {
                peer.state = PeerState::Disconnected;
                break;
            }
        }
    }

    async fn handle_tx_gossip(&self, msg: TransactionGossipMessage) -> Result<(), String> {
        let mut chain = self.chain.write().await;
        let submitted = chain.submit_transition(msg.transaction);
        if submitted.is_ok() {
            if let Some(bridge) = &self.app_state {
                let _ = bridge.sync_from_chain(&chain).await;
            }
        }
        Ok(())
    }

    async fn handle_law_sync(
        &self,
        msg: sccgub_network::messages::LawSyncMessage,
    ) -> Result<(), String> {
        if !verify_law_sync_signature(&msg) {
            return Err("Law sync signature invalid".into());
        }
        if msg.protocol_version != self.config.protocol_version {
            return Err("Law sync protocol version mismatch".into());
        }
        Ok(())
    }

    async fn handle_block_proposal(&self, msg: BlockProposalMessage) -> Result<(), String> {
        if !verify_block_proposal_signature(&msg) {
            return Err("Block proposal signature invalid".into());
        }
        let should_gossip = msg.proposer_id != self.validator_id;
        let BlockProposalMessage {
            proposer_id,
            block,
            round,
            signature,
        } = msg;
        if proposer_id != block.header.validator_id {
            return Err("Block proposal proposer_id mismatch".into());
        }
        {
            let validator_set = self.validator_set.read().await;
            if !validator_set.is_empty() && !validator_set.contains_key(&proposer_id) {
                return Err("Block proposer not in authorized set".into());
            }
        }
        {
            let chain = self.chain.read().await;
            chain.validate_candidate_block(&block)?;
        }
        self.pending_blocks
            .lock()
            .await
            .insert(block.header.block_id, block.clone());

        let epoch = self.current_epoch().await;
        let height = block.header.height;
        let desired_quorum = self.consensus_quorum().await;
        let mut rounds = self.consensus_rounds.lock().await;
        let validator_set = self.validator_set.read().await.clone();
        let (state, created) = match rounds.entry(height) {
            Entry::Occupied(entry) => (entry.into_mut(), false),
            Entry::Vacant(entry) => (
                entry.insert(RoundState {
                    round: ConsensusRound::new(
                        self.chain_id,
                        epoch,
                        block.header.block_id,
                        height,
                        round,
                        validator_set,
                        self.config.max_rounds,
                    ),
                    last_round_ms: now_ms(),
                }),
                true,
            ),
        };
        if created {
            state.round.quorum = desired_quorum;
        }
        if state.round.epoch != epoch {
            return Err("Consensus epoch mismatch".into());
        }
        if state.round.round != round {
            return Err(format!(
                "Consensus round mismatch: expected {}, got {}",
                state.round.round, round
            ));
        }
        if state.round.block_hash == EMPTY_HASH {
            state.round.block_hash = block.header.block_id;
        } else if state.round.block_hash != block.header.block_id {
            return Err("Consensus round already tracking another block hash".into());
        }
        if !state.round.prevotes.contains_key(&self.validator_id)
            && self.is_local_validator_active().await
        {
            let vote = self.sign_vote_with_epoch(
                epoch,
                block.header.block_id,
                height,
                round,
                VoteType::Prevote,
            );
            state.round.add_prevote(vote.clone())?;
            self.broadcast(NetworkMessage::ConsensusVote(vote)).await;
        }
        drop(rounds);
        self.persist_consensus_state().await;
        self.maybe_advance_consensus(height).await?;
        if should_gossip {
            self.broadcast(NetworkMessage::BlockProposal(BlockProposalMessage {
                proposer_id,
                block,
                round,
                signature,
            }))
            .await;
        }
        Ok(())
    }

    async fn handle_block_request(
        &self,
        msg: BlockRequestMessage,
        peer_addr: &str,
    ) -> Result<(), String> {
        let chain = self.chain.read().await;
        let block = chain.block_at(msg.height).cloned();
        let response = NetworkMessage::BlockResponse(BlockResponseMessage {
            responder_id: self.validator_id,
            block,
            height: msg.height,
        });
        self.send_to_peer(peer_addr, response).await?;
        Ok(())
    }

    async fn handle_block_response(&self, msg: BlockResponseMessage) -> Result<(), String> {
        if let Some(block) = msg.block {
            let height = block.header.height;
            let mut chain = self.chain.write().await;
            if let Err(e) = chain.import_block(block.clone()) {
                tracing::warn!("Block import failed for height {}: {:?}", height, e);
            } else {
                if let Err(e) = chain.state.flush_store() {
                    eprintln!("Warning: state store flush failed: {}", e);
                }
                if let Some(bridge) = &self.app_state {
                    let _ = bridge.sync_from_chain(&chain).await;
                }
                let snapshot = if self.snapshot_interval > 0
                    && height > 0
                    && height.is_multiple_of(self.snapshot_interval)
                {
                    Some(chain.create_snapshot())
                } else {
                    None
                };
                drop(chain);
                self.pending_blocks
                    .lock()
                    .await
                    .remove(&block.header.block_id);
                self.consensus_rounds.lock().await.remove(&height);
                self.persist_consensus_state().await;
                if let Some(store) = &self.store {
                    let store = store.clone();
                    let block = block.clone();
                    tokio::task::spawn_blocking(move || {
                        if let Err(e) = store.save_block(&block) {
                            eprintln!("Warning: failed to persist block: {}", e);
                        }
                        if let Some(snapshot) = snapshot {
                            if let Err(e) = store.save_snapshot(&snapshot) {
                                eprintln!("Warning: failed to persist snapshot: {}", e);
                            }
                        }
                    });
                }
            }
        }
        Ok(())
    }

    async fn handle_consensus_vote(&self, vote: Vote) -> Result<(), String> {
        if vote.height == 0 {
            return Ok(());
        }
        let pending = {
            self.pending_blocks
                .lock()
                .await
                .get(&vote.block_hash)
                .cloned()
        };
        if pending.is_none() {
            return Ok(());
        }
        let epoch = self.current_epoch().await;
        let desired_quorum = self.consensus_quorum().await;
        self.verify_vote_signature(&vote, epoch).await?;
        let mut rounds = self.consensus_rounds.lock().await;
        let validator_set = self.validator_set.read().await.clone();
        let (state, created) = match rounds.entry(vote.height) {
            Entry::Occupied(entry) => (entry.into_mut(), false),
            Entry::Vacant(entry) => (
                entry.insert(RoundState {
                    round: ConsensusRound::new(
                        self.chain_id,
                        epoch,
                        vote.block_hash,
                        vote.height,
                        vote.round,
                        validator_set,
                        self.config.max_rounds,
                    ),
                    last_round_ms: now_ms(),
                }),
                true,
            ),
        };
        if created {
            state.round.quorum = desired_quorum;
        }
        if state.round.epoch != epoch {
            return Ok(());
        }
        if state.round.block_hash == EMPTY_HASH {
            return Ok(());
        }
        if vote.block_hash != state.round.block_hash {
            return Ok(());
        }
        let height = vote.height;
        let mut existing_vote: Option<Vote> = None;
        let mut vote_added = false;
        match vote.vote_type {
            VoteType::Prevote => {
                if let Some(existing) = state.round.prevotes.get(&vote.validator_id) {
                    if existing.block_hash != vote.block_hash {
                        existing_vote = Some(existing.clone());
                    }
                } else {
                    let _ = state.round.add_prevote(vote.clone());
                    vote_added = true;
                }
            }
            VoteType::Precommit => {
                if let Some(existing) = state.round.precommits.get(&vote.validator_id) {
                    if existing.block_hash != vote.block_hash {
                        existing_vote = Some(existing.clone());
                    }
                } else {
                    let _ = state.round.add_precommit(vote.clone());
                    vote_added = true;
                }
            }
            VoteType::Nil => {}
        }
        drop(rounds);
        if vote_added {
            self.persist_consensus_state().await;
            if vote.validator_id != self.validator_id {
                self.broadcast(NetworkMessage::ConsensusVote(vote.clone()))
                    .await;
            }
        }
        if let Some(existing) = existing_vote {
            self.maybe_record_equivocation(existing, vote, epoch)
                .await?;
            return Ok(());
        }
        self.maybe_advance_consensus(height).await?;
        Ok(())
    }

    async fn handle_equivocation_evidence(
        &self,
        msg: EquivocationEvidenceMessage,
    ) -> Result<(), String> {
        self.record_equivocation(msg.vote_a, msg.vote_b, msg.epoch, false)
            .await
    }

    async fn handle_finality_certificate(&self, cert: SafetyCertificate) -> Result<(), String> {
        let validator_set = self.validator_set.read().await;
        cert.verify_cryptographic(&validator_set)?;
        let mut chain = self.chain.write().await;
        let known = chain
            .block_at(cert.height)
            .map(|b| b.header.block_id == cert.block_hash)
            .unwrap_or(false);
        if !known {
            return Err("Finality certificate references unknown block".into());
        }
        let height = cert.height;
        let block_hash = cert.block_hash;
        chain.record_safety_certificate(cert);
        if let Some(store) = &self.store {
            if let Some(block) = chain.block_at(height).cloned() {
                let snapshot = if self.snapshot_interval > 0
                    && height > 0
                    && height.is_multiple_of(self.snapshot_interval)
                {
                    Some(chain.create_snapshot())
                } else {
                    None
                };
                let store = store.clone();
                tokio::task::spawn_blocking(move || {
                    if let Err(e) = store.save_block(&block) {
                        eprintln!("Warning: failed to persist block: {}", e);
                    }
                    if let Some(snapshot) = snapshot {
                        if let Err(e) = store.save_snapshot(&snapshot) {
                            eprintln!("Warning: failed to persist snapshot: {}", e);
                        }
                    }
                });
            }
        }
        if let Err(e) = chain.state.flush_store() {
            eprintln!("Warning: state store flush failed: {}", e);
        }
        if let Some(bridge) = &self.app_state {
            let _ = bridge.sync_from_chain(&chain).await;
        }
        drop(chain);
        self.pending_blocks.lock().await.remove(&block_hash);
        self.consensus_rounds.lock().await.remove(&height);
        self.persist_consensus_state().await;
        Ok(())
    }

    async fn record_equivocation(
        &self,
        vote_a: Vote,
        vote_b: Vote,
        epoch: u64,
        broadcast: bool,
    ) -> Result<(), String> {
        if vote_a.validator_id != vote_b.validator_id {
            return Ok(());
        }
        if vote_a.height != vote_b.height || vote_a.round != vote_b.round {
            return Ok(());
        }
        if vote_a.vote_type != vote_b.vote_type {
            return Ok(());
        }
        if vote_a.block_hash == vote_b.block_hash {
            return Ok(());
        }

        self.verify_vote_signature(&vote_a, epoch).await?;
        self.verify_vote_signature(&vote_b, epoch).await?;

        let (block_hash_a, block_hash_b) = if vote_a.block_hash <= vote_b.block_hash {
            (vote_a.block_hash, vote_b.block_hash)
        } else {
            (vote_b.block_hash, vote_a.block_hash)
        };
        let key = EquivocationKey {
            validator_id: vote_a.validator_id,
            height: vote_a.height,
            round: vote_a.round,
            vote_type: vote_a.vote_type as u8,
            block_hash_a,
            block_hash_b,
            epoch,
        };

        {
            let mut seen = self.equivocations.lock().await;
            if seen.contains(&key) {
                return Ok(());
            }
            seen.insert(key);
        }

        let proof = EquivocationProof {
            validator_id: vote_a.validator_id,
            height: vote_a.height,
            round: vote_a.round,
            vote_type: vote_a.vote_type,
            block_hash_a,
            block_hash_b,
        };
        {
            let mut chain = self.chain.write().await;
            // Execute slashing: deduct from internal stakes AND real balance.
            if let Ok(event) = chain.slashing.slash_double_sign(proof.clone(), epoch) {
                let actual = chain.execute_slashing_penalty(&event.validator_id, event.penalty);
                tracing::warn!(
                    "Slashed validator {} for double-signing: penalty={}, actual_deducted={}",
                    hex::encode(event.validator_id),
                    event.penalty,
                    actual,
                );
            }
            chain.record_equivocation(proof, epoch);
        }

        if broadcast {
            let evidence = NetworkMessage::EquivocationEvidence(EquivocationEvidenceMessage {
                vote_a,
                vote_b,
                epoch,
            });
            self.broadcast(evidence).await;
        }

        Ok(())
    }

    async fn maybe_record_equivocation(
        &self,
        existing: Vote,
        incoming: Vote,
        epoch: u64,
    ) -> Result<(), String> {
        self.record_equivocation(existing, incoming, epoch, true)
            .await
    }

    async fn verify_vote_signature(&self, vote: &Vote, epoch: u64) -> Result<(), String> {
        let validator_set = self.validator_set.read().await;
        let public_key = validator_set.get(&vote.validator_id).ok_or_else(|| {
            format!(
                "Validator {} not in authorized set",
                hex::encode(vote.validator_id)
            )
        })?;
        if vote.signature.len() < 64 {
            return Err("Vote signature must be at least 64 bytes (Ed25519)".into());
        }
        let vote_data = vote_sign_data(
            &self.chain_id,
            epoch,
            &vote.block_hash,
            vote.height,
            vote.round,
            vote.vote_type,
        );
        if !sccgub_crypto::signature::verify(public_key, &vote_data, &vote.signature) {
            return Err("Vote signature verification failed".into());
        }
        Ok(())
    }

    async fn is_local_validator_active(&self) -> bool {
        let validator_set = self.validator_set.read().await;
        validator_set.contains_key(&self.validator_id)
    }

    async fn check_rate_limit(&self, peer_addr: &str, priority: bool) -> Result<(), String> {
        let now = now_ms();
        let mut limits = self.rate_limits.lock().await;
        let entry = limits.entry(peer_addr.to_string()).or_insert(RateState {
            window_start_ms: now,
            count: 0,
            violations: 0,
        });
        if now.saturating_sub(entry.window_start_ms) >= self.config.inbound_msg_window_ms {
            entry.window_start_ms = now;
            entry.count = 0;
        }
        entry.count = entry.count.saturating_add(1);
        let limit = if priority {
            self.config.inbound_msg_limit.saturating_mul(2)
        } else {
            self.config.inbound_msg_limit
        };
        if entry.count > limit {
            entry.violations = entry.violations.saturating_add(1);
            let banned = self.record_peer_violation(peer_addr).await;
            if banned || entry.violations >= self.config.peer_max_violations {
                return Err("disconnect: rate limit exceeded".into());
            }
            return Err("Rate limit exceeded".into());
        }
        Ok(())
    }

    async fn record_peer_violation(&self, peer_addr: &str) -> bool {
        let validator_id = self.validator_id_for_addr(peer_addr).await;
        let Some(validator_id) = validator_id else {
            return false;
        };
        let mut registry = self.registry.lock().await;
        if let Some(peer) = registry.peers.get_mut(&validator_id) {
            peer.score = peer.score.saturating_sub(self.config.peer_score_penalty);
            peer.violations = peer.violations.saturating_add(1);
            if peer.score <= self.config.peer_score_ban_threshold
                || peer.violations >= self.config.peer_max_violations
            {
                peer.state = PeerState::Banned;
                return true;
            }
        }
        drop(registry);
        self.sync_peer_stats(peer_addr).await;
        false
    }

    async fn check_bandwidth_limit(&self, peer_addr: &str) -> Result<(), String> {
        let now = now_ms();
        let mut usage = self.bandwidth.lock().await;
        let entry = usage
            .entry(peer_addr.to_string())
            .or_insert(BandwidthState {
                inbound_bytes: 0,
                outbound_bytes: 0,
                window_start_ms: now,
            });
        if now.saturating_sub(entry.window_start_ms) >= self.config.bandwidth_window_ms {
            entry.window_start_ms = now;
            entry.inbound_bytes = 0;
            entry.outbound_bytes = 0;
        }
        let inbound_over = entry.inbound_bytes > self.config.inbound_bytes_limit;
        let outbound_over = entry.outbound_bytes > self.config.outbound_bytes_limit;
        if inbound_over || outbound_over {
            drop(usage);
            let banned = self.record_peer_violation(peer_addr).await;
            if banned {
                return Err("disconnect: bandwidth limit exceeded".into());
            }
            return Err("Bandwidth limit exceeded".into());
        }
        Ok(())
    }

    async fn validator_id_for_addr(&self, peer_addr: &str) -> Option<Hash> {
        let registry = self.registry.lock().await;
        registry
            .peers
            .values()
            .find(|peer| peer.address == peer_addr)
            .map(|peer| peer.validator_id)
    }

    async fn sync_peer_stats(&self, peer_addr: &str) {
        let Some(bridge) = &self.app_state else {
            return;
        };
        let (address, validator_id, score, violations, state, last_seen_ms) = {
            let registry = self.registry.lock().await;
            let peer = registry
                .peers
                .values()
                .find(|peer| peer.address == peer_addr);
            let Some(peer) = peer else {
                return;
            };
            (
                peer.address.clone(),
                peer.validator_id,
                peer.score,
                peer.violations,
                format!("{:?}", peer.state),
                peer.last_seen_ms,
            )
        };
        let bandwidth_map = self.bandwidth.lock().await;
        let bandwidth = bandwidth_map.get(peer_addr).cloned();
        drop(bandwidth_map);
        let (inbound, outbound) = if let Some(stats) = bandwidth {
            (stats.inbound_bytes, stats.outbound_bytes)
        } else {
            (0, 0)
        };
        let snapshot = sccgub_api::handlers::PeerStatsSnapshot {
            address,
            validator_id: Some(validator_id),
            score,
            violations,
            state,
            inbound_bytes: inbound,
            outbound_bytes: outbound,
            last_seen_ms,
        };
        bridge.update_peer_stats(snapshot).await;
    }

    #[cfg(test)]
    async fn bandwidth_snapshot(&self, peer_addr: &str) -> Option<BandwidthState> {
        let usage = self.bandwidth.lock().await;
        usage.get(peer_addr).cloned()
    }

    async fn current_epoch(&self) -> u64 {
        let chain = self.chain.read().await;
        chain.treasury.epoch
    }

    async fn consensus_quorum(&self) -> u32 {
        let chain = self.chain.read().await;
        let finality_mode = chain.state.state.governance_state.finality_mode;
        drop(chain);
        let validator_set = self.validator_set.read().await;
        let validator_count = validator_set.len() as u32;
        match finality_mode {
            FinalityMode::BftCertified { quorum_threshold } => {
                let mut quorum = quorum_threshold.max(1);
                if validator_count > 0 && quorum > validator_count {
                    quorum = validator_count;
                }
                quorum
            }
            FinalityMode::Deterministic => 1,
        }
    }

    async fn maybe_advance_consensus(&self, height: u64) -> Result<(), String> {
        if self.config.enable {
            let validator_set = self.validator_set.read().await;
            let effective_min_peers = self
                .config
                .min_connected_peers
                .min(validator_set.len().saturating_sub(1));
            drop(validator_set);
            let registry = self.registry.lock().await;
            if let Err(e) =
                registry.check_diversity_with(effective_min_peers, self.config.max_same_subnet_pct)
            {
                return Err(format!("Peer diversity gate: {}", e));
            }
        }
        let mut should_finalize = false;
        let mut block_hash = None;
        let mut cert_to_broadcast: Option<SafetyCertificate> = None;
        let mut aborted = false;
        {
            let mut rounds = self.consensus_rounds.lock().await;
            let Some(state) = rounds.get_mut(&height) else {
                return Ok(());
            };

            let quorum = state.round.has_prevote_quorum();
            if quorum
                && !state.round.precommits.contains_key(&self.validator_id)
                && self.is_local_validator_active().await
            {
                let vote = self.sign_vote_with_epoch(
                    state.round.epoch,
                    state.round.block_hash,
                    height,
                    state.round.round,
                    VoteType::Precommit,
                );
                let _ = state.round.add_precommit(vote.clone());
                self.broadcast(NetworkMessage::ConsensusVote(vote)).await;
            }

            match state.round.evaluate() {
                ConsensusResult::Finalized { .. } => {
                    should_finalize = true;
                    block_hash = Some(state.round.block_hash);
                    cert_to_broadcast = Some(SafetyCertificate::from_round(
                        self.chain_id,
                        state.round.epoch,
                        state.round.block_hash,
                        height,
                        state.round.round,
                        &state.round.precommits,
                        state.round.validator_count,
                    ));
                }
                ConsensusResult::NextRound { .. } => {
                    if quorum {
                        state.round.phase = sccgub_consensus::protocol::ConsensusPhase::Precommit;
                    } else {
                        state.round.phase = sccgub_consensus::protocol::ConsensusPhase::Prevote;
                    }
                }
                ConsensusResult::Aborted { .. } => {
                    state.round.phase = sccgub_consensus::protocol::ConsensusPhase::Abort;
                    aborted = true;
                }
            }
        }

        if should_finalize {
            if let Some(hash) = block_hash {
                let block = { self.pending_blocks.lock().await.remove(&hash) };
                if let Some(block) = block {
                    let mut imported = false;
                    let (block_to_persist, snapshot_to_persist) = {
                        let mut chain = self.chain.write().await;
                        let import = chain.import_block(block);
                        if import.is_ok() {
                            imported = true;
                            if let Some(cert) = cert_to_broadcast.clone() {
                                chain.record_safety_certificate(cert);
                            }
                            if let Err(e) = chain.state.flush_store() {
                                eprintln!("Warning: state store flush failed: {}", e);
                            }
                            if let Some(bridge) = &self.app_state {
                                let _ = bridge.sync_from_chain(&chain).await;
                            }
                            let height = chain.height();
                            let block = chain.latest_block().cloned();
                            let snapshot = if self.snapshot_interval > 0
                                && height > 0
                                && height.is_multiple_of(self.snapshot_interval)
                            {
                                Some(chain.create_snapshot())
                            } else {
                                None
                            };
                            (block, snapshot)
                        } else {
                            (None, None)
                        }
                    };

                    if let (Some(store), Some(block)) = (self.store.clone(), block_to_persist) {
                        let snapshot = snapshot_to_persist.clone();
                        tokio::task::spawn_blocking(move || {
                            if let Err(e) = store.save_block(&block) {
                                eprintln!("Warning: failed to persist block: {}", e);
                            }
                            if let Some(snapshot) = snapshot {
                                if let Err(e) = store.save_snapshot(&snapshot) {
                                    eprintln!("Warning: failed to persist snapshot: {}", e);
                                }
                            }
                        });
                    }
                    if imported {
                        if let Some(cert) = cert_to_broadcast {
                            self.broadcast(NetworkMessage::FinalityCertificate(cert))
                                .await;
                        }
                    }
                }
            }
            self.consensus_rounds.lock().await.remove(&height);
            // Clear persisted consensus state after successful finalization.
            if let Some(store) = &self.store {
                let _ = store.clear_consensus_state();
            }
        }
        if aborted {
            let mut rounds = self.consensus_rounds.lock().await;
            if let Some(state) = rounds.remove(&height) {
                let hash = state.round.block_hash;
                if hash != EMPTY_HASH {
                    self.pending_blocks.lock().await.remove(&hash);
                }
            }
            self.persist_consensus_state().await;
        }
        Ok(())
    }

    async fn consensus_timeout_loop(self: Arc<Self>) {
        let mut ticker = interval(Duration::from_millis(self.config.round_timeout_ms.max(500)));
        loop {
            ticker.tick().await;
            let now = now_ms();
            let current_epoch = self.current_epoch().await;
            let mut stale_hashes = Vec::new();
            let mut updated = false;
            let mut to_remove = Vec::new();
            {
                let mut rounds = self.consensus_rounds.lock().await;
                for (height, state) in rounds.iter_mut() {
                    if state.round.epoch != current_epoch {
                        if state.round.block_hash != EMPTY_HASH {
                            stale_hashes.push(state.round.block_hash);
                        }
                        to_remove.push(*height);
                        updated = true;
                        continue;
                    }
                    if let Some(old_hash) = advance_round_if_timed_out(state, &self.config, now) {
                        if old_hash != EMPTY_HASH {
                            stale_hashes.push(old_hash);
                        }
                        updated = true;
                    }
                }
                for height in to_remove {
                    rounds.remove(&height);
                }
            }
            if !stale_hashes.is_empty() {
                let mut pending = self.pending_blocks.lock().await;
                for hash in stale_hashes {
                    pending.remove(&hash);
                }
            }
            if updated {
                self.persist_consensus_state().await;
            }
        }
    }

    async fn send_hello(&self, peer_addr: &str) -> Result<(), String> {
        let chain = self.chain.read().await;
        let known_peers = self.seed_peers_snapshot().await;
        let hello = signed_hello(
            &self.validator_key,
            HelloMessage {
                validator_id: self.validator_id,
                chain_id: self.chain_id,
                current_height: chain.height(),
                finalized_height: chain.finalized_height(),
                protocol_version: self.config.protocol_version,
                epoch: chain.treasury.epoch,
                known_peers,
                signature: Vec::new(),
            },
        );
        drop(chain);
        self.send_to_peer(peer_addr, NetworkMessage::Hello(hello))
            .await
    }

    async fn send_to_peer(&self, peer_addr: &str, message: NetworkMessage) -> Result<(), String> {
        let sender = { self.connections.lock().await.get(peer_addr).cloned() };
        if let Some(tx) = sender {
            tx.send(message)
                .await
                .map_err(|_| "P2P send failed".to_string())?;
        }
        Ok(())
    }

    async fn broadcast(&self, message: NetworkMessage) {
        let peers = self.collect_broadcast_targets().await;
        for peer in peers {
            let _ = self.send_to_peer(&peer, message.clone()).await;
        }
    }

    async fn collect_broadcast_targets(&self) -> Vec<String> {
        let connections: HashSet<String> = self.connections.lock().await.keys().cloned().collect();
        if connections.is_empty() {
            return Vec::new();
        }

        let validator_set = self.validator_set.read().await;
        if validator_set.is_empty() {
            let mut peers: Vec<String> = connections.into_iter().collect();
            peers.sort();
            return peers;
        }

        let mut targets = HashSet::new();
        let registry = self.registry.lock().await;
        for peer in registry.peers.values() {
            if peer.state != PeerState::Connected {
                continue;
            }
            if !validator_set.contains_key(&peer.validator_id) {
                continue;
            }
            if connections.contains(&peer.address) {
                targets.insert(peer.address.clone());
            }
        }

        let mut peers: Vec<String> = targets.into_iter().collect();
        peers.sort();
        peers
    }

    async fn seed_peers_snapshot(&self) -> Vec<String> {
        let seeds = self.peer_seeds.lock().await;
        let mut peers: Vec<String> = seeds.iter().cloned().collect();
        peers.sort();
        peers.truncate(32);
        peers
    }

    async fn update_peer_seeds(&self, peer_addr: &str, candidates: &[String]) {
        let self_addr = format!("{}:{}", self.config.bind, self.config.port);
        let mut seeds = self.peer_seeds.lock().await;
        if seeds.len() < MAX_SEED_PEERS {
            seeds.insert(peer_addr.to_string());
        }
        for entry in candidates {
            if seeds.len() >= MAX_SEED_PEERS {
                break;
            }
            let entry = entry.trim();
            if entry.is_empty() || entry.len() > 128 {
                continue;
            }
            if !entry.contains(':') {
                continue;
            }
            if entry == peer_addr || entry == self_addr {
                continue;
            }
            if !self.is_peer_allowed(entry) {
                continue;
            }
            seeds.insert(entry.to_string());
        }
    }

    async fn heartbeat_loop(self: Arc<Self>) {
        let mut ticker = interval(Duration::from_millis(2_000));
        loop {
            ticker.tick().await;
            let chain = self.chain.read().await;
            let heartbeat = NetworkMessage::Heartbeat(HeartbeatMessage {
                validator_id: self.validator_id,
                current_height: chain.height(),
                protocol_version: self.config.protocol_version,
                epoch: chain.treasury.epoch,
                timestamp_ms: now_ms(),
            });
            drop(chain);
            self.broadcast(heartbeat).await;
        }
    }

    async fn decay_loop(self: Arc<Self>) {
        let mut ticker = interval(Duration::from_millis(
            self.config.peer_score_decay_interval_ms.max(1_000),
        ));
        loop {
            ticker.tick().await;
            let now = now_ms();
            let mut registry = self.registry.lock().await;
            registry.decay_scores(
                now,
                self.config.peer_score_decay_interval_ms,
                self.config.peer_score_decay_amount,
                self.config.peer_score_initial,
                self.config.peer_violation_forgive_interval_ms,
            );
        }
    }

    async fn validator_set_refresh_loop(self: Arc<Self>) {
        let mut ticker = interval(Duration::from_millis(5_000));
        loop {
            ticker.tick().await;
            if !self.config.validators.is_empty() {
                continue;
            }
            let chain_validators = { self.chain.read().await.validator_set.clone() };
            if chain_validators.is_empty() {
                continue;
            }
            let mut validator_set = HashMap::new();
            for validator in chain_validators.iter().filter(|v| v.active) {
                validator_set.insert(validator.node_id, validator.node_id);
            }
            if validator_set.is_empty() {
                continue;
            }
            let updated = {
                let current = self.validator_set.read().await;
                current.len() != validator_set.len()
                    || !current.keys().all(|k| validator_set.contains_key(k))
            };
            if updated {
                {
                    let mut current = self.validator_set.write().await;
                    *current = validator_set.clone();
                }
                self.enforce_validator_set_on_registry(&validator_set).await;
                self.consensus_rounds.lock().await.clear();
                self.pending_blocks.lock().await.clear();
                if let Some(store) = &self.store {
                    let _ = store.clear_consensus_state();
                }
                self.persist_consensus_state().await;
            }
        }
    }

    async fn enforce_validator_set_on_registry(&self, validator_set: &HashMap<Hash, [u8; 32]>) {
        if validator_set.is_empty() {
            return;
        }

        let mut to_disconnect = Vec::new();
        {
            let mut registry = self.registry.lock().await;
            for (validator_id, peer) in registry.peers.iter_mut() {
                if !validator_set.contains_key(validator_id) {
                    peer.state = PeerState::Banned;
                    to_disconnect.push(peer.address.clone());
                }
            }
        }

        if to_disconnect.is_empty() {
            return;
        }
        let mut connections = self.connections.lock().await;
        for addr in to_disconnect {
            connections.remove(&addr);
        }
    }

    async fn sync_loop(self: Arc<Self>) {
        let mut ticker = interval(Duration::from_millis(2_000));
        loop {
            ticker.tick().await;
            let (needs_sync, target_height, peer_addr) = {
                let chain = self.chain.read().await;
                let registry = self.registry.lock().await;
                if !registry.needs_sync(chain.height()) {
                    (false, 0, None)
                } else {
                    let candidate = registry.sync_candidates(chain.height()).first().cloned();
                    if let Some(peer) = candidate {
                        (true, chain.height() + 1, Some(peer.address.clone()))
                    } else {
                        (false, 0, None)
                    }
                }
            };
            if !needs_sync {
                continue;
            }
            if let Some(addr) = peer_addr {
                let request = NetworkMessage::BlockRequest(BlockRequestMessage {
                    requester_id: self.validator_id,
                    height: target_height,
                });
                let _ = self.send_to_peer(&addr, request).await;
            }
        }
    }

    async fn proposer_loop(self: Arc<Self>) {
        let mut ticker = interval(Duration::from_millis(self.config.block_interval_ms));
        loop {
            ticker.tick().await;
            let next_height = { self.chain.read().await.height().saturating_add(1) };
            let is_proposer = self.is_proposer_for_height(next_height).await;
            if !is_proposer {
                continue;
            }
            let (round, phase, existing_hash) = {
                let rounds = self.consensus_rounds.lock().await;
                if let Some(state) = rounds.get(&next_height) {
                    let existing_hash = if state.round.block_hash == EMPTY_HASH {
                        None
                    } else {
                        Some(state.round.block_hash)
                    };
                    (state.round.round, state.round.phase, existing_hash)
                } else {
                    (0, sccgub_consensus::protocol::ConsensusPhase::Propose, None)
                }
            };
            if phase != sccgub_consensus::protocol::ConsensusPhase::Propose {
                continue;
            }
            let block = if let Some(hash) = existing_hash {
                let block = self.pending_blocks.lock().await.get(&hash).cloned();
                let Some(block) = block else {
                    continue;
                };
                block
            } else {
                let chain = self.chain.read().await;
                match chain.build_candidate_block() {
                    Ok(block) => block,
                    Err(_) => continue,
                }
            };
            let msg = NetworkMessage::BlockProposal(signed_block_proposal(
                &self.validator_key,
                BlockProposalMessage {
                    proposer_id: self.validator_id,
                    block,
                    round,
                    signature: Vec::new(),
                },
            ));
            if let Err(e) = self.handle_message(msg.clone(), "local").await {
                tracing::warn!("Local proposal handling failed: {}", e);
            }
            self.broadcast(msg).await;
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_millis(0))
        .as_millis() as u64
}

fn signed_hello(key: &ed25519_dalek::SigningKey, mut msg: HelloMessage) -> HelloMessage {
    msg.signature = Vec::new();
    let bytes = canonical_bytes(&NetworkMessage::Hello(msg.clone()));
    msg.signature = sign(key, &bytes);
    msg
}

fn verify_hello_signature(msg: &HelloMessage) -> bool {
    if msg.signature.len() < 64 {
        return false;
    }
    let mut unsigned = msg.clone();
    unsigned.signature = Vec::new();
    let bytes = canonical_bytes(&NetworkMessage::Hello(unsigned));
    verify(&msg.validator_id, &bytes, &msg.signature)
}

fn verify_law_sync_signature(msg: &sccgub_network::messages::LawSyncMessage) -> bool {
    if msg.signature.len() < 64 {
        return false;
    }
    let mut unsigned = msg.clone();
    unsigned.signature = Vec::new();
    let bytes = canonical_bytes(&NetworkMessage::LawSync(unsigned));
    verify(&msg.validator_id, &bytes, &msg.signature)
}

fn signed_block_proposal(
    key: &ed25519_dalek::SigningKey,
    mut msg: BlockProposalMessage,
) -> BlockProposalMessage {
    msg.signature = Vec::new();
    let bytes = canonical_bytes(&NetworkMessage::BlockProposal(msg.clone()));
    msg.signature = sign(key, &bytes);
    msg
}

fn verify_block_proposal_signature(msg: &BlockProposalMessage) -> bool {
    if msg.signature.len() < 64 {
        return false;
    }
    let mut unsigned = msg.clone();
    unsigned.signature = Vec::new();
    let bytes = canonical_bytes(&NetworkMessage::BlockProposal(unsigned));
    verify(&msg.proposer_id, &bytes, &msg.signature)
}

fn validator_set_map(config: &NetworkConfig) -> Result<HashMap<Hash, [u8; 32]>, String> {
    let mut set = HashMap::new();
    for entry in &config.validators {
        let bytes = hex::decode(entry.trim())
            .map_err(|e| format!("Validator key hex decode failed: {}", e))?;
        if bytes.len() != 32 {
            return Err(format!(
                "Validator public key must be 32 bytes, got {}",
                bytes.len()
            ));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&bytes);
        set.insert(pk, pk);
    }
    Ok(set)
}

impl NetworkRuntime {
    fn is_peer_allowed(&self, peer_addr: &str) -> bool {
        if self.config.allowed_peers.is_empty() {
            return true;
        }
        let host = peer_addr.split(':').next().unwrap_or(peer_addr);
        self.config.allowed_peers.iter().any(|entry| {
            let entry = entry.trim();
            if entry.is_empty() {
                return false;
            }
            entry == peer_addr || entry == host
        })
    }
}

impl NetworkRuntime {
    fn sign_vote_with_epoch(
        &self,
        epoch: u64,
        block_hash: Hash,
        height: u64,
        round: u32,
        vote_type: VoteType,
    ) -> Vote {
        let payload = vote_sign_data(&self.chain_id, epoch, &block_hash, height, round, vote_type);
        let signature = sign(&self.validator_key, &payload);
        Vote {
            validator_id: self.validator_id,
            block_hash,
            height,
            round,
            vote_type,
            signature,
        }
    }
}

async fn read_frame(reader: &mut tokio::net::tcp::OwnedReadHalf) -> Result<Vec<u8>, String> {
    let mut len_buf = [0u8; FRAME_HEADER_LEN];
    reader
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| format!("read frame header failed: {}", e))?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 8 * 1024 * 1024 {
        return Err(format!("invalid frame length {}", len));
    }
    let mut payload = vec![0u8; len];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|e| format!("read frame payload failed: {}", e))?;
    Ok(payload)
}

async fn write_frame(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    payload: &[u8],
) -> Result<(), String> {
    let len = payload.len();
    if len == 0 || len > 8 * 1024 * 1024 {
        return Err(format!("invalid frame length {}", len));
    }
    let len_buf = (len as u32).to_be_bytes();
    writer
        .write_all(&len_buf)
        .await
        .map_err(|e| format!("write frame header failed: {}", e))?;
    writer
        .write_all(payload)
        .await
        .map_err(|e| format!("write frame payload failed: {}", e))?;
    Ok(())
}

async fn record_bandwidth(
    usage: &Arc<Mutex<HashMap<String, BandwidthState>>>,
    peer_addr: &str,
    inbound: u64,
    outbound: u64,
) {
    let mut usage = usage.lock().await;
    let entry = usage
        .entry(peer_addr.to_string())
        .or_insert(BandwidthState {
            inbound_bytes: 0,
            outbound_bytes: 0,
            window_start_ms: now_ms(),
        });
    entry.inbound_bytes = entry.inbound_bytes.saturating_add(inbound);
    entry.outbound_bytes = entry.outbound_bytes.saturating_add(outbound);
}

fn advance_round_if_timed_out(
    state: &mut RoundState,
    config: &NetworkConfig,
    now_ms: u64,
) -> Option<Hash> {
    if now_ms.saturating_sub(state.last_round_ms) < config.round_timeout_ms {
        return None;
    }
    let old_hash = state.round.block_hash;
    if state.round.round >= config.max_rounds {
        state.round.phase = sccgub_consensus::protocol::ConsensusPhase::Abort;
        return Some(old_hash);
    }
    state.round.round = state.round.round.saturating_add(1);
    state.round.phase = sccgub_consensus::protocol::ConsensusPhase::Propose;
    state.round.prevotes.clear();
    state.round.precommits.clear();
    state.round.block_hash = EMPTY_HASH;
    state.last_round_ms = now_ms;
    Some(old_hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::persistence::ChainStore;
    use sccgub_crypto::keys::generate_keypair;
    use sccgub_governance::validator::round_robin_proposer;
    use sccgub_network::messages::HelloMessage;
    use sccgub_types::governance::FinalityMode;
    use sccgub_types::tension::TensionValue;
    use std::fs;
    use tokio::time::{sleep, Duration, Instant};

    fn default_network_config_with_validator(pk: &[u8; 32]) -> NetworkConfig {
        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(pk)];
        config
    }

    async fn wait_for_persisted_height(store: &ChainStore, height: u64, timeout_ms: u64) -> bool {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        while Instant::now() < deadline {
            if let Ok(Some(latest)) = store.latest_height() {
                if latest >= height {
                    return true;
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
        false
    }

    async fn wait_for_snapshot_height(
        store: &ChainStore,
        min_height: u64,
        timeout_ms: u64,
    ) -> Option<crate::persistence::StateSnapshot> {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        while Instant::now() < deadline {
            if let Ok(Some(snapshot)) = store.load_latest_snapshot() {
                if snapshot.height >= min_height {
                    return Some(snapshot);
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
        None
    }

    #[tokio::test]
    async fn test_handle_hello_rejects_unknown_validator() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_key = { chain.read().await.validator_key.clone() };
        let local_pk = *local_key.verifying_key().as_bytes();
        let config = default_network_config_with_validator(&local_pk);
        let runtime = NetworkRuntime::new(chain, config).await.unwrap();

        let other_key = generate_keypair();
        let other_pk = *other_key.verifying_key().as_bytes();
        let hello = signed_hello(
            &other_key,
            HelloMessage {
                validator_id: other_pk,
                chain_id: runtime.chain_id,
                current_height: 0,
                finalized_height: 0,
                protocol_version: runtime.config.protocol_version,
                epoch: runtime.current_epoch().await,
                known_peers: vec![],
                signature: Vec::new(),
            },
        );

        let err = runtime
            .handle_hello(hello, "127.0.0.1:4000")
            .await
            .unwrap_err();
        assert!(
            err.contains("authorized set"),
            "Expected allowlist rejection, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_handle_hello_rejects_address_mismatch() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_key = { chain.read().await.validator_key.clone() };
        let local_pk = *local_key.verifying_key().as_bytes();
        let config = default_network_config_with_validator(&local_pk);
        let runtime = NetworkRuntime::new(chain, config).await.unwrap();

        let hello = signed_hello(
            &local_key,
            HelloMessage {
                validator_id: local_pk,
                chain_id: runtime.chain_id,
                current_height: 0,
                finalized_height: 0,
                protocol_version: runtime.config.protocol_version,
                epoch: runtime.current_epoch().await,
                known_peers: vec![],
                signature: Vec::new(),
            },
        );

        runtime
            .handle_hello(hello.clone(), "127.0.0.1:4001")
            .await
            .unwrap();

        let err = runtime
            .handle_hello(hello, "127.0.0.1:4002")
            .await
            .unwrap_err();
        assert!(
            err.contains("address mismatch"),
            "Expected address mismatch rejection, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_enforce_validator_set_bans_unknown_peers() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = {
            let guard = chain.read().await;
            *guard.validator_key.verifying_key().as_bytes()
        };
        let config = default_network_config_with_validator(&local_pk);
        let runtime = NetworkRuntime::new(chain, config).await.unwrap();

        let other_key = generate_keypair();
        let other_pk = *other_key.verifying_key().as_bytes();
        let other_addr = "127.0.0.1:5111";
        {
            let mut registry = runtime.registry.lock().await;
            registry
                .upsert(PeerInfo {
                    validator_id: other_pk,
                    address: other_addr.to_string(),
                    current_height: 0,
                    finalized_height: 0,
                    protocol_version: runtime.config.protocol_version,
                    last_seen_ms: now_ms(),
                    score: runtime.config.peer_score_initial,
                    violations: 0,
                    last_score_decay_ms: now_ms(),
                    last_violation_forgive_ms: now_ms(),
                    state: PeerState::Connected,
                })
                .unwrap();
        }
        {
            let (tx, _rx) = mpsc::channel(1);
            runtime
                .connections
                .lock()
                .await
                .insert(other_addr.to_string(), tx);
        }

        let validator_set = runtime.validator_set.read().await.clone();
        runtime
            .enforce_validator_set_on_registry(&validator_set)
            .await;

        let registry = runtime.registry.lock().await;
        let peer = registry.peers.get(&other_pk).unwrap();
        assert_eq!(peer.state, PeerState::Banned);
        drop(registry);
        assert!(!runtime.connections.lock().await.contains_key(other_addr));
    }

    #[tokio::test]
    async fn test_mark_peer_disconnected_updates_state() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = {
            let guard = chain.read().await;
            *guard.validator_key.verifying_key().as_bytes()
        };
        let config = default_network_config_with_validator(&local_pk);
        let runtime = NetworkRuntime::new(chain, config).await.unwrap();

        let peer_addr = "127.0.0.1:6123";
        {
            let mut registry = runtime.registry.lock().await;
            registry
                .upsert(PeerInfo {
                    validator_id: [8u8; 32],
                    address: peer_addr.to_string(),
                    current_height: 0,
                    finalized_height: 0,
                    protocol_version: runtime.config.protocol_version,
                    last_seen_ms: now_ms(),
                    score: runtime.config.peer_score_initial,
                    violations: 0,
                    last_score_decay_ms: now_ms(),
                    last_violation_forgive_ms: now_ms(),
                    state: PeerState::Connected,
                })
                .unwrap();
        }

        runtime.mark_peer_disconnected(peer_addr).await;

        let registry = runtime.registry.lock().await;
        let peer = registry
            .peers
            .values()
            .find(|p| p.address == peer_addr)
            .unwrap();
        assert_eq!(peer.state, PeerState::Disconnected);
    }

    #[tokio::test]
    async fn test_collect_peer_targets_includes_registry_validators() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = {
            let guard = chain.read().await;
            *guard.validator_key.verifying_key().as_bytes()
        };
        let other_key = generate_keypair();
        let other_pk = *other_key.verifying_key().as_bytes();
        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(local_pk), hex::encode(other_pk)];
        let runtime = NetworkRuntime::new(chain, config).await.unwrap();

        let peer_addr = "127.0.0.1:7001";
        {
            let mut registry = runtime.registry.lock().await;
            registry
                .upsert(PeerInfo {
                    validator_id: other_pk,
                    address: peer_addr.to_string(),
                    current_height: 0,
                    finalized_height: 0,
                    protocol_version: runtime.config.protocol_version,
                    last_seen_ms: now_ms(),
                    score: runtime.config.peer_score_initial,
                    violations: 0,
                    last_score_decay_ms: now_ms(),
                    last_violation_forgive_ms: now_ms(),
                    state: PeerState::Disconnected,
                })
                .unwrap();
        }

        let peers = runtime.collect_peer_targets().await;
        assert!(
            peers.contains(&peer_addr.to_string()),
            "Expected peer targets to include registry address"
        );
    }

    #[tokio::test]
    async fn test_collect_broadcast_targets_filters_non_validators() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = {
            let guard = chain.read().await;
            *guard.validator_key.verifying_key().as_bytes()
        };
        let validator_key = generate_keypair();
        let validator_pk = *validator_key.verifying_key().as_bytes();
        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(local_pk), hex::encode(validator_pk)];
        let runtime = NetworkRuntime::new(chain, config).await.unwrap();

        let validator_addr = "127.0.0.1:7101";
        let non_validator_addr = "127.0.0.1:7102";
        {
            let mut registry = runtime.registry.lock().await;
            registry
                .upsert(PeerInfo {
                    validator_id: validator_pk,
                    address: validator_addr.to_string(),
                    current_height: 0,
                    finalized_height: 0,
                    protocol_version: runtime.config.protocol_version,
                    last_seen_ms: now_ms(),
                    score: runtime.config.peer_score_initial,
                    violations: 0,
                    last_score_decay_ms: now_ms(),
                    last_violation_forgive_ms: now_ms(),
                    state: PeerState::Connected,
                })
                .unwrap();
            registry
                .upsert(PeerInfo {
                    validator_id: [55u8; 32],
                    address: non_validator_addr.to_string(),
                    current_height: 0,
                    finalized_height: 0,
                    protocol_version: runtime.config.protocol_version,
                    last_seen_ms: now_ms(),
                    score: runtime.config.peer_score_initial,
                    violations: 0,
                    last_score_decay_ms: now_ms(),
                    last_violation_forgive_ms: now_ms(),
                    state: PeerState::Connected,
                })
                .unwrap();
        }
        {
            let (tx, _rx) = mpsc::channel(1);
            runtime
                .connections
                .lock()
                .await
                .insert(validator_addr.to_string(), tx);
        }
        {
            let (tx, _rx) = mpsc::channel(1);
            runtime
                .connections
                .lock()
                .await
                .insert(non_validator_addr.to_string(), tx);
        }

        let targets = runtime.collect_broadcast_targets().await;
        assert!(targets.contains(&validator_addr.to_string()));
        assert!(!targets.contains(&non_validator_addr.to_string()));
    }

    #[tokio::test]
    async fn test_handle_consensus_vote_rejects_bad_signature() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = {
            let guard = chain.read().await;
            *guard.validator_key.verifying_key().as_bytes()
        };
        let config = default_network_config_with_validator(&local_pk);
        let runtime = NetworkRuntime::new(chain.clone(), config).await.unwrap();

        let block = {
            let mut guard = chain.write().await;
            guard.governance_limits.max_consecutive_proposals = 100;
            guard.produce_block().unwrap().clone()
        };
        runtime
            .pending_blocks
            .lock()
            .await
            .insert(block.header.block_id, block.clone());

        let other_key = generate_keypair();
        let epoch = runtime.current_epoch().await;
        let payload = vote_sign_data(
            &runtime.chain_id,
            epoch,
            &block.header.block_id,
            block.header.height,
            0,
            VoteType::Prevote,
        );
        let bad_signature = sign(&other_key, &payload);
        let vote = Vote {
            validator_id: local_pk,
            block_hash: block.header.block_id,
            height: block.header.height,
            round: 0,
            vote_type: VoteType::Prevote,
            signature: bad_signature,
        };

        let err = runtime.handle_consensus_vote(vote).await.unwrap_err();
        assert!(
            err.contains("Vote signature verification failed"),
            "Expected bad signature rejection, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_handle_heartbeat_rejects_unknown_validator() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = {
            let guard = chain.read().await;
            *guard.validator_key.verifying_key().as_bytes()
        };
        let config = default_network_config_with_validator(&local_pk);
        let runtime = NetworkRuntime::new(chain, config).await.unwrap();

        let other_key = generate_keypair();
        let other_pk = *other_key.verifying_key().as_bytes();
        let err = runtime
            .handle_heartbeat(
                HeartbeatMessage {
                    validator_id: other_pk,
                    current_height: 1,
                    protocol_version: runtime.config.protocol_version,
                    epoch: runtime.current_epoch().await,
                    timestamp_ms: now_ms(),
                },
                "127.0.0.1:4010",
            )
            .await
            .unwrap_err();
        assert!(
            err.contains("authorized set"),
            "Expected allowlist rejection, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_bft_quorum_override_uses_governance_threshold() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_key = { chain.read().await.validator_key.clone() };
        let local_pk = *local_key.verifying_key().as_bytes();
        let other_key = generate_keypair();
        let third_key = generate_keypair();

        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![
            hex::encode(local_pk),
            hex::encode(*other_key.verifying_key().as_bytes()),
            hex::encode(*third_key.verifying_key().as_bytes()),
        ];

        {
            let mut guard = chain.write().await;
            guard.validator_key = local_key.clone();
            guard.state.state.governance_state.finality_mode = FinalityMode::BftCertified {
                quorum_threshold: 2,
            };
            guard.set_validator_set(vec![ValidatorAuthority {
                node_id: local_pk,
                governance_level: PrecedenceLevel::Safety,
                norm_compliance: TensionValue::from_integer(1),
                causal_reliability: TensionValue::from_integer(1),
                active: true,
            }]);
        }

        let runtime = NetworkRuntime::new(chain.clone(), config).await.unwrap();
        // Override chain validator set to just local so it's always proposer.
        // Runtime validator set still has 3 for quorum calculation.
        {
            let mut guard = chain.write().await;
            guard.set_validator_set(vec![ValidatorAuthority {
                node_id: local_pk,
                governance_level: PrecedenceLevel::Safety,
                norm_compliance: TensionValue::from_integer(1),
                causal_reliability: TensionValue::from_integer(1),
                active: true,
            }]);
        }
        let block = { chain.read().await.build_candidate_block().unwrap() };
        runtime
            .handle_block_proposal(signed_block_proposal(
                &local_key,
                BlockProposalMessage {
                    proposer_id: local_pk,
                    block: block.clone(),
                    round: 0,
                    signature: Vec::new(),
                },
            ))
            .await
            .unwrap();

        let rounds = runtime.consensus_rounds.lock().await;
        let state = rounds.get(&block.header.height).expect("round created");
        assert_eq!(state.round.quorum, 2);
    }

    #[tokio::test]
    async fn test_runtime_uses_chain_validator_set_when_config_empty() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_key = { chain.read().await.validator_key.clone() };
        let local_pk = *local_key.verifying_key().as_bytes();
        let other_key = generate_keypair();
        let other_pk = *other_key.verifying_key().as_bytes();

        {
            let mut guard = chain.write().await;
            guard.validator_set = vec![
                ValidatorAuthority {
                    node_id: local_pk,
                    governance_level: PrecedenceLevel::Safety,
                    norm_compliance: TensionValue::from_integer(1),
                    causal_reliability: TensionValue::from_integer(1),
                    active: true,
                },
                ValidatorAuthority {
                    node_id: other_pk,
                    governance_level: PrecedenceLevel::Safety,
                    norm_compliance: TensionValue::from_integer(1),
                    causal_reliability: TensionValue::from_integer(1),
                    active: true,
                },
            ];
        }

        let mut config = crate::config::NodeConfig::default().network;
        config.validators = Vec::new();

        let runtime = NetworkRuntime::new(chain, config).await.unwrap();
        let validator_set = runtime.validator_set.read().await;
        assert!(validator_set.contains_key(&local_pk));
        assert!(validator_set.contains_key(&other_pk));
        assert_eq!(validator_set.len(), 2);
    }

    #[tokio::test]
    async fn test_load_persisted_consensus_state() {
        let dir =
            std::env::temp_dir().join(format!("sccgub_consensus_state_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Arc::new(ChainStore::new(&dir).unwrap());

        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = { *chain.read().await.validator_key.verifying_key().as_bytes() };
        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(local_pk)];

        let runtime = NetworkRuntime::new(chain, config)
            .await
            .unwrap()
            .with_persistence(store.clone(), 1);

        let validator_set = runtime.validator_set.read().await.clone();
        let round = ConsensusRound::new(
            runtime.chain_id,
            0,
            [9u8; 32],
            1,
            0,
            validator_set,
            runtime.config.max_rounds,
        );
        let mut state = RoundState {
            round,
            last_round_ms: now_ms(),
        };
        state.round.prevotes.insert(
            local_pk,
            Vote {
                validator_id: local_pk,
                block_hash: [9u8; 32],
                height: 1,
                round: 0,
                vote_type: VoteType::Prevote,
                signature: vec![1u8; 64],
            },
        );
        let mut payload = std::collections::HashMap::new();
        payload.insert(
            1u64,
            serde_json::to_value(round_state_to_persisted(&state)).unwrap(),
        );
        store.save_consensus_state(&payload).unwrap();

        runtime.load_persisted_consensus_state().await;

        let rounds = runtime.consensus_rounds.lock().await;
        let round = rounds.get(&1u64).expect("Expected persisted round");
        assert_eq!(round.round.block_hash, EMPTY_HASH);
        assert!(round.round.prevotes.is_empty());
        assert!(round.round.precommits.is_empty());

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_deterministic_quorum_is_one() {
        // Single validator — always the proposer, quorum=1 in deterministic mode.
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_key = { chain.read().await.validator_key.clone() };
        let local_pk = *local_key.verifying_key().as_bytes();

        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(local_pk)];

        {
            let mut guard = chain.write().await;
            guard.validator_key = local_key.clone();
            guard.state.state.governance_state.finality_mode = FinalityMode::Deterministic;
        }

        let runtime = NetworkRuntime::new(chain.clone(), config).await.unwrap();
        let block = { chain.read().await.build_candidate_block().unwrap() };
        runtime
            .handle_block_proposal(signed_block_proposal(
                &local_key,
                BlockProposalMessage {
                    proposer_id: local_pk,
                    block: block.clone(),
                    round: 0,
                    signature: Vec::new(),
                },
            ))
            .await
            .unwrap();

        // With quorum=1 (deterministic mode), the single proposer's prevote
        // immediately reaches quorum, the block finalizes, and the round is
        // cleaned up — all within handle_block_proposal. Verify the block was
        // imported as proof that quorum=1 worked.
        let guard = chain.read().await;
        assert_eq!(
            guard.height(),
            block.header.height,
            "Deterministic quorum=1 must finalize the block immediately"
        );
    }

    #[tokio::test]
    async fn test_peer_restart_matches_synced_chain_state() {
        let dir = std::env::temp_dir().join(format!("sccgub_peer_restart_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Arc::new(ChainStore::new(&dir).unwrap());

        let proposer_key = generate_keypair();
        let peer_key = generate_keypair();
        let proposer_pk = *proposer_key.verifying_key().as_bytes();
        let peer_pk = *peer_key.verifying_key().as_bytes();

        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(proposer_pk), hex::encode(peer_pk)];

        let base_chain = Chain::init();
        let chain_proposer = Arc::new(RwLock::new(base_chain.clone()));
        let chain_peer = Arc::new(RwLock::new(base_chain));
        {
            let mut guard = chain_proposer.write().await;
            guard.governance_limits.max_consecutive_proposals = 100;
            guard.validator_key = proposer_key.clone();
            let validators = NetworkRuntime::validators_from_config(&config).unwrap();
            guard.set_validator_set(validators);
        }
        {
            let mut guard = chain_peer.write().await;
            guard.governance_limits.max_consecutive_proposals = 100;
            guard.validator_key = peer_key.clone();
            let validators = NetworkRuntime::validators_from_config(&config).unwrap();
            guard.set_validator_set(validators);
        }

        let runtime_peer = Arc::new(
            NetworkRuntime::new(chain_peer.clone(), config)
                .await
                .unwrap()
                .with_persistence(store.clone(), 1),
        );

        let genesis = { chain_peer.read().await.latest_block().unwrap().clone() };
        store.save_block(&genesis).unwrap();

        for _ in 0..3 {
            let (block, expected_proposer_id, expected_signing_key) = {
                let mut guard = chain_proposer.write().await;
                let height = guard.height() + 1;
                let expected = round_robin_proposer(&guard.validator_set, height)
                    .expect("expected active proposer");
                if expected.node_id == proposer_pk {
                    guard.validator_key = proposer_key.clone();
                    (
                        guard.build_candidate_block_unchecked().unwrap(),
                        expected.node_id,
                        proposer_key.clone(),
                    )
                } else {
                    guard.validator_key = peer_key.clone();
                    (
                        guard.build_candidate_block_unchecked().unwrap(),
                        expected.node_id,
                        peer_key.clone(),
                    )
                }
            };

            runtime_peer
                .handle_message(
                    NetworkMessage::BlockProposal(signed_block_proposal(
                        &expected_signing_key,
                        BlockProposalMessage {
                            proposer_id: expected_proposer_id,
                            block: block.clone(),
                            round: 0,
                            signature: Vec::new(),
                        },
                    )),
                    "127.0.0.1:9101",
                )
                .await
                .unwrap();

            let epoch = runtime_peer.current_epoch().await;
            let data = vote_sign_data(
                &runtime_peer.chain_id,
                epoch,
                &block.header.block_id,
                block.header.height,
                0,
                VoteType::Prevote,
            );
            let vote1 = Vote {
                validator_id: proposer_pk,
                block_hash: block.header.block_id,
                height: block.header.height,
                round: 0,
                vote_type: VoteType::Prevote,
                signature: sign(&proposer_key, &data),
            };
            let vote2 = Vote {
                validator_id: peer_pk,
                block_hash: block.header.block_id,
                height: block.header.height,
                round: 0,
                vote_type: VoteType::Prevote,
                signature: sign(&peer_key, &data),
            };

            runtime_peer
                .handle_message(NetworkMessage::ConsensusVote(vote1), "127.0.0.1:9101")
                .await
                .unwrap();
            runtime_peer
                .handle_message(NetworkMessage::ConsensusVote(vote2), "127.0.0.1:9102")
                .await
                .unwrap();

            let data_commit = vote_sign_data(
                &runtime_peer.chain_id,
                epoch,
                &block.header.block_id,
                block.header.height,
                0,
                VoteType::Precommit,
            );
            let commit1 = Vote {
                validator_id: proposer_pk,
                block_hash: block.header.block_id,
                height: block.header.height,
                round: 0,
                vote_type: VoteType::Precommit,
                signature: sign(&proposer_key, &data_commit),
            };
            let commit2 = Vote {
                validator_id: peer_pk,
                block_hash: block.header.block_id,
                height: block.header.height,
                round: 0,
                vote_type: VoteType::Precommit,
                signature: sign(&peer_key, &data_commit),
            };

            runtime_peer
                .handle_message(NetworkMessage::ConsensusVote(commit1), "127.0.0.1:9101")
                .await
                .unwrap();
            runtime_peer
                .handle_message(NetworkMessage::ConsensusVote(commit2), "127.0.0.1:9102")
                .await
                .unwrap();

            {
                let mut proposer = chain_proposer.write().await;
                proposer.validator_key = expected_signing_key;
                let _ = proposer.import_block(block.clone());
            }

            {
                let peer = chain_peer.read().await;
                assert_eq!(peer.height(), block.header.height);
                assert_eq!(
                    peer.latest_block().unwrap().header.block_id,
                    block.header.block_id
                );
            }

            let persisted =
                wait_for_persisted_height(store.as_ref(), block.header.height, 15_000).await;
            assert!(
                persisted,
                "Expected persisted block at height {}",
                block.header.height
            );
        }

        let blocks = store.load_all_blocks().unwrap();
        let mut replayed = Chain::from_blocks(blocks).unwrap();
        let snapshot = wait_for_snapshot_height(store.as_ref(), replayed.height(), 15_000)
            .await
            .expect("expected snapshot for restart");

        assert_eq!(snapshot.height, replayed.height());
        assert_eq!(snapshot.state_root, replayed.state.state_root());

        replayed.restore_from_snapshot(&snapshot);
        let peer = chain_peer.read().await;
        assert_eq!(replayed.state.state_root(), peer.state.state_root());
        assert_eq!(
            replayed.balances.total_supply(),
            peer.balances.total_supply()
        );
        assert_eq!(
            replayed.governance_limits.max_consecutive_proposals,
            peer.governance_limits.max_consecutive_proposals
        );
        assert_eq!(
            replayed.finality_config.confirmation_depth,
            snapshot.finality_config.confirmation_depth
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_rate_limit_bans_peer() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = {
            let guard = chain.read().await;
            *guard.validator_key.verifying_key().as_bytes()
        };
        let mut config = default_network_config_with_validator(&local_pk);
        config.inbound_msg_limit = 1;
        config.peer_max_violations = 1;
        config.peer_score_initial = 10;
        config.peer_score_penalty = 10;
        config.peer_score_ban_threshold = 0;

        let runtime = NetworkRuntime::new(chain, config).await.unwrap();
        let addr = "127.0.0.1:4000";
        {
            let mut registry = runtime.registry.lock().await;
            registry
                .upsert(PeerInfo {
                    validator_id: local_pk,
                    address: addr.to_string(),
                    current_height: 0,
                    finalized_height: 0,
                    protocol_version: runtime.config.protocol_version,
                    last_seen_ms: now_ms(),
                    score: runtime.config.peer_score_initial,
                    violations: 0,
                    last_score_decay_ms: now_ms(),
                    last_violation_forgive_ms: now_ms(),
                    state: PeerState::Connected,
                })
                .unwrap();
        }

        runtime.check_rate_limit(addr, false).await.unwrap();
        let err = runtime.check_rate_limit(addr, false).await.unwrap_err();
        assert!(
            err.contains("disconnect: rate limit exceeded"),
            "Expected disconnect on rate limit, got: {}",
            err
        );

        let registry = runtime.registry.lock().await;
        let peer = registry.peers.get(&local_pk).unwrap();
        assert_eq!(peer.state, PeerState::Banned);
    }

    #[test]
    fn test_advance_round_on_timeout() {
        let mut config = crate::config::NodeConfig::default().network;
        config.round_timeout_ms = 1_000;
        config.max_rounds = 3;

        let mut state = RoundState {
            round: ConsensusRound::new(
                [1u8; 32],
                0,
                [2u8; 32],
                1,
                0,
                HashMap::new(),
                config.max_rounds,
            ),
            last_round_ms: 0,
        };
        state.round.prevotes.insert(
            [3u8; 32],
            Vote {
                validator_id: [3u8; 32],
                block_hash: [2u8; 32],
                height: 1,
                round: 0,
                vote_type: VoteType::Prevote,
                signature: vec![1u8; 64],
            },
        );

        let old_hash = advance_round_if_timed_out(&mut state, &config, 2_000);
        assert_eq!(state.round.round, 1);
        assert_eq!(
            state.round.phase,
            sccgub_consensus::protocol::ConsensusPhase::Propose
        );
        assert!(state.round.prevotes.is_empty());
        assert!(state.round.precommits.is_empty());
        assert_eq!(state.round.block_hash, EMPTY_HASH);
        assert_eq!(old_hash, Some([2u8; 32]));
        assert_eq!(state.last_round_ms, 2_000);
    }

    #[test]
    fn test_advance_round_aborts_at_max() {
        let mut config = crate::config::NodeConfig::default().network;
        config.round_timeout_ms = 1_000;
        config.max_rounds = 1;

        let mut state = RoundState {
            round: ConsensusRound::new(
                [1u8; 32],
                0,
                [2u8; 32],
                1,
                1,
                HashMap::new(),
                config.max_rounds,
            ),
            last_round_ms: 0,
        };

        let old_hash = advance_round_if_timed_out(&mut state, &config, 2_000);
        assert_eq!(
            state.round.phase,
            sccgub_consensus::protocol::ConsensusPhase::Abort
        );
        assert_eq!(old_hash, Some([2u8; 32]));
    }

    #[tokio::test]
    async fn test_consensus_phase_progression() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = {
            let guard = chain.read().await;
            *guard.validator_key.verifying_key().as_bytes()
        };
        let mut config = default_network_config_with_validator(&local_pk);
        config.max_rounds = 3;

        let runtime = Arc::new(NetworkRuntime::new(chain.clone(), config).await.unwrap());

        let validator_set = runtime.validator_set.read().await.clone();
        let mut rounds = runtime.consensus_rounds.lock().await;
        rounds.insert(
            1,
            RoundState {
                round: ConsensusRound::new(
                    runtime.chain_id,
                    runtime.current_epoch().await,
                    [9u8; 32],
                    1,
                    0,
                    validator_set,
                    runtime.config.max_rounds,
                ),
                last_round_ms: now_ms(),
            },
        );
        drop(rounds);

        runtime.maybe_advance_consensus(1).await.unwrap();
        let rounds = runtime.consensus_rounds.lock().await;
        let state = rounds.get(&1).unwrap();
        assert_eq!(
            state.round.phase,
            sccgub_consensus::protocol::ConsensusPhase::Prevote
        );
    }

    #[tokio::test]
    async fn test_consensus_phase_moves_to_precommit_on_quorum() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = {
            let guard = chain.read().await;
            *guard.validator_key.verifying_key().as_bytes()
        };
        let key2 = sccgub_crypto::keys::generate_keypair();
        let key3 = sccgub_crypto::keys::generate_keypair();
        let pk2 = *key2.verifying_key().as_bytes();
        let pk3 = *key3.verifying_key().as_bytes();

        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(local_pk), hex::encode(pk2), hex::encode(pk3)];

        let runtime = Arc::new(NetworkRuntime::new(chain, config).await.unwrap());
        let validator_set = runtime.validator_set.read().await.clone();
        let mut round = ConsensusRound::new(
            runtime.chain_id,
            runtime.current_epoch().await,
            [9u8; 32],
            1,
            0,
            validator_set,
            runtime.config.max_rounds,
        );
        round.prevotes.insert(
            local_pk,
            Vote {
                validator_id: local_pk,
                block_hash: [9u8; 32],
                height: 1,
                round: 0,
                vote_type: VoteType::Prevote,
                signature: vec![1u8; 64],
            },
        );
        round.prevotes.insert(
            pk2,
            Vote {
                validator_id: pk2,
                block_hash: [9u8; 32],
                height: 1,
                round: 0,
                vote_type: VoteType::Prevote,
                signature: vec![1u8; 64],
            },
        );
        round.prevotes.insert(
            pk3,
            Vote {
                validator_id: pk3,
                block_hash: [9u8; 32],
                height: 1,
                round: 0,
                vote_type: VoteType::Prevote,
                signature: vec![1u8; 64],
            },
        );

        let mut rounds = runtime.consensus_rounds.lock().await;
        rounds.insert(
            1,
            RoundState {
                round,
                last_round_ms: now_ms(),
            },
        );
        drop(rounds);

        runtime.maybe_advance_consensus(1).await.unwrap();
        let rounds = runtime.consensus_rounds.lock().await;
        let state = rounds.get(&1).unwrap();
        assert_eq!(
            state.round.phase,
            sccgub_consensus::protocol::ConsensusPhase::Precommit
        );
    }

    #[tokio::test]
    async fn test_consensus_finalization_clears_round() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = {
            let guard = chain.read().await;
            *guard.validator_key.verifying_key().as_bytes()
        };
        let key2 = sccgub_crypto::keys::generate_keypair();
        let key3 = sccgub_crypto::keys::generate_keypair();
        let pk2 = *key2.verifying_key().as_bytes();
        let pk3 = *key3.verifying_key().as_bytes();

        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(local_pk), hex::encode(pk2), hex::encode(pk3)];

        let runtime = Arc::new(NetworkRuntime::new(chain, config).await.unwrap());
        let validator_set = runtime.validator_set.read().await.clone();
        let mut round = ConsensusRound::new(
            runtime.chain_id,
            runtime.current_epoch().await,
            [7u8; 32],
            1,
            0,
            validator_set,
            runtime.config.max_rounds,
        );

        for validator_id in [local_pk, pk2, pk3] {
            round.prevotes.insert(
                validator_id,
                Vote {
                    validator_id,
                    block_hash: [7u8; 32],
                    height: 1,
                    round: 0,
                    vote_type: VoteType::Prevote,
                    signature: vec![1u8; 64],
                },
            );
            round.precommits.insert(
                validator_id,
                Vote {
                    validator_id,
                    block_hash: [7u8; 32],
                    height: 1,
                    round: 0,
                    vote_type: VoteType::Precommit,
                    signature: vec![1u8; 64],
                },
            );
        }

        let mut rounds = runtime.consensus_rounds.lock().await;
        rounds.insert(
            1,
            RoundState {
                round,
                last_round_ms: now_ms(),
            },
        );
        drop(rounds);

        runtime.maybe_advance_consensus(1).await.unwrap();
        let rounds = runtime.consensus_rounds.lock().await;
        assert!(
            rounds.get(&1).is_none(),
            "round must be cleared on finality"
        );
    }

    #[tokio::test]
    async fn test_consensus_finalizes_and_imports_block() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = {
            let guard = chain.read().await;
            *guard.validator_key.verifying_key().as_bytes()
        };
        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(local_pk)];

        let runtime = Arc::new(NetworkRuntime::new(chain.clone(), config).await.unwrap());

        let block = {
            let guard = chain.read().await;
            guard.build_candidate_block_unchecked().unwrap()
        };

        runtime
            .pending_blocks
            .lock()
            .await
            .insert(block.header.block_id, block.clone());

        let validator_set = runtime.validator_set.read().await.clone();
        let mut round = ConsensusRound::new(
            runtime.chain_id,
            runtime.current_epoch().await,
            block.header.block_id,
            block.header.height,
            0,
            validator_set,
            runtime.config.max_rounds,
        );
        round.prevotes.insert(
            local_pk,
            Vote {
                validator_id: local_pk,
                block_hash: block.header.block_id,
                height: block.header.height,
                round: 0,
                vote_type: VoteType::Prevote,
                signature: vec![1u8; 64],
            },
        );
        round.precommits.insert(
            local_pk,
            Vote {
                validator_id: local_pk,
                block_hash: block.header.block_id,
                height: block.header.height,
                round: 0,
                vote_type: VoteType::Precommit,
                signature: vec![1u8; 64],
            },
        );

        let mut rounds = runtime.consensus_rounds.lock().await;
        rounds.insert(
            block.header.height,
            RoundState {
                round,
                last_round_ms: now_ms(),
            },
        );
        drop(rounds);

        runtime
            .maybe_advance_consensus(block.header.height)
            .await
            .unwrap();

        let rounds = runtime.consensus_rounds.lock().await;
        assert!(
            rounds.get(&block.header.height).is_none(),
            "round must be cleared after finality"
        );

        let pending = runtime.pending_blocks.lock().await;
        assert!(
            !pending.contains_key(&block.header.block_id),
            "pending block must be cleared after import"
        );
        drop(pending);

        let chain = chain.read().await;
        assert_eq!(chain.height(), block.header.height);
    }

    #[tokio::test]
    async fn test_peer_flow_block_proposal_to_import() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_key = { chain.read().await.validator_key.clone() };
        let local_pk = *local_key.verifying_key().as_bytes();
        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(local_pk)];

        {
            let mut guard = chain.write().await;
            guard.governance_limits.max_consecutive_proposals = 100;
            let validators = NetworkRuntime::validators_from_config(&config).unwrap();
            guard.set_validator_set(validators);
        }

        let runtime = Arc::new(NetworkRuntime::new(chain.clone(), config).await.unwrap());
        let block = {
            let guard = chain.read().await;
            guard.build_candidate_block_unchecked().unwrap()
        };

        runtime
            .handle_message(
                NetworkMessage::BlockProposal(signed_block_proposal(
                    &local_key,
                    BlockProposalMessage {
                        proposer_id: local_pk,
                        block: block.clone(),
                        round: 0,
                        signature: Vec::new(),
                    },
                )),
                "127.0.0.1:9001",
            )
            .await
            .unwrap();

        let precommit = runtime.sign_vote_with_epoch(
            runtime.current_epoch().await,
            block.header.block_id,
            block.header.height,
            0,
            VoteType::Precommit,
        );
        runtime
            .handle_message(NetworkMessage::ConsensusVote(precommit), "127.0.0.1:9001")
            .await
            .unwrap();

        let chain = chain.read().await;
        assert_eq!(chain.height(), block.header.height);
    }

    #[tokio::test]
    async fn test_block_proposal_rejects_mismatched_proposer() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = {
            let guard = chain.read().await;
            *guard.validator_key.verifying_key().as_bytes()
        };
        let other_key = generate_keypair();
        let other_pk = *other_key.verifying_key().as_bytes();
        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(local_pk)];

        {
            let mut guard = chain.write().await;
            guard.governance_limits.max_consecutive_proposals = 100;
            let validators = NetworkRuntime::validators_from_config(&config).unwrap();
            guard.set_validator_set(validators);
        }

        let runtime = Arc::new(NetworkRuntime::new(chain.clone(), config).await.unwrap());
        let block = {
            let guard = chain.read().await;
            guard.build_candidate_block_unchecked().unwrap()
        };

        let err = runtime
            .handle_message(
                NetworkMessage::BlockProposal(signed_block_proposal(
                    &other_key,
                    BlockProposalMessage {
                        proposer_id: other_pk,
                        block,
                        round: 0,
                        signature: Vec::new(),
                    },
                )),
                "127.0.0.1:9001",
            )
            .await
            .unwrap_err();
        assert!(
            err.contains("proposer_id mismatch"),
            "Expected proposer mismatch rejection, got: {}",
            err
        );
    }

    #[tokio::test]
    async fn test_peer_flow_timeout_then_finalize() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_key = { chain.read().await.validator_key.clone() };
        let local_pk = *local_key.verifying_key().as_bytes();
        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(local_pk)];
        config.round_timeout_ms = 1_000;
        config.max_rounds = 2;

        {
            let mut guard = chain.write().await;
            guard.governance_limits.max_consecutive_proposals = 100;
            let validators = NetworkRuntime::validators_from_config(&config).unwrap();
            guard.set_validator_set(validators);
        }

        let runtime = Arc::new(NetworkRuntime::new(chain.clone(), config).await.unwrap());
        let block = {
            let guard = chain.read().await;
            guard.build_candidate_block_unchecked().unwrap()
        };

        runtime
            .handle_message(
                NetworkMessage::BlockProposal(signed_block_proposal(
                    &local_key,
                    BlockProposalMessage {
                        proposer_id: local_pk,
                        block: block.clone(),
                        round: 0,
                        signature: Vec::new(),
                    },
                )),
                "127.0.0.1:9001",
            )
            .await
            .unwrap();

        runtime
            .pending_blocks
            .lock()
            .await
            .insert(block.header.block_id, block.clone());

        let validator_set = runtime.validator_set.read().await.clone();
        let mut rounds = runtime.consensus_rounds.lock().await;
        rounds.insert(
            block.header.height,
            RoundState {
                round: ConsensusRound::new(
                    runtime.chain_id,
                    runtime.current_epoch().await,
                    block.header.block_id,
                    block.header.height,
                    0,
                    validator_set,
                    runtime.config.max_rounds,
                ),
                last_round_ms: now_ms(),
            },
        );
        drop(rounds);

        {
            let mut rounds = runtime.consensus_rounds.lock().await;
            let state = rounds.get_mut(&block.header.height).unwrap();
            state.last_round_ms = 0;
            let _ = advance_round_if_timed_out(state, &runtime.config, 2_000);
            assert_eq!(state.round.round, 1);
        }

        let precommit = runtime.sign_vote_with_epoch(
            runtime.current_epoch().await,
            block.header.block_id,
            block.header.height,
            1,
            VoteType::Precommit,
        );
        runtime
            .handle_message(NetworkMessage::ConsensusVote(precommit), "127.0.0.1:9001")
            .await
            .unwrap();

        let chain = chain.read().await;
        assert_eq!(chain.height(), block.header.height);
    }

    #[tokio::test]
    async fn test_two_validator_vote_gossip_finalizes() {
        let key1 = sccgub_crypto::keys::generate_keypair();
        let key2 = sccgub_crypto::keys::generate_keypair();
        let pk1 = *key1.verifying_key().as_bytes();
        let pk2 = *key2.verifying_key().as_bytes();

        let (proposer_key, proposer_pk, peer_key, peer_pk) = if pk1 > pk2 {
            (key1, pk1, key2, pk2)
        } else {
            (key2, pk2, key1, pk1)
        };

        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(pk1), hex::encode(pk2)];

        let base_chain = Chain::init();
        let chain_proposer = Arc::new(RwLock::new(base_chain.clone()));
        let chain_peer = Arc::new(RwLock::new(base_chain));
        {
            let mut guard = chain_proposer.write().await;
            guard.governance_limits.max_consecutive_proposals = 100;
            guard.validator_key = proposer_key.clone();
            let validators = NetworkRuntime::validators_from_config(&config).unwrap();
            guard.set_validator_set(validators);
        }
        {
            let mut guard = chain_peer.write().await;
            guard.governance_limits.max_consecutive_proposals = 100;
            guard.validator_key = peer_key.clone();
            let validators = NetworkRuntime::validators_from_config(&config).unwrap();
            guard.set_validator_set(validators);
        }

        let runtime_peer = Arc::new(
            NetworkRuntime::new(chain_peer.clone(), config)
                .await
                .unwrap(),
        );
        let block = {
            let guard = chain_proposer.read().await;
            guard.build_candidate_block_unchecked().unwrap()
        };

        runtime_peer
            .handle_message(
                NetworkMessage::BlockProposal(signed_block_proposal(
                    &proposer_key,
                    BlockProposalMessage {
                        proposer_id: proposer_pk,
                        block: block.clone(),
                        round: 0,
                        signature: Vec::new(),
                    },
                )),
                "127.0.0.1:9101",
            )
            .await
            .unwrap();

        let epoch = runtime_peer.current_epoch().await;
        let data = vote_sign_data(
            &runtime_peer.chain_id,
            epoch,
            &block.header.block_id,
            block.header.height,
            0,
            VoteType::Prevote,
        );
        let vote1 = Vote {
            validator_id: proposer_pk,
            block_hash: block.header.block_id,
            height: block.header.height,
            round: 0,
            vote_type: VoteType::Prevote,
            signature: sign(&proposer_key, &data),
        };
        let vote2 = Vote {
            validator_id: peer_pk,
            block_hash: block.header.block_id,
            height: block.header.height,
            round: 0,
            vote_type: VoteType::Prevote,
            signature: sign(&peer_key, &data),
        };

        runtime_peer
            .handle_message(NetworkMessage::ConsensusVote(vote1), "127.0.0.1:9101")
            .await
            .unwrap();
        runtime_peer
            .handle_message(NetworkMessage::ConsensusVote(vote2), "127.0.0.1:9102")
            .await
            .unwrap();

        let data_commit = vote_sign_data(
            &runtime_peer.chain_id,
            epoch,
            &block.header.block_id,
            block.header.height,
            0,
            VoteType::Precommit,
        );
        let commit1 = Vote {
            validator_id: proposer_pk,
            block_hash: block.header.block_id,
            height: block.header.height,
            round: 0,
            vote_type: VoteType::Precommit,
            signature: sign(&proposer_key, &data_commit),
        };
        let commit2 = Vote {
            validator_id: peer_pk,
            block_hash: block.header.block_id,
            height: block.header.height,
            round: 0,
            vote_type: VoteType::Precommit,
            signature: sign(&peer_key, &data_commit),
        };

        runtime_peer
            .handle_message(NetworkMessage::ConsensusVote(commit1), "127.0.0.1:9101")
            .await
            .unwrap();
        runtime_peer
            .handle_message(NetworkMessage::ConsensusVote(commit2), "127.0.0.1:9102")
            .await
            .unwrap();

        let chain = chain_peer.read().await;
        assert_eq!(chain.height(), block.header.height);
        assert_eq!(
            chain.latest_block().unwrap().header.validator_id,
            proposer_pk
        );
        assert_eq!(chain.safety_certificates.len(), 1);
        assert_eq!(
            chain.safety_certificates[0].block_hash,
            block.header.block_id
        );
    }

    #[tokio::test]
    async fn test_three_validator_quorum_finalizes() {
        let key1 = sccgub_crypto::keys::generate_keypair();
        let key2 = sccgub_crypto::keys::generate_keypair();
        let key3 = sccgub_crypto::keys::generate_keypair();
        let pk1 = *key1.verifying_key().as_bytes();
        let pk2 = *key2.verifying_key().as_bytes();
        let pk3 = *key3.verifying_key().as_bytes();

        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(pk1), hex::encode(pk2), hex::encode(pk3)];

        let validators = NetworkRuntime::validators_from_config(&config).unwrap();
        let base_chain = Chain::init();
        let height = base_chain.height().saturating_add(1);
        let proposer = sccgub_governance::validator::round_robin_proposer(&validators, height)
            .expect("validator set must pick proposer");

        let (proposer_key, proposer_pk) = if proposer.node_id == pk1 {
            (key1.clone(), pk1)
        } else if proposer.node_id == pk2 {
            (key2.clone(), pk2)
        } else {
            (key3.clone(), pk3)
        };

        let chain_proposer = Arc::new(RwLock::new(base_chain.clone()));
        let chain_peer = Arc::new(RwLock::new(base_chain));
        {
            let mut guard = chain_proposer.write().await;
            guard.governance_limits.max_consecutive_proposals = 100;
            guard.validator_key = proposer_key.clone();
            guard.state.state.governance_state.finality_mode = FinalityMode::BftCertified {
                quorum_threshold: 3,
            };
            guard.set_validator_set(validators.clone());
        }
        {
            let mut guard = chain_peer.write().await;
            guard.governance_limits.max_consecutive_proposals = 100;
            guard.validator_key = key2.clone();
            guard.state.state.governance_state.finality_mode = FinalityMode::BftCertified {
                quorum_threshold: 3,
            };
            guard.set_validator_set(validators);
        }

        let runtime_peer = Arc::new(
            NetworkRuntime::new(chain_peer.clone(), config)
                .await
                .unwrap(),
        );
        let block = {
            let guard = chain_proposer.read().await;
            guard.build_candidate_block_unchecked().unwrap()
        };
        let proposer_signing_key = if proposer_pk == pk1 {
            &key1
        } else if proposer_pk == pk2 {
            &key2
        } else {
            &key3
        };

        runtime_peer
            .handle_message(
                NetworkMessage::BlockProposal(signed_block_proposal(
                    proposer_signing_key,
                    BlockProposalMessage {
                        proposer_id: proposer_pk,
                        block: block.clone(),
                        round: 0,
                        signature: Vec::new(),
                    },
                )),
                "127.0.0.1:9201",
            )
            .await
            .unwrap();

        let epoch = runtime_peer.current_epoch().await;
        let data = vote_sign_data(
            &runtime_peer.chain_id,
            epoch,
            &block.header.block_id,
            block.header.height,
            0,
            VoteType::Prevote,
        );
        let votes = [(pk1, &key1), (pk2, &key2), (pk3, &key3)];
        for (idx, (pk, key)) in votes.iter().enumerate() {
            let vote = Vote {
                validator_id: *pk,
                block_hash: block.header.block_id,
                height: block.header.height,
                round: 0,
                vote_type: VoteType::Prevote,
                signature: sign(key, &data),
            };
            let addr = format!("127.0.0.1:92{:02}", idx + 2);
            runtime_peer
                .handle_message(NetworkMessage::ConsensusVote(vote), &addr)
                .await
                .unwrap();
        }

        let data_commit = vote_sign_data(
            &runtime_peer.chain_id,
            epoch,
            &block.header.block_id,
            block.header.height,
            0,
            VoteType::Precommit,
        );
        for (idx, (pk, key)) in votes.iter().enumerate() {
            let vote = Vote {
                validator_id: *pk,
                block_hash: block.header.block_id,
                height: block.header.height,
                round: 0,
                vote_type: VoteType::Precommit,
                signature: sign(key, &data_commit),
            };
            let addr = format!("127.0.0.1:92{:02}", idx + 5);
            runtime_peer
                .handle_message(NetworkMessage::ConsensusVote(vote), &addr)
                .await
                .unwrap();
        }

        let chain = chain_peer.read().await;
        assert_eq!(chain.height(), block.header.height);
        assert_eq!(
            chain.latest_block().unwrap().header.validator_id,
            proposer_pk
        );
        assert_eq!(chain.safety_certificates.len(), 1);
        assert_eq!(
            chain.safety_certificates[0].block_hash,
            block.header.block_id
        );
    }

    #[tokio::test]
    async fn test_three_validator_timeout_then_finalize_next_round() {
        let key1 = sccgub_crypto::keys::generate_keypair();
        let key2 = sccgub_crypto::keys::generate_keypair();
        let key3 = sccgub_crypto::keys::generate_keypair();
        let pk1 = *key1.verifying_key().as_bytes();
        let pk2 = *key2.verifying_key().as_bytes();
        let pk3 = *key3.verifying_key().as_bytes();

        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(pk1), hex::encode(pk2), hex::encode(pk3)];
        config.round_timeout_ms = 1_000;
        config.max_rounds = 3;

        let validators = NetworkRuntime::validators_from_config(&config).unwrap();
        let base_chain = Chain::init();
        let height = base_chain.height().saturating_add(1);
        let proposer = sccgub_governance::validator::round_robin_proposer(&validators, height)
            .expect("validator set must pick proposer");

        let (proposer_key, proposer_pk) = if proposer.node_id == pk1 {
            (key1.clone(), pk1)
        } else if proposer.node_id == pk2 {
            (key2.clone(), pk2)
        } else {
            (key3.clone(), pk3)
        };

        let chain_proposer = Arc::new(RwLock::new(base_chain.clone()));
        let chain_peer = Arc::new(RwLock::new(base_chain));
        {
            let mut guard = chain_proposer.write().await;
            guard.governance_limits.max_consecutive_proposals = 100;
            guard.validator_key = proposer_key.clone();
            guard.state.state.governance_state.finality_mode = FinalityMode::BftCertified {
                quorum_threshold: 3,
            };
            guard.set_validator_set(validators.clone());
        }
        {
            let mut guard = chain_peer.write().await;
            guard.governance_limits.max_consecutive_proposals = 100;
            guard.validator_key = key2.clone();
            guard.state.state.governance_state.finality_mode = FinalityMode::BftCertified {
                quorum_threshold: 3,
            };
            guard.set_validator_set(validators);
        }

        let runtime_peer = Arc::new(
            NetworkRuntime::new(chain_peer.clone(), config)
                .await
                .unwrap(),
        );
        let quorum = runtime_peer.consensus_quorum().await;
        assert_eq!(quorum, 3);
        let validator_set = runtime_peer.validator_set.read().await;
        assert_eq!(validator_set.len(), 3);
        let block = {
            let guard = chain_proposer.read().await;
            guard.build_candidate_block_unchecked().unwrap()
        };

        runtime_peer
            .handle_message(
                NetworkMessage::BlockProposal(signed_block_proposal(
                    &proposer_key,
                    BlockProposalMessage {
                        proposer_id: proposer_pk,
                        block: block.clone(),
                        round: 0,
                        signature: Vec::new(),
                    },
                )),
                "127.0.0.1:9301",
            )
            .await
            .unwrap();

        let epoch = runtime_peer.current_epoch().await;
        let prevote_round0 = vote_sign_data(
            &runtime_peer.chain_id,
            epoch,
            &block.header.block_id,
            block.header.height,
            0,
            VoteType::Prevote,
        );
        let validators_keys = [(pk1, &key1), (pk2, &key2), (pk3, &key3)];
        for (idx, (pk, key)) in validators_keys.iter().enumerate() {
            let vote = Vote {
                validator_id: *pk,
                block_hash: block.header.block_id,
                height: block.header.height,
                round: 0,
                vote_type: VoteType::Prevote,
                signature: sign(key, &prevote_round0),
            };
            let addr = format!("127.0.0.1:93{:02}", idx + 2);
            runtime_peer
                .handle_message(NetworkMessage::ConsensusVote(vote), &addr)
                .await
                .unwrap();
        }

        let chain_height = { chain_peer.read().await.height() };
        assert!(chain_height < block.header.height);

        {
            let desired_quorum = runtime_peer.consensus_quorum().await;
            let validator_set = runtime_peer.validator_set.read().await.clone();
            let mut rounds = runtime_peer.consensus_rounds.lock().await;
            let state = rounds
                .entry(block.header.height)
                .or_insert_with(|| RoundState {
                    round: ConsensusRound::new(
                        runtime_peer.chain_id,
                        epoch,
                        block.header.block_id,
                        block.header.height,
                        0,
                        validator_set,
                        runtime_peer.config.max_rounds,
                    ),
                    last_round_ms: now_ms(),
                });
            state.round.quorum = desired_quorum;
            state.last_round_ms = 0;
            let _ = advance_round_if_timed_out(state, &runtime_peer.config, 2_000);
            assert_eq!(state.round.round, 1);
        }

        runtime_peer
            .handle_message(
                NetworkMessage::BlockProposal(signed_block_proposal(
                    &proposer_key,
                    BlockProposalMessage {
                        proposer_id: proposer_pk,
                        block: block.clone(),
                        round: 1,
                        signature: Vec::new(),
                    },
                )),
                "127.0.0.1:9302",
            )
            .await
            .unwrap();

        let prevote_round1 = vote_sign_data(
            &runtime_peer.chain_id,
            epoch,
            &block.header.block_id,
            block.header.height,
            1,
            VoteType::Prevote,
        );
        for (idx, (pk, key)) in validators_keys.iter().enumerate() {
            let vote = Vote {
                validator_id: *pk,
                block_hash: block.header.block_id,
                height: block.header.height,
                round: 1,
                vote_type: VoteType::Prevote,
                signature: sign(key, &prevote_round1),
            };
            let addr = format!("127.0.0.1:93{:02}", idx + 5);
            runtime_peer
                .handle_message(NetworkMessage::ConsensusVote(vote), &addr)
                .await
                .unwrap();
        }

        let precommit_round1 = vote_sign_data(
            &runtime_peer.chain_id,
            epoch,
            &block.header.block_id,
            block.header.height,
            1,
            VoteType::Precommit,
        );
        for (idx, (pk, key)) in validators_keys.iter().enumerate() {
            let vote = Vote {
                validator_id: *pk,
                block_hash: block.header.block_id,
                height: block.header.height,
                round: 1,
                vote_type: VoteType::Precommit,
                signature: sign(key, &precommit_round1),
            };
            let addr = format!("127.0.0.1:93{:02}", idx + 8);
            runtime_peer
                .handle_message(NetworkMessage::ConsensusVote(vote), &addr)
                .await
                .unwrap();
        }

        let chain = chain_peer.read().await;
        assert_eq!(chain.height(), block.header.height);
        assert_eq!(
            chain.latest_block().unwrap().header.validator_id,
            proposer_pk
        );
        assert_eq!(chain.safety_certificates.len(), 1);
    }

    #[tokio::test]
    async fn test_peer_diversity_gate_blocks_finality() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = {
            let guard = chain.read().await;
            *guard.validator_key.verifying_key().as_bytes()
        };
        let other_key = generate_keypair();
        let other_pk = *other_key.verifying_key().as_bytes();
        let mut config = crate::config::NodeConfig::default().network;
        config.enable = true;
        config.validators = vec![hex::encode(local_pk), hex::encode(other_pk)];

        let runtime = Arc::new(NetworkRuntime::new(chain.clone(), config).await.unwrap());
        let block = {
            let guard = chain.read().await;
            guard.build_candidate_block_unchecked().unwrap()
        };

        runtime
            .pending_blocks
            .lock()
            .await
            .insert(block.header.block_id, block.clone());

        let validator_set = runtime.validator_set.read().await.clone();
        let mut round = ConsensusRound::new(
            runtime.chain_id,
            runtime.current_epoch().await,
            block.header.block_id,
            block.header.height,
            0,
            validator_set,
            runtime.config.max_rounds,
        );
        round.prevotes.insert(
            local_pk,
            Vote {
                validator_id: local_pk,
                block_hash: block.header.block_id,
                height: block.header.height,
                round: 0,
                vote_type: VoteType::Prevote,
                signature: vec![1u8; 64],
            },
        );
        round.precommits.insert(
            local_pk,
            Vote {
                validator_id: local_pk,
                block_hash: block.header.block_id,
                height: block.header.height,
                round: 0,
                vote_type: VoteType::Precommit,
                signature: vec![1u8; 64],
            },
        );

        let mut rounds = runtime.consensus_rounds.lock().await;
        rounds.insert(
            block.header.height,
            RoundState {
                round,
                last_round_ms: now_ms(),
            },
        );
        drop(rounds);

        let err = runtime
            .maybe_advance_consensus(block.header.height)
            .await
            .unwrap_err();
        assert!(err.contains("Peer diversity gate"));
    }

    #[tokio::test]
    async fn test_bandwidth_accounting_updates() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = {
            let guard = chain.read().await;
            *guard.validator_key.verifying_key().as_bytes()
        };
        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(local_pk)];

        let runtime = Arc::new(NetworkRuntime::new(chain, config).await.unwrap());
        let addr = "127.0.0.1:9200";

        record_bandwidth(&runtime.bandwidth, addr, 120, 80).await;
        let usage = runtime.bandwidth_snapshot(addr).await.unwrap();
        assert_eq!(usage.inbound_bytes, 120);
        assert_eq!(usage.outbound_bytes, 80);
    }

    #[tokio::test]
    async fn test_bandwidth_limit_exceeded_disconnects() {
        let chain = Arc::new(RwLock::new(Chain::init()));
        let local_pk = {
            let guard = chain.read().await;
            *guard.validator_key.verifying_key().as_bytes()
        };
        let mut config = crate::config::NodeConfig::default().network;
        config.validators = vec![hex::encode(local_pk)];
        config.inbound_bytes_limit = 100;
        config.peer_max_violations = 1;

        let runtime = Arc::new(NetworkRuntime::new(chain, config).await.unwrap());
        let addr = "127.0.0.1:9300";
        {
            let mut registry = runtime.registry.lock().await;
            registry
                .upsert(PeerInfo {
                    validator_id: local_pk,
                    address: addr.to_string(),
                    current_height: 0,
                    finalized_height: 0,
                    protocol_version: runtime.config.protocol_version,
                    last_seen_ms: now_ms(),
                    score: runtime.config.peer_score_initial,
                    violations: 0,
                    last_score_decay_ms: now_ms(),
                    last_violation_forgive_ms: now_ms(),
                    state: PeerState::Connected,
                })
                .unwrap();
        }

        record_bandwidth(&runtime.bandwidth, addr, 200, 0).await;
        let err = runtime.check_bandwidth_limit(addr).await.unwrap_err();
        assert!(err.contains("bandwidth limit exceeded"));
    }
}
