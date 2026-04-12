//! Purpose: API bridge to keep HTTP state in sync with the live chain.
//! Governance scope: read-only mirror of chain state into API memory.
//! Dependencies: sccgub-api handlers, chain state snapshots.
//! Invariants: never mutates chain; sync is atomic under API RwLock.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::chain::Chain;
use crate::observability::ChainMetrics;

#[derive(Clone)]
pub struct ApiBridge {
    pub app_state: sccgub_api::handlers::SharedState,
    metrics: std::sync::Arc<std::sync::Mutex<ChainMetrics>>,
    last_sync_ms: std::sync::Arc<AtomicU64>,
    min_interval_ms: u64,
    bandwidth_inbound: std::sync::Arc<AtomicU64>,
    bandwidth_outbound: std::sync::Arc<AtomicU64>,
}

impl ApiBridge {
    pub fn new(app_state: sccgub_api::handlers::SharedState) -> Self {
        Self {
            app_state,
            metrics: std::sync::Arc::new(std::sync::Mutex::new(ChainMetrics::default())),
            last_sync_ms: std::sync::Arc::new(AtomicU64::new(0)),
            min_interval_ms: 250,
            bandwidth_inbound: std::sync::Arc::new(AtomicU64::new(0)),
            bandwidth_outbound: std::sync::Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn metrics(&self) -> std::sync::Arc<std::sync::Mutex<ChainMetrics>> {
        self.metrics.clone()
    }

    pub fn with_min_interval_ms(mut self, min_interval_ms: u64) -> Self {
        self.min_interval_ms = min_interval_ms.max(1);
        self
    }

    pub fn should_sync(&self, now_ms: u64) -> bool {
        let last = self.last_sync_ms.load(Ordering::Relaxed);
        if now_ms.saturating_sub(last) < self.min_interval_ms {
            return false;
        }
        self.last_sync_ms
            .compare_exchange(last, now_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    pub fn record_bandwidth(&self, inbound: u64, outbound: u64) {
        self.bandwidth_inbound.fetch_add(inbound, Ordering::Relaxed);
        self.bandwidth_outbound
            .fetch_add(outbound, Ordering::Relaxed);
    }

    pub async fn record_peer_bandwidth(&self, address: &str, inbound: u64, outbound: u64) {
        let mut app = self.app_state.write().await;
        let entry = app.peer_stats.entry(address.to_string()).or_insert(
            sccgub_api::handlers::PeerStatsSnapshot {
                address: address.to_string(),
                validator_id: None,
                score: 0,
                violations: 0,
                state: "Unknown".into(),
                inbound_bytes: 0,
                outbound_bytes: 0,
                last_seen_ms: 0,
            },
        );
        entry.inbound_bytes = entry.inbound_bytes.saturating_add(inbound);
        entry.outbound_bytes = entry.outbound_bytes.saturating_add(outbound);
    }

    pub async fn update_peer_stats(&self, snapshot: sccgub_api::handlers::PeerStatsSnapshot) {
        let mut app = self.app_state.write().await;
        app.peer_stats.insert(snapshot.address.clone(), snapshot);
    }

    pub async fn sync_from_chain(&self, chain: &Chain) -> Result<(), String> {
        let mut app = self.app_state.write().await;
        app.blocks = chain.blocks.clone();
        app.state = chain.state.clone();
        app.chain_id = chain.chain_id;
        app.finalized_height = chain.finality.finalized_height;
        app.proposals = chain.proposals.proposals.clone();
        app.governance_limits = chain.governance_limits.clone();
        app.finality_config = chain.finality_config.clone();
        app.slashing_events = chain.slashing.events.clone();
        app.slashing_stakes = chain
            .slashing
            .stakes
            .iter()
            .map(|(k, v)| (*k, v.raw()))
            .collect();
        app.slashing_removed = chain.slashing.removed.clone();
        app.equivocation_records = chain.equivocation_records.clone();
        app.pending_txs = chain.mempool.pending_snapshot();
        app.seen_tx_ids = app.pending_txs.iter().map(|tx| tx.tx_id).collect();
        app.bandwidth_inbound_bytes = self.bandwidth_inbound.load(Ordering::Relaxed);
        app.bandwidth_outbound_bytes = self.bandwidth_outbound.load(Ordering::Relaxed);
        if let Ok(mut metrics) = self.metrics.try_lock() {
            metrics.record_api_sync();
        }
        Ok(())
    }

    pub async fn sync_from_chain_arc(
        &self,
        chain: &tokio::sync::RwLock<Chain>,
    ) -> Result<(), String> {
        let chain_guard = chain.read().await;
        self.sync_from_chain(&chain_guard).await
    }
}
