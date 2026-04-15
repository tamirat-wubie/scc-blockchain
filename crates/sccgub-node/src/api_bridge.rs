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
        app.safety_certificates = chain.safety_certificates.clone();
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    fn test_shared_state() -> sccgub_api::handlers::SharedState {
        Arc::new(RwLock::new(sccgub_api::handlers::AppState {
            blocks: vec![],
            state: sccgub_state::world::ManagedWorldState::new(),
            chain_id: [1u8; 32],
            finalized_height: 0,
            proposals: Vec::new(),
            governance_limits: sccgub_governance::anti_concentration::GovernanceLimits::default(),
            finality_config: sccgub_consensus::finality::FinalityConfig::default(),
            slashing_events: Vec::new(),
            slashing_stakes: Vec::new(),
            slashing_removed: Vec::new(),
            equivocation_records: Vec::new(),
            safety_certificates: Vec::new(),
            bandwidth_inbound_bytes: 0,
            bandwidth_outbound_bytes: 0,
            peer_stats: std::collections::HashMap::new(),
            pending_txs: Vec::new(),
            seen_tx_ids: HashSet::new(),
        }))
    }

    #[test]
    fn test_should_sync_respects_interval() {
        let bridge = ApiBridge::new(test_shared_state()).with_min_interval_ms(100);

        // First sync always succeeds.
        assert!(bridge.should_sync(1000));
        // Too soon — should be throttled.
        assert!(!bridge.should_sync(1050));
        // After interval — should succeed.
        assert!(bridge.should_sync(1100));
    }

    #[test]
    fn test_with_min_interval_clamps_to_one() {
        let bridge = ApiBridge::new(test_shared_state()).with_min_interval_ms(0);
        // min_interval_ms is clamped to at least 1.
        assert_eq!(bridge.min_interval_ms, 1);
    }

    #[test]
    fn test_record_bandwidth_accumulates() {
        let bridge = ApiBridge::new(test_shared_state());
        bridge.record_bandwidth(100, 200);
        bridge.record_bandwidth(50, 30);
        assert_eq!(bridge.bandwidth_inbound.load(Ordering::Relaxed), 150);
        assert_eq!(bridge.bandwidth_outbound.load(Ordering::Relaxed), 230);
    }

    #[test]
    fn test_metrics_returns_shared_handle() {
        let bridge = ApiBridge::new(test_shared_state());
        let m1 = bridge.metrics();
        let m2 = bridge.metrics();
        // Both should point to the same underlying Mutex.
        assert!(Arc::ptr_eq(&m1, &m2));
    }

    #[tokio::test]
    async fn test_record_peer_bandwidth_creates_entry() {
        let bridge = ApiBridge::new(test_shared_state());
        bridge
            .record_peer_bandwidth("192.168.1.1:8080", 500, 300)
            .await;

        let app = bridge.app_state.read().await;
        let entry = app.peer_stats.get("192.168.1.1:8080").unwrap();
        assert_eq!(entry.inbound_bytes, 500);
        assert_eq!(entry.outbound_bytes, 300);
    }

    #[tokio::test]
    async fn test_record_peer_bandwidth_accumulates() {
        let bridge = ApiBridge::new(test_shared_state());
        bridge
            .record_peer_bandwidth("10.0.0.1:9000", 100, 200)
            .await;
        bridge.record_peer_bandwidth("10.0.0.1:9000", 50, 25).await;

        let app = bridge.app_state.read().await;
        let entry = app.peer_stats.get("10.0.0.1:9000").unwrap();
        assert_eq!(entry.inbound_bytes, 150);
        assert_eq!(entry.outbound_bytes, 225);
    }

    #[tokio::test]
    async fn test_update_peer_stats_inserts_snapshot() {
        let bridge = ApiBridge::new(test_shared_state());
        let snapshot = sccgub_api::handlers::PeerStatsSnapshot {
            address: "10.0.0.5:7000".into(),
            validator_id: Some([42u8; 32]),
            score: 100,
            violations: 0,
            state: "Connected".into(),
            inbound_bytes: 1024,
            outbound_bytes: 2048,
            last_seen_ms: 99999,
        };
        bridge.update_peer_stats(snapshot.clone()).await;

        let app = bridge.app_state.read().await;
        let entry = app.peer_stats.get("10.0.0.5:7000").unwrap();
        assert_eq!(entry.score, 100);
        assert_eq!(entry.validator_id, Some([42u8; 32]));
    }

    #[tokio::test]
    async fn test_sync_from_chain_populates_api_state() {
        let bridge = ApiBridge::new(test_shared_state());
        let chain = Chain::init();

        bridge.sync_from_chain(&chain).await.unwrap();

        let app = bridge.app_state.read().await;
        assert_eq!(app.blocks.len(), chain.blocks.len());
        assert_eq!(app.chain_id, chain.chain_id);
        assert_eq!(app.finalized_height, chain.finality.finalized_height);
    }

    #[tokio::test]
    async fn test_sync_from_chain_arc_delegates() {
        let bridge = ApiBridge::new(test_shared_state());
        let chain = Chain::init();
        let chain_arc = tokio::sync::RwLock::new(chain);

        bridge.sync_from_chain_arc(&chain_arc).await.unwrap();

        let app = bridge.app_state.read().await;
        assert!(!app.blocks.is_empty());
    }
}
