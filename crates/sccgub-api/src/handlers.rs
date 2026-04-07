use std::sync::Arc;
use tokio::sync::RwLock;

use sccgub_state::world::ManagedWorldState;
use sccgub_types::block::Block;

use crate::responses::*;

/// Shared application state for the API server.
pub struct AppState {
    pub blocks: Vec<Block>,
    pub state: ManagedWorldState,
    pub chain_id: [u8; 32],
    pub finalized_height: u64,
}

pub type SharedState = Arc<RwLock<AppState>>;

/// GET /status — chain summary.
pub async fn get_status(
    state: axum::extract::State<SharedState>,
) -> axum::Json<ApiResponse<ChainStatusResponse>> {
    let app = state.read().await;
    let latest = match app.blocks.last() {
        Some(b) => b,
        None => {
            return axum::Json(ApiResponse::err("No blocks"));
        }
    };

    let total_txs: u64 = app.blocks.iter().map(|b| b.body.transition_count as u64).sum();

    let resp = ChainStatusResponse {
        chain_id: hex::encode(app.chain_id),
        height: latest.header.height,
        block_count: app.blocks.len() as u64,
        total_transactions: total_txs,
        state_root: hex::encode(latest.header.state_root),
        finalized_height: app.finalized_height,
        finality_gap: latest.header.height.saturating_sub(app.finalized_height),
        tension: format!("{}", latest.header.tension_after),
        emergency_mode: latest.governance.emergency_mode,
        mfidel_seal: format!(
            "f[{}][{}]",
            latest.header.mfidel_seal.row, latest.header.mfidel_seal.column
        ),
    };

    axum::Json(ApiResponse::ok(resp))
}

/// GET /block/:height — block detail.
pub async fn get_block(
    state: axum::extract::State<SharedState>,
    axum::extract::Path(height): axum::extract::Path<u64>,
) -> axum::Json<ApiResponse<BlockResponse>> {
    let app = state.read().await;
    let block = match app.blocks.get(height as usize) {
        Some(b) => b,
        None => {
            return axum::Json(ApiResponse::err(format!("Block {} not found", height)));
        }
    };

    let transactions: Vec<TransactionSummary> = block
        .body
        .transitions
        .iter()
        .map(|tx| TransactionSummary {
            tx_id: hex::encode(tx.tx_id),
            kind: format!("{:?}", tx.intent.kind),
            target: String::from_utf8_lossy(&tx.intent.target).to_string(),
            purpose: tx.intent.declared_purpose.clone(),
            actor: hex::encode(tx.actor.agent_id),
            nonce: tx.nonce,
        })
        .collect();

    let resp = BlockResponse {
        height: block.header.height,
        block_id: hex::encode(block.header.block_id),
        parent_id: hex::encode(block.header.parent_id),
        state_root: hex::encode(block.header.state_root),
        transition_root: hex::encode(block.header.transition_root),
        mfidel_seal: format!(
            "f[{}][{}]",
            block.header.mfidel_seal.row, block.header.mfidel_seal.column
        ),
        transaction_count: block.body.transition_count,
        receipt_count: block.receipts.len(),
        tension_before: format!("{}", block.header.tension_before),
        tension_after: format!("{}", block.header.tension_after),
        validator_id: hex::encode(block.header.validator_id),
        transactions,
    };

    axum::Json(ApiResponse::ok(resp))
}

/// GET /state — all state entries.
pub async fn get_state(
    state: axum::extract::State<SharedState>,
) -> axum::Json<ApiResponse<Vec<StateEntry>>> {
    let app = state.read().await;
    let entries: Vec<StateEntry> = app
        .state
        .trie
        .iter()
        .map(|(k, v)| StateEntry {
            key: String::from_utf8_lossy(k).to_string(),
            value: String::from_utf8_lossy(v).to_string(),
        })
        .collect();

    axum::Json(ApiResponse::ok(entries))
}

/// GET /health — system health.
pub async fn get_health(
    state: axum::extract::State<SharedState>,
) -> axum::Json<ApiResponse<HealthResponse>> {
    let app = state.read().await;
    let latest = match app.blocks.last() {
        Some(b) => b,
        None => {
            return axum::Json(ApiResponse::err("No blocks"));
        }
    };

    let total_txs: u64 = app.blocks.iter().map(|b| b.body.transition_count as u64).sum();
    let total_edges: u64 = app
        .blocks
        .iter()
        .map(|b| b.causal_delta.new_edges.len() as u64)
        .sum();

    let finality_config = sccgub_consensus::finality::FinalityConfig::default();

    let resp = HealthResponse {
        status: "ok".into(),
        height: latest.header.height,
        finalized_height: app.finalized_height,
        finality_gap: latest.header.height.saturating_sub(app.finalized_height),
        sla_met: finality_config.meets_sla(),
        blocks_produced: app.blocks.len() as u64,
        total_transactions: total_txs,
        state_entries: app.state.trie.len() as u64,
        causal_edges: total_edges,
    };

    axum::Json(ApiResponse::ok(resp))
}
