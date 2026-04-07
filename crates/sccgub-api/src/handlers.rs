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
            return axum::Json(ApiResponse::err(ErrorCode::NoBlocks, "No blocks in chain"));
        }
    };

    let total_txs: u64 = app
        .blocks
        .iter()
        .map(|b| b.body.transition_count as u64)
        .sum();

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
) -> (
    axum::http::StatusCode,
    axum::Json<ApiResponse<BlockResponse>>,
) {
    let app = state.read().await;
    let block = match app.blocks.get(height as usize) {
        Some(b) => b,
        None => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(ApiResponse::err(
                    ErrorCode::BlockNotFound,
                    format!("Block {} not found", height),
                )),
            );
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

    (
        axum::http::StatusCode::OK,
        axum::Json(ApiResponse::ok(resp)),
    )
}

/// Pagination query parameters.
#[derive(Debug, serde::Deserialize)]
pub struct PaginationParams {
    pub offset: Option<usize>,
    pub limit: Option<usize>,
}

/// GET /state — paginated state entries.
pub async fn get_state(
    state: axum::extract::State<SharedState>,
    axum::extract::Query(params): axum::extract::Query<PaginationParams>,
) -> axum::Json<ApiResponse<PaginatedStateResponse>> {
    let app = state.read().await;
    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(100).min(1000); // Max 1000 per page.

    let all_entries: Vec<StateEntry> = app
        .state
        .trie
        .iter()
        .map(|(k, v)| StateEntry {
            key: String::from_utf8_lossy(k).to_string(),
            value: hex::encode(v), // Hex encode to handle binary values safely.
        })
        .collect();

    let total = all_entries.len();
    let page = all_entries.into_iter().skip(offset).take(limit).collect();

    axum::Json(ApiResponse::ok(PaginatedStateResponse {
        entries: page,
        total,
        offset,
        limit,
    }))
}

/// POST /tx/submit — submit a raw signed transaction.
pub async fn submit_tx(
    _state: axum::extract::State<SharedState>,
    axum::extract::Json(req): axum::extract::Json<SubmitTransactionRequest>,
) -> (
    axum::http::StatusCode,
    axum::Json<ApiResponse<TxSubmitResponse>>,
) {
    // Validate request.
    if req.tx_hex.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ApiResponse::err(
                ErrorCode::EmptyPayload,
                "tx_hex is required",
            )),
        );
    }

    // Decode the transaction from hex-encoded canonical bytes.
    let tx_bytes = match hex::decode(&req.tx_hex) {
        Ok(b) => b,
        Err(e) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidHex,
                    format!("Invalid hex: {}", e),
                )),
            );
        }
    };

    let tx: sccgub_types::transition::SymbolicTransition =
        match sccgub_crypto::canonical::from_canonical_bytes(&tx_bytes) {
            Ok(t) => t,
            Err(e) => {
                return (
                    axum::http::StatusCode::BAD_REQUEST,
                    axum::Json(ApiResponse::err(
                        ErrorCode::InvalidTransaction,
                        format!("Invalid transaction: {}", e),
                    )),
                );
            }
        };

    let tx_id = hex::encode(tx.tx_id);

    // For now, acknowledge receipt. Full mempool integration requires chain access.
    // In production, this would push to the mempool and return pending status.
    let _ = tx; // Transaction deserialized and validated.

    (
        axum::http::StatusCode::ACCEPTED,
        axum::Json(ApiResponse::ok(TxSubmitResponse {
            tx_id,
            status: "accepted".into(),
        })),
    )
}

/// GET /tx/:tx_id — lookup a transaction by hex ID across all blocks.
pub async fn get_tx(
    state: axum::extract::State<SharedState>,
    axum::extract::Path(tx_id_hex): axum::extract::Path<String>,
) -> (
    axum::http::StatusCode,
    axum::Json<ApiResponse<TxDetailResponse>>,
) {
    let tx_id_bytes = match hex::decode(&tx_id_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidHex,
                    "Invalid tx_id: expected 64-char hex",
                )),
            );
        }
    };

    let app = state.read().await;
    for block in &app.blocks {
        for tx in &block.body.transitions {
            if tx.tx_id == tx_id_bytes {
                let resp = TxDetailResponse {
                    tx_id: hex::encode(tx.tx_id),
                    block_height: block.header.height,
                    block_id: hex::encode(block.header.block_id),
                    kind: format!("{:?}", tx.intent.kind),
                    target: String::from_utf8_lossy(&tx.intent.target).to_string(),
                    purpose: tx.intent.declared_purpose.clone(),
                    actor: hex::encode(tx.actor.agent_id),
                    nonce: tx.nonce,
                };
                return (
                    axum::http::StatusCode::OK,
                    axum::Json(ApiResponse::ok(resp)),
                );
            }
        }
    }

    (
        axum::http::StatusCode::NOT_FOUND,
        axum::Json(ApiResponse::err(
            ErrorCode::TxNotFound,
            format!("Transaction {} not found", tx_id_hex),
        )),
    )
}

/// GET /health — system health.
pub async fn get_health(
    state: axum::extract::State<SharedState>,
) -> axum::Json<ApiResponse<HealthResponse>> {
    let app = state.read().await;
    let latest = match app.blocks.last() {
        Some(b) => b,
        None => {
            return axum::Json(ApiResponse::err(ErrorCode::NoBlocks, "No blocks in chain"));
        }
    };

    let total_txs: u64 = app
        .blocks
        .iter()
        .map(|b| b.body.transition_count as u64)
        .sum();
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
