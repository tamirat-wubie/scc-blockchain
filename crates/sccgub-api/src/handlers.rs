use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use sccgub_consensus::protocol::EquivocationProof;
use sccgub_consensus::slashing::{SlashingEvent, SlashingEvidence};
use sccgub_state::world::ManagedWorldState;
use sccgub_types::block::Block;
use sccgub_types::Hash;

use crate::responses::*;

/// Maximum pending transactions before rejecting new submissions.
pub const MAX_PENDING_TXS: usize = 10_000;
/// Maximum tracked seen IDs (LRU-style: oldest evicted when full).
pub const MAX_SEEN_TX_IDS: usize = 100_000;
const GOVERNED_PARAMETER_KEYS: [&str; 9] = [
    "governance.max_consecutive_proposals",
    "governance.max_actions_per_agent_pct",
    "governance.safety_change_min_signers",
    "governance.genesis_change_min_signers",
    "governance.max_authority_term_epochs",
    "governance.authority_cooldown_epochs",
    "finality.confirmation_depth",
    "finality.max_finality_ms",
    "finality.target_block_time_ms",
];

/// Shared application state for the API server.
pub struct AppState {
    pub blocks: Vec<Block>,
    pub state: ManagedWorldState,
    pub chain_id: [u8; 32],
    pub finalized_height: u64,
    pub proposals: Vec<sccgub_governance::proposals::GovernanceProposal>,
    pub governance_limits: sccgub_governance::anti_concentration::GovernanceLimits,
    pub finality_config: sccgub_consensus::finality::FinalityConfig,
    pub slashing_events: Vec<SlashingEvent>,
    pub slashing_stakes: Vec<(Hash, i128)>,
    pub slashing_removed: Vec<Hash>,
    pub equivocation_records: Vec<(EquivocationProof, u64)>,
    pub bandwidth_inbound_bytes: u64,
    pub bandwidth_outbound_bytes: u64,
    pub peer_stats: HashMap<String, PeerStatsSnapshot>,
    /// Pending transactions submitted via API (bounded by MAX_PENDING_TXS).
    pub pending_txs: Vec<sccgub_types::transition::SymbolicTransition>,
    /// Transaction IDs already seen (bounded by MAX_SEEN_TX_IDS).
    pub seen_tx_ids: std::collections::HashSet<[u8; 32]>,
}

/// Peer-level network stats snapshot for API exposure.
#[derive(Debug, Clone)]
pub struct PeerStatsSnapshot {
    pub address: String,
    pub validator_id: Option<Hash>,
    pub score: i32,
    pub violations: u32,
    pub state: String,
    pub inbound_bytes: u64,
    pub outbound_bytes: u64,
    pub last_seen_ms: u64,
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
        active_norm_count: latest.governance.active_norm_count,
        finality_expected_ms: app.finality_config.expected_finality_ms(),
        finality_sla_met: app.finality_config.meets_sla(),
        mfidel_seal: format!(
            "f[{}][{}]",
            latest.header.mfidel_seal.row, latest.header.mfidel_seal.column
        ),
        governed_parameters: GOVERNED_PARAMETER_KEYS
            .iter()
            .map(|k| k.to_string())
            .collect(),
        governed_parameter_values: std::collections::HashMap::from([
            (
                "governance.max_consecutive_proposals".to_string(),
                app.governance_limits.max_consecutive_proposals.to_string(),
            ),
            (
                "governance.max_actions_per_agent_pct".to_string(),
                app.governance_limits.max_actions_per_agent_pct.to_string(),
            ),
            (
                "governance.safety_change_min_signers".to_string(),
                app.governance_limits.safety_change_min_signers.to_string(),
            ),
            (
                "governance.genesis_change_min_signers".to_string(),
                app.governance_limits.genesis_change_min_signers.to_string(),
            ),
            (
                "governance.max_authority_term_epochs".to_string(),
                app.governance_limits.max_authority_term_epochs.to_string(),
            ),
            (
                "governance.authority_cooldown_epochs".to_string(),
                app.governance_limits.authority_cooldown_epochs.to_string(),
            ),
            (
                "finality.confirmation_depth".to_string(),
                app.finality_config.confirmation_depth.to_string(),
            ),
            (
                "finality.max_finality_ms".to_string(),
                app.finality_config.max_finality_ms.to_string(),
            ),
            (
                "finality.target_block_time_ms".to_string(),
                app.finality_config.target_block_time_ms.to_string(),
            ),
        ]),
        bandwidth_inbound_bytes: app.bandwidth_inbound_bytes,
        bandwidth_outbound_bytes: app.bandwidth_outbound_bytes,
    };

    axum::Json(ApiResponse::ok(resp))
}

/// GET /status/schema — JSON schema for status output.
pub async fn get_status_schema() -> axum::Json<ApiResponse<serde_json::Value>> {
    let schema = serde_json::from_str(include_str!("../../../specs/STATUS_JSON_SCHEMA.json"))
        .unwrap_or_else(|_| serde_json::json!({ "error": "invalid status schema" }));
    axum::Json(ApiResponse::ok(schema))
}

/// GET /governance/params — governed parameter values.
pub async fn get_governance_params(
    state: axum::extract::State<SharedState>,
) -> axum::Json<ApiResponse<GovernanceParamsResponse>> {
    let app = state.read().await;
    let resp = GovernanceParamsResponse {
        governance_limits: app.governance_limits.clone(),
        finality_config: app.finality_config.clone(),
    };
    axum::Json(ApiResponse::ok(resp))
}

/// GET /governance/params/schema — JSON schema for governed parameters.
pub async fn get_governance_params_schema() -> axum::Json<ApiResponse<serde_json::Value>> {
    let schema = serde_json::from_str(include_str!("../../../specs/GOVERNED_JSON_SCHEMA.json"))
        .unwrap_or_else(|_| serde_json::json!({ "error": "invalid governed schema" }));
    axum::Json(ApiResponse::ok(schema))
}

/// GET /governance/proposals — governance proposal registry summary.
pub async fn get_governance_proposals(
    state: axum::extract::State<SharedState>,
    params: Result<
        axum::extract::Query<GovernanceProposalsParams>,
        axum::extract::rejection::QueryRejection,
    >,
) -> (
    axum::http::StatusCode,
    axum::Json<ApiResponse<GovernanceProposalsResponse>>,
) {
    let params = match params {
        Ok(axum::extract::Query(params)) => params,
        Err(rejection) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidRequest,
                    format!("Invalid query parameters: {}", rejection),
                )),
            );
        }
    };

    if params.limit == Some(0) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ApiResponse::err(
                ErrorCode::InvalidRequest,
                "limit must be >= 1",
            )),
        );
    }

    let offset = params.offset.unwrap_or(0);
    let limit = params.limit.unwrap_or(100).min(1000);
    let status_filter = params.status.as_deref();
    let allowed_statuses = [
        "Submitted",
        "Voting",
        "Accepted",
        "Rejected",
        "Timelocked",
        "Activated",
        "Expired",
    ];
    if let Some(status) = status_filter {
        let valid = allowed_statuses
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(status));
        if !valid {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidRequest,
                    format!(
                        "Invalid status '{}'. Allowed: {}",
                        status,
                        allowed_statuses.join(", ")
                    ),
                )),
            );
        }
    }

    let app = state.read().await;
    let mut proposals = app
        .proposals
        .iter()
        .filter(|proposal| {
            status_filter
                .is_none_or(|status| status.eq_ignore_ascii_case(&format!("{:?}", proposal.status)))
        })
        .map(|proposal| GovernanceProposalSummary {
            id: hex::encode(proposal.id),
            status: format!("{:?}", proposal.status),
            votes_for: proposal.votes_for,
            votes_against: proposal.votes_against,
            timelock_until: proposal.timelock_until,
            submitted_at: proposal.submitted_at,
        })
        .collect::<Vec<_>>();
    proposals.sort_by(|a, b| b.submitted_at.cmp(&a.submitted_at));

    let total = proposals.len();
    let page = proposals
        .into_iter()
        .skip(offset)
        .take(limit)
        .collect::<Vec<_>>();

    (
        axum::http::StatusCode::OK,
        axum::Json(ApiResponse::ok(GovernanceProposalsResponse {
            count: total as u64,
            proposals: page,
        })),
    )
}

/// GET /openapi — OpenAPI spec as a string payload.
pub async fn get_openapi_spec() -> axum::Json<ApiResponse<OpenApiSpecResponse>> {
    let spec = crate::openapi::render_openapi_yaml();
    axum::Json(ApiResponse::ok(OpenApiSpecResponse { spec }))
}

/// GET /network/peers — peer network stats.
pub async fn get_network_peers(
    state: axum::extract::State<SharedState>,
) -> axum::Json<ApiResponse<NetworkPeersResponse>> {
    let app = state.read().await;
    let mut peers: Vec<NetworkPeerResponse> = app
        .peer_stats
        .values()
        .map(|peer| NetworkPeerResponse {
            address: peer.address.clone(),
            validator_id: peer.validator_id.map(hex::encode),
            score: peer.score,
            violations: peer.violations,
            state: peer.state.clone(),
            inbound_bytes: peer.inbound_bytes,
            outbound_bytes: peer.outbound_bytes,
            last_seen_ms: peer.last_seen_ms,
        })
        .collect();
    peers.sort_by(|a, b| a.address.cmp(&b.address));

    axum::Json(ApiResponse::ok(NetworkPeersResponse {
        count: peers.len() as u64,
        peers,
    }))
}

/// GET /network/peers/:validator_id — peer detail by validator id.
pub async fn get_network_peer(
    state: axum::extract::State<SharedState>,
    axum::extract::Path(validator_hex): axum::extract::Path<String>,
) -> (
    axum::http::StatusCode,
    axum::Json<ApiResponse<NetworkPeerResponse>>,
) {
    let validator_id = match hex::decode(&validator_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidHex,
                    "Invalid validator_id: expected 64-char hex",
                )),
            );
        }
    };

    let app = state.read().await;
    let peer = app
        .peer_stats
        .values()
        .find(|peer| peer.validator_id == Some(validator_id));
    let Some(peer) = peer else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(ApiResponse::err(
                ErrorCode::ValidatorNotFound,
                format!("Validator {} not found", validator_hex),
            )),
        );
    };

    (
        axum::http::StatusCode::OK,
        axum::Json(ApiResponse::ok(NetworkPeerResponse {
            address: peer.address.clone(),
            validator_id: peer.validator_id.map(hex::encode),
            score: peer.score,
            violations: peer.violations,
            state: peer.state.clone(),
            inbound_bytes: peer.inbound_bytes,
            outbound_bytes: peer.outbound_bytes,
            last_seen_ms: peer.last_seen_ms,
        })),
    )
}

/// GET /block/:height — block detail.
pub async fn get_block(
    state: axum::extract::State<SharedState>,
    height: Result<axum::extract::Path<u64>, axum::extract::rejection::PathRejection>,
) -> (
    axum::http::StatusCode,
    axum::Json<ApiResponse<BlockResponse>>,
) {
    let height = match height {
        Ok(axum::extract::Path(height)) => height,
        Err(rejection) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidRequest,
                    format!("Invalid path parameter: {}", rejection),
                )),
            );
        }
    };

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
        governance_limits: block.governance.governance_limits,
        finality_config: block.governance.finality_config,
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

/// Governance proposal query parameters.
#[derive(Debug, serde::Deserialize)]
pub struct GovernanceProposalsParams {
    pub offset: Option<usize>,
    pub limit: Option<usize>,
    pub status: Option<String>,
}

/// GET /state — paginated state entries.
pub async fn get_state(
    state: axum::extract::State<SharedState>,
    params: Result<
        axum::extract::Query<PaginationParams>,
        axum::extract::rejection::QueryRejection,
    >,
) -> (
    axum::http::StatusCode,
    axum::Json<ApiResponse<PaginatedStateResponse>>,
) {
    let params = match params {
        Ok(axum::extract::Query(params)) => params,
        Err(rejection) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidRequest,
                    format!("Invalid query parameters: {}", rejection),
                )),
            );
        }
    };

    if params.limit == Some(0) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ApiResponse::err(
                ErrorCode::InvalidRequest,
                "limit must be >= 1",
            )),
        );
    }

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

    (
        axum::http::StatusCode::OK,
        axum::Json(ApiResponse::ok(PaginatedStateResponse {
            entries: page,
            total,
            offset,
            limit,
        })),
    )
}

/// POST /tx/submit — submit a raw signed transaction to the pending pool.
pub async fn submit_tx(
    state: axum::extract::State<SharedState>,
    req: Result<
        axum::extract::Json<SubmitTransactionRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> (
    axum::http::StatusCode,
    axum::Json<ApiResponse<TxSubmitResponse>>,
) {
    let req = match req {
        Ok(axum::extract::Json(req)) => req,
        Err(rejection) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidRequest,
                    format!("Invalid request body: {}", rejection),
                )),
            );
        }
    };

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

    let tx = match decode_tx_hex(&req.tx_hex) {
        Ok(tx) => tx,
        Err(resp) => return resp,
    };

    let mut app = state.write().await;
    submit_tx_internal(&mut app, tx)
}

/// POST /governance/params/propose — submit a signed governance parameter proposal.
pub async fn submit_governance_param(
    state: axum::extract::State<SharedState>,
    req: Result<
        axum::extract::Json<SubmitGovernanceParamRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> (
    axum::http::StatusCode,
    axum::Json<ApiResponse<TxSubmitResponse>>,
) {
    let req = match req {
        Ok(axum::extract::Json(req)) => req,
        Err(rejection) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidRequest,
                    format!("Invalid request body: {}", rejection),
                )),
            );
        }
    };

    if req.tx_hex.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ApiResponse::err(
                ErrorCode::EmptyPayload,
                "tx_hex is required",
            )),
        );
    }

    let tx = match decode_tx_hex(&req.tx_hex) {
        Ok(tx) => tx,
        Err(resp) => return resp,
    };

    if tx.intent.kind != sccgub_types::transition::TransitionKind::GovernanceUpdate {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ApiResponse::err(
                ErrorCode::InvalidTransaction,
                "Governance param proposal must be GovernanceUpdate",
            )),
        );
    }

    let payload = match &tx.payload {
        sccgub_types::transition::OperationPayload::Write { key, value } => (key, value),
        _ => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidTransaction,
                    "Governance param proposal must be a Write payload",
                )),
            )
        }
    };

    if !payload.0.starts_with(b"norms/governance/params/propose") {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ApiResponse::err(
                ErrorCode::InvalidTransaction,
                "Governance param proposal must target norms/governance/params/propose",
            )),
        );
    }

    let decoded = match std::str::from_utf8(payload.1) {
        Ok(v) => v,
        Err(_) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidTransaction,
                    "Governance param proposal value must be UTF-8 key=value",
                )),
            )
        }
    };
    let mut parts = decoded.splitn(2, '=');
    let key = parts.next().unwrap_or("").trim();
    let value = parts.next().unwrap_or("").trim();
    if key.is_empty() || value.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ApiResponse::err(
                ErrorCode::InvalidTransaction,
                "Governance param proposal value must be key=value",
            )),
        );
    }
    if !GOVERNED_PARAMETER_KEYS.contains(&key) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ApiResponse::err(
                ErrorCode::InvalidTransaction,
                format!("Unsupported governed parameter key: {}", key),
            )),
        );
    }

    let mut app = state.write().await;
    submit_tx_internal(&mut app, tx)
}

/// POST /governance/proposals/vote — submit a signed governance proposal vote.
pub async fn submit_governance_vote(
    state: axum::extract::State<SharedState>,
    req: Result<
        axum::extract::Json<SubmitGovernanceVoteRequest>,
        axum::extract::rejection::JsonRejection,
    >,
) -> (
    axum::http::StatusCode,
    axum::Json<ApiResponse<TxSubmitResponse>>,
) {
    let req = match req {
        Ok(axum::extract::Json(req)) => req,
        Err(rejection) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidRequest,
                    format!("Invalid request body: {}", rejection),
                )),
            );
        }
    };

    if req.tx_hex.is_empty() {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ApiResponse::err(
                ErrorCode::EmptyPayload,
                "tx_hex is required",
            )),
        );
    }

    let tx = match decode_tx_hex(&req.tx_hex) {
        Ok(tx) => tx,
        Err(resp) => return resp,
    };

    if tx.intent.kind != sccgub_types::transition::TransitionKind::GovernanceUpdate {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ApiResponse::err(
                ErrorCode::InvalidTransaction,
                "Governance vote must be GovernanceUpdate",
            )),
        );
    }

    let payload = match &tx.payload {
        sccgub_types::transition::OperationPayload::Write { key, value } => (key, value),
        _ => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidTransaction,
                    "Governance vote must be a Write payload",
                )),
            )
        }
    };

    if !payload.0.starts_with(b"norms/governance/proposals/") {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ApiResponse::err(
                ErrorCode::InvalidTransaction,
                "Governance vote must target norms/governance/proposals/...",
            )),
        );
    }
    if payload.1.len() != 32 {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ApiResponse::err(
                ErrorCode::InvalidTransaction,
                "Governance vote value must be 32-byte proposal id",
            )),
        );
    }

    let mut app = state.write().await;
    submit_tx_internal(&mut app, tx)
}

fn decode_tx_hex(
    tx_hex: &str,
) -> Result<
    sccgub_types::transition::SymbolicTransition,
    (
        axum::http::StatusCode,
        axum::Json<ApiResponse<TxSubmitResponse>>,
    ),
> {
    let tx_bytes = match hex::decode(tx_hex) {
        Ok(b) => b,
        Err(e) => {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidHex,
                    format!("Invalid hex: {}", e),
                )),
            ))
        }
    };

    let tx = match sccgub_crypto::canonical::from_canonical_bytes(&tx_bytes) {
        Ok(t) => t,
        Err(e) => {
            return Err((
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidTransaction,
                    format!("Invalid transaction: {}", e),
                )),
            ))
        }
    };
    Ok(tx)
}

fn submit_tx_internal(
    app: &mut AppState,
    tx: sccgub_types::transition::SymbolicTransition,
) -> (
    axum::http::StatusCode,
    axum::Json<ApiResponse<TxSubmitResponse>>,
) {
    let tx_id = hex::encode(tx.tx_id);

    if app.seen_tx_ids.contains(&tx.tx_id) {
        return (
            axum::http::StatusCode::CONFLICT,
            axum::Json(ApiResponse::err(
                ErrorCode::NonceReplay,
                format!("Transaction {} already submitted", tx_id),
            )),
        );
    }

    if let Err(errors) = sccgub_execution::validate::validate_transition(&tx, &app.state) {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(ApiResponse::err(
                ErrorCode::InvalidTransaction,
                format!("Validation failed: {}", errors.join("; ")),
            )),
        );
    }

    if app.pending_txs.len() >= MAX_PENDING_TXS {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(ApiResponse::err(
                ErrorCode::RateLimited,
                "Pending transaction pool is full",
            )),
        );
    }

    if app.seen_tx_ids.len() >= MAX_SEEN_TX_IDS {
        app.seen_tx_ids.clear();
    }

    app.seen_tx_ids.insert(tx.tx_id);
    app.pending_txs.push(tx);

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

/// GET /block/:height/receipts — receipts for a specific block.
pub async fn get_block_receipts(
    state: axum::extract::State<SharedState>,
    height: Result<axum::extract::Path<u64>, axum::extract::rejection::PathRejection>,
) -> (
    axum::http::StatusCode,
    axum::Json<ApiResponse<BlockReceiptsResponse>>,
) {
    let height = match height {
        Ok(axum::extract::Path(height)) => height,
        Err(rejection) => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidRequest,
                    format!("Invalid path parameter: {}", rejection),
                )),
            );
        }
    };

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

    let receipts: Vec<ReceiptSummary> = block
        .receipts
        .iter()
        .map(|r| ReceiptSummary {
            tx_id: hex::encode(r.tx_id),
            verdict: format!("{}", r.verdict),
            compute_steps: r.resource_used.compute_steps,
            state_reads: r.resource_used.state_reads,
            state_writes: r.resource_used.state_writes,
            phi_phase_reached: r.phi_phase_reached,
        })
        .collect();

    let resp = BlockReceiptsResponse {
        height: block.header.height,
        receipt_count: receipts.len(),
        receipts,
    };

    (
        axum::http::StatusCode::OK,
        axum::Json(ApiResponse::ok(resp)),
    )
}

/// GET /receipt/:tx_id — receipt for a specific transaction.
pub async fn get_receipt(
    state: axum::extract::State<SharedState>,
    axum::extract::Path(tx_id_hex): axum::extract::Path<String>,
) -> (
    axum::http::StatusCode,
    axum::Json<ApiResponse<ReceiptSummary>>,
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
        for receipt in &block.receipts {
            if receipt.tx_id == tx_id_bytes {
                let resp = ReceiptSummary {
                    tx_id: hex::encode(receipt.tx_id),
                    verdict: format!("{}", receipt.verdict),
                    compute_steps: receipt.resource_used.compute_steps,
                    state_reads: receipt.resource_used.state_reads,
                    state_writes: receipt.resource_used.state_writes,
                    phi_phase_reached: receipt.phi_phase_reached,
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
            format!("Receipt for tx {} not found", tx_id_hex),
        )),
    )
}

/// GET /health — system health.
fn slashing_event_response(event: &SlashingEvent) -> SlashingEventResponse {
    let evidence = match &event.evidence {
        SlashingEvidence::Equivocation(proof) => serde_json::json!({
            "type": "Equivocation",
            "validator_id": hex::encode(proof.validator_id),
            "height": proof.height,
            "round": proof.round,
            "vote_type": format!("{:?}", proof.vote_type),
            "block_hash_a": hex::encode(proof.block_hash_a),
            "block_hash_b": hex::encode(proof.block_hash_b),
        }),
        SlashingEvidence::LawDivergence {
            validator_law_hash,
            consensus_law_hash,
        } => serde_json::json!({
            "type": "LawDivergence",
            "validator_law_hash": hex::encode(validator_law_hash),
            "consensus_law_hash": hex::encode(consensus_law_hash),
        }),
        SlashingEvidence::AbsenceRecord { absent_epochs } => serde_json::json!({
            "type": "AbsenceRecord",
            "absent_epochs": absent_epochs,
        }),
    };

    SlashingEventResponse {
        validator_id: hex::encode(event.validator_id),
        violation: format!("{:?}", event.violation),
        penalty: format!("{}", event.penalty),
        epoch: event.epoch,
        evidence,
    }
}

/// GET /slashing â€” slashing summary and events.
pub async fn get_slashing_summary(
    state: axum::extract::State<SharedState>,
) -> axum::Json<ApiResponse<SlashingSummaryResponse>> {
    let app = state.read().await;
    let events: Vec<SlashingEventResponse> = app
        .slashing_events
        .iter()
        .map(slashing_event_response)
        .collect();
    let removed_validators: Vec<String> = app.slashing_removed.iter().map(hex::encode).collect();

    axum::Json(ApiResponse::ok(SlashingSummaryResponse {
        total_events: events.len() as u64,
        total_removed: removed_validators.len() as u64,
        removed_validators,
        events,
    }))
}

/// GET /slashing/:validator_id â€” slashing details for a validator.
pub async fn get_slashing_validator(
    state: axum::extract::State<SharedState>,
    axum::extract::Path(validator_hex): axum::extract::Path<String>,
) -> (
    axum::http::StatusCode,
    axum::Json<ApiResponse<SlashingValidatorResponse>>,
) {
    let validator_id = match hex::decode(&validator_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidHex,
                    "Invalid validator_id: expected 64-char hex",
                )),
            );
        }
    };

    let app = state.read().await;
    let stake = match app
        .slashing_stakes
        .iter()
        .find(|(id, _)| *id == validator_id)
    {
        Some((_, raw)) => *raw,
        None => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(ApiResponse::err(
                    ErrorCode::ValidatorNotFound,
                    format!("Validator {} not found", validator_hex),
                )),
            );
        }
    };
    let removed = app.slashing_removed.contains(&validator_id);
    let events: Vec<SlashingEventResponse> = app
        .slashing_events
        .iter()
        .filter(|event| event.validator_id == validator_id)
        .map(slashing_event_response)
        .collect();

    (
        axum::http::StatusCode::OK,
        axum::Json(ApiResponse::ok(SlashingValidatorResponse {
            validator_id: hex::encode(validator_id),
            stake: format!("{}", sccgub_types::tension::TensionValue(stake)),
            removed,
            events,
        })),
    )
}

/// GET /slashing/evidence â€” equivocation evidence (all validators).
pub async fn get_slashing_evidence(
    state: axum::extract::State<SharedState>,
) -> axum::Json<ApiResponse<SlashingEvidenceListResponse>> {
    let app = state.read().await;
    let evidence: Vec<SlashingEvidenceResponse> = if !app.equivocation_records.is_empty() {
        app.equivocation_records
            .iter()
            .map(|(proof, epoch)| SlashingEvidenceResponse {
                validator_id: hex::encode(proof.validator_id),
                height: proof.height,
                round: proof.round,
                vote_type: format!("{:?}", proof.vote_type),
                block_hash_a: hex::encode(proof.block_hash_a),
                block_hash_b: hex::encode(proof.block_hash_b),
                epoch: *epoch,
            })
            .collect()
    } else {
        app.slashing_events
            .iter()
            .filter_map(|event| match &event.evidence {
                SlashingEvidence::Equivocation(proof) => Some(SlashingEvidenceResponse {
                    validator_id: hex::encode(proof.validator_id),
                    height: proof.height,
                    round: proof.round,
                    vote_type: format!("{:?}", proof.vote_type),
                    block_hash_a: hex::encode(proof.block_hash_a),
                    block_hash_b: hex::encode(proof.block_hash_b),
                    epoch: event.epoch,
                }),
                _ => None,
            })
            .collect()
    };

    axum::Json(ApiResponse::ok(SlashingEvidenceListResponse {
        count: evidence.len() as u64,
        evidence,
    }))
}

/// GET /slashing/evidence/:validator_id â€” equivocation evidence for a validator.
pub async fn get_slashing_evidence_for_validator(
    state: axum::extract::State<SharedState>,
    axum::extract::Path(validator_hex): axum::extract::Path<String>,
) -> (
    axum::http::StatusCode,
    axum::Json<ApiResponse<SlashingEvidenceListResponse>>,
) {
    let validator_id = match hex::decode(&validator_hex) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        _ => {
            return (
                axum::http::StatusCode::BAD_REQUEST,
                axum::Json(ApiResponse::err(
                    ErrorCode::InvalidHex,
                    "Invalid validator_id: expected 64-char hex",
                )),
            );
        }
    };

    let app = state.read().await;
    if app
        .slashing_stakes
        .iter()
        .all(|(id, _)| *id != validator_id)
    {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(ApiResponse::err(
                ErrorCode::ValidatorNotFound,
                format!("Validator {} not found", validator_hex),
            )),
        );
    }

    let evidence: Vec<SlashingEvidenceResponse> = if !app.equivocation_records.is_empty() {
        app.equivocation_records
            .iter()
            .filter(|(proof, _)| proof.validator_id == validator_id)
            .map(|(proof, epoch)| SlashingEvidenceResponse {
                validator_id: hex::encode(proof.validator_id),
                height: proof.height,
                round: proof.round,
                vote_type: format!("{:?}", proof.vote_type),
                block_hash_a: hex::encode(proof.block_hash_a),
                block_hash_b: hex::encode(proof.block_hash_b),
                epoch: *epoch,
            })
            .collect()
    } else {
        app.slashing_events
            .iter()
            .filter_map(|event| match &event.evidence {
                SlashingEvidence::Equivocation(proof) if proof.validator_id == validator_id => {
                    Some(SlashingEvidenceResponse {
                        validator_id: hex::encode(proof.validator_id),
                        height: proof.height,
                        round: proof.round,
                        vote_type: format!("{:?}", proof.vote_type),
                        block_hash_a: hex::encode(proof.block_hash_a),
                        block_hash_b: hex::encode(proof.block_hash_b),
                        epoch: event.epoch,
                    })
                }
                _ => None,
            })
            .collect()
    };

    (
        axum::http::StatusCode::OK,
        axum::Json(ApiResponse::ok(SlashingEvidenceListResponse {
            count: evidence.len() as u64,
            evidence,
        })),
    )
}

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
