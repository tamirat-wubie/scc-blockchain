use serde::Serialize;

/// Standard API response wrapper.
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(msg.into()),
        }
    }
}

/// Chain status response.
#[derive(Debug, Serialize)]
pub struct ChainStatusResponse {
    pub chain_id: String,
    pub height: u64,
    pub block_count: u64,
    pub total_transactions: u64,
    pub state_root: String,
    pub finalized_height: u64,
    pub finality_gap: u64,
    pub tension: String,
    pub emergency_mode: bool,
    pub mfidel_seal: String,
}

/// Block summary response.
#[derive(Debug, Serialize)]
pub struct BlockResponse {
    pub height: u64,
    pub block_id: String,
    pub parent_id: String,
    pub state_root: String,
    pub transition_root: String,
    pub mfidel_seal: String,
    pub transaction_count: u32,
    pub receipt_count: usize,
    pub tension_before: String,
    pub tension_after: String,
    pub validator_id: String,
    pub transactions: Vec<TransactionSummary>,
}

/// Transaction summary in a block.
#[derive(Debug, Serialize)]
pub struct TransactionSummary {
    pub tx_id: String,
    pub kind: String,
    pub target: String,
    pub purpose: String,
    pub actor: String,
    pub nonce: u128,
}

/// Balance query response.
#[derive(Debug, Serialize)]
pub struct BalanceResponse {
    pub agent_id: String,
    pub balance: String,
}

/// State entry response.
#[derive(Debug, Serialize)]
pub struct StateEntry {
    pub key: String,
    pub value: String,
}

/// Health response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub height: u64,
    pub finalized_height: u64,
    pub finality_gap: u64,
    pub sla_met: bool,
    pub blocks_produced: u64,
    pub total_transactions: u64,
    pub state_entries: u64,
    pub causal_edges: u64,
}

/// Individual transaction detail response.
#[derive(Debug, Serialize)]
pub struct TxDetailResponse {
    pub tx_id: String,
    pub block_height: u64,
    pub block_id: String,
    pub kind: String,
    pub target: String,
    pub purpose: String,
    pub actor: String,
    pub nonce: u128,
}

/// Transaction submission request (hex-encoded canonical bytes).
#[derive(Debug, serde::Deserialize)]
pub struct SubmitTransactionRequest {
    /// Hex-encoded bincode-serialized SymbolicTransition.
    pub tx_hex: String,
}

/// Transaction submission response.
#[derive(Debug, Serialize)]
pub struct TxSubmitResponse {
    pub tx_id: String,
    pub status: String,
}

/// Paginated state response.
#[derive(Debug, Serialize)]
pub struct PaginatedStateResponse {
    pub entries: Vec<StateEntry>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
}
