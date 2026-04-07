use serde::Serialize;

/// Standard API response wrapper with structured error codes.
///
/// Every response includes:
/// - `success`: boolean flag for quick checks.
/// - `data`: the response payload (only on success).
/// - `error`: structured error with machine-readable code (only on failure).
/// - `request_id`: optional idempotency/correlation key echoed back to caller.
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
}

/// Structured error with machine-readable code for client integration.
#[derive(Debug, Serialize)]
pub struct ApiError {
    /// Machine-readable error code (e.g., "INVALID_HEX", "TX_NOT_FOUND").
    pub code: ErrorCode,
    /// Human-readable description.
    pub message: String,
}

/// Machine-readable error codes for every rejection path.
/// Clients can switch on these codes without parsing message strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ErrorCode {
    // Chain state errors.
    NoBlocks,
    BlockNotFound,
    TxNotFound,

    // Submission errors.
    EmptyPayload,
    InvalidHex,
    InvalidTransaction,
    InsufficientFunds,
    NonceReplay,
    GasExceeded,

    // Auth errors.
    Unauthorized,
    RateLimited,

    // Internal errors.
    InternalError,
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            request_id: None,
        }
    }

    pub fn ok_with_request_id(data: T, request_id: String) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
            request_id: Some(request_id),
        }
    }

    pub fn err(code: ErrorCode, msg: impl Into<String>) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(ApiError {
                code,
                message: msg.into(),
            }),
            request_id: None,
        }
    }

    pub fn err_with_request_id(
        code: ErrorCode,
        msg: impl Into<String>,
        request_id: String,
    ) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(ApiError {
                code,
                message: msg.into(),
            }),
            request_id: Some(request_id),
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
    /// Optional idempotency key — if the same key is submitted twice,
    /// the second submission returns the first result without re-processing.
    pub idempotency_key: Option<String>,
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
