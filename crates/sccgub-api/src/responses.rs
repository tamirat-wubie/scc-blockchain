use serde::Serialize;

/// Standard API response wrapper with structured error codes.
///
/// Every response includes:
/// - `success`: boolean flag for quick checks.
/// - `data`: the response payload (only on success).
/// - `error`: structured error with machine-readable code (only on failure).
#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ApiError>,
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
    ValidatorNotFound,

    // Submission errors.
    EmptyPayload,
    InvalidRequest,
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

impl ErrorCode {
    pub const ALL: [Self; 14] = [
        Self::NoBlocks,
        Self::BlockNotFound,
        Self::TxNotFound,
        Self::ValidatorNotFound,
        Self::EmptyPayload,
        Self::InvalidRequest,
        Self::InvalidHex,
        Self::InvalidTransaction,
        Self::InsufficientFunds,
        Self::NonceReplay,
        Self::GasExceeded,
        Self::Unauthorized,
        Self::RateLimited,
        Self::InternalError,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoBlocks => "NoBlocks",
            Self::BlockNotFound => "BlockNotFound",
            Self::TxNotFound => "TxNotFound",
            Self::ValidatorNotFound => "ValidatorNotFound",
            Self::EmptyPayload => "EmptyPayload",
            Self::InvalidRequest => "InvalidRequest",
            Self::InvalidHex => "InvalidHex",
            Self::InvalidTransaction => "InvalidTransaction",
            Self::InsufficientFunds => "InsufficientFunds",
            Self::NonceReplay => "NonceReplay",
            Self::GasExceeded => "GasExceeded",
            Self::Unauthorized => "Unauthorized",
            Self::RateLimited => "RateLimited",
            Self::InternalError => "InternalError",
        }
    }
}

impl<T: Serialize> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
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
    pub active_norm_count: u32,
    pub finality_expected_ms: u64,
    pub finality_sla_met: bool,
    pub mfidel_seal: String,
    pub governed_parameters: Vec<String>,
    pub governed_parameter_values: std::collections::HashMap<String, String>,
    pub bandwidth_inbound_bytes: u64,
    pub bandwidth_outbound_bytes: u64,
}

/// Governed parameter response.
#[derive(Debug, Serialize)]
pub struct GovernanceParamsResponse {
    pub governance_limits: sccgub_governance::anti_concentration::GovernanceLimits,
    pub finality_config: sccgub_consensus::finality::FinalityConfig,
}

/// Governance proposal summary.
#[derive(Debug, Serialize)]
pub struct GovernanceProposalSummary {
    pub id: String,
    pub status: String,
    pub votes_for: u32,
    pub votes_against: u32,
    pub timelock_until: u64,
    pub submitted_at: u64,
}

/// Governance proposal registry response.
#[derive(Debug, Serialize)]
pub struct GovernanceProposalsResponse {
    pub count: u64,
    pub proposals: Vec<GovernanceProposalSummary>,
}

/// OpenAPI spec response.
#[derive(Debug, Serialize)]
pub struct OpenApiSpecResponse {
    pub spec: String,
}

/// Network peer summary response.
#[derive(Debug, Serialize)]
pub struct NetworkPeerResponse {
    pub address: String,
    pub validator_id: Option<String>,
    pub score: i32,
    pub violations: u32,
    pub state: String,
    pub inbound_bytes: u64,
    pub outbound_bytes: u64,
    pub last_seen_ms: u64,
}

/// Network peers response.
#[derive(Debug, Serialize)]
pub struct NetworkPeersResponse {
    pub count: u64,
    pub peers: Vec<NetworkPeerResponse>,
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
    pub governance_limits: sccgub_types::governance::GovernanceLimitsSnapshot,
    pub finality_config: sccgub_types::governance::FinalityConfigSnapshot,
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

/// Receipt summary for a processed transaction.
#[derive(Debug, Serialize)]
pub struct ReceiptSummary {
    pub tx_id: String,
    pub verdict: String,
    pub compute_steps: u64,
    pub state_reads: u32,
    pub state_writes: u32,
    pub phi_phase_reached: u8,
}

/// Block receipts response.
#[derive(Debug, Serialize)]
pub struct BlockReceiptsResponse {
    pub height: u64,
    pub receipt_count: usize,
    pub receipts: Vec<ReceiptSummary>,
}

/// Transaction submission request (hex-encoded canonical bytes).
#[derive(Debug, serde::Deserialize)]
pub struct SubmitTransactionRequest {
    /// Hex-encoded bincode-serialized SymbolicTransition.
    pub tx_hex: String,
}

/// Governance parameter proposal submission request.
#[derive(Debug, serde::Deserialize)]
pub struct SubmitGovernanceParamRequest {
    /// Hex-encoded bincode-serialized SymbolicTransition.
    pub tx_hex: String,
}

/// Governance proposal vote submission request.
#[derive(Debug, serde::Deserialize)]
pub struct SubmitGovernanceVoteRequest {
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

/// Slashing event summary.
#[derive(Debug, Serialize)]
pub struct SlashingEventResponse {
    pub validator_id: String,
    pub violation: String,
    pub penalty: String,
    pub epoch: u64,
    pub evidence: serde_json::Value,
}

/// Slashing summary across the chain.
#[derive(Debug, Serialize)]
pub struct SlashingSummaryResponse {
    pub total_events: u64,
    pub total_removed: u64,
    pub removed_validators: Vec<String>,
    pub events: Vec<SlashingEventResponse>,
}

/// Slashing details for a specific validator.
#[derive(Debug, Serialize)]
pub struct SlashingValidatorResponse {
    pub validator_id: String,
    pub stake: String,
    pub removed: bool,
    pub events: Vec<SlashingEventResponse>,
}

/// Equivocation evidence response (normalized for API use).
#[derive(Debug, Serialize)]
pub struct SlashingEvidenceResponse {
    pub validator_id: String,
    pub height: u64,
    pub round: u32,
    pub vote_type: String,
    pub block_hash_a: String,
    pub block_hash_b: String,
    pub epoch: u64,
}

/// Equivocation evidence list response.
#[derive(Debug, Serialize)]
pub struct SlashingEvidenceListResponse {
    pub count: u64,
    pub evidence: Vec<SlashingEvidenceResponse>,
}

/// Safety certificate signature entry.
#[derive(Debug, Serialize)]
pub struct SafetyCertificateSignatureResponse {
    pub validator_id: String,
    pub signature: String,
}

/// Safety certificate summary.
#[derive(Debug, Serialize)]
pub struct SafetyCertificateResponse {
    pub chain_id: String,
    pub epoch: u64,
    pub height: u64,
    pub block_hash: String,
    pub round: u32,
    pub quorum: u32,
    pub validator_count: u32,
    pub precommit_signatures: Vec<SafetyCertificateSignatureResponse>,
}

/// Safety certificate list response.
#[derive(Debug, Serialize)]
pub struct FinalityCertificatesResponse {
    pub count: u64,
    pub certificates: Vec<SafetyCertificateResponse>,
}

#[cfg(test)]
mod tests {
    const RESPONSES_SOURCE: &str = include_str!("responses.rs");

    fn openapi_spec() -> &'static str {
        static OPENAPI_SPEC: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        OPENAPI_SPEC
            .get_or_init(crate::openapi::render_openapi_yaml)
            .as_str()
    }

    fn openapi_schema_block(schema_name: &str) -> String {
        let openapi_spec = openapi_spec();
        let marker = format!("    {}:\n", schema_name);
        let start = openapi_spec
            .find(&marker)
            .unwrap_or_else(|| panic!("OpenAPI schema {} must exist", schema_name));
        let after = &openapi_spec[start + marker.len()..];
        let mut block = String::new();

        for line in after.lines() {
            if line.starts_with("    ") && !line.starts_with("      ") && line.ends_with(':') {
                break;
            }
            block.push_str(line);
            block.push('\n');
        }

        block
    }

    fn openapi_required_fields(schema_name: &str) -> Vec<String> {
        let block = openapi_schema_block(schema_name);
        let Some(required_start) = block.find("required:") else {
            return Vec::new();
        };
        let required = block[required_start + "required:".len()..].trim_start();
        let end = required
            .find(']')
            .unwrap_or_else(|| panic!("OpenAPI schema {} required list is malformed", schema_name));
        required[..=end]
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .split(',')
            .map(|field| field.trim().to_string())
            .filter(|field| !field.is_empty())
            .collect()
    }

    fn rust_error_codes() -> Vec<String> {
        let enum_start = RESPONSES_SOURCE
            .find("pub enum ErrorCode {")
            .expect("ErrorCode enum must exist in responses.rs");
        let enum_body = &RESPONSES_SOURCE[enum_start..];
        let end = enum_body
            .find("\n}")
            .expect("ErrorCode enum must terminate");
        enum_body[..end]
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.ends_with(',') && !trimmed.starts_with("//") {
                    Some(trimmed.trim_end_matches(',').to_string())
                } else {
                    None
                }
            })
            .filter(|name| !name.contains(' '))
            .collect()
    }

    fn openapi_error_codes() -> Vec<String> {
        let openapi_spec = openapi_spec();
        let enum_start = openapi_spec
            .find("    ErrorCode:")
            .expect("OpenAPI ErrorCode schema must exist");
        let enum_body = &openapi_spec[enum_start..];
        let enum_marker = enum_body
            .find("\n      enum:")
            .expect("OpenAPI ErrorCode enum must exist");
        let values = &enum_body[enum_marker..];
        let next_schema = values
            .find("\n    ApiError:")
            .expect("OpenAPI ErrorCode enum must be followed by ApiError schema");
        values[..next_schema]
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                trimmed
                    .strip_prefix("- ")
                    .map(|value| value.trim().to_string())
            })
            .collect()
    }

    fn rust_submit_request_fields() -> Vec<(String, bool)> {
        let struct_start = RESPONSES_SOURCE
            .find("pub struct SubmitTransactionRequest {")
            .expect("SubmitTransactionRequest must exist in responses.rs");
        let struct_body = &RESPONSES_SOURCE[struct_start..];
        let end = struct_body
            .find("\n}")
            .expect("SubmitTransactionRequest must terminate");
        struct_body[..end]
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if !trimmed.starts_with("pub ") || !trimmed.contains(':') {
                    return None;
                }

                let trimmed = trimmed.trim_end_matches(',');
                let field = trimmed.trim_start_matches("pub ");
                let mut parts = field.splitn(2, ':');
                let name = parts.next()?.trim().to_string();
                let ty = parts.next()?.trim();
                Some((name, ty.starts_with("Option<")))
            })
            .collect()
    }

    #[test]
    fn test_openapi_error_codes_match_rust_enum() {
        let rust_codes = rust_error_codes();
        let openapi_codes = openapi_error_codes();

        assert_eq!(
            openapi_codes, rust_codes,
            "OpenAPI ErrorCode enum must match responses.rs exactly"
        );
        assert_eq!(
            rust_codes.len(),
            14,
            "expected 14 machine-readable error codes"
        );
    }

    #[test]
    fn test_openapi_submit_request_schema_matches_rust_struct() {
        let rust_fields = rust_submit_request_fields();
        assert_eq!(
            rust_fields,
            vec![("tx_hex".to_string(), false)],
            "SubmitTransactionRequest fields must remain stable"
        );

        let schema_block = openapi_schema_block("SubmitTransactionRequest");
        let required = openapi_required_fields("SubmitTransactionRequest");

        assert!(
            schema_block.contains("tx_hex:"),
            "OpenAPI request schema must include tx_hex"
        );
        assert!(
            !schema_block.contains("idempotency_key:"),
            "idempotency_key was removed (future feature)"
        );
        assert_eq!(
            required,
            vec!["tx_hex".to_string()],
            "Only tx_hex should be required in OpenAPI"
        );
        assert!(
            schema_block.contains("tx_hex:\n          type: string"),
            "tx_hex must remain a string in OpenAPI"
        );
    }
}
