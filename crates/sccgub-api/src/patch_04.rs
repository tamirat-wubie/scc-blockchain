//! Patch-04 v3 API endpoints.
//!
//! Read-only views into v3 on-chain state:
//!
//! - `GET  /api/v1/validators`           — current active validator set
//! - `GET  /api/v1/validators/history`   — ValidatorSet record metadata
//! - `GET  /api/v1/ceilings`             — constitutional ceilings
//!
//! Submission:
//!
//! - `POST /api/v1/tx/key-rotation`      — submit a signed KeyRotation
//!   for inclusion in the next block
//!
//! All handlers return the standard `ApiResponse<T>` envelope and
//! short-circuit to a structured error if the relevant v3 system entry
//! is absent (v2 chains).

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use sccgub_governance::patch_04::{
    validate_key_rotation_submission, KeyRotationSubmissionRejection,
};
use sccgub_state::constitutional_ceilings_state::constitutional_ceilings_from_trie;
use sccgub_state::key_rotation_state::key_rotation_registry_from_trie;
use sccgub_state::validator_set_state::{
    pending_changes_from_trie, validator_set_change_history_from_trie, validator_set_from_trie,
};
use sccgub_types::constitutional_ceilings::ConstitutionalCeilings;
use sccgub_types::key_rotation::KeyRotation;
use sccgub_types::validator_set::{
    RemovalReason, ValidatorRecord, ValidatorSetChange, ValidatorSetChangeKind,
};

use crate::handlers::SharedState;
use crate::responses::{ApiResponse, ErrorCode};

// ── Response DTOs ──────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub struct ValidatorRecordResponse {
    pub agent_id: String,
    pub validator_id: String,
    pub voting_power: u64,
    pub active_from: u64,
    pub active_until: Option<u64>,
    pub is_active_at_current_height: bool,
}

#[derive(Debug, Serialize)]
pub struct ValidatorSetResponse {
    pub current_height: u64,
    pub total_records: usize,
    pub active_count: usize,
    pub total_active_power: u128,
    pub quorum_power: u128,
    pub records: Vec<ValidatorRecordResponse>,
}

#[derive(Debug, Serialize)]
pub struct ValidatorSetChangeHistoryEntry {
    pub change_id: String,
    pub kind: String,
    pub target_agent_id: String,
    pub effective_height: u64,
    pub proposed_at: u64,
    pub reason: Option<String>,
    pub quorum_signer_count: usize,
}

#[derive(Debug, Serialize)]
pub struct ValidatorSetHistoryResponse {
    pub pending_count: usize,
    pub pending_changes: Vec<ValidatorSetChangeHistoryEntry>,
}

#[derive(Debug, Deserialize, Default)]
pub struct ValidatorHistoryAllParams {
    /// Skip entries strictly preceding this change_id (hex). Typical
    /// pagination: caller supplies the last change_id from the previous
    /// page; the server returns entries starting immediately after.
    /// Omitted → start from the beginning of admission history.
    pub after_change_id: Option<String>,
    /// Maximum entries to return. Server-side cap at 500.
    pub limit: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct ValidatorHistoryAllResponse {
    pub total_count: usize,
    pub returned_count: usize,
    pub next_cursor: Option<String>,
    pub entries: Vec<ValidatorSetChangeHistoryEntry>,
}

#[derive(Debug, Serialize)]
pub struct ConstitutionalCeilingsResponse {
    pub ceilings: ConstitutionalCeilings,
}

#[derive(Debug, Deserialize)]
pub struct KeyRotationSubmitRequest {
    pub rotation: KeyRotation,
}

#[derive(Debug, Serialize)]
pub struct KeyRotationSubmitResponse {
    pub accepted: bool,
    pub rotation_height: u64,
    pub agent_id: String,
    pub queued_count: usize,
}

// ── Handlers ───────────────────────────────────────────────────────

/// `GET /api/v1/validators` — current active validator set with power tallies.
pub async fn get_validators(
    state: axum::extract::State<SharedState>,
) -> (StatusCode, axum::Json<ApiResponse<ValidatorSetResponse>>) {
    let app = state.read().await;
    let set = match validator_set_from_trie(&app.state) {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                axum::Json(ApiResponse::err(
                    ErrorCode::ValidatorNotFound,
                    "No validator set committed (pre-v3 chain)",
                )),
            );
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ApiResponse::err(
                    ErrorCode::InternalError,
                    format!("validator_set decode failed: {}", e),
                )),
            );
        }
    };
    let height = app.state.state.height;
    let records: Vec<ValidatorRecordResponse> = set
        .records()
        .iter()
        .map(|r| ValidatorRecordResponse {
            agent_id: hex::encode(r.agent_id),
            validator_id: hex::encode(r.validator_id),
            voting_power: r.voting_power,
            active_from: r.active_from,
            active_until: r.active_until,
            is_active_at_current_height: r.is_active_at(height),
        })
        .collect();
    let active_count = records
        .iter()
        .filter(|r| r.is_active_at_current_height)
        .count();
    let resp = ValidatorSetResponse {
        current_height: height,
        total_records: set.records().len(),
        active_count,
        total_active_power: set.total_power_at(height),
        quorum_power: set.quorum_power_at(height),
        records,
    };
    (StatusCode::OK, axum::Json(ApiResponse::ok(resp)))
}

/// `GET /api/v1/validators/history` — pending `ValidatorSetChange` events.
///
/// Note: the full admitted-change history across all blocks is not yet
/// indexed separately; this endpoint returns the pending queue (admitted
/// but not yet effective). Closed-out changes will surface here as a
/// separate follow-up once a block indexer is in place.
pub async fn get_validator_history(
    state: axum::extract::State<SharedState>,
) -> (
    StatusCode,
    axum::Json<ApiResponse<ValidatorSetHistoryResponse>>,
) {
    let app = state.read().await;
    let pending = match pending_changes_from_trie(&app.state) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ApiResponse::err(
                    ErrorCode::InternalError,
                    format!("pending_validator_set_changes decode failed: {}", e),
                )),
            );
        }
    };
    let entries: Vec<ValidatorSetChangeHistoryEntry> =
        pending.iter().map(describe_change).collect();
    let resp = ValidatorSetHistoryResponse {
        pending_count: entries.len(),
        pending_changes: entries,
    };
    (StatusCode::OK, axum::Json(ApiResponse::ok(resp)))
}

/// `GET /api/v1/validators/history/all` — Patch-05 §27 full admission
/// history projection.
///
/// Cursor-based pagination: supply `after_change_id` (hex) to skip
/// entries strictly preceding that change; omit for page 1. `limit`
/// caps the response at min(requested, 500). Returns `next_cursor`
/// (the last entry's `change_id`) when more entries exist beyond the
/// page, else `None`.
pub async fn get_validator_history_all(
    state: axum::extract::State<SharedState>,
    params: axum::extract::Query<ValidatorHistoryAllParams>,
) -> (
    StatusCode,
    axum::Json<ApiResponse<ValidatorHistoryAllResponse>>,
) {
    const HARD_CAP: usize = 500;
    let app = state.read().await;
    let history = match validator_set_change_history_from_trie(&app.state) {
        Ok(v) => v,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                axum::Json(ApiResponse::err(
                    ErrorCode::InternalError,
                    format!("validator_set_change_history decode failed: {}", e),
                )),
            );
        }
    };
    let total_count = history.len();
    let limit = params.0.limit.unwrap_or(HARD_CAP).min(HARD_CAP);

    // Resolve cursor to a starting index.
    let start_idx = if let Some(cursor) = params.0.after_change_id.as_deref() {
        match hex::decode(cursor) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut cid = [0u8; 32];
                cid.copy_from_slice(&bytes);
                // Return the position AFTER the cursor change_id, so the
                // client's next-page cursor naturally points past the
                // last-returned entry.
                match history.iter().position(|c| c.change_id == cid) {
                    Some(i) => i + 1,
                    None => {
                        return (
                            StatusCode::BAD_REQUEST,
                            axum::Json(ApiResponse::err(
                                ErrorCode::InvalidRequest,
                                "after_change_id not found in history",
                            )),
                        );
                    }
                }
            }
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    axum::Json(ApiResponse::err(
                        ErrorCode::InvalidHex,
                        "after_change_id must be 32-byte hex",
                    )),
                );
            }
        }
    } else {
        0
    };

    let page_end = (start_idx + limit).min(total_count);
    let page: Vec<ValidatorSetChangeHistoryEntry> = history[start_idx..page_end]
        .iter()
        .map(describe_change)
        .collect();
    let next_cursor = if page_end < total_count {
        page.last().map(|e| e.change_id.clone())
    } else {
        None
    };
    let resp = ValidatorHistoryAllResponse {
        total_count,
        returned_count: page.len(),
        next_cursor,
        entries: page,
    };
    (StatusCode::OK, axum::Json(ApiResponse::ok(resp)))
}

fn describe_change(c: &ValidatorSetChange) -> ValidatorSetChangeHistoryEntry {
    let (kind_name, reason) = match &c.kind {
        ValidatorSetChangeKind::Add(_) => ("Add", None),
        ValidatorSetChangeKind::Remove { reason, .. } => {
            ("Remove", Some(reason_str(*reason).to_string()))
        }
        ValidatorSetChangeKind::RotatePower { .. } => ("RotatePower", None),
        ValidatorSetChangeKind::RotateKey { .. } => ("RotateKey", None),
    };
    ValidatorSetChangeHistoryEntry {
        change_id: hex::encode(c.change_id),
        kind: kind_name.into(),
        target_agent_id: hex::encode(c.kind.target_agent_id()),
        effective_height: c.kind.effective_height(),
        proposed_at: c.proposed_at,
        reason,
        quorum_signer_count: c.quorum_signatures.len(),
    }
}

fn reason_str(r: RemovalReason) -> &'static str {
    match r {
        RemovalReason::Voluntary => "Voluntary",
        RemovalReason::Equivocation => "Equivocation",
        RemovalReason::Inactivity => "Inactivity",
        RemovalReason::Governance => "Governance",
    }
}

/// `GET /api/v1/ceilings` — constitutional ceilings (§17.1).
pub async fn get_ceilings(
    state: axum::extract::State<SharedState>,
) -> (
    StatusCode,
    axum::Json<ApiResponse<ConstitutionalCeilingsResponse>>,
) {
    let app = state.read().await;
    match constitutional_ceilings_from_trie(&app.state) {
        Ok(Some(ceilings)) => (
            StatusCode::OK,
            axum::Json(ApiResponse::ok(ConstitutionalCeilingsResponse { ceilings })),
        ),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            axum::Json(ApiResponse::err(
                ErrorCode::ValidatorNotFound,
                "No constitutional ceilings committed (pre-v3 chain)",
            )),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(ApiResponse::err(
                ErrorCode::InternalError,
                format!("ceilings decode failed: {}", e),
            )),
        ),
    }
}

/// `POST /api/v1/tx/key-rotation` — submit a signed `KeyRotation` for
/// mempool admission.
///
/// Structural validation runs first (`validate_key_rotation_submission`);
/// if it passes, the event is appended to the `AppState.pending_rotations`
/// queue for the block producer to consume.
pub async fn submit_key_rotation(
    state: axum::extract::State<SharedState>,
    axum::Json(req): axum::Json<KeyRotationSubmitRequest>,
) -> (
    StatusCode,
    axum::Json<ApiResponse<KeyRotationSubmitResponse>>,
) {
    if let Err(rejection) = validate_key_rotation_submission(&req.rotation) {
        let code = match rejection {
            KeyRotationSubmissionRejection::NoOp
            | KeyRotationSubmissionRejection::ZeroPublicKey => ErrorCode::InvalidRequest,
            KeyRotationSubmissionRejection::OldSignatureLength { .. }
            | KeyRotationSubmissionRejection::NewSignatureLength { .. } => {
                ErrorCode::InvalidTransaction
            }
        };
        return (
            StatusCode::BAD_REQUEST,
            axum::Json(ApiResponse::err(code, rejection.to_string())),
        );
    }

    // Idempotency: reject re-submission of a rotation already in the
    // pending queue keyed by (agent_id, rotation_height).
    let mut app = state.write().await;
    if app.pending_key_rotations.iter().any(|r| {
        r.agent_id == req.rotation.agent_id && r.rotation_height == req.rotation.rotation_height
    }) {
        return (
            StatusCode::CONFLICT,
            axum::Json(ApiResponse::err(
                ErrorCode::NonceReplay,
                "KeyRotation for this (agent_id, rotation_height) already queued",
            )),
        );
    }

    // Registry sanity: if an identical rotation has already been admitted
    // at this height in chain state, reject.
    if let Ok(registry) = key_rotation_registry_from_trie(&app.state) {
        if registry.rotations().iter().any(|r| {
            r.agent_id == req.rotation.agent_id && r.rotation_height == req.rotation.rotation_height
        }) {
            return (
                StatusCode::CONFLICT,
                axum::Json(ApiResponse::err(
                    ErrorCode::NonceReplay,
                    "KeyRotation already applied on-chain",
                )),
            );
        }
    }

    app.pending_key_rotations.push(req.rotation.clone());
    let queued_count = app.pending_key_rotations.len();
    let agent_id = hex::encode(req.rotation.agent_id);
    let rotation_height = req.rotation.rotation_height;

    let resp = KeyRotationSubmitResponse {
        accepted: true,
        rotation_height,
        agent_id,
        queued_count,
    };
    (StatusCode::ACCEPTED, axum::Json(ApiResponse::ok(resp)))
}

/// Validator record description used internally by tests and CLI.
pub fn format_validator_record(r: &ValidatorRecord, height: u64) -> String {
    format!(
        "agent={} validator_id={} power={} active_from={} active_until={} \
         active_at={}={}",
        hex::encode(r.agent_id),
        hex::encode(r.validator_id),
        r.voting_power,
        r.active_from,
        match r.active_until {
            Some(h) => h.to_string(),
            None => "none".into(),
        },
        height,
        r.is_active_at(height),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_04_api_format_validator_record() {
        let r = ValidatorRecord {
            agent_id: [1; 32],
            validator_id: [2; 32],
            mfidel_seal: sccgub_types::mfidel::MfidelAtomicSeal::from_height(0),
            voting_power: 42,
            active_from: 5,
            active_until: None,
        };
        let out = format_validator_record(&r, 10);
        assert!(out.contains("power=42"));
        assert!(out.contains("active_from=5"));
        assert!(out.contains("active_at=10=true"));
    }

    #[test]
    fn patch_04_api_reason_string_complete() {
        // Ensure every RemovalReason variant has a stable string label.
        assert_eq!(reason_str(RemovalReason::Voluntary), "Voluntary");
        assert_eq!(reason_str(RemovalReason::Equivocation), "Equivocation");
        assert_eq!(reason_str(RemovalReason::Inactivity), "Inactivity");
        assert_eq!(reason_str(RemovalReason::Governance), "Governance");
    }
}
