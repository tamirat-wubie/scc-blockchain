use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

use crate::handlers::{self, SharedState};
use crate::patch_04;

/// Build the API router with all endpoints.
///
/// Endpoints:
///   GET  /api/v1/slashing         -- slashing summary
///   GET  /api/v1/slashing/{validator_id} -- validator slashing detail
///   GET  /api/v1/slashing/evidence -- equivocation evidence
///   GET  /api/v1/slashing/evidence/{validator_id} -- validator evidence
///   GET  /api/v1/status           — chain summary
///   GET  /api/v1/health           — system health + finality
///   GET  /api/v1/finality/certificates — finality safety certificates
///   GET  /api/v1/network/peers    — peer network stats
///   GET  /api/v1/network/peers/{validator_id} — peer detail
///   GET  /api/v1/block/:height    — block detail with transactions
///   GET  /api/v1/block/:height/receipts — block receipts with gas breakdown
///   GET  /api/v1/state            — paginated world state entries
///   GET  /api/v1/tx/:tx_id        — transaction detail by ID
///   GET  /api/v1/receipt/:tx_id   — receipt detail by transaction ID
///   POST /api/v1/tx/submit        — submit a signed transaction
///   POST /api/v1/governance/params/propose — submit a signed param proposal
///   POST /api/v1/governance/proposals/vote — submit a signed proposal vote
///
/// Endpoints (ASCII reference):
///   GET  /api/v1/slashing                  - slashing summary
///   GET  /api/v1/slashing/{validator_id}   - validator slashing detail
///   GET  /api/v1/slashing/evidence         - equivocation evidence
///   GET  /api/v1/slashing/evidence/{validator_id} - validator evidence
///   GET  /api/v1/status                    - chain summary
///   GET  /api/v1/status/schema             - status JSON schema
///   GET  /api/v1/health                    - system health + finality
///   GET  /api/v1/finality/certificates     - finality safety certificates
///   GET  /api/v1/governance/params         - governed parameter values
///   GET  /api/v1/governance/params/schema  - governed JSON schema
///   GET  /api/v1/governance/proposals      - governance proposal registry
///   GET  /api/v1/governance/proposals      - governance proposal registry
///   GET  /api/v1/network/peers             - peer network stats
///   GET  /api/v1/network/peers/{validator_id} - peer detail
///   GET  /api/v1/block/:height             - block detail with transactions
///   GET  /api/v1/block/:height/receipts    - block receipts with gas breakdown
///   GET  /api/v1/state                     - paginated world state entries
///   GET  /api/v1/tx/:tx_id                 - transaction detail by ID
///   GET  /api/v1/receipt/:tx_id            - receipt detail by transaction ID
///   POST /api/v1/tx/submit                 - submit a signed transaction
///   POST /api/v1/governance/params/propose - submit a signed param proposal
///   POST /api/v1/governance/proposals/vote - submit a signed proposal vote
///
/// Legacy (unversioned) lookup routes preserved for backward compatibility.
pub fn build_router(state: SharedState) -> Router {
    Router::new()
        // Versioned routes (preferred).
        .route("/api/v1/status", get(handlers::get_status))
        .route("/api/v1/status/schema", get(handlers::get_status_schema))
        .route("/api/v1/openapi", get(handlers::get_openapi_spec))
        .route("/api/v1/health", get(handlers::get_health))
        .route(
            "/api/v1/finality/certificates",
            get(handlers::get_finality_certificates),
        )
        .route(
            "/api/v1/governance/params",
            get(handlers::get_governance_params),
        )
        .route(
            "/api/v1/governance/params/schema",
            get(handlers::get_governance_params_schema),
        )
        .route(
            "/api/v1/governance/proposals",
            get(handlers::get_governance_proposals),
        )
        .route("/api/v1/network/peers", get(handlers::get_network_peers))
        .route(
            "/api/v1/network/peers/{validator_id}",
            get(handlers::get_network_peer),
        )
        .route("/api/v1/slashing", get(handlers::get_slashing_summary))
        .route(
            "/api/v1/slashing/{validator_id}",
            get(handlers::get_slashing_validator),
        )
        .route(
            "/api/v1/slashing/evidence",
            get(handlers::get_slashing_evidence),
        )
        .route(
            "/api/v1/slashing/evidence/{validator_id}",
            get(handlers::get_slashing_evidence_for_validator),
        )
        .route("/api/v1/block/{height}", get(handlers::get_block))
        .route("/api/v1/state", get(handlers::get_state))
        .route("/api/v1/tx/submit", post(handlers::submit_tx))
        .route(
            "/api/v1/governance/params/propose",
            post(handlers::submit_governance_param),
        )
        .route(
            "/api/v1/governance/proposals/vote",
            post(handlers::submit_governance_vote),
        )
        // Patch-04 v3 endpoints (§15, §17, §18).
        .route("/api/v1/validators", get(patch_04::get_validators))
        .route(
            "/api/v1/validators/history",
            get(patch_04::get_validator_history),
        )
        .route("/api/v1/ceilings", get(patch_04::get_ceilings))
        .route(
            "/api/v1/tx/key-rotation",
            post(patch_04::submit_key_rotation),
        )
        .route("/api/v1/tx/{tx_id}", get(handlers::get_tx))
        .route(
            "/api/v1/block/{height}/receipts",
            get(handlers::get_block_receipts),
        )
        .route("/api/v1/receipt/{tx_id}", get(handlers::get_receipt))
        // Legacy unversioned routes.
        .route("/api/status", get(handlers::get_status))
        .route("/api/status/schema", get(handlers::get_status_schema))
        .route("/api/openapi", get(handlers::get_openapi_spec))
        .route("/api/health", get(handlers::get_health))
        .route(
            "/api/finality/certificates",
            get(handlers::get_finality_certificates),
        )
        .route(
            "/api/governance/params",
            get(handlers::get_governance_params),
        )
        .route(
            "/api/governance/params/schema",
            get(handlers::get_governance_params_schema),
        )
        .route(
            "/api/governance/proposals",
            get(handlers::get_governance_proposals),
        )
        .route("/api/network/peers", get(handlers::get_network_peers))
        .route(
            "/api/network/peers/{validator_id}",
            get(handlers::get_network_peer),
        )
        .route("/api/block/{height}", get(handlers::get_block))
        .route("/api/state", get(handlers::get_state))
        .route("/api/tx/{tx_id}", get(handlers::get_tx))
        .route(
            "/api/governance/params/propose",
            post(handlers::submit_governance_param),
        )
        .route(
            "/api/governance/proposals/vote",
            post(handlers::submit_governance_vote),
        )
        .layer(DefaultBodyLimit::max(1_048_576))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handlers::AppState;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use sccgub_crypto::canonical::canonical_bytes;
    use sccgub_crypto::hash::blake3_hash;
    use sccgub_crypto::keys::generate_keypair;
    use sccgub_crypto::signature::sign;
    use sccgub_state::world::ManagedWorldState;
    use sccgub_types::agent::{AgentIdentity, ResponsibilityState};
    use sccgub_types::block::{Block, BlockBody, BlockHeader, CURRENT_BLOCK_VERSION};
    use sccgub_types::causal::CausalGraphDelta;
    use sccgub_types::governance::{FinalityMode, GovernanceSnapshot, PrecedenceLevel};
    use sccgub_types::mfidel::MfidelAtomicSeal;
    use sccgub_types::proof::{CausalProof, PhiTraversalLog};
    use sccgub_types::receipt::{CausalReceipt, ResourceUsage, Verdict};
    use sccgub_types::tension::TensionValue;
    use sccgub_types::timestamp::CausalTimestamp;
    use sccgub_types::transition::{
        CausalJustification, OperationPayload, StateDelta, StateWrite, SymbolicTransition,
        TransitionIntent, TransitionKind, TransitionMechanism, ValidationResult, WHBindingIntent,
        WHBindingResolved,
    };
    use sccgub_types::ZERO_HASH;
    use serde_json::Value;
    use std::collections::BTreeSet;
    use std::collections::HashSet;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tower::util::ServiceExt;

    const ROUTER_SOURCE: &str = include_str!("router.rs");

    fn openapi_spec() -> &'static str {
        static OPENAPI_SPEC: std::sync::OnceLock<String> = std::sync::OnceLock::new();
        OPENAPI_SPEC
            .get_or_init(crate::openapi::render_openapi_yaml)
            .as_str()
    }

    fn test_state() -> SharedState {
        Arc::new(RwLock::new(AppState {
            blocks: vec![],
            state: ManagedWorldState::new(),
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
            seen_tx_order: std::collections::VecDeque::new(),
            pending_key_rotations: Vec::new(),
        }))
    }

    fn make_signed_write_tx() -> SymbolicTransition {
        let key = generate_keypair();
        let public_key = *key.verifying_key().as_bytes();
        let mfidel_seal = MfidelAtomicSeal::from_height(1);
        let agent_id =
            sccgub_crypto::hash::blake3_hash_concat(&[&public_key, &canonical_bytes(&mfidel_seal)]);
        let actor = AgentIdentity {
            agent_id,
            public_key,
            mfidel_seal,
            registration_block: 0,
            governance_level: PrecedenceLevel::Meaning,
            norm_set: BTreeSet::new(),
            responsibility: ResponsibilityState::default(),
        };

        let target = b"data/test/key".to_vec();
        let mut tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor,
            intent: TransitionIntent {
                kind: TransitionKind::StateWrite,
                target: target.clone(),
                declared_purpose: "API contract test write".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: target.clone(),
                value: b"value".to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: agent_id,
                when: CausalTimestamp::genesis(),
                r#where: target,
                why: CausalJustification {
                    invoking_rule: blake3_hash(b"api-contract-test-rule"),
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "API contract test write".into(),
            },
            nonce: 1,
            signature: vec![],
        };

        let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
        tx.tx_id = blake3_hash(&canonical);
        tx.signature = sign(&key, &canonical);
        tx
    }

    fn populated_state() -> (SharedState, String) {
        let tx = make_signed_write_tx();
        let mut state = ManagedWorldState::new();
        let write = StateWrite {
            address: b"data/test/key".to_vec(),
            value: b"value".to_vec(),
        };
        let object_id = blake3_hash(&write.address);
        state.apply_delta(&StateDelta {
            writes: vec![write.clone()],
            deletes: vec![],
        });
        let state_root = state.state_root();
        let tx_id_hex = hex::encode(tx.tx_id);

        let receipt = CausalReceipt {
            tx_id: tx.tx_id,
            verdict: Verdict::Accept,
            pre_state_root: ZERO_HASH,
            post_state_root: state_root,
            read_set: vec![object_id],
            write_set: vec![object_id],
            causes: vec![],
            resource_used: ResourceUsage {
                compute_steps: 1,
                state_reads: 1,
                state_writes: 1,
                proof_size_bytes: 0,
            },
            emitted_events: vec![],
            wh_binding: WHBindingResolved {
                intent: tx.wh_binding_intent.clone(),
                what_actual: StateDelta {
                    writes: vec![write],
                    deletes: vec![],
                },
                whether: ValidationResult::Valid,
            },
            phi_phase_reached: 13,
            tension_delta: TensionValue::ZERO,
        };

        let block = Block {
            header: BlockHeader {
                chain_id: [1u8; 32],
                block_id: [2u8; 32],
                parent_id: ZERO_HASH,
                height: 0,
                timestamp: CausalTimestamp::genesis(),
                state_root,
                transition_root: [3u8; 32],
                receipt_root: [4u8; 32],
                causal_root: [5u8; 32],
                proof_root: [6u8; 32],
                governance_hash: [7u8; 32],
                tension_before: TensionValue::ZERO,
                tension_after: TensionValue::ZERO,
                mfidel_seal: MfidelAtomicSeal::from_height(0),
                balance_root: [8u8; 32],
                validator_id: [9u8; 32],
                version: CURRENT_BLOCK_VERSION,
                round_history_root: ZERO_HASH,
            },
            body: BlockBody {
                transitions: vec![tx],
                transition_count: 1,
                total_tension_delta: TensionValue::ZERO,
                constraint_satisfaction: vec![],
                genesis_consensus_params: None,
                validator_set_changes: None,
            },
            receipts: vec![receipt],
            causal_delta: CausalGraphDelta::default(),
            proof: CausalProof {
                block_height: 0,
                transitions_proven: vec![],
                phi_traversal_log: PhiTraversalLog::default(),
                governance_snapshot_hash: [7u8; 32],
                tension_before: TensionValue::ZERO,
                tension_after: TensionValue::ZERO,
                constraint_results: vec![],
                recursion_depth: 0,
                validator_signature: vec![],
                causal_hash: ZERO_HASH,
            },
            governance: GovernanceSnapshot {
                state_hash: ZERO_HASH,
                active_norm_count: 0,
                emergency_mode: false,
                finality_mode: FinalityMode::Deterministic,
                governance_limits: sccgub_types::governance::GovernanceLimitsSnapshot::default(),
                finality_config: sccgub_types::governance::FinalityConfigSnapshot::default(),
            },
        };

        (
            Arc::new(RwLock::new(AppState {
                blocks: vec![block],
                state,
                chain_id: [1u8; 32],
                finalized_height: 0,
                proposals: Vec::new(),
                governance_limits: sccgub_governance::anti_concentration::GovernanceLimits::default(
                ),
                finality_config: sccgub_consensus::finality::FinalityConfig::default(),
                slashing_events: Vec::new(),
                slashing_stakes: vec![([9u8; 32], 1000)],
                slashing_removed: Vec::new(),
                equivocation_records: Vec::new(),
                safety_certificates: Vec::new(),
                bandwidth_inbound_bytes: 0,
                bandwidth_outbound_bytes: 0,
                peer_stats: std::collections::HashMap::new(),
                pending_txs: Vec::new(),
                seen_tx_ids: HashSet::new(),
                seen_tx_order: std::collections::VecDeque::new(),
            pending_key_rotations: Vec::new(),
            })),
            tx_id_hex,
        )
    }

    fn governance_state_with_proposals() -> SharedState {
        let proposal_a = sccgub_governance::proposals::GovernanceProposal {
            id: [0xAAu8; 32],
            proposer: [0x10u8; 32],
            kind: sccgub_governance::proposals::ProposalKind::AddNorm {
                name: "Alpha".into(),
                description: "Alpha norm".into(),
                initial_fitness: TensionValue::from_integer(1),
                enforcement_cost: TensionValue::from_integer(1),
            },
            status: sccgub_governance::proposals::ProposalStatus::Voting,
            submitted_at: 10,
            votes_for: 2,
            votes_against: 1,
            required_level: PrecedenceLevel::Meaning,
            voting_deadline: 20,
            voters: BTreeSet::new(),
            timelock_until: 0,
        };
        let proposal_b = sccgub_governance::proposals::GovernanceProposal {
            id: [0xBBu8; 32],
            proposer: [0x11u8; 32],
            kind: sccgub_governance::proposals::ProposalKind::ActivateEmergency,
            status: sccgub_governance::proposals::ProposalStatus::Rejected,
            submitted_at: 12,
            votes_for: 1,
            votes_against: 3,
            required_level: PrecedenceLevel::Safety,
            voting_deadline: 18,
            voters: BTreeSet::new(),
            timelock_until: 0,
        };

        Arc::new(RwLock::new(AppState {
            blocks: vec![],
            state: ManagedWorldState::new(),
            chain_id: [1u8; 32],
            finalized_height: 0,
            proposals: vec![proposal_a, proposal_b],
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
            seen_tx_order: std::collections::VecDeque::new(),
            pending_key_rotations: Vec::new(),
        }))
    }

    fn openapi_path_block(path: &str) -> String {
        let openapi_spec = openapi_spec();
        let marker = format!("  {}:", path);
        let start = openapi_spec
            .find(&marker)
            .unwrap_or_else(|| panic!("OpenAPI path {} not found", path));
        let after = &openapi_spec[start + marker.len()..];
        let next = after.find("\n  /api/v1/").unwrap_or(after.len());
        after[..next].to_string()
    }

    fn assert_openapi_path_has_status(path: &str, status: u16) {
        let block = openapi_path_block(path);
        let marker = format!("        \"{}\":", status);
        assert!(
            block.contains(&marker),
            "OpenAPI path {} is missing status {}",
            path,
            status
        );
    }

    fn assert_openapi_path_contains(path: &str, snippet: &str) {
        let block = openapi_path_block(path);
        assert!(
            block.contains(snippet),
            "OpenAPI path {} is missing snippet:\n{}",
            path,
            snippet
        );
    }

    fn router_versioned_paths() -> Vec<String> {
        let mut paths = Vec::new();
        let mut rest = ROUTER_SOURCE;

        while let Some(route_start) = rest.find(".route(") {
            rest = &rest[route_start + ".route(".len()..];

            let Some(path_start) = rest.find('"') else {
                break;
            };
            let after_quote = &rest[path_start + 1..];
            let Some(path_end) = after_quote.find('"') else {
                break;
            };
            let path = &after_quote[..path_end];

            if path.starts_with("/api/v1/") {
                paths.push(path.to_string());
            }
        }

        paths
    }

    fn openapi_schema_block(schema_name: &str) -> String {
        let openapi_spec = openapi_spec();
        let marker = format!("    {}:\n", schema_name);
        let start = openapi_spec
            .find(&marker)
            .unwrap_or_else(|| panic!("OpenAPI schema {} not found", schema_name));
        let after = &openapi_spec[start + marker.len()..];
        let next = after.find("\n    ").unwrap_or(after.len());
        after[..next].to_string()
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

    fn assert_json_matches_schema_required_fields(value: &Value, schema_name: &str) {
        let object = value
            .as_object()
            .unwrap_or_else(|| panic!("{} must serialize as a JSON object", schema_name));
        for field in openapi_required_fields(schema_name) {
            assert!(
                object.contains_key(&field),
                "JSON object for {} is missing required field {}",
                schema_name,
                field
            );
        }
    }

    fn assert_success_response_shape(value: &Value, wrapper_schema: &str, data_schema: &str) {
        assert_json_matches_schema_required_fields(value, wrapper_schema);
        assert_eq!(
            value.get("success"),
            Some(&Value::Bool(true)),
            "{} must set success=true",
            wrapper_schema
        );
        assert!(
            value.get("error").is_none() || value.get("error") == Some(&Value::Null),
            "{} success response must not include an error payload",
            wrapper_schema
        );
        let data = value
            .get("data")
            .unwrap_or_else(|| panic!("{} must include data", wrapper_schema));
        assert_json_matches_schema_required_fields(data, data_schema);
    }

    fn assert_error_response_shape(value: &Value) {
        assert_json_matches_schema_required_fields(value, "ErrorApiResponse");
        assert_eq!(
            value.get("success"),
            Some(&Value::Bool(false)),
            "ErrorApiResponse must set success=false"
        );
        let error = value
            .get("error")
            .unwrap_or_else(|| panic!("ErrorApiResponse must include error"));
        assert_json_matches_schema_required_fields(error, "ApiError");
    }

    async fn response_json(response: axum::response::Response) -> Value {
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body must be readable");
        serde_json::from_slice(&bytes).expect("response body must be valid JSON")
    }

    #[tokio::test]
    async fn test_status_empty_chain() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_block_not_found() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/block/999")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_state_endpoint() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/state")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ===== Versioned route tests =====

    #[tokio::test]
    async fn test_v1_status() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_v1_health() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_v1_slashing_summary() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/slashing")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_v1_slashing_validator_bad_id_returns_structured_error() {
        let app = build_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/slashing/not-hex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response_json = response_json(response).await;
        assert_error_response_shape(&response_json);
        assert_eq!(
            response_json["error"]["code"],
            Value::String("InvalidHex".into())
        );
    }

    #[tokio::test]
    async fn test_v1_slashing_evidence_summary() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/slashing/evidence")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_v1_slashing_evidence_bad_id_returns_structured_error() {
        let app = build_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/slashing/evidence/not-hex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response_json = response_json(response).await;
        assert_error_response_shape(&response_json);
        assert_eq!(
            response_json["error"]["code"],
            Value::String("InvalidHex".into())
        );
    }

    #[tokio::test]
    async fn test_v1_slashing_evidence_validator_not_found() {
        let app = build_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/slashing/evidence/1111111111111111111111111111111111111111111111111111111111111111")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);

        let response_json = response_json(response).await;
        assert_error_response_shape(&response_json);
        assert_eq!(
            response_json["error"]["code"],
            Value::String("ValidatorNotFound".into())
        );
    }

    #[tokio::test]
    async fn test_v1_block_not_found() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/block/0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_v1_block_bad_height_returns_structured_error() {
        let app = build_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/block/not-a-number")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response_json = response_json(response).await;
        assert_error_response_shape(&response_json);
        assert_eq!(
            response_json["error"]["code"],
            Value::String("InvalidRequest".into())
        );
    }

    #[tokio::test]
    async fn test_v1_state_pagination() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/state?offset=0&limit=10")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_v1_state_limit_zero_returns_structured_error() {
        let app = build_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/state?limit=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response_json = response_json(response).await;
        assert_error_response_shape(&response_json);
        assert_eq!(
            response_json["error"]["code"],
            Value::String("InvalidRequest".into())
        );
    }

    #[tokio::test]
    async fn test_v1_state_non_numeric_limit_returns_structured_error() {
        let app = build_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/state?limit=abc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response_json = response_json(response).await;
        assert_error_response_shape(&response_json);
        assert_eq!(
            response_json["error"]["code"],
            Value::String("InvalidRequest".into())
        );
    }

    #[tokio::test]
    async fn test_v1_tx_lookup_bad_id() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/tx/not-a-valid-hex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_v1_tx_lookup_not_found() {
        let app = build_router(test_state());
        let tx_id = hex::encode([0u8; 32]);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/tx/{}", tx_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Empty chain has no transactions.
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_v1_submit_empty_body() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/tx/submit")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"tx_hex":""}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_unknown_route_404() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_v1_block_receipts_not_found() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/block/999/receipts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_v1_block_receipts_bad_height_returns_structured_error() {
        let app = build_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/block/not-a-number/receipts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response_json = response_json(response).await;
        assert_error_response_shape(&response_json);
        assert_eq!(
            response_json["error"]["code"],
            Value::String("InvalidRequest".into())
        );
    }

    #[tokio::test]
    async fn test_v1_receipt_bad_id() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/receipt/not-valid-hex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_v1_receipt_not_found() {
        let app = build_router(test_state());
        let tx_id = hex::encode([0u8; 32]);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/api/v1/receipt/{}", tx_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn test_openapi_lists_all_versioned_routes() {
        let router_paths = router_versioned_paths();
        let router_count = router_paths.len();
        let spec_count = openapi_spec().matches("\n  /api/v1/").count();

        assert_eq!(router_count, 26, "router must expose 26 versioned routes");
        assert_eq!(spec_count, 26, "OpenAPI must list 26 versioned routes");
        assert_eq!(
            spec_count, router_count,
            "OpenAPI path count must match router path count"
        );

        for path in [
            "/api/v1/status",
            "/api/v1/health",
            "/api/v1/finality/certificates",
            "/api/v1/network/peers",
            "/api/v1/network/peers/{validator_id}",
            "/api/v1/slashing",
            "/api/v1/slashing/{validator_id}",
            "/api/v1/slashing/evidence",
            "/api/v1/slashing/evidence/{validator_id}",
            "/api/v1/block/{height}",
            "/api/v1/block/{height}/receipts",
            "/api/v1/state",
            "/api/v1/tx/submit",
            "/api/v1/tx/{tx_id}",
            "/api/v1/receipt/{tx_id}",
            "/api/v1/validators",
            "/api/v1/validators/history",
            "/api/v1/ceilings",
            "/api/v1/tx/key-rotation",
        ] {
            assert!(
                router_paths.iter().any(|router_path| router_path == path),
                "router must include {}",
                path
            );
            assert!(
                openapi_spec().contains(&format!("  {}:", path)),
                "OpenAPI must include {}",
                path
            );
        }
    }

    #[test]
    fn test_openapi_status_codes_cover_versioned_router_contract() {
        assert_openapi_path_has_status("/api/v1/status", 200);
        assert_openapi_path_has_status("/api/v1/status/schema", 200);
        assert_openapi_path_has_status("/api/v1/openapi", 200);
        assert_openapi_path_has_status("/api/v1/health", 200);
        assert_openapi_path_has_status("/api/v1/finality/certificates", 200);
        assert_openapi_path_has_status("/api/v1/governance/params", 200);
        assert_openapi_path_has_status("/api/v1/governance/params/schema", 200);
        assert_openapi_path_has_status("/api/v1/governance/proposals", 200);
        assert_openapi_path_has_status("/api/v1/governance/proposals", 400);
        assert_openapi_path_has_status("/api/v1/network/peers", 200);
        assert_openapi_path_has_status("/api/v1/network/peers/{validator_id}", 200);
        assert_openapi_path_has_status("/api/v1/network/peers/{validator_id}", 400);
        assert_openapi_path_has_status("/api/v1/network/peers/{validator_id}", 404);
        assert_openapi_path_has_status("/api/v1/slashing", 200);
        assert_openapi_path_has_status("/api/v1/slashing/{validator_id}", 200);
        assert_openapi_path_has_status("/api/v1/slashing/{validator_id}", 400);
        assert_openapi_path_has_status("/api/v1/slashing/{validator_id}", 404);
        assert_openapi_path_has_status("/api/v1/slashing/evidence", 200);
        assert_openapi_path_has_status("/api/v1/slashing/evidence/{validator_id}", 200);
        assert_openapi_path_has_status("/api/v1/slashing/evidence/{validator_id}", 400);
        assert_openapi_path_has_status("/api/v1/slashing/evidence/{validator_id}", 404);

        assert_openapi_path_has_status("/api/v1/block/{height}", 400);
        assert_openapi_path_has_status("/api/v1/block/{height}", 200);
        assert_openapi_path_has_status("/api/v1/block/{height}", 404);

        assert_openapi_path_has_status("/api/v1/block/{height}/receipts", 400);
        assert_openapi_path_has_status("/api/v1/block/{height}/receipts", 200);
        assert_openapi_path_has_status("/api/v1/block/{height}/receipts", 404);

        assert_openapi_path_has_status("/api/v1/state", 400);
        assert_openapi_path_has_status("/api/v1/state", 200);

        assert_openapi_path_has_status("/api/v1/tx/submit", 202);
        assert_openapi_path_has_status("/api/v1/tx/submit", 400);
        assert_openapi_path_has_status("/api/v1/tx/submit", 409);
        assert_openapi_path_has_status("/api/v1/tx/submit", 413);
        assert_openapi_path_has_status("/api/v1/tx/submit", 503);
        assert_openapi_path_has_status("/api/v1/governance/params/propose", 202);
        assert_openapi_path_has_status("/api/v1/governance/params/propose", 400);
        assert_openapi_path_has_status("/api/v1/governance/params/propose", 409);
        assert_openapi_path_has_status("/api/v1/governance/params/propose", 413);
        assert_openapi_path_has_status("/api/v1/governance/params/propose", 503);
        assert_openapi_path_has_status("/api/v1/governance/proposals/vote", 202);
        assert_openapi_path_has_status("/api/v1/governance/proposals/vote", 400);
        assert_openapi_path_has_status("/api/v1/governance/proposals/vote", 409);
        assert_openapi_path_has_status("/api/v1/governance/proposals/vote", 413);
        assert_openapi_path_has_status("/api/v1/governance/proposals/vote", 503);

        assert_openapi_path_has_status("/api/v1/tx/{tx_id}", 200);
        assert_openapi_path_has_status("/api/v1/tx/{tx_id}", 400);
        assert_openapi_path_has_status("/api/v1/tx/{tx_id}", 404);

        assert_openapi_path_has_status("/api/v1/receipt/{tx_id}", 200);
        assert_openapi_path_has_status("/api/v1/receipt/{tx_id}", 400);
        assert_openapi_path_has_status("/api/v1/receipt/{tx_id}", 404);
    }

    #[test]
    fn test_openapi_parameter_contracts_cover_versioned_router_paths() {
        assert_openapi_path_contains(
            "/api/v1/block/{height}",
            "parameters:\n        - name: height\n          in: path\n          required: true\n          schema:\n            type: integer\n            format: uint64",
        );
        assert_openapi_path_contains(
            "/api/v1/block/{height}/receipts",
            "parameters:\n        - name: height\n          in: path\n          required: true\n          schema:\n            type: integer\n            format: uint64",
        );
        assert_openapi_path_contains(
            "/api/v1/state",
            "parameters:\n        - name: offset\n          in: query\n          required: false\n          schema:\n            type: integer\n            minimum: 0",
        );
        assert_openapi_path_contains(
            "/api/v1/state",
            "- name: limit\n          in: query\n          required: false\n          schema:\n            type: integer\n            minimum: 1\n            maximum: 1000",
        );
        assert_openapi_path_contains(
            "/api/v1/governance/proposals",
            "- name: status\n          in: query\n          required: false\n          schema:\n            type: string\n            enum:\n              - Submitted\n              - Voting\n              - Accepted\n              - Rejected\n              - Timelocked\n              - Activated\n              - Expired",
        );
        assert_openapi_path_contains(
            "/api/v1/tx/{tx_id}",
            "parameters:\n        - name: tx_id\n          in: path\n          required: true\n          schema:\n            type: string\n            pattern: \"^[0-9a-fA-F]{64}$\"",
        );
        assert_openapi_path_contains(
            "/api/v1/receipt/{tx_id}",
            "parameters:\n        - name: tx_id\n          in: path\n          required: true\n          schema:\n            type: string\n            pattern: \"^[0-9a-fA-F]{64}$\"",
        );
        assert_openapi_path_contains(
            "/api/v1/slashing/{validator_id}",
            "parameters:\n        - name: validator_id\n          in: path\n          required: true\n          schema:\n            type: string\n            pattern: \"^[0-9a-fA-F]{64}$\"",
        );
        assert_openapi_path_contains(
            "/api/v1/slashing/evidence/{validator_id}",
            "parameters:\n        - name: validator_id\n          in: path\n          required: true\n          schema:\n            type: string\n            pattern: \"^[0-9a-fA-F]{64}$\"",
        );
    }

    #[tokio::test]
    async fn test_v1_success_responses_match_openapi_shapes() {
        let (state, tx_id) = populated_state();
        {
            let mut app_state = state.write().await;
            app_state.peer_stats.insert(
                "127.0.0.1:9400".into(),
                crate::handlers::PeerStatsSnapshot {
                    address: "127.0.0.1:9400".into(),
                    validator_id: Some([0xFFu8; 32]),
                    score: 42,
                    violations: 1,
                    state: "Connected".into(),
                    inbound_bytes: 10,
                    outbound_bytes: 20,
                    last_seen_ms: 1234,
                },
            );
        }
        let app = build_router(state);

        let status_json = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/status")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(
            &status_json,
            "ChainStatusApiResponse",
            "ChainStatusResponse",
        );

        let status_schema_json = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/status/schema")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(&status_schema_json, "SchemaApiResponse", "SchemaResponse");

        let openapi_json = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/openapi")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(
            &openapi_json,
            "OpenApiSpecApiResponse",
            "OpenApiSpecResponse",
        );

        let health_json = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/health")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(&health_json, "HealthApiResponse", "HealthResponse");

        let governance_json = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/governance/params")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(
            &governance_json,
            "GovernanceParamsApiResponse",
            "GovernanceParamsResponse",
        );

        let governance_schema_json = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/governance/params/schema")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(
            &governance_schema_json,
            "SchemaApiResponse",
            "SchemaResponse",
        );

        let peers_json = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/network/peers")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(
            &peers_json,
            "NetworkPeersApiResponse",
            "NetworkPeersResponse",
        );

        let peer_not_found = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/network/peers/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_error_response_shape(&peer_not_found);
        assert_eq!(peer_not_found["error"]["code"], "ValidatorNotFound");

        let peer_bad = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/network/peers/not-hex")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_error_response_shape(&peer_bad);
        assert_eq!(peer_bad["error"]["code"], "InvalidHex");

        let peer_ok = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/network/peers/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(&peer_ok, "NetworkPeerApiResponse", "NetworkPeerResponse");
        assert_eq!(peer_ok["data"]["score"], 42);

        let slashing_json = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/slashing")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(
            &slashing_json,
            "SlashingSummaryApiResponse",
            "SlashingSummaryResponse",
        );

        let slashing_validator_json = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/slashing/0909090909090909090909090909090909090909090909090909090909090909")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(
            &slashing_validator_json,
            "SlashingValidatorApiResponse",
            "SlashingValidatorResponse",
        );

        let slashing_evidence_json = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/slashing/evidence")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(
            &slashing_evidence_json,
            "SlashingEvidenceApiResponse",
            "SlashingEvidenceListResponse",
        );

        let slashing_evidence_validator_json = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/slashing/evidence/0909090909090909090909090909090909090909090909090909090909090909")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(
            &slashing_evidence_validator_json,
            "SlashingEvidenceApiResponse",
            "SlashingEvidenceListResponse",
        );

        let state_json = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/state?offset=0&limit=10")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(
            &state_json,
            "PaginatedStateApiResponse",
            "PaginatedStateResponse",
        );
        let state_entry = state_json["data"]["entries"]
            .as_array()
            .and_then(|entries| entries.first())
            .expect("state response must include one entry");
        assert_json_matches_schema_required_fields(state_entry, "StateEntry");

        let block_json = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/v1/block/0")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(&block_json, "BlockApiResponse", "BlockResponse");
        let transaction = block_json["data"]["transactions"]
            .as_array()
            .and_then(|transactions| transactions.first())
            .expect("block response must include one transaction");
        assert_json_matches_schema_required_fields(transaction, "TransactionSummary");

        let tx_json = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/tx/{}", tx_id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(&tx_json, "TxDetailApiResponse", "TxDetailResponse");

        let receipt_json = response_json(
            app.clone()
                .oneshot(
                    Request::builder()
                        .uri(format!("/api/v1/receipt/{}", tx_id))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_success_response_shape(&receipt_json, "ReceiptApiResponse", "ReceiptSummary");

        let block_receipts_json = response_json(
            app.oneshot(
                Request::builder()
                    .uri("/api/v1/block/0/receipts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap(),
        )
        .await;
        assert_success_response_shape(
            &block_receipts_json,
            "BlockReceiptsApiResponse",
            "BlockReceiptsResponse",
        );
        let receipt = block_receipts_json["data"]["receipts"]
            .as_array()
            .and_then(|receipts| receipts.first())
            .expect("block receipts response must include one receipt");
        assert_json_matches_schema_required_fields(receipt, "ReceiptSummary");
    }

    #[tokio::test]
    async fn test_v1_submit_success_response_matches_openapi_shape() {
        let app = build_router(test_state());
        let tx = make_signed_write_tx();
        let request_body = serde_json::to_vec(&serde_json::json!({
            "tx_hex": hex::encode(canonical_bytes(&tx)),
        }))
        .expect("submit request must serialize");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/tx/submit")
                    .header("content-type", "application/json")
                    .body(Body::from(request_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let response_json = response_json(response).await;
        assert_success_response_shape(&response_json, "TxSubmitApiResponse", "TxSubmitResponse");
        assert_eq!(
            response_json["data"]["status"],
            Value::String("accepted".into())
        );
    }

    #[tokio::test]
    async fn test_v1_submit_missing_required_field_returns_structured_error() {
        let app = build_router(test_state());
        let request_body =
            serde_json::to_vec(&serde_json::json!({})).expect("submit request must serialize");

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/tx/submit")
                    .header("content-type", "application/json")
                    .body(Body::from(request_body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response_json = response_json(response).await;
        assert_error_response_shape(&response_json);
        assert_eq!(
            response_json["error"]["code"],
            Value::String("InvalidRequest".into())
        );
    }

    #[tokio::test]
    async fn test_v1_error_response_matches_openapi_shape() {
        let app = build_router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/tx/not-a-valid-hex")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response_json = response_json(response).await;
        assert_error_response_shape(&response_json);
        assert_eq!(
            response_json["error"]["code"],
            Value::String("InvalidHex".into())
        );
    }

    #[tokio::test]
    async fn test_v1_governance_proposals_rejects_invalid_status() {
        let app = build_router(governance_state_with_proposals());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/governance/proposals?status=not-a-status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let response_json = response_json(response).await;
        assert_error_response_shape(&response_json);
        assert_eq!(
            response_json["error"]["code"],
            Value::String("InvalidRequest".into())
        );
    }

    #[tokio::test]
    async fn test_v1_governance_proposals_filters_by_status() {
        let app = build_router(governance_state_with_proposals());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/governance/proposals?status=Rejected")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let response_json = response_json(response).await;
        assert_success_response_shape(
            &response_json,
            "GovernanceProposalsApiResponse",
            "GovernanceProposalsResponse",
        );
        assert_eq!(response_json["data"]["count"], Value::from(1));
        let proposals = response_json["data"]["proposals"]
            .as_array()
            .expect("proposals must be an array");
        assert_eq!(proposals.len(), 1);
        assert_eq!(proposals[0]["status"], Value::String("Rejected".into()));
    }

    // ===== Transaction submission edge cases =====

    #[tokio::test]
    async fn test_v1_submit_duplicate_tx_returns_conflict() {
        let state = test_state();
        let tx = make_signed_write_tx();
        let body = serde_json::json!({ "tx_hex": hex::encode(canonical_bytes(&tx)) });

        // First submission — accepted.
        let resp1 = build_router(state.clone())
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/tx/submit")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp1.status(), StatusCode::ACCEPTED);

        // Second submission — conflict.
        let resp2 = build_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/tx/submit")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::CONFLICT);

        let json = response_json(resp2).await;
        assert_error_response_shape(&json);
        assert_eq!(json["error"]["code"], Value::String("NonceReplay".into()));
    }

    #[tokio::test]
    async fn test_v1_submit_pool_full_returns_service_unavailable() {
        let state = test_state();
        {
            let mut app = state.write().await;
            // Fill the pending pool to MAX_PENDING_TXS.
            for _ in 0..handlers::MAX_PENDING_TXS {
                app.pending_txs.push(make_signed_write_tx());
            }
        }

        let tx = make_signed_write_tx();
        let body = serde_json::json!({ "tx_hex": hex::encode(canonical_bytes(&tx)) });
        let resp = build_router(state)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/tx/submit")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        let json = response_json(resp).await;
        assert_error_response_shape(&json);
        assert_eq!(json["error"]["code"], Value::String("RateLimited".into()));
    }

    #[tokio::test]
    async fn test_v1_submit_invalid_hex_returns_bad_request() {
        let app = build_router(test_state());
        let body = serde_json::json!({ "tx_hex": "not-valid-hex!!" });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/tx/submit")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let json = response_json(resp).await;
        assert_error_response_shape(&json);
        assert_eq!(json["error"]["code"], Value::String("InvalidHex".into()));
    }

    #[tokio::test]
    async fn test_v1_submit_valid_hex_invalid_bincode_returns_bad_request() {
        let app = build_router(test_state());
        let body = serde_json::json!({ "tx_hex": hex::encode(b"not valid bincode") });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/tx/submit")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let json = response_json(resp).await;
        assert_error_response_shape(&json);
        assert_eq!(
            json["error"]["code"],
            Value::String("InvalidTransaction".into())
        );
    }

    // ===== Request body size limit =====

    #[tokio::test]
    async fn test_v1_submit_oversized_body_returns_payload_too_large() {
        let app = build_router(test_state());
        // 1 MiB + 1 byte exceeds the DefaultBodyLimit.
        let oversized = vec![b'A'; 1_048_576 + 1];
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/tx/submit")
                    .header("content-type", "application/json")
                    .body(Body::from(oversized))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    // ===== Governance param propose endpoint =====

    fn make_governance_propose_tx(key: &str, value: &str) -> SymbolicTransition {
        let signing_key = generate_keypair();
        let public_key = *signing_key.verifying_key().as_bytes();
        let mfidel_seal = MfidelAtomicSeal::from_height(1);
        let agent_id =
            sccgub_crypto::hash::blake3_hash_concat(&[&public_key, &canonical_bytes(&mfidel_seal)]);
        let actor = AgentIdentity {
            agent_id,
            public_key,
            mfidel_seal,
            registration_block: 0,
            governance_level: PrecedenceLevel::Meaning,
            norm_set: BTreeSet::new(),
            responsibility: ResponsibilityState::default(),
        };

        let target = b"norms/governance/params/propose".to_vec();
        let payload_value = format!("{}={}", key, value);
        let mut tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor,
            intent: TransitionIntent {
                kind: TransitionKind::GovernanceUpdate,
                target: target.clone(),
                declared_purpose: "governance param proposal".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: target.clone(),
                value: payload_value.into_bytes(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: agent_id,
                when: CausalTimestamp::genesis(),
                r#where: target,
                why: CausalJustification {
                    invoking_rule: blake3_hash(b"governance-propose-test"),
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "governance param proposal".into(),
            },
            nonce: 1,
            signature: vec![],
        };

        let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
        tx.tx_id = blake3_hash(&canonical);
        tx.signature = sign(&signing_key, &canonical);
        tx
    }

    #[tokio::test]
    async fn test_v1_governance_propose_valid_param() {
        let app = build_router(test_state());
        let tx = make_governance_propose_tx("finality.confirmation_depth", "10");
        let body = serde_json::json!({ "tx_hex": hex::encode(canonical_bytes(&tx)) });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/params/propose")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let json = response_json(resp).await;
        assert_success_response_shape(&json, "TxSubmitApiResponse", "TxSubmitResponse");
    }

    #[tokio::test]
    async fn test_v1_governance_propose_unsupported_key() {
        let app = build_router(test_state());
        let tx = make_governance_propose_tx("not.a.real.key", "42");
        let body = serde_json::json!({ "tx_hex": hex::encode(canonical_bytes(&tx)) });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/params/propose")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let json = response_json(resp).await;
        assert_error_response_shape(&json);
        assert_eq!(
            json["error"]["code"],
            Value::String("InvalidTransaction".into())
        );
    }

    #[tokio::test]
    async fn test_v1_governance_propose_empty_body() {
        let app = build_router(test_state());
        let body = serde_json::json!({ "tx_hex": "" });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/params/propose")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let json = response_json(resp).await;
        assert_error_response_shape(&json);
        assert_eq!(json["error"]["code"], Value::String("EmptyPayload".into()));
    }

    #[tokio::test]
    async fn test_v1_governance_propose_wrong_kind_rejected() {
        let app = build_router(test_state());
        // A StateWrite tx submitted to the governance propose endpoint.
        let tx = make_signed_write_tx();
        let body = serde_json::json!({ "tx_hex": hex::encode(canonical_bytes(&tx)) });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/params/propose")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let json = response_json(resp).await;
        assert_error_response_shape(&json);
        assert_eq!(
            json["error"]["code"],
            Value::String("InvalidTransaction".into())
        );
    }

    // ===== Governance vote endpoint =====

    fn make_governance_vote_tx() -> SymbolicTransition {
        let signing_key = generate_keypair();
        let public_key = *signing_key.verifying_key().as_bytes();
        let mfidel_seal = MfidelAtomicSeal::from_height(1);
        let agent_id =
            sccgub_crypto::hash::blake3_hash_concat(&[&public_key, &canonical_bytes(&mfidel_seal)]);
        let actor = AgentIdentity {
            agent_id,
            public_key,
            mfidel_seal,
            registration_block: 0,
            governance_level: PrecedenceLevel::Meaning,
            norm_set: BTreeSet::new(),
            responsibility: ResponsibilityState::default(),
        };

        let target = b"norms/governance/proposals/vote".to_vec();
        let proposal_id = [0xAAu8; 32];
        let mut tx = SymbolicTransition {
            tx_id: [0u8; 32],
            actor,
            intent: TransitionIntent {
                kind: TransitionKind::GovernanceUpdate,
                target: target.clone(),
                declared_purpose: "governance vote".into(),
            },
            preconditions: vec![],
            postconditions: vec![],
            payload: OperationPayload::Write {
                key: target.clone(),
                value: proposal_id.to_vec(),
            },
            causal_chain: vec![],
            wh_binding_intent: WHBindingIntent {
                who: agent_id,
                when: CausalTimestamp::genesis(),
                r#where: target,
                why: CausalJustification {
                    invoking_rule: blake3_hash(b"governance-vote-test"),
                    precedence_level: PrecedenceLevel::Meaning,
                    causal_ancestors: vec![],
                    constraint_proof: vec![],
                },
                how: TransitionMechanism::DirectStateWrite,
                which: BTreeSet::new(),
                what_declared: "governance vote".into(),
            },
            nonce: 1,
            signature: vec![],
        };

        let canonical = sccgub_execution::validate::canonical_tx_bytes(&tx);
        tx.tx_id = blake3_hash(&canonical);
        tx.signature = sign(&signing_key, &canonical);
        tx
    }

    #[tokio::test]
    async fn test_v1_governance_vote_accepted() {
        let app = build_router(test_state());
        let tx = make_governance_vote_tx();
        let body = serde_json::json!({ "tx_hex": hex::encode(canonical_bytes(&tx)) });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/proposals/vote")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let json = response_json(resp).await;
        assert_success_response_shape(&json, "TxSubmitApiResponse", "TxSubmitResponse");
    }

    #[tokio::test]
    async fn test_v1_governance_vote_wrong_kind_rejected() {
        let app = build_router(test_state());
        let tx = make_signed_write_tx();
        let body = serde_json::json!({ "tx_hex": hex::encode(canonical_bytes(&tx)) });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/proposals/vote")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let json = response_json(resp).await;
        assert_error_response_shape(&json);
        assert_eq!(
            json["error"]["code"],
            Value::String("InvalidTransaction".into())
        );
    }

    #[tokio::test]
    async fn test_v1_governance_vote_empty_body() {
        let app = build_router(test_state());
        let body = serde_json::json!({ "tx_hex": "" });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/governance/proposals/vote")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let json = response_json(resp).await;
        assert_error_response_shape(&json);
        assert_eq!(json["error"]["code"], Value::String("EmptyPayload".into()));
    }

    // ===== Governance proposals pagination =====

    #[tokio::test]
    async fn test_v1_governance_proposals_limit_zero_returns_error() {
        let app = build_router(governance_state_with_proposals());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/governance/proposals?limit=0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let json = response_json(response).await;
        assert_error_response_shape(&json);
        assert_eq!(
            json["error"]["code"],
            Value::String("InvalidRequest".into())
        );
    }

    #[tokio::test]
    async fn test_v1_governance_proposals_pagination_offset() {
        let app = build_router(governance_state_with_proposals());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/governance/proposals?offset=1&limit=1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let json = response_json(response).await;
        // Total count is 2 (both proposals), but page has 1 (offset=1, limit=1).
        assert_eq!(json["data"]["count"], Value::from(2));
        let proposals = json["data"]["proposals"]
            .as_array()
            .expect("proposals must be an array");
        assert_eq!(proposals.len(), 1);
    }

    #[tokio::test]
    async fn test_v1_governance_proposals_case_insensitive_filter() {
        let app = build_router(governance_state_with_proposals());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/governance/proposals?status=voting")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let json = response_json(response).await;
        assert_eq!(json["data"]["count"], Value::from(1));
    }

    // ───────────────────────────────────────────────────────────────────
    // N-60: Response-body caps on unbounded-list endpoints.
    // ───────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_v1_finality_certificates_response_is_capped() {
        use sccgub_consensus::safety::SafetyCertificate;

        let state = test_state();
        // Populate with 2× MAX_API_RESPONSE_ENTRIES distinct certs.
        {
            let mut app = state.write().await;
            let count = crate::handlers::MAX_API_RESPONSE_ENTRIES * 2;
            for i in 0..count {
                app.safety_certificates.push(SafetyCertificate {
                    chain_id: [0u8; 32],
                    epoch: 0,
                    height: i as u64,
                    block_hash: [(i % 251) as u8; 32],
                    round: 0,
                    precommit_signatures: vec![],
                    quorum: 1,
                    validator_count: 1,
                });
            }
        }
        let app = build_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/finality/certificates")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        // count reports the chain-side total; certificates array is capped.
        assert_eq!(
            json["data"]["count"].as_u64().unwrap(),
            (crate::handlers::MAX_API_RESPONSE_ENTRIES * 2) as u64
        );
        let certs = json["data"]["certificates"].as_array().unwrap();
        assert_eq!(certs.len(), crate::handlers::MAX_API_RESPONSE_ENTRIES);
    }

    #[tokio::test]
    async fn test_v1_slashing_evidence_response_is_capped() {
        use sccgub_consensus::protocol::{EquivocationProof, VoteType};

        let state = test_state();
        {
            let mut app = state.write().await;
            let count = crate::handlers::MAX_API_RESPONSE_ENTRIES + 200;
            for i in 0..count {
                app.equivocation_records.push((
                    EquivocationProof {
                        validator_id: [1u8; 32],
                        height: i as u64,
                        round: 0,
                        vote_type: VoteType::Prevote,
                        block_hash_a: [2u8; 32],
                        block_hash_b: [3u8; 32],
                    },
                    0,
                ));
            }
        }
        let app = build_router(state.clone());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/api/v1/slashing/evidence")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let json = response_json(response).await;
        let evidence = json["data"]["evidence"].as_array().unwrap();
        assert_eq!(evidence.len(), crate::handlers::MAX_API_RESPONSE_ENTRIES);
    }
}
