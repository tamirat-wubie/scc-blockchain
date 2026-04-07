use axum::{
    routing::{get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

use crate::handlers::{self, SharedState};

/// Build the API router with all endpoints.
///
/// Endpoints:
///   GET  /api/v1/status           — chain summary
///   GET  /api/v1/health           — system health + finality
///   GET  /api/v1/block/:height    — block detail with transactions
///   GET  /api/v1/state            — paginated world state entries
///   GET  /api/v1/tx/:tx_id        — transaction detail by ID
///   POST /api/v1/tx/submit        — submit a signed transaction
///
/// Legacy (unversioned) routes preserved for backward compatibility.
pub fn build_router(state: SharedState) -> Router {
    Router::new()
        // Versioned routes (preferred).
        .route("/api/v1/status", get(handlers::get_status))
        .route("/api/v1/health", get(handlers::get_health))
        .route("/api/v1/block/{height}", get(handlers::get_block))
        .route("/api/v1/state", get(handlers::get_state))
        .route("/api/v1/tx/submit", post(handlers::submit_tx))
        .route("/api/v1/tx/{tx_id}", get(handlers::get_tx))
        // Legacy unversioned routes.
        .route("/api/status", get(handlers::get_status))
        .route("/api/health", get(handlers::get_health))
        .route("/api/block/{height}", get(handlers::get_block))
        .route("/api/state", get(handlers::get_state))
        .route("/api/tx/{tx_id}", get(handlers::get_tx))
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
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use sccgub_state::world::ManagedWorldState;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tower::util::ServiceExt;

    fn test_state() -> SharedState {
        Arc::new(RwLock::new(AppState {
            blocks: vec![],
            state: ManagedWorldState::new(),
            chain_id: [1u8; 32],
            finalized_height: 0,
        }))
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
                    .uri(&format!("/api/v1/tx/{}", tx_id))
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
}
