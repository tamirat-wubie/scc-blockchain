use axum::{routing::get, Router};

use crate::handlers::{self, SharedState};

/// Build the API router with all endpoints.
///
/// Endpoints:
///   GET  /api/status         — chain summary
///   GET  /api/health         — system health + finality
///   GET  /api/block/:height  — block detail with transactions
///   GET  /api/state          — all world state entries
pub fn build_router(state: SharedState) -> Router {
    Router::new()
        .route("/api/status", get(handlers::get_status))
        .route("/api/health", get(handlers::get_health))
        .route("/api/block/{height}", get(handlers::get_block))
        .route("/api/state", get(handlers::get_state))
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
        assert_eq!(resp.status(), StatusCode::OK); // Returns 200 with error in body.
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
}
