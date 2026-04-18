//! Operator authentication layer (Patch-07 §C / audit H.3′).
//!
//! Closes the "A11 mental-drift risk" identified in the v0.6.3 audit:
//! PATCH_06.md §33.6 implied the existence of `sccgub-api::admin::*`
//! endpoints "gated behind operator authentication," but no such
//! mental model existed in code. A future author wiring admin
//! endpoints (e.g., the §33.6 pruned-archive reader) would have had to
//! define the auth model from scratch, with the risk of shipping
//! unauthenticated admin endpoints by default.
//!
//! This module establishes the contract before the endpoints arrive:
//!
//! 1. An `OperatorToken` type carrying a single secret string. Cloned
//!    into `SharedState` at router construction; compared constant-time
//!    against the incoming `Authorization: Bearer <token>` header.
//! 2. A `require_operator_auth` axum middleware that 401s requests
//!    missing the header, the `Bearer` prefix, or the correct token.
//! 3. Default posture: `OperatorToken::Disabled`, which 503s every
//!    admin endpoint. Operators explicitly opt in by constructing
//!    `OperatorToken::Enabled(secret)`. No admin endpoint is reachable
//!    until the operator sets a token.
//!
//! Constant-time comparison uses `subtle::ConstantTimeEq` so a timing
//! oracle cannot distinguish between wrong-length and partial-match
//! tokens.

use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use subtle::ConstantTimeEq;

/// Operator authentication configuration.
///
/// `Disabled` is the default: all admin routes reject with `503 Service
/// Unavailable`. `Enabled(secret)` accepts any request whose
/// `Authorization: Bearer <secret>` matches under constant-time
/// comparison.
#[derive(Debug, Clone, Default)]
pub enum OperatorToken {
    #[default]
    Disabled,
    Enabled(String),
}

impl OperatorToken {
    /// Construct from an optional environment-provided secret. Empty or
    /// missing → `Disabled`. Any non-empty string becomes the secret.
    pub fn from_env(value: Option<&str>) -> Self {
        match value {
            Some(s) if !s.is_empty() => Self::Enabled(s.to_string()),
            _ => Self::Disabled,
        }
    }

    /// True iff any admin route should be reachable.
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled(_))
    }

    /// Constant-time compare against a candidate token.
    fn accepts(&self, candidate: &str) -> bool {
        match self {
            Self::Disabled => false,
            Self::Enabled(expected) => {
                // Constant-time compare. Lengths may differ — `ct_eq`
                // of unequal-length byte slices returns `Choice(0)`;
                // call it anyway so the code path does not branch on
                // length.
                let exp = expected.as_bytes();
                let cand = candidate.as_bytes();
                if exp.len() != cand.len() {
                    // Still touch the memory to avoid a length-only
                    // side channel; result is always false.
                    let _ = exp.ct_eq(exp);
                    return false;
                }
                exp.ct_eq(cand).into()
            }
        }
    }
}

/// Extract the bearer token from an `Authorization` header. Returns
/// `None` if the header is missing or not in `Bearer <token>` form.
fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Axum middleware enforcing operator authentication.
///
/// Flow:
///
/// - If `token` is `Disabled`, reject every request with
///   `503 Service Unavailable`. Admin routes are explicitly off.
/// - If `token` is `Enabled`, require a matching `Authorization:
///   Bearer <secret>` header; reject mismatches with `401 Unauthorized`.
///
/// The middleware is applied per-route (only admin routes) rather than
/// globally so the public `/api/v1/*` surface is unaffected.
pub async fn require_operator_auth(
    State(token): State<OperatorToken>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if !token.is_enabled() {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let candidate = extract_bearer(request.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    if !token.accepts(candidate) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_07_disabled_rejects_any_token() {
        let t = OperatorToken::Disabled;
        assert!(!t.accepts("anything"));
        assert!(!t.accepts(""));
    }

    #[test]
    fn patch_07_enabled_accepts_exact_match() {
        let t = OperatorToken::Enabled("secret".to_string());
        assert!(t.accepts("secret"));
    }

    #[test]
    fn patch_07_enabled_rejects_mismatch() {
        let t = OperatorToken::Enabled("secret".to_string());
        assert!(!t.accepts("wrong"));
        assert!(!t.accepts("secre"));
        assert!(!t.accepts("secrett"));
        assert!(!t.accepts(""));
    }

    #[test]
    fn patch_07_from_env_handles_empty_and_missing() {
        assert!(!OperatorToken::from_env(None).is_enabled());
        assert!(!OperatorToken::from_env(Some("")).is_enabled());
        assert!(OperatorToken::from_env(Some("x")).is_enabled());
    }

    #[test]
    fn patch_07_extract_bearer_happy_path() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer abc123".parse().unwrap(),
        );
        assert_eq!(extract_bearer(&h), Some("abc123"));
    }

    #[test]
    fn patch_07_extract_bearer_rejects_non_bearer_schemes() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Basic abc".parse().unwrap(),
        );
        assert_eq!(extract_bearer(&h), None);
    }

    #[test]
    fn patch_07_extract_bearer_rejects_empty_bearer() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer ".parse().unwrap(),
        );
        assert_eq!(extract_bearer(&h), None);
    }

    #[test]
    fn patch_07_extract_bearer_trims_whitespace() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            "Bearer   token   ".parse().unwrap(),
        );
        assert_eq!(extract_bearer(&h), Some("token"));
    }

    #[test]
    fn patch_07_extract_bearer_missing_header() {
        let h = HeaderMap::new();
        assert_eq!(extract_bearer(&h), None);
    }

    #[test]
    fn patch_07_constant_time_compare_does_not_panic_on_length_mismatch() {
        // Regression: earlier drafts used `==` which short-circuits.
        // Ensure the length-guard path still returns false without
        // panicking.
        let t = OperatorToken::Enabled("0123456789".to_string());
        assert!(!t.accepts("short"));
        assert!(!t.accepts("muchmuchlongerthantheoriginalsecret"));
    }
}
