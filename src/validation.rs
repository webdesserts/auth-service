//! Token validation endpoint for Caddy forward_auth
//!
//! This endpoint is called by Caddy before proxying requests to protected services.
//! It validates either:
//! - OAuth Bearer tokens
//! - API keys

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
};

use crate::storage::hash_token;
use crate::AppState;

/// Validation endpoint for Caddy forward_auth
///
/// Returns 200 if the request is authenticated, 401 otherwise.
/// Caddy will proxy the request only if this returns 200.
pub async fn handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Extract Authorization header
    let auth_header = match headers.get("authorization") {
        Some(h) => h,
        None => {
            tracing::debug!("No Authorization header present");
            return (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Bearer")],
                "Missing Authorization header",
            );
        }
    };

    let auth_str = match auth_header.to_str() {
        Ok(s) => s,
        Err(_) => {
            tracing::debug!("Invalid Authorization header encoding");
            return (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Bearer")],
                "Invalid Authorization header",
            );
        }
    };

    // Check for Bearer token
    if let Some(token) = auth_str.strip_prefix("Bearer ") {
        let token = token.trim();

        // First, check if it's an API key
        if state.config.validate_api_key(token) {
            tracing::debug!("Request authenticated via API key");
            return (StatusCode::OK, [("WWW-Authenticate", "")], "OK");
        }

        // Otherwise, check if it's a valid OAuth token
        let token_hash = hash_token(token);
        if let Some(stored_token) = state.storage.validate_token(&token_hash) {
            if stored_token.token_type == crate::storage::TokenType::Access {
                tracing::debug!(
                    "Request authenticated via OAuth token for client {}",
                    stored_token.client_id
                );
                return (StatusCode::OK, [("WWW-Authenticate", "")], "OK");
            }
        }

        tracing::debug!("Invalid or expired token");
        return (
            StatusCode::UNAUTHORIZED,
            [("WWW-Authenticate", "Bearer error=\"invalid_token\"")],
            "Invalid or expired token",
        );
    }

    tracing::debug!("Authorization header does not start with 'Bearer '");
    (
        StatusCode::UNAUTHORIZED,
        [("WWW-Authenticate", "Bearer")],
        "Invalid Authorization header format",
    )
}
