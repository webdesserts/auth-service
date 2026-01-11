//! OAuth 2.1 Token Endpoint
//!
//! Handles:
//! - Authorization code exchange (with PKCE verification)
//! - Refresh token grants

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Form, Json,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

use crate::storage::{generate_random_string, hash_token, StoredToken, TokenType};
use crate::AppState;

/// Token request (form-encoded)
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    /// Grant type: "authorization_code" or "refresh_token"
    pub grant_type: String,

    /// Authorization code (for authorization_code grant)
    #[serde(default)]
    pub code: Option<String>,

    /// Redirect URI (for authorization_code grant, must match original)
    #[serde(default)]
    pub redirect_uri: Option<String>,

    /// PKCE code verifier (for authorization_code grant)
    #[serde(default)]
    pub code_verifier: Option<String>,

    /// Client ID
    pub client_id: String,

    /// Refresh token (for refresh_token grant)
    #[serde(default)]
    pub refresh_token: Option<String>,
}

/// Successful token response
#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

/// Token error response
#[derive(Debug, Serialize)]
pub struct TokenError {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

/// Handler for `POST /token`
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Form(request): Form<TokenRequest>,
) -> Response {
    match request.grant_type.as_str() {
        "authorization_code" => handle_authorization_code(&state, &request).await,
        "refresh_token" => handle_refresh_token(&state, &request).await,
        _ => (
            StatusCode::BAD_REQUEST,
            Json(TokenError {
                error: "unsupported_grant_type".to_string(),
                error_description: Some("Only authorization_code and refresh_token grants are supported".to_string()),
            }),
        ).into_response(),
    }
}

/// Handle authorization_code grant
async fn handle_authorization_code(
    state: &AppState,
    request: &TokenRequest,
) -> Response {
    // Validate required fields
    let code = match &request.code {
        Some(c) => c,
        None => return (
            StatusCode::BAD_REQUEST,
            Json(TokenError {
                error: "invalid_request".to_string(),
                error_description: Some("code is required".to_string()),
            }),
        ).into_response(),
    };

    let code_verifier = match &request.code_verifier {
        Some(v) => v,
        None => return (
            StatusCode::BAD_REQUEST,
            Json(TokenError {
                error: "invalid_request".to_string(),
                error_description: Some("code_verifier is required".to_string()),
            }),
        ).into_response(),
    };

    let redirect_uri = match &request.redirect_uri {
        Some(r) => r,
        None => return (
            StatusCode::BAD_REQUEST,
            Json(TokenError {
                error: "invalid_request".to_string(),
                error_description: Some("redirect_uri is required".to_string()),
            }),
        ).into_response(),
    };

    // Look up and consume the authorization code
    let code_hash = hash_token(code);
    let auth_code = match state.storage.consume_auth_code(&code_hash) {
        Some(c) => c,
        None => return (
            StatusCode::BAD_REQUEST,
            Json(TokenError {
                error: "invalid_grant".to_string(),
                error_description: Some("Authorization code is invalid or expired".to_string()),
            }),
        ).into_response(),
    };

    // Verify client_id matches
    if auth_code.client_id != request.client_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(TokenError {
                error: "invalid_grant".to_string(),
                error_description: Some("client_id does not match".to_string()),
            }),
        ).into_response();
    }

    // Verify redirect_uri matches
    if auth_code.redirect_uri != *redirect_uri {
        return (
            StatusCode::BAD_REQUEST,
            Json(TokenError {
                error: "invalid_grant".to_string(),
                error_description: Some("redirect_uri does not match".to_string()),
            }),
        ).into_response();
    }

    // Verify PKCE code_verifier
    if !verify_pkce(&auth_code.code_challenge, code_verifier) {
        return (
            StatusCode::BAD_REQUEST,
            Json(TokenError {
                error: "invalid_grant".to_string(),
                error_description: Some("code_verifier does not match code_challenge".to_string()),
            }),
        ).into_response();
    }

    // Generate tokens
    let access_token = generate_random_string(48);
    let refresh_token = generate_random_string(48);
    let now = Utc::now();

    let access_token_lifetime = state.config.tokens.access_token_lifetime_secs;
    let refresh_token_lifetime = state.config.tokens.refresh_token_lifetime_secs;

    // Store access token
    let access_token_hash = hash_token(&access_token);
    let stored_access = StoredToken {
        token_hash: access_token_hash.clone(),
        client_id: request.client_id.clone(),
        token_type: TokenType::Access,
        expires_at: now + Duration::seconds(access_token_lifetime as i64),
        created_at: now,
        associated_token: None,
    };

    if let Err(e) = state.storage.store_token(stored_access) {
        tracing::error!("Failed to store access token: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(TokenError {
                error: "server_error".to_string(),
                error_description: Some("Failed to generate token".to_string()),
            }),
        ).into_response();
    }

    // Store refresh token
    let refresh_token_hash = hash_token(&refresh_token);
    let stored_refresh = StoredToken {
        token_hash: refresh_token_hash,
        client_id: request.client_id.clone(),
        token_type: TokenType::Refresh,
        expires_at: now + Duration::seconds(refresh_token_lifetime as i64),
        created_at: now,
        associated_token: Some(access_token_hash),
    };

    if let Err(e) = state.storage.store_token(stored_refresh) {
        tracing::error!("Failed to store refresh token: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(TokenError {
                error: "server_error".to_string(),
                error_description: Some("Failed to generate token".to_string()),
            }),
        ).into_response();
    }

    tracing::info!("Issued access token for client {}", request.client_id);

    (
        StatusCode::OK,
        Json(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: access_token_lifetime,
            refresh_token: Some(refresh_token),
        }),
    ).into_response()
}

/// Handle refresh_token grant
async fn handle_refresh_token(
    state: &AppState,
    request: &TokenRequest,
) -> Response {
    let refresh_token = match &request.refresh_token {
        Some(t) => t,
        None => return (
            StatusCode::BAD_REQUEST,
            Json(TokenError {
                error: "invalid_request".to_string(),
                error_description: Some("refresh_token is required".to_string()),
            }),
        ).into_response(),
    };

    // Validate refresh token
    let refresh_token_hash = hash_token(refresh_token);
    let stored_refresh = match state.storage.validate_token(&refresh_token_hash) {
        Some(t) if t.token_type == TokenType::Refresh => t,
        _ => return (
            StatusCode::BAD_REQUEST,
            Json(TokenError {
                error: "invalid_grant".to_string(),
                error_description: Some("Refresh token is invalid or expired".to_string()),
            }),
        ).into_response(),
    };

    // Verify client_id matches
    if stored_refresh.client_id != request.client_id {
        return (
            StatusCode::BAD_REQUEST,
            Json(TokenError {
                error: "invalid_grant".to_string(),
                error_description: Some("client_id does not match".to_string()),
            }),
        ).into_response();
    }

    // Revoke old access token if it exists
    if let Some(old_access_hash) = &stored_refresh.associated_token {
        let _ = state.storage.revoke_token(old_access_hash);
    }

    // Generate new access token
    let access_token = generate_random_string(48);
    let now = Utc::now();
    let access_token_lifetime = state.config.tokens.access_token_lifetime_secs;

    let access_token_hash = hash_token(&access_token);
    let stored_access = StoredToken {
        token_hash: access_token_hash,
        client_id: request.client_id.clone(),
        token_type: TokenType::Access,
        expires_at: now + Duration::seconds(access_token_lifetime as i64),
        created_at: now,
        associated_token: None,
    };

    if let Err(e) = state.storage.store_token(stored_access) {
        tracing::error!("Failed to store access token: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(TokenError {
                error: "server_error".to_string(),
                error_description: Some("Failed to generate token".to_string()),
            }),
        ).into_response();
    }

    tracing::info!("Refreshed access token for client {}", request.client_id);

    // Note: We don't issue a new refresh token on refresh (simpler rotation strategy)
    (
        StatusCode::OK,
        Json(TokenResponse {
            access_token,
            token_type: "Bearer".to_string(),
            expires_in: access_token_lifetime,
            refresh_token: None, // Keep using the same refresh token
        }),
    ).into_response()
}

/// Verify PKCE code_verifier against code_challenge (S256 method)
fn verify_pkce(code_challenge: &str, code_verifier: &str) -> bool {
    // S256: BASE64URL(SHA256(code_verifier)) == code_challenge
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let hash = hasher.finalize();
    let computed_challenge = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        hash,
    );

    computed_challenge == code_challenge
}
