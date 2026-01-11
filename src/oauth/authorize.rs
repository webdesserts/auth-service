//! OAuth 2.1 Authorization Endpoint
//!
//! Handles authorization requests with PKCE support.
//! For now, this auto-approves requests (passkey auth is Phase 2).

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::storage::{generate_random_string, hash_token, StoredAuthCode};
use crate::AppState;

/// Authorization request parameters
#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    /// Must be "code" for authorization code flow
    pub response_type: String,

    /// The client identifier
    pub client_id: String,

    /// Redirect URI (must match registered URI)
    pub redirect_uri: String,

    /// PKCE code challenge
    pub code_challenge: String,

    /// PKCE code challenge method (must be "S256")
    pub code_challenge_method: String,

    /// Client state (passed through to redirect)
    #[serde(default)]
    pub state: Option<String>,

    /// Requested scopes (not used for now, but part of OAuth spec)
    #[serde(default)]
    #[allow(dead_code)]
    pub scope: Option<String>,
}

/// Authorization error response
fn auth_error_redirect(redirect_uri: &str, error: &str, description: &str, state: Option<&str>) -> Redirect {
    let mut url = format!("{}?error={}&error_description={}", redirect_uri, error, urlencoding::encode(description));
    if let Some(s) = state {
        url.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    Redirect::to(&url)
}

/// Handler for `GET /authorize` - shows consent page (simplified for now)
pub async fn get_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeRequest>,
) -> Response {
    // Validate request
    if let Err(response) = validate_authorize_request(&state, &params) {
        return response;
    }

    // For Phase 1, we auto-approve and redirect immediately
    // Phase 2 will add passkey authentication here

    // In a real implementation, you'd show a consent page here
    // For now, just generate the auth code and redirect

    let code = generate_random_string(32);
    let code_hash = hash_token(&code);

    let auth_code = StoredAuthCode {
        code_hash,
        client_id: params.client_id.clone(),
        redirect_uri: params.redirect_uri.clone(),
        code_challenge: params.code_challenge.clone(),
        code_challenge_method: params.code_challenge_method.clone(),
        expires_at: Utc::now() + Duration::minutes(10),
        created_at: Utc::now(),
    };

    state.storage.store_auth_code(auth_code);

    // Redirect with authorization code
    let mut redirect_url = format!("{}?code={}", params.redirect_uri, code);
    if let Some(s) = &params.state {
        redirect_url.push_str(&format!("&state={}", urlencoding::encode(s)));
    }

    tracing::info!(
        "Issued authorization code for client {} (auto-approved, passkey auth not yet implemented)",
        params.client_id
    );

    Redirect::to(&redirect_url).into_response()
}

/// Handler for `POST /authorize` - processes consent form (for future use)
pub async fn post_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AuthorizeRequest>,
) -> Response {
    // For now, same as GET - auto-approve
    get_handler(State(state), Query(params)).await
}

/// Validate an authorization request
fn validate_authorize_request(
    state: &AppState,
    params: &AuthorizeRequest,
) -> Result<(), Response> {
    // Check response_type
    if params.response_type != "code" {
        return Err((
            StatusCode::BAD_REQUEST,
            Html("Invalid response_type. Only 'code' is supported."),
        ).into_response());
    }

    // Check code_challenge_method
    if params.code_challenge_method != "S256" {
        return Err(auth_error_redirect(
            &params.redirect_uri,
            "invalid_request",
            "code_challenge_method must be S256",
            params.state.as_deref(),
        ).into_response());
    }

    // Validate code_challenge is present and reasonable length
    if params.code_challenge.is_empty() || params.code_challenge.len() < 43 {
        return Err(auth_error_redirect(
            &params.redirect_uri,
            "invalid_request",
            "code_challenge is required and must be a valid S256 hash",
            params.state.as_deref(),
        ).into_response());
    }

    // Look up client
    let client = match state.storage.get_client(&params.client_id) {
        Some(c) => c,
        None => {
            return Err((
                StatusCode::BAD_REQUEST,
                Html("Unknown client_id. Please register first."),
            ).into_response());
        }
    };

    // Validate redirect_uri matches registered URI
    if !client.redirect_uris.contains(&params.redirect_uri) {
        return Err((
            StatusCode::BAD_REQUEST,
            Html("redirect_uri does not match registered URIs for this client."),
        ).into_response());
    }

    Ok(())
}

mod urlencoding {
    pub fn encode(s: &str) -> String {
        url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
    }
}
