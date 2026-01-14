//! OAuth 2.1 Authorization Endpoint
//!
//! Handles authorization requests with PKCE support.
//! Requires passkey authentication before issuing auth codes.

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
};
use chrono::{Duration, Utc};
use serde::Deserialize;

use crate::passkey::validate_session_from_headers;
use crate::storage::{generate_random_string, hash_token, PendingOAuthRequest, StoredAuthCode};
use crate::AppState;

/// Authorization request parameters
#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    /// Must be "code" for authorization code flow
    #[serde(default)]
    pub response_type: Option<String>,

    /// The client identifier
    #[serde(default)]
    pub client_id: Option<String>,

    /// Redirect URI (must match registered URI)
    #[serde(default)]
    pub redirect_uri: Option<String>,

    /// PKCE code challenge
    #[serde(default)]
    pub code_challenge: Option<String>,

    /// PKCE code challenge method (must be "S256")
    #[serde(default)]
    pub code_challenge_method: Option<String>,

    /// Client state (passed through to redirect)
    #[serde(default)]
    pub state: Option<String>,

    /// Requested scopes (not used for now, but part of OAuth spec)
    #[serde(default)]
    #[allow(dead_code)]
    pub scope: Option<String>,

    /// Pending OAuth request ID (when returning from login)
    #[serde(default)]
    pub pending: Option<String>,
}

/// Authorization error response
fn auth_error_redirect(redirect_uri: &str, error: &str, description: &str, state: Option<&str>) -> Redirect {
    let mut url = format!("{}?error={}&error_description={}", redirect_uri, error, urlencoding::encode(description));
    if let Some(s) = state {
        url.push_str(&format!("&state={}", urlencoding::encode(s)));
    }
    Redirect::to(&url)
}

/// Handler for `GET /authorize`
pub async fn get_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(params): Query<AuthorizeRequest>,
) -> Response {
    // Resolve OAuth params - either from query string or from pending request
    let oauth_params = if let Some(pending_id) = &params.pending {
        // Returning from login - retrieve stored OAuth params
        match state.storage.consume_pending_oauth(pending_id) {
            Some(pending) => pending,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Html("Invalid or expired authorization request. Please start over."),
                )
                    .into_response();
            }
        }
    } else {
        // Fresh request - extract from query params
        let response_type = match &params.response_type {
            Some(rt) => rt.clone(),
            None => {
                return (StatusCode::BAD_REQUEST, Html("Missing response_type")).into_response();
            }
        };

        if response_type != "code" {
            return (
                StatusCode::BAD_REQUEST,
                Html("Invalid response_type. Only 'code' is supported."),
            )
                .into_response();
        }

        let client_id = match &params.client_id {
            Some(c) => c.clone(),
            None => {
                return (StatusCode::BAD_REQUEST, Html("Missing client_id")).into_response();
            }
        };

        let redirect_uri = match &params.redirect_uri {
            Some(r) => r.clone(),
            None => {
                return (StatusCode::BAD_REQUEST, Html("Missing redirect_uri")).into_response();
            }
        };

        let code_challenge = match &params.code_challenge {
            Some(c) => c.clone(),
            None => {
                return (StatusCode::BAD_REQUEST, Html("Missing code_challenge")).into_response();
            }
        };

        let code_challenge_method = match &params.code_challenge_method {
            Some(m) => m.clone(),
            None => {
                return (StatusCode::BAD_REQUEST, Html("Missing code_challenge_method"))
                    .into_response();
            }
        };

        PendingOAuthRequest {
            client_id,
            redirect_uri,
            code_challenge,
            code_challenge_method,
            state: params.state.clone(),
        }
    };

    // Validate the OAuth request
    if let Err(response) = validate_oauth_params(&state, &oauth_params) {
        return response;
    }

    // Check for valid session
    let _user = match validate_session_from_headers(&headers, &state) {
        Some(u) => u,
        None => {
            // No valid session - store OAuth params and redirect to login
            let pending_id = generate_random_string(32);
            state.storage.store_pending_oauth(pending_id.clone(), oauth_params);

            tracing::info!("No session - redirecting to login");
            return Redirect::to(&format!("{}/login?pending={}", state.path_prefix, pending_id)).into_response();
        }
    };

    // Valid session - issue auth code
    let code = generate_random_string(32);
    let code_hash = hash_token(&code);

    let auth_code = StoredAuthCode {
        code_hash,
        client_id: oauth_params.client_id.clone(),
        redirect_uri: oauth_params.redirect_uri.clone(),
        code_challenge: oauth_params.code_challenge.clone(),
        code_challenge_method: oauth_params.code_challenge_method.clone(),
        expires_at: Utc::now() + Duration::minutes(10),
        created_at: Utc::now(),
    };

    state.storage.store_auth_code(auth_code);

    // Redirect with authorization code
    let mut redirect_url = format!("{}?code={}", oauth_params.redirect_uri, code);
    if let Some(s) = &oauth_params.state {
        redirect_url.push_str(&format!("&state={}", urlencoding::encode(s)));
    }

    tracing::info!(
        "Issued authorization code for client {}",
        oauth_params.client_id
    );

    Redirect::to(&redirect_url).into_response()
}

/// Handler for `POST /authorize`
pub async fn post_handler(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Query(params): Query<AuthorizeRequest>,
) -> Response {
    // Same as GET
    get_handler(State(state), headers, Query(params)).await
}

/// Validate OAuth request parameters
fn validate_oauth_params(
    state: &AppState,
    params: &PendingOAuthRequest,
) -> Result<(), Response> {
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
