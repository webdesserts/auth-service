//! Login endpoints for passkey authentication

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    Json,
};
use cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

use crate::storage::generate_random_string;
use crate::AppState;

use super::html;

pub const SESSION_COOKIE_NAME: &str = "auth_session";

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    /// Return URL after successful login (for OAuth flow)
    pub return_to: Option<String>,
    /// Pending OAuth request ID
    pub pending: Option<String>,
}

/// GET /login - Show login page
pub async fn get_login(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LoginQuery>,
) -> impl IntoResponse {
    // If no users exist, redirect to setup
    if !state.storage.has_any_users() {
        return Html(html::redirect_page("/setup"));
    }

    // Determine the return URL
    let return_to = query
        .pending
        .map(|p| format!("/authorize?pending={}", p))
        .or(query.return_to);

    Html(html::login_page(return_to.as_deref()))
}

#[derive(Debug, Serialize)]
pub struct StartAuthResponse {
    pub challenge_id: String,
    pub options: RequestChallengeResponse,
}

/// POST /login/auth/start - Start passkey authentication
pub async fn start_auth(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // Get all registered passkeys to allow any of them
    let stored_passkeys = state.storage.get_all_passkeys();
    if stored_passkeys.is_empty() {
        return (StatusCode::BAD_REQUEST, "No passkeys registered").into_response();
    }

    // Collect all passkeys for authentication
    let passkeys: Vec<Passkey> = stored_passkeys.iter().map(|sp| sp.passkey.clone()).collect();

    // Start WebAuthn authentication
    let result = state.webauthn.start_passkey_authentication(&passkeys);

    let (rcr, auth_state) = match result {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to start authentication: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to start authentication",
            )
                .into_response();
        }
    };

    // Store the authentication state
    let challenge_id = generate_random_string(32);
    state
        .storage
        .store_authentication_challenge(challenge_id.clone(), auth_state);

    Json(StartAuthResponse {
        challenge_id,
        options: rcr,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct FinishAuthRequest {
    pub challenge_id: String,
    pub credential: PublicKeyCredential,
    pub return_to: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct FinishAuthResponse {
    pub redirect_to: String,
}

/// POST /login/auth/finish - Complete passkey authentication and create session
pub async fn finish_auth(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FinishAuthRequest>,
) -> Response {
    // Consume the authentication challenge
    let auth_state = match state.storage.consume_authentication_challenge(&req.challenge_id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid or expired challenge. Please try again.",
            )
                .into_response();
        }
    };

    // Complete WebAuthn authentication
    let auth_result = match state
        .webauthn
        .finish_passkey_authentication(&req.credential, &auth_state)
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to finish authentication: {:?}", e);
            return (
                StatusCode::UNAUTHORIZED,
                "Authentication failed. Please try again.",
            )
                .into_response();
        }
    };

    // Find the user by credential ID
    let (user, mut passkey) =
        match state.storage.find_user_by_credential(auth_result.cred_id().as_ref()) {
            Some(r) => r,
            None => {
                tracing::error!("Credential not found after successful auth");
                return (StatusCode::INTERNAL_SERVER_ERROR, "User not found").into_response();
            }
        };

    // Update the passkey's counter (important for detecting cloned keys)
    if auth_result.needs_update() {
        passkey.update_credential(&auth_result);
        if let Err(e) = state.storage.update_passkey(&passkey) {
            tracing::warn!("Failed to update passkey counter: {:?}", e);
        }
    }

    // Create a NEW session (session regeneration for security)
    let session_token = match state
        .storage
        .create_session(user.id, state.config.session.session_lifetime_secs)
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to create session: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create session").into_response();
        }
    };

    // Build session cookie
    let cookie = Cookie::build((SESSION_COOKIE_NAME, session_token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax) // Allow on top-level OAuth redirects
        .max_age(time::Duration::seconds(
            state.config.session.session_lifetime_secs as i64,
        ))
        .build();

    // Determine redirect URL
    let redirect_to = req.return_to.unwrap_or_else(|| "/".to_string());

    tracing::info!("User {} authenticated successfully", user.username);

    // Return response with Set-Cookie header
    (
        [(header::SET_COOKIE, cookie.to_string())],
        Json(FinishAuthResponse { redirect_to }),
    )
        .into_response()
}

/// POST /logout - Clear session
pub async fn logout(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Get and revoke session from cookie
    if let Some(cookie_header) = headers.get(header::COOKIE) {
        if let Ok(cookie_str) = cookie_header.to_str() {
            for cookie_part in cookie_str.split(';') {
                if let Ok(cookie) = Cookie::parse(cookie_part.trim()) {
                    if cookie.name() == SESSION_COOKIE_NAME {
                        let _ = state.storage.revoke_session(cookie.value());
                        break;
                    }
                }
            }
        }
    }

    // Clear the cookie
    let cookie = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .max_age(time::Duration::ZERO)
        .build();

    (
        [(header::SET_COOKIE, cookie.to_string())],
        "Logged out",
    )
        .into_response()
}

/// Helper to validate session from request headers
pub fn validate_session_from_headers(
    headers: &axum::http::HeaderMap,
    state: &AppState,
) -> Option<crate::storage::StoredUser> {
    let cookie_header = headers.get(header::COOKIE)?;
    let cookie_str = cookie_header.to_str().ok()?;

    for cookie_part in cookie_str.split(';') {
        if let Ok(cookie) = Cookie::parse(cookie_part.trim()) {
            if cookie.name() == SESSION_COOKIE_NAME {
                return state.storage.validate_session(cookie.value());
            }
        }
    }
    None
}
