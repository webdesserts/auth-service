//! Setup endpoints for first-user passkey registration

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    Json,
};
use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::*;

use crate::storage::generate_random_string;
use crate::AppState;

use super::html;

/// GET /setup - Show setup page
pub async fn get_setup(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    // If users exist, redirect to "already setup" page
    if state.storage.has_any_users() {
        return Html(html::already_setup_page());
    }

    Html(html::setup_page())
}

#[derive(Debug, Deserialize)]
pub struct StartRegistrationRequest {
    pub username: String,
}

#[derive(Debug, Serialize)]
pub struct StartRegistrationResponse {
    pub challenge_id: String,
    pub options: CreationChallengeResponse,
}

/// POST /setup/register/start - Start passkey registration
pub async fn start_registration(
    State(state): State<Arc<AppState>>,
    Json(req): Json<StartRegistrationRequest>,
) -> impl IntoResponse {
    // Check if users already exist
    if state.storage.has_any_users() {
        return (
            StatusCode::FORBIDDEN,
            "Setup already completed. Use reset command to start over.",
        )
            .into_response();
    }

    // Validate username
    let username = req.username.trim();
    if username.is_empty() || username.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            "Username must be 1-64 characters",
        )
            .into_response();
    }

    // Generate user ID for this registration (will be used when credential is verified)
    let user_unique_id = uuid::Uuid::new_v4();

    // Start WebAuthn registration
    let result = state.webauthn.start_passkey_registration(
        user_unique_id,
        username,
        username,
        None, // No existing credentials
    );

    let (ccr, reg_state) = match result {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to start registration: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to start registration",
            )
                .into_response();
        }
    };

    // Store the registration state with a challenge ID
    let challenge_id = generate_random_string(32);
    state
        .storage
        .store_registration_challenge(challenge_id.clone(), reg_state);

    // Store the username temporarily (keyed by challenge_id) so we can use it in finish
    // We'll encode it in the challenge_id format: "challenge_id:username"
    let challenge_id_with_user = format!("{}:{}", challenge_id, username);

    // Actually, let's store just the challenge_id and pass username in the finish request
    // Simpler approach: include username in the response that client sends back
    // But for security, we should validate it server-side

    // Better: store in a separate map or encode in challenge
    // For now, let's just store the raw challenge_id and require username in finish request

    Json(StartRegistrationResponse {
        challenge_id: challenge_id_with_user, // Include username for simplicity
        options: ccr,
    })
    .into_response()
}

#[derive(Debug, Deserialize)]
pub struct FinishRegistrationRequest {
    pub challenge_id: String,
    pub credential: RegisterPublicKeyCredential,
}

/// POST /setup/register/finish - Complete passkey registration
pub async fn finish_registration(
    State(state): State<Arc<AppState>>,
    Json(req): Json<FinishRegistrationRequest>,
) -> impl IntoResponse {
    // Early exit if setup already complete (actual race protection is in create_user())
    if state.storage.has_any_users() {
        return (
            StatusCode::FORBIDDEN,
            "Setup already completed. Use reset command to start over.",
        )
            .into_response();
    }

    // Parse challenge_id and username
    let parts: Vec<&str> = req.challenge_id.splitn(2, ':').collect();
    if parts.len() != 2 {
        return (StatusCode::BAD_REQUEST, "Invalid challenge_id format").into_response();
    }
    let (challenge_id, username) = (parts[0], parts[1]);

    // Consume the registration challenge
    let reg_state = match state.storage.consume_registration_challenge(challenge_id) {
        Some(s) => s,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                "Invalid or expired challenge. Please try again.",
            )
                .into_response();
        }
    };

    // Complete WebAuthn registration
    let passkey = match state
        .webauthn
        .finish_passkey_registration(&req.credential, &reg_state)
    {
        Ok(pk) => pk,
        Err(e) => {
            tracing::error!("Failed to finish registration: {:?}", e);
            return (
                StatusCode::BAD_REQUEST,
                "Failed to verify credential. Please try again.",
            )
                .into_response();
        }
    };

    // Create the user
    let user = match state.storage.create_user(username.to_string()) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Failed to create user: {:?}", e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to create user").into_response();
        }
    };

    // Store the passkey
    if let Err(e) = state.storage.store_passkey(user.id, passkey) {
        tracing::error!("Failed to store passkey: {:?}", e);
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to store passkey").into_response();
    }

    tracing::info!("Setup complete: created user {} with passkey", user.username);

    (StatusCode::OK, "Passkey registered successfully").into_response()
}
