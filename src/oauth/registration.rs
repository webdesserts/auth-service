//! RFC 7591: OAuth 2.0 Dynamic Client Registration
//!
//! Allows clients (like Claude iOS) to register themselves automatically
//! without manual configuration.

use std::sync::Arc;

use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::storage::{generate_random_string, RegisteredClient};
use crate::AppState;

/// Client registration request (RFC 7591 Section 2)
#[derive(Debug, Deserialize)]
pub struct RegistrationRequest {
    /// Array of redirect URIs for this client
    pub redirect_uris: Vec<String>,

    /// Human-readable name for this client
    #[serde(default)]
    pub client_name: Option<String>,

    /// Type of client (we only support "public" for now, but accept per RFC 7591)
    #[serde(default)]
    #[allow(dead_code)]
    pub token_endpoint_auth_method: Option<String>,

    /// Grant types this client will use (accepted per RFC 7591)
    #[serde(default)]
    #[allow(dead_code)]
    pub grant_types: Option<Vec<String>>,

    /// Response types this client will use (accepted per RFC 7591)
    #[serde(default)]
    #[allow(dead_code)]
    pub response_types: Option<Vec<String>>,
}

/// Client registration response (RFC 7591 Section 3.2.1)
#[derive(Debug, Serialize)]
pub struct RegistrationResponse {
    /// Unique client identifier
    pub client_id: String,

    /// Client secret (null for public clients)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    /// Time at which the client was registered
    pub client_id_issued_at: i64,

    /// The registered redirect URIs
    pub redirect_uris: Vec<String>,

    /// Human-readable client name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    /// Token endpoint auth method
    pub token_endpoint_auth_method: String,

    /// Grant types
    pub grant_types: Vec<String>,

    /// Response types
    pub response_types: Vec<String>,
}

/// Error response for registration failures
#[derive(Debug, Serialize)]
pub struct RegistrationError {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<String>,
}

/// Handler for `POST /register`
pub async fn handler(
    State(state): State<Arc<AppState>>,
    Json(request): Json<RegistrationRequest>,
) -> impl IntoResponse {
    tracing::info!(
        "Client registration request: name={:?}, redirect_uris={:?}",
        request.client_name,
        request.redirect_uris
    );

    // Validate redirect URIs
    if request.redirect_uris.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(RegistrationError {
                error: "invalid_redirect_uri".to_string(),
                error_description: Some("At least one redirect_uri is required".to_string()),
            }),
        )
            .into_response();
    }

    // Check each redirect URI against allowed list
    for uri in &request.redirect_uris {
        if !state.config.is_redirect_allowed(uri) {
            tracing::warn!("Rejected registration with disallowed redirect URI: {}", uri);
            return (
                StatusCode::BAD_REQUEST,
                Json(RegistrationError {
                    error: "invalid_redirect_uri".to_string(),
                    error_description: Some(format!("Redirect URI not allowed: {}", uri)),
                }),
            )
                .into_response();
        }
    }

    // Generate client ID
    let client_id = format!("client_{}", generate_random_string(24));
    let now = Utc::now();

    // Create registered client
    let client = RegisteredClient {
        client_id: client_id.clone(),
        client_name: request.client_name.clone(),
        redirect_uris: request.redirect_uris.clone(),
        created_at: now,
    };

    // Store the client
    if let Err(e) = state.storage.register_client(client) {
        tracing::error!("Failed to store registered client: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(RegistrationError {
                error: "server_error".to_string(),
                error_description: Some("Failed to register client".to_string()),
            }),
        )
            .into_response();
    }

    tracing::info!("Registered new client: {} ({:?})", client_id, request.client_name);

    // Return registration response
    let response = RegistrationResponse {
        client_id,
        client_secret: None, // Public client
        client_id_issued_at: now.timestamp(),
        redirect_uris: request.redirect_uris,
        client_name: request.client_name,
        token_endpoint_auth_method: "none".to_string(),
        grant_types: vec!["authorization_code".to_string(), "refresh_token".to_string()],
        response_types: vec!["code".to_string()],
    };

    (StatusCode::CREATED, Json(response)).into_response()
}
