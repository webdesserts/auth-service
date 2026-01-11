//! RFC 8414: OAuth 2.0 Authorization Server Metadata
//!
//! Provides the `/.well-known/oauth-authorization-server` endpoint that clients
//! use to discover OAuth endpoints and capabilities.

use std::sync::Arc;

use axum::{extract::State, Json};
use serde::Serialize;

use crate::AppState;

/// OAuth 2.0 Authorization Server Metadata (RFC 8414)
#[derive(Debug, Serialize)]
pub struct AuthorizationServerMetadata {
    /// The authorization server's issuer identifier (URL)
    pub issuer: String,

    /// URL of the authorization endpoint
    pub authorization_endpoint: String,

    /// URL of the token endpoint
    pub token_endpoint: String,

    /// URL of the dynamic client registration endpoint
    pub registration_endpoint: String,

    /// JSON array of OAuth 2.0 response_type values supported
    pub response_types_supported: Vec<String>,

    /// JSON array of OAuth 2.0 grant_type values supported
    pub grant_types_supported: Vec<String>,

    /// JSON array of PKCE code challenge methods supported
    pub code_challenge_methods_supported: Vec<String>,

    /// JSON array of client authentication methods supported at token endpoint
    pub token_endpoint_auth_methods_supported: Vec<String>,
}

/// Handler for `GET /.well-known/oauth-authorization-server`
pub async fn handler(State(state): State<Arc<AppState>>) -> Json<AuthorizationServerMetadata> {
    let base_url = &state.public_url;

    let metadata = AuthorizationServerMetadata {
        issuer: base_url.clone(),
        authorization_endpoint: format!("{}/authorize", base_url),
        token_endpoint: format!("{}/token", base_url),
        registration_endpoint: format!("{}/register", base_url),
        response_types_supported: vec!["code".to_string()],
        grant_types_supported: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        code_challenge_methods_supported: vec!["S256".to_string()],
        token_endpoint_auth_methods_supported: vec!["none".to_string()],
    };

    tracing::debug!("Serving authorization server metadata");
    Json(metadata)
}
