//! Token validation endpoint for Caddy forward_auth
//!
//! This endpoint is called by Caddy before proxying requests to protected services.
//! It validates:
//! - OAuth Bearer tokens
//! - API keys
//! - Passkey session cookies (browser clients)
//!
//! **Every 2xx response unconditionally sets `X-Auth-User`**, identifying the caller.
//! This is a security invariant, not a style choice: Caddy's `forward_auth` +
//! `copy_headers X-Auth-User` relays this header into the proxied request, and
//! Caddy versions before 2.11.2 don't strip a client's own forged copy of a header
//! the backend sometimes omits (GHSA-7r4p-vjf4-gxv4). Always setting the header on
//! every success path closes that gap regardless of the deployed Caddy version.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

use crate::AppState;
use crate::storage::hash_token;

const X_AUTH_USER: HeaderName = HeaderName::from_static("x-auth-user");

/// Outcome of attempting to authenticate via the `Authorization: Bearer` header
/// (API key or OAuth access token).
enum BearerAttempt {
    /// Authenticated; carries the identity to record in `X-Auth-User`.
    Success(String),
    /// A Bearer credential was presented but is invalid or expired.
    Invalid,
    /// No `Authorization: Bearer` credential was present in the request.
    Absent,
}

/// Validation endpoint for Caddy forward_auth
///
/// Returns 200 if the request is authenticated, 401 otherwise.
/// Caddy will proxy the request only if this returns 200.
pub async fn handler(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    // Cheapest checks first: API key / OAuth bearer token.
    let bearer_attempt = authenticate_bearer(&state, &headers);
    if let BearerAttempt::Success(identity) = &bearer_attempt {
        return authorized(identity);
    }

    // Passkey session cookie (browser clients) — tried last since it requires a
    // session-store lookup.
    if let Some(identity) = authenticate_session(&state, &headers) {
        return authorized(&identity);
    }

    match bearer_attempt {
        BearerAttempt::Invalid => unauthorized(
            "Bearer error=\"invalid_token\"",
            "Invalid or expired token",
        ),
        BearerAttempt::Absent | BearerAttempt::Success(_) => {
            unauthorized("Bearer", "Missing or invalid credentials")
        }
    }
}

/// Attempt to authenticate via `Authorization: Bearer <token>` (API key or OAuth
/// access token).
fn authenticate_bearer(state: &AppState, headers: &HeaderMap) -> BearerAttempt {
    let Some(auth_header) = headers.get("authorization") else {
        tracing::debug!("No Authorization header present");
        return BearerAttempt::Absent;
    };

    let Ok(auth_str) = auth_header.to_str() else {
        tracing::debug!("Invalid Authorization header encoding");
        return BearerAttempt::Invalid;
    };

    let Some(token) = auth_str.strip_prefix("Bearer ") else {
        tracing::debug!("Authorization header does not start with 'Bearer '");
        return BearerAttempt::Invalid;
    };
    let token = token.trim();

    // First, check if it's an API key
    if let Some(api_key) = state.config.find_api_key(token) {
        tracing::debug!("Request authenticated via API key {}", api_key.name);
        return BearerAttempt::Success(api_key.name.clone());
    }

    // Otherwise, check if it's a valid OAuth token
    let token_hash = hash_token(token);
    if let Some(stored_token) = state.storage.validate_token(&token_hash)
        && stored_token.token_type == crate::storage::TokenType::Access
    {
        tracing::debug!(
            "Request authenticated via OAuth token for client {}",
            stored_token.client_id
        );
        return BearerAttempt::Success(stored_token.client_id.clone());
    }

    tracing::debug!("Invalid or expired token");
    BearerAttempt::Invalid
}

/// Attempt to authenticate via the passkey session cookie (browser clients).
fn authenticate_session(state: &AppState, headers: &HeaderMap) -> Option<String> {
    let user = crate::passkey::validate_session_from_headers(headers, state)?;
    tracing::debug!(
        "Request authenticated via session cookie for user {}",
        user.username
    );
    Some(user.username)
}

/// Build a 200 response carrying `X-Auth-User` — the mandatory identity-injection
/// invariant. See module docs.
fn authorized(identity: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(X_AUTH_USER, identity_header_value(identity));
    (StatusCode::OK, headers, "OK").into_response()
}

fn unauthorized(www_authenticate: &'static str, body: &'static str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, www_authenticate)],
        body,
    )
        .into_response()
}

/// Build a `HeaderValue` from an identity string, replacing any bytes that would
/// make it an invalid HTTP header value (non-ASCII, control characters) so
/// `X-Auth-User` can always be set on 2xx responses regardless of what a human
/// typed into an API key name or username.
fn identity_header_value(identity: &str) -> HeaderValue {
    let sanitized: String = identity
        .chars()
        .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '_' })
        .collect();
    HeaderValue::from_str(&sanitized).unwrap_or_else(|_| HeaderValue::from_static("unknown"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiKey, Config};
    use crate::storage::{Storage, StoredToken, TokenType};
    use chrono::{Duration, Utc};
    use tempfile::TempDir;
    use webauthn_rs::prelude::*;

    fn build_webauthn() -> Webauthn {
        let rp_origin = Url::parse("http://localhost:3001").unwrap();
        WebauthnBuilder::new("localhost", &rp_origin)
            .unwrap()
            .rp_name("Test")
            .build()
            .unwrap()
    }

    /// Build a real `AppState` backed by a scratch temp directory (dropped, and the
    /// directory removed, when the returned `TempDir` goes out of scope).
    fn test_state(config: Config) -> (Arc<AppState>, TempDir) {
        let dir = TempDir::new().expect("create temp dir");
        let storage = Storage::new(dir.path().to_str().unwrap()).expect("create storage");
        let state = Arc::new(AppState {
            config,
            storage,
            public_url: "http://localhost:3001".to_string(),
            path_prefix: String::new(),
            webauthn: build_webauthn(),
        });
        (state, dir)
    }

    #[tokio::test]
    async fn api_key_success_sets_x_auth_user() {
        let config = Config {
            api_keys: vec![ApiKey {
                key: "test-api-key".to_string(),
                name: "ci-bot".to_string(),
                active: true,
            }],
            ..Config::default()
        };
        let (state, _dir) = test_state(config);

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer test-api-key"),
        );

        let response = handler(State(state), headers).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("x-auth-user").unwrap(), "ci-bot");
    }

    #[tokio::test]
    async fn inactive_api_key_is_rejected() {
        let config = Config {
            api_keys: vec![ApiKey {
                key: "test-api-key".to_string(),
                name: "ci-bot".to_string(),
                active: false,
            }],
            ..Config::default()
        };
        let (state, _dir) = test_state(config);

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer test-api-key"),
        );

        let response = handler(State(state), headers).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get("x-auth-user").is_none());
    }

    #[tokio::test]
    async fn oauth_bearer_success_sets_x_auth_user() {
        let (state, _dir) = test_state(Config::default());

        let raw_token = "raw-access-token";
        let token_hash = hash_token(raw_token);
        state
            .storage
            .store_token(StoredToken {
                token_hash,
                client_id: "test-client".to_string(),
                token_type: TokenType::Access,
                expires_at: Utc::now() + Duration::hours(1),
                created_at: Utc::now(),
                associated_token: None,
            })
            .expect("store token");

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {raw_token}")).unwrap(),
        );

        let response = handler(State(state), headers).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-auth-user").unwrap(),
            "test-client"
        );
    }

    #[tokio::test]
    async fn oauth_refresh_token_is_not_accepted_for_validation() {
        let (state, _dir) = test_state(Config::default());

        let raw_token = "raw-refresh-token";
        let token_hash = hash_token(raw_token);
        state
            .storage
            .store_token(StoredToken {
                token_hash,
                client_id: "test-client".to_string(),
                token_type: TokenType::Refresh,
                expires_at: Utc::now() + Duration::hours(1),
                created_at: Utc::now(),
                associated_token: None,
            })
            .expect("store token");

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {raw_token}")).unwrap(),
        );

        let response = handler(State(state), headers).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get("x-auth-user").is_none());
    }

    #[tokio::test]
    async fn session_cookie_success_sets_x_auth_user() {
        let (state, _dir) = test_state(Config::default());

        let user = state
            .storage
            .create_user("michael".to_string())
            .expect("create user");
        let session_token = state
            .storage
            .create_session(user.id, 3600)
            .expect("create session");

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("auth_session={session_token}")).unwrap(),
        );

        let response = handler(State(state), headers).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("x-auth-user").unwrap(), "michael");
    }

    #[tokio::test]
    async fn invalid_session_cookie_is_rejected() {
        let (state, _dir) = test_state(Config::default());

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("auth_session=not-a-real-session"),
        );

        let response = handler(State(state), headers).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get("x-auth-user").is_none());
    }

    #[tokio::test]
    async fn no_credentials_returns_401_without_x_auth_user() {
        let (state, _dir) = test_state(Config::default());

        let response = handler(State(state), HeaderMap::new()).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get("x-auth-user").is_none());
    }

    #[tokio::test]
    async fn invalid_bearer_token_is_rejected() {
        let (state, _dir) = test_state(Config::default());

        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static("Bearer nope"));

        let response = handler(State(state), headers).await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get("x-auth-user").is_none());
    }
}
