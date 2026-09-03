//! API key → session exchange (`POST /login/key`).
//!
//! Trades an active, actor-bound runtime API key for a session. This is the
//! header-less scripted guest floor: a caller that holds a key but cannot run
//! the WebAuthn passkey ceremony (e.g. a curl session from a clean machine)
//! posts its key here and receives a session it can carry on subsequent
//! requests. Mounted under the ungated `/auth/*` prefix (Caddy path
//! `/auth/login/key`), so it is reachable without an existing session.

use std::sync::Arc;

use axum::{
    Json,
    extract::State,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AppState;
use crate::passkey::login::build_session_cookie;

#[derive(Debug, Deserialize)]
pub struct KeyLoginRequest {
    pub key: String,
}

#[derive(Debug, Serialize)]
pub struct KeyLoginResponse {
    /// The raw session token. Returned in the body for header-less agents; also
    /// set as the `auth_session` cookie for browsers.
    pub session_token: String,
    pub expires_in_secs: u64,
    /// The handle the session is attributed to.
    pub user: String,
    /// The actor uuid the session is bound to.
    pub actor_uuid: Uuid,
}

/// POST /login/key — exchange a runtime API key for a session.
///
/// The presented key must be an active, actor-bound storage key whose principal
/// still resolves to a live user; otherwise nothing is minted and the response
/// is 4xx. This is criterion `login-binds-actor`: an unknown or dead actor is
/// rejected at login, not later.
///
/// On success the session token is returned BOTH as an `auth_session` cookie
/// (for browsers) and in the JSON body (for header-less scripted agents).
pub async fn login_key(
    State(state): State<Arc<AppState>>,
    Json(req): Json<KeyLoginRequest>,
) -> Response {
    let Some(stored) = state.storage.find_api_key_by_secret(req.key.trim()) else {
        return (StatusCode::UNAUTHORIZED, "Invalid or revoked key").into_response();
    };

    let Some(actor_uuid) = stored.actor_uuid else {
        // A key with no bound principal (e.g. a migrated config key) has no
        // actor to attribute a session to, so it cannot be exchanged.
        return (
            StatusCode::FORBIDDEN,
            "Key is not bound to a login-capable principal",
        )
            .into_response();
    };

    // The principal must resolve to a live user before anything is minted.
    let Some(user) = state.storage.get_user(actor_uuid) else {
        return (StatusCode::UNAUTHORIZED, "Key principal no longer exists").into_response();
    };

    let lifetime = state.config.session.session_lifetime_secs;
    let session_token = match state.storage.create_session(user.id, lifetime) {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("Failed to create session for key login: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create session",
            )
                .into_response();
        }
    };

    let cookie = build_session_cookie(&session_token, lifetime);

    tracing::info!(
        "Key login: minted session for {} ({})",
        user.username,
        user.id
    );

    (
        [(header::SET_COOKIE, cookie.to_string())],
        Json(KeyLoginResponse {
            session_token,
            expires_in_secs: lifetime,
            user: user.username,
            actor_uuid,
        }),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::storage::Storage;
    use axum::http::{HeaderMap, HeaderValue, header};
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

    fn test_state(config: Config) -> (Arc<AppState>, TempDir) {
        let dir = TempDir::new().expect("create temp dir");
        let storage = Storage::new(dir.path().to_str().unwrap()).expect("create storage");
        crate::migrate_config_keys(&storage, &config).expect("migrate config keys");
        let state = Arc::new(AppState {
            config,
            storage,
            public_url: "http://localhost:3001".to_string(),
            path_prefix: String::new(),
            webauthn: build_webauthn(),
        });
        (state, dir)
    }

    async fn body_json(response: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("read body");
        serde_json::from_slice(&bytes).expect("parse json body")
    }

    #[tokio::test]
    async fn valid_key_exchanges_for_session_bound_to_actor() {
        let (state, _dir) = test_state(Config::default());
        let guest = state
            .storage
            .create_guest_user("guest")
            .expect("create guest");
        let raw_key = state
            .storage
            .issue_api_key(Some(guest.id), "guest-key")
            .expect("issue key");

        let response = login_key(
            State(state.clone()),
            Json(KeyLoginRequest {
                key: raw_key.clone(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers().get(header::SET_COOKIE).is_some(),
            "browser cookie must be set"
        );

        let json = body_json(response).await;
        let token = json["session_token"].as_str().expect("token in body");
        assert_eq!(
            json["actor_uuid"].as_str().unwrap(),
            guest.id.to_string().as_str()
        );

        // The returned session is valid and resolves to the bound principal.
        let validated = state
            .storage
            .validate_session(token)
            .expect("session valid");
        assert_eq!(validated.id, guest.id);

        // End to end: /validate with that session cookie emits the bound actor.
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_str(&format!("auth_session={token}")).unwrap(),
        );
        let validate = crate::validation::handler(State(state), headers).await;
        assert_eq!(validate.status(), StatusCode::OK);
        assert_eq!(
            validate.headers().get("x-auth-actor").unwrap(),
            guest.id.to_string().as_str()
        );
    }

    #[tokio::test]
    async fn revoked_key_exchange_is_rejected_and_mints_nothing() {
        let (state, dir) = test_state(Config::default());
        let guest = state
            .storage
            .create_guest_user("guest")
            .expect("create guest");
        let raw_key = state
            .storage
            .issue_api_key(Some(guest.id), "guest-key")
            .expect("issue key");
        assert!(state.storage.revoke_api_key("guest-key").expect("revoke"));

        let response = login_key(State(state), Json(KeyLoginRequest { key: raw_key })).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            !dir.path().join("sessions.json").exists(),
            "no session must be minted"
        );
    }

    #[tokio::test]
    async fn key_for_deleted_principal_is_rejected() {
        // A key bound to a uuid with no live StoredUser must not mint a session.
        // Severing the get_user check makes this go red (a session is minted).
        let (state, dir) = test_state(Config::default());
        let orphan_uuid = Uuid::new_v4();
        let raw_key = state
            .storage
            .issue_api_key(Some(orphan_uuid), "orphan-key")
            .expect("issue key");

        let response = login_key(State(state), Json(KeyLoginRequest { key: raw_key })).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(
            !dir.path().join("sessions.json").exists(),
            "no session must be minted for a dead principal"
        );
    }

    #[tokio::test]
    async fn key_without_actor_uuid_cannot_exchange() {
        let (state, dir) = test_state(Config::default());
        let raw_key = state
            .storage
            .issue_api_key(None, "uuidless-key")
            .expect("issue key");

        let response = login_key(State(state), Json(KeyLoginRequest { key: raw_key })).await;
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(!dir.path().join("sessions.json").exists());
    }

    #[tokio::test]
    async fn unknown_key_exchange_is_rejected() {
        let (state, dir) = test_state(Config::default());

        let response = login_key(
            State(state),
            Json(KeyLoginRequest {
                key: "no-such-key".to_string(),
            }),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(!dir.path().join("sessions.json").exists());
    }
}
