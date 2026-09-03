//! Token validation endpoint for Caddy forward_auth
//!
//! This endpoint is called by Caddy before proxying requests to protected services.
//! It validates:
//! - API keys
//! - Passkey session cookies (browser clients)
//!
//! **Every 2xx response unconditionally sets `X-Auth-User`**, identifying the caller.
//! This is a security invariant, not a style choice: Caddy's `forward_auth` +
//! `copy_headers X-Auth-User` relays this header into the proxied request, and
//! Caddy versions before 2.11.2 don't strip a client's own forged copy of a header
//! the backend sometimes omits (GHSA-7r4p-vjf4-gxv4). Always setting the header on
//! every success path closes that gap regardless of the deployed Caddy version.
//!
//! **`X-Auth-Actor` is set conditionally**, only when the winning credential
//! carries a known actor uuid (today: session-cookie logins, via
//! `StoredUser.id`). API keys have no uuid to attach yet (they gain one at
//! t:227), so the header is omitted entirely rather than always-set with an
//! empty/placeholder value — absence maps directly onto
//! `headers.get(...) == None` with no special-casing, unlike a blank
//! sentinel a consumer would have to know to treat as "actually absent".
//! Unlike `X-Auth-User`, this header has no in-app always-set fallback, so
//! its forgery-safety is a live-Caddy-version property: Caddy >=2.11.2's
//! `copy_headers` unconditionally deletes a client-supplied copy of a named
//! header before conditionally setting it from the auth response, so a
//! forged `X-Auth-Actor` on the inbound request is always stripped. Verified
//! against the pinned deployment version in `deploy/t228/verify/`.

use std::sync::Arc;

use axum::{
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use uuid::Uuid;

use crate::AppState;

const X_AUTH_USER: HeaderName = HeaderName::from_static("x-auth-user");
const X_AUTH_ACTOR: HeaderName = HeaderName::from_static("x-auth-actor");

/// Outcome of attempting to authenticate via the `Authorization: Bearer` header
/// (API key).
enum BearerAttempt {
    /// Authenticated; carries the identity to record in `X-Auth-User` and, for
    /// an actor-bound storage key, the uuid to record in `X-Auth-Actor`.
    Success {
        identity: String,
        actor_uuid: Option<Uuid>,
    },
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
    // Cheapest check first: API key bearer token.
    let bearer_attempt = authenticate_bearer(&state, &headers);
    if let BearerAttempt::Success {
        identity,
        actor_uuid,
    } = &bearer_attempt
        && let Some(response) = try_authorized(identity, *actor_uuid)
    {
        return response;
    }

    // Passkey session cookie (browser clients) — tried last since it requires a
    // session-store lookup. Note: falling through to the session cookie here
    // after a Bearer credential was present-but-invalid (revoked/expired
    // token, wrong API key) is intentional, not a bypass — each credential is
    // fully and independently validated; a failed one just doesn't rule out
    // a different, valid one arriving on the same request.
    if let Some(user) = authenticate_session(&state, &headers)
        && let Some(response) = try_authorized(&user.username, Some(user.id))
    {
        return response;
    }

    match bearer_attempt {
        BearerAttempt::Invalid => {
            unauthorized("Bearer error=\"invalid_token\"", "Invalid or expired token")
        }
        BearerAttempt::Absent | BearerAttempt::Success { .. } => {
            unauthorized("Bearer", "Missing or invalid credentials")
        }
    }
}

/// Attempt to authenticate via `Authorization: Bearer <token>` (API key).
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

    // Runtime storage keys (actor-bound, hashed, constant-time compare) win
    // first: they can carry an actor uuid for X-Auth-Actor.
    if let Some(stored) = state.storage.find_api_key_by_secret(token) {
        tracing::debug!("Request authenticated via storage API key {}", stored.name);
        return BearerAttempt::Success {
            identity: stored.name,
            actor_uuid: stored.actor_uuid,
        };
    }

    // Legacy config-file api keys — read-once plaintext fallback, kept so the
    // live config key keeps authenticating unchanged until it is migrated into
    // runtime storage.
    if let Some(api_key) = state.config.find_api_key(token) {
        tracing::debug!("Request authenticated via config API key {}", api_key.name);
        return BearerAttempt::Success {
            identity: api_key.name.clone(),
            actor_uuid: None,
        };
    }

    tracing::debug!("Invalid or expired token");
    BearerAttempt::Invalid
}

/// Attempt to authenticate via the passkey session cookie (browser clients).
fn authenticate_session(
    state: &AppState,
    headers: &HeaderMap,
) -> Option<crate::storage::StoredUser> {
    let user = crate::passkey::validate_session_from_headers(headers, state)?;
    tracing::debug!(
        "Request authenticated via session cookie for user {}",
        user.username
    );
    Some(user)
}

/// Build a 200 response carrying `X-Auth-User` — the mandatory identity-injection
/// invariant — and, when `actor_uuid` is known, `X-Auth-Actor`. See module docs
/// for why the actor header is conditional rather than always-set.
///
/// Returns `None` (refusing to authorize) if `identity` is empty after
/// trimming — e.g. an `ApiKey` with a blank `name` in `config.json`, which
/// nothing validates on load. This is the single chokepoint every credential
/// type funnels through, so the check only needs to exist once: an
/// unidentifiable credential is treated as not authenticated at all, rather
/// than authorized with a blank (or placeholder) `X-Auth-User`. A blank
/// value would still technically satisfy "the header is always present" for
/// the GHSA-7r4p-vjf4-gxv4 mitigation, but it defeats the header's actual
/// purpose — a real caller identity for audit/accountability — so refusing
/// outright is the safer default for an auth boundary. This check is
/// independent of `actor_uuid`, so it never blocks a uuid-less credential
/// (API keys today) from authorizing.
fn try_authorized(identity: &str, actor_uuid: Option<Uuid>) -> Option<Response> {
    if identity.trim().is_empty() {
        tracing::warn!("Refusing to authorize a request with an empty caller identity");
        return None;
    }
    let mut headers = HeaderMap::new();
    headers.insert(X_AUTH_USER, identity_header_value(identity));
    if let Some(uuid) = actor_uuid {
        // Uuid's Display form is a fixed hyphenated-lowercase-hex charset —
        // always a valid HeaderValue, so no sanitization is needed here
        // unlike `identity_header_value` above.
        headers.insert(
            X_AUTH_ACTOR,
            HeaderValue::from_str(&uuid.to_string()).expect("uuid string is a valid header value"),
        );
    }
    Some((StatusCode::OK, headers, "OK").into_response())
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
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();
    HeaderValue::from_str(&sanitized).unwrap_or_else(|_| HeaderValue::from_static("unknown"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ApiKey, Config};
    use crate::storage::Storage;
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
    async fn empty_identity_credential_is_refused_not_authorized_with_blank_header() {
        // A misconfigured API key with a blank `name` — nothing validates
        // this on config.json load — must not produce a 2xx with an empty
        // (or missing-but-still-200) X-Auth-User. It's refused outright.
        let config = Config {
            api_keys: vec![ApiKey {
                key: "test-api-key".to_string(),
                name: "".to_string(),
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

    #[tokio::test]
    async fn session_cookie_success_sets_x_auth_actor_uuid() {
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
        assert_eq!(
            response.headers().get("x-auth-actor").unwrap(),
            user.id.to_string().as_str()
        );
    }

    #[tokio::test]
    async fn api_key_success_omits_x_auth_actor() {
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
        assert!(response.headers().get("x-auth-actor").is_none());
    }

    #[tokio::test]
    async fn revoked_storage_key_is_rejected() {
        let (state, _dir) = test_state(Config::default());
        let actor = Uuid::new_v4();
        let raw_key = state
            .storage
            .issue_api_key(Some(actor), "runtime-key")
            .expect("issue key");

        // An active storage key authenticates and carries its bound actor uuid.
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {raw_key}")).unwrap(),
        );
        let response = handler(State(state.clone()), headers.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-auth-user").unwrap(),
            "runtime-key"
        );
        assert_eq!(
            response.headers().get("x-auth-actor").unwrap(),
            actor.to_string().as_str()
        );

        // Revocation takes effect on the very next request, no restart.
        assert!(state.storage.revoke_api_key("runtime-key").expect("revoke"));
        let response = handler(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get("x-auth-user").is_none());
    }

    #[tokio::test]
    async fn storage_key_without_actor_uuid_omits_x_auth_actor() {
        let (state, _dir) = test_state(Config::default());
        let raw_key = state
            .storage
            .issue_api_key(None, "uuidless-key")
            .expect("issue key");

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {raw_key}")).unwrap(),
        );
        let response = handler(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get("x-auth-user").unwrap(),
            "uuidless-key"
        );
        assert!(response.headers().get("x-auth-actor").is_none());
    }

    #[tokio::test]
    async fn config_api_key_authenticates_via_legacy_fallback() {
        // A config-file key (no storage key present) still authenticates via the
        // legacy read-once fallback. Severing that fallback makes this go red.
        let config = Config {
            api_keys: vec![ApiKey {
                key: "legacy-config-key".to_string(),
                name: "OpenCode".to_string(),
                active: true,
            }],
            ..Config::default()
        };
        let (state, _dir) = test_state(config);

        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_static("Bearer legacy-config-key"),
        );
        let response = handler(State(state), headers).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("x-auth-user").unwrap(), "OpenCode");
        assert!(response.headers().get("x-auth-actor").is_none());
    }
}
