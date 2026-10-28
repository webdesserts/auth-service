//! Login endpoints for passkey authentication

use std::sync::Arc;

use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use cookie::{Cookie, SameSite};
use serde::{Deserialize, Serialize};
use url::Url;
use webauthn_rs::prelude::*;

use crate::AppState;
use crate::storage::generate_random_string;

use super::html;

pub const SESSION_COOKIE_NAME: &str = "auth_session";

/// Build the session cookie used by both the passkey login flow and the API
/// key→session exchange (`/login/key`). Shared so the cookie's security
/// attributes (http-only, secure, `SameSite=Lax` for top-level redirects) stay
/// identical across every login path.
pub(crate) fn build_session_cookie(
    session_token: &str,
    lifetime_secs: u64,
    domain: Option<&str>,
) -> Cookie<'static> {
    let mut builder = Cookie::build((SESSION_COOKIE_NAME, session_token.to_string()))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::seconds(lifetime_secs as i64));
    if let Some(domain) = domain {
        builder = builder.domain(domain.trim_start_matches('.').to_string());
    }
    builder.build()
}

pub(crate) fn expired_cookie(domain: Option<&str>) -> Cookie<'static> {
    let mut builder = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(time::Duration::ZERO);
    if let Some(domain) = domain {
        builder = builder.domain(domain.trim_start_matches('.').to_string());
    }
    builder.build()
}

pub(crate) fn session_cookies(state: &AppState, token: &str) -> Vec<Cookie<'static>> {
    let domain = state.config.session.cookie_domain.as_deref();
    let mut cookies = vec![build_session_cookie(
        token,
        state.config.session.session_lifetime_secs,
        domain,
    )];
    // A pre-migration host-only cookie has the same name but different scope.
    // Expire it when we mint the shared cookie so it cannot mask the new login.
    if domain.is_some() {
        cookies.push(expired_cookie(None));
    }
    cookies
}

pub(crate) fn with_cookies(mut response: Response, cookies: Vec<Cookie<'static>>) -> Response {
    for cookie in cookies {
        if let Ok(value) = HeaderValue::from_str(&cookie.to_string()) {
            response.headers_mut().append(header::SET_COOKIE, value);
        }
    }
    response
}

pub(crate) fn session_tokens(headers: &HeaderMap) -> Vec<String> {
    let mut tokens = Vec::new();
    for cookie_header in headers.get_all(header::COOKIE) {
        let Ok(cookie_str) = cookie_header.to_str() else {
            continue;
        };
        for cookie_part in cookie_str.split(';') {
            if let Ok(cookie) = Cookie::parse(cookie_part.trim())
                && cookie.name() == SESSION_COOKIE_NAME
            {
                tokens.push(cookie.value().to_string());
            }
        }
    }
    tokens
}

pub(crate) fn origin_allowed(headers: &HeaderMap, state: &AppState, required: bool) -> bool {
    let Some(origin) = headers.get(header::ORIGIN) else {
        return !required;
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    state
        .config
        .central_origin(&state.public_url)
        .map(|central| origin == central.origin().ascii_serialization())
        .unwrap_or(false)
}

/// Validate a post-login destination with URL parsing and exact host matching.
pub(crate) fn safe_return_to(state: &AppState, raw: Option<&str>) -> String {
    let Some(raw) = raw else {
        return "/".to_string();
    };
    if raw.is_empty()
        || raw.chars().any(|c| c.is_control())
        || raw.contains('\\')
        || raw.starts_with("//")
    {
        return "/".to_string();
    }
    let Ok(central) = state.config.central_origin(&state.public_url) else {
        return "/".to_string();
    };
    let parsed = if raw.starts_with('/') {
        central.join(raw).ok()
    } else {
        Url::parse(raw).ok()
    };
    let Some(mut url) = parsed else {
        return "/".to_string();
    };
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some_and(|port| port != 443)
        || !url.path().starts_with('/')
    {
        return "/".to_string();
    }
    let Some(host) = url.host_str().map(|host| host.to_ascii_lowercase()) else {
        return "/".to_string();
    };
    if !state
        .config
        .allowed_return_hosts(&state.public_url)
        .unwrap_or_default()
        .iter()
        .any(|allowed| allowed == &host)
    {
        return "/".to_string();
    }
    url.set_fragment(None);
    url.to_string()
}

#[derive(Debug, Deserialize)]
pub struct LoginQuery {
    /// Return URL after successful login
    pub return_to: Option<String>,
}

/// GET /login - Show login page
pub async fn get_login(
    State(state): State<Arc<AppState>>,
    Query(query): Query<LoginQuery>,
) -> impl IntoResponse {
    // If no users exist, redirect to setup
    if !state.storage.has_any_users() {
        return Html(html::redirect_page(&format!("{}/setup", state.path_prefix)));
    }

    Html(html::login_page(
        &state.path_prefix,
        query
            .return_to
            .as_deref()
            .map(|raw| safe_return_to(&state, Some(raw)))
            .filter(|safe| safe != "/")
            .as_deref(),
    ))
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
    let passkeys: Vec<Passkey> = stored_passkeys
        .iter()
        .map(|sp| sp.passkey.clone())
        .collect();

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
    headers: HeaderMap,
    Json(req): Json<FinishAuthRequest>,
) -> Response {
    if !origin_allowed(&headers, &state, true) {
        return (StatusCode::FORBIDDEN, "Invalid Origin").into_response();
    }
    // Consume the authentication challenge
    let auth_state = match state
        .storage
        .consume_authentication_challenge(&req.challenge_id)
    {
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
    let (user, mut passkey) = match state
        .storage
        .find_user_by_credential(auth_result.cred_id().as_ref())
    {
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create session",
            )
                .into_response();
        }
    };

    // Determine redirect URL
    let redirect_to = safe_return_to(&state, req.return_to.as_deref());

    tracing::info!("User {} authenticated successfully", user.username);

    // Return response with the shared cookie and, during migration, explicitly
    // expire the old host-only same-name cookie so it cannot mask the new one.
    with_cookies(
        Json(FinishAuthResponse { redirect_to }).into_response(),
        session_cookies(&state, &session_token),
    )
}

/// POST /logout — Clear all presented session variants.
pub async fn logout(State(state): State<Arc<AppState>>, headers: HeaderMap) -> Response {
    // Missing Origin remains accepted for legacy/non-browser logout clients;
    // a present Origin must be the central login origin.
    if !origin_allowed(&headers, &state, false) {
        return (StatusCode::FORBIDDEN, "Invalid Origin").into_response();
    }

    for token in session_tokens(&headers) {
        let _ = state.storage.revoke_session(&token);
    }

    let domain = state.config.session.cookie_domain.as_deref();
    let mut cookies = vec![expired_cookie(domain)];
    if domain.is_some() {
        cookies.push(expired_cookie(None));
    }
    with_cookies("Logged out".into_response(), cookies)
}

/// Helper to validate session from request headers. Try every same-name cookie
/// across all Cookie headers and accept the first valid session.
pub fn validate_session_from_headers(
    headers: &axum::http::HeaderMap,
    state: &AppState,
) -> Option<crate::storage::StoredUser> {
    for token in session_tokens(headers) {
        if let Some(user) = state.storage.validate_session(&token) {
            return Some(user);
        }
    }
    None
}
