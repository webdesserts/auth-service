//! Persistent storage for OAuth clients, tokens, authorization codes,
//! users, passkeys, and sessions.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use webauthn_rs::prelude::*;

/// Storage for OAuth data, users, passkeys, and sessions
pub struct Storage {
    config_path: PathBuf,
    /// Registered OAuth clients
    clients: RwLock<ClientStore>,
    /// Active access tokens
    tokens: RwLock<TokenStore>,
    /// Pending authorization codes (in-memory, short-lived)
    auth_codes: RwLock<AuthCodeStore>,
    /// Registered users
    users: RwLock<UserStore>,
    /// User passkeys
    passkeys: RwLock<PasskeyStore>,
    /// Active sessions
    sessions: RwLock<SessionStore>,
    /// WebAuthn challenge state (in-memory, short-lived)
    webauthn_challenges: RwLock<WebAuthnChallengeStore>,
    /// Pending OAuth requests (in-memory, preserved through login redirect)
    pending_oauth: RwLock<PendingOAuthStore>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ClientStore {
    clients: HashMap<String, RegisteredClient>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TokenStore {
    /// Maps token hash -> token data
    tokens: HashMap<String, StoredToken>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct AuthCodeStore {
    /// Maps code hash -> auth code data (short-lived)
    codes: HashMap<String, StoredAuthCode>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct UserStore {
    /// Maps user_id -> user data
    users: HashMap<Uuid, StoredUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PasskeyStore {
    /// Maps credential_id (base64) -> passkey data
    passkeys: HashMap<String, StoredPasskey>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct SessionStore {
    /// Maps session_hash -> session data
    sessions: HashMap<String, StoredSession>,
}

/// In-memory WebAuthn challenge state (not persisted)
#[derive(Default)]
struct WebAuthnChallengeStore {
    /// Maps challenge_id -> (state, created_at)
    registration: HashMap<String, (PasskeyRegistration, Instant)>,
    authentication: HashMap<String, (PasskeyAuthentication, Instant)>,
}

/// In-memory pending OAuth requests (not persisted)
#[derive(Default)]
struct PendingOAuthStore {
    /// Maps pending_id -> (params, created_at)
    requests: HashMap<String, (PendingOAuthRequest, Instant)>,
}

/// A registered OAuth client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredClient {
    pub client_id: String,
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub created_at: DateTime<Utc>,
}

/// A stored access/refresh token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredToken {
    pub token_hash: String,
    pub client_id: String,
    pub token_type: TokenType,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    /// For refresh tokens, the associated access token hash
    pub associated_token: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenType {
    Access,
    Refresh,
}

/// A pending authorization code
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredAuthCode {
    pub code_hash: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// A registered user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredUser {
    pub id: Uuid,
    pub username: String,
    pub created_at: DateTime<Utc>,
}

/// A stored passkey credential
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPasskey {
    pub credential_id: String,
    pub user_id: Uuid,
    pub passkey: Passkey,
    pub created_at: DateTime<Utc>,
}

/// A user session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSession {
    pub session_hash: String,
    pub user_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

/// Pending OAuth request (preserved through login redirect)
#[derive(Debug, Clone)]
pub struct PendingOAuthRequest {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub state: Option<String>,
}

impl Storage {
    /// Create a new storage instance
    pub fn new(config_path: &str) -> Result<Self> {
        let config_path = PathBuf::from(config_path);
        std::fs::create_dir_all(&config_path)
            .with_context(|| format!("Failed to create config directory: {:?}", config_path))?;

        let storage = Self {
            config_path: config_path.clone(),
            clients: RwLock::new(ClientStore::default()),
            tokens: RwLock::new(TokenStore::default()),
            auth_codes: RwLock::new(AuthCodeStore::default()),
            users: RwLock::new(UserStore::default()),
            passkeys: RwLock::new(PasskeyStore::default()),
            sessions: RwLock::new(SessionStore::default()),
            webauthn_challenges: RwLock::new(WebAuthnChallengeStore::default()),
            pending_oauth: RwLock::new(PendingOAuthStore::default()),
        };

        // Load persisted data
        storage.load_clients()?;
        storage.load_tokens()?;
        storage.load_users()?;
        storage.load_passkeys()?;
        storage.load_sessions()?;

        // Cleanup expired sessions on startup
        storage.cleanup_expired_sessions();

        Ok(storage)
    }

    // --- Client Management ---

    /// Register a new OAuth client
    pub fn register_client(&self, client: RegisteredClient) -> Result<()> {
        {
            let mut store = self.clients.write().unwrap();
            store.clients.insert(client.client_id.clone(), client);
        }
        self.save_clients()?;
        Ok(())
    }

    /// Get a registered client by ID
    pub fn get_client(&self, client_id: &str) -> Option<RegisteredClient> {
        let store = self.clients.read().unwrap();
        store.clients.get(client_id).cloned()
    }

    // --- Token Management ---

    /// Store a new token
    pub fn store_token(&self, token: StoredToken) -> Result<()> {
        {
            let mut store = self.tokens.write().unwrap();
            store.tokens.insert(token.token_hash.clone(), token);
        }
        self.save_tokens()?;
        Ok(())
    }

    /// Validate and get a token by its hash
    pub fn validate_token(&self, token_hash: &str) -> Option<StoredToken> {
        let store = self.tokens.read().unwrap();
        store.tokens.get(token_hash).and_then(|t| {
            if t.expires_at > Utc::now() {
                Some(t.clone())
            } else {
                None
            }
        })
    }

    /// Revoke a token by its hash
    pub fn revoke_token(&self, token_hash: &str) -> Result<bool> {
        let removed = {
            let mut store = self.tokens.write().unwrap();
            store.tokens.remove(token_hash).is_some()
        };
        if removed {
            self.save_tokens()?;
        }
        Ok(removed)
    }

    // --- Authorization Code Management ---

    /// Store a new authorization code
    pub fn store_auth_code(&self, code: StoredAuthCode) {
        let mut store = self.auth_codes.write().unwrap();
        store.codes.insert(code.code_hash.clone(), code);
        // Auth codes are short-lived and not persisted
    }

    /// Consume an authorization code (returns and removes it)
    pub fn consume_auth_code(&self, code_hash: &str) -> Option<StoredAuthCode> {
        let mut store = self.auth_codes.write().unwrap();
        store.codes.remove(code_hash).and_then(|c| {
            if c.expires_at > Utc::now() {
                Some(c)
            } else {
                None
            }
        })
    }

    // --- Persistence ---

    fn clients_path(&self) -> PathBuf {
        self.config_path.join("clients.json")
    }

    fn tokens_path(&self) -> PathBuf {
        self.config_path.join("tokens.json")
    }

    fn load_clients(&self) -> Result<()> {
        let path = self.clients_path();
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let store: ClientStore = serde_json::from_str(&content)?;
            *self.clients.write().unwrap() = store;
            tracing::info!("Loaded {} registered clients", self.clients.read().unwrap().clients.len());
        }
        Ok(())
    }

    fn save_clients(&self) -> Result<()> {
        let store = self.clients.read().unwrap();
        let content = serde_json::to_string_pretty(&*store)?;
        std::fs::write(self.clients_path(), content)?;
        Ok(())
    }

    fn load_tokens(&self) -> Result<()> {
        let path = self.tokens_path();
        if path.exists() {
            let content = std::fs::read_to_string(&path)?;
            let mut store: TokenStore = serde_json::from_str(&content)?;

            // Clean up expired tokens on load
            let now = Utc::now();
            store.tokens.retain(|_, t| t.expires_at > now);

            *self.tokens.write().unwrap() = store;
            tracing::info!("Loaded {} active tokens", self.tokens.read().unwrap().tokens.len());
        }
        Ok(())
    }

    fn save_tokens(&self) -> Result<()> {
        let store = self.tokens.read().unwrap();
        let content = serde_json::to_string_pretty(&*store)?;
        std::fs::write(self.tokens_path(), content)?;
        Ok(())
    }

    /// Clean up expired tokens and auth codes
    pub fn cleanup_expired(&self) -> Result<()> {
        let now = Utc::now();

        // Clean tokens
        {
            let mut store = self.tokens.write().unwrap();
            let before = store.tokens.len();
            store.tokens.retain(|_, t| t.expires_at > now);
            let after = store.tokens.len();
            if before != after {
                tracing::info!("Cleaned up {} expired tokens", before - after);
            }
        }
        self.save_tokens()?;

        // Clean auth codes
        {
            let mut store = self.auth_codes.write().unwrap();
            store.codes.retain(|_, c| c.expires_at > now);
        }

        Ok(())
    }

    // --- User Management ---

    /// Check if any users exist
    pub fn has_any_users(&self) -> bool {
        !self.users.read().unwrap().users.is_empty()
    }

    /// Create a new user (only if no users exist)
    pub fn create_user(&self, username: String) -> Result<StoredUser> {
        let user = StoredUser {
            id: Uuid::new_v4(),
            username,
            created_at: Utc::now(),
        };

        {
            let mut store = self.users.write().unwrap();

            // Atomic check inside the lock - prevents TOCTOU race condition
            // where two concurrent registrations both pass has_any_users() check
            if !store.users.is_empty() {
                anyhow::bail!("A user already exists. Setup is complete.");
            }

            store.users.insert(user.id, user.clone());
        }
        self.save_users()?;

        tracing::info!("Created new user: {} ({})", user.username, user.id);
        Ok(user)
    }

    /// Get a user by ID
    pub fn get_user(&self, user_id: Uuid) -> Option<StoredUser> {
        self.users.read().unwrap().users.get(&user_id).cloned()
    }

    // --- Passkey Management ---

    /// Store a new passkey for a user
    pub fn store_passkey(&self, user_id: Uuid, passkey: Passkey) -> Result<()> {
        let credential_id = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            passkey.cred_id().as_ref(),
        );

        let stored = StoredPasskey {
            credential_id: credential_id.clone(),
            user_id,
            passkey,
            created_at: Utc::now(),
        };

        {
            let mut store = self.passkeys.write().unwrap();
            store.passkeys.insert(credential_id, stored);
        }
        self.save_passkeys()?;

        tracing::info!("Stored new passkey for user {}", user_id);
        Ok(())
    }

    /// Get all passkeys for a user
    pub fn get_passkeys_for_user(&self, user_id: Uuid) -> Vec<Passkey> {
        self.passkeys
            .read()
            .unwrap()
            .passkeys
            .values()
            .filter(|p| p.user_id == user_id)
            .map(|p| p.passkey.clone())
            .collect()
    }

    /// Get all passkeys (for authentication flow where we don't know the user yet)
    pub fn get_all_passkeys(&self) -> Vec<StoredPasskey> {
        self.passkeys
            .read()
            .unwrap()
            .passkeys
            .values()
            .cloned()
            .collect()
    }

    /// Find user by credential ID (for authentication)
    pub fn find_user_by_credential(&self, credential_id: &[u8]) -> Option<(StoredUser, Passkey)> {
        let cred_id_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            credential_id,
        );

        let store = self.passkeys.read().unwrap();
        if let Some(stored) = store.passkeys.get(&cred_id_b64) {
            let user = self.get_user(stored.user_id)?;
            Some((user, stored.passkey.clone()))
        } else {
            None
        }
    }

    /// Update passkey (for sign count updates)
    pub fn update_passkey(&self, passkey: &Passkey) -> Result<()> {
        let credential_id = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            passkey.cred_id().as_ref(),
        );

        {
            let mut store = self.passkeys.write().unwrap();
            if let Some(stored) = store.passkeys.get_mut(&credential_id) {
                stored.passkey = passkey.clone();
            }
        }
        self.save_passkeys()?;
        Ok(())
    }

    // --- Session Management ---

    /// Create a new session for a user (returns raw session token)
    pub fn create_session(&self, user_id: Uuid, lifetime_secs: u64) -> Result<String> {
        let session_token = generate_random_string(64);
        let session_hash = hash_token(&session_token);

        let session = StoredSession {
            session_hash: session_hash.clone(),
            user_id,
            expires_at: Utc::now() + chrono::Duration::seconds(lifetime_secs as i64),
            created_at: Utc::now(),
        };

        {
            let mut store = self.sessions.write().unwrap();
            store.sessions.insert(session_hash, session);
        }
        self.save_sessions()?;

        tracing::info!("Created new session for user {}", user_id);
        Ok(session_token)
    }

    /// Validate a session token and return the associated user
    pub fn validate_session(&self, session_token: &str) -> Option<StoredUser> {
        let session_hash = hash_token(session_token);

        let session = {
            let store = self.sessions.read().unwrap();
            store.sessions.get(&session_hash).cloned()
        };

        if let Some(session) = session {
            if session.expires_at > Utc::now() {
                return self.get_user(session.user_id);
            } else {
                // Lazy cleanup of expired session
                let _ = self.revoke_session_by_hash(&session_hash);
            }
        }
        None
    }

    /// Revoke a session by its token
    pub fn revoke_session(&self, session_token: &str) -> Result<bool> {
        let session_hash = hash_token(session_token);
        self.revoke_session_by_hash(&session_hash)
    }

    fn revoke_session_by_hash(&self, session_hash: &str) -> Result<bool> {
        let removed = {
            let mut store = self.sessions.write().unwrap();
            store.sessions.remove(session_hash).is_some()
        };
        if removed {
            self.save_sessions()?;
        }
        Ok(removed)
    }

    /// Clean up expired sessions
    fn cleanup_expired_sessions(&self) {
        let now = Utc::now();
        let mut store = self.sessions.write().unwrap();
        let before = store.sessions.len();
        store.sessions.retain(|_, s| s.expires_at > now);
        let after = store.sessions.len();
        if before != after {
            tracing::info!("Cleaned up {} expired sessions", before - after);
        }
    }

    // --- WebAuthn Challenge Management (in-memory, short-lived) ---

    const CHALLENGE_TTL: Duration = Duration::from_secs(300); // 5 minutes

    /// Store registration challenge state
    pub fn store_registration_challenge(&self, challenge_id: String, state: PasskeyRegistration) {
        let mut store = self.webauthn_challenges.write().unwrap();
        // Clean up expired challenges
        store
            .registration
            .retain(|_, (_, created)| created.elapsed() < Self::CHALLENGE_TTL);
        store.registration.insert(challenge_id, (state, Instant::now()));
    }

    /// Consume registration challenge (returns and removes it)
    pub fn consume_registration_challenge(&self, challenge_id: &str) -> Option<PasskeyRegistration> {
        let mut store = self.webauthn_challenges.write().unwrap();
        store.registration.remove(challenge_id).and_then(|(state, created)| {
            if created.elapsed() < Self::CHALLENGE_TTL {
                Some(state)
            } else {
                None
            }
        })
    }

    /// Store authentication challenge state
    pub fn store_authentication_challenge(&self, challenge_id: String, state: PasskeyAuthentication) {
        let mut store = self.webauthn_challenges.write().unwrap();
        // Clean up expired challenges
        store
            .authentication
            .retain(|_, (_, created)| created.elapsed() < Self::CHALLENGE_TTL);
        store.authentication.insert(challenge_id, (state, Instant::now()));
    }

    /// Consume authentication challenge (returns and removes it)
    pub fn consume_authentication_challenge(&self, challenge_id: &str) -> Option<PasskeyAuthentication> {
        let mut store = self.webauthn_challenges.write().unwrap();
        store.authentication.remove(challenge_id).and_then(|(state, created)| {
            if created.elapsed() < Self::CHALLENGE_TTL {
                Some(state)
            } else {
                None
            }
        })
    }

    // --- Pending OAuth Request Management (in-memory, short-lived) ---

    const PENDING_OAUTH_TTL: Duration = Duration::from_secs(300); // 5 minutes

    /// Store pending OAuth request (for preserving params through login redirect)
    pub fn store_pending_oauth(&self, pending_id: String, request: PendingOAuthRequest) {
        let mut store = self.pending_oauth.write().unwrap();
        // Clean up expired requests
        store
            .requests
            .retain(|_, (_, created)| created.elapsed() < Self::PENDING_OAUTH_TTL);
        store.requests.insert(pending_id, (request, Instant::now()));
    }

    /// Consume pending OAuth request (returns and removes it)
    pub fn consume_pending_oauth(&self, pending_id: &str) -> Option<PendingOAuthRequest> {
        let mut store = self.pending_oauth.write().unwrap();
        store.requests.remove(pending_id).and_then(|(req, created)| {
            if created.elapsed() < Self::PENDING_OAUTH_TTL {
                Some(req)
            } else {
                None
            }
        })
    }

    // --- Additional Persistence Paths ---

    fn users_path(&self) -> PathBuf {
        self.config_path.join("users.json")
    }

    fn passkeys_path(&self) -> PathBuf {
        self.config_path.join("passkeys.json")
    }

    fn sessions_path(&self) -> PathBuf {
        self.config_path.join("sessions.json")
    }

    // --- User/Passkey/Session Persistence (with file locking) ---

    fn load_users(&self) -> Result<()> {
        let path = self.users_path();
        if path.exists() {
            let content = self.read_with_lock(&path)?;
            let store: UserStore = serde_json::from_str(&content)?;
            *self.users.write().unwrap() = store;
            tracing::info!("Loaded {} users", self.users.read().unwrap().users.len());
        }
        Ok(())
    }

    fn save_users(&self) -> Result<()> {
        let store = self.users.read().unwrap();
        let content = serde_json::to_string_pretty(&*store)?;
        self.write_with_lock(&self.users_path(), &content)?;
        Ok(())
    }

    fn load_passkeys(&self) -> Result<()> {
        let path = self.passkeys_path();
        if path.exists() {
            let content = self.read_with_lock(&path)?;
            let store: PasskeyStore = serde_json::from_str(&content)?;
            *self.passkeys.write().unwrap() = store;
            tracing::info!(
                "Loaded {} passkeys",
                self.passkeys.read().unwrap().passkeys.len()
            );
        }
        Ok(())
    }

    fn save_passkeys(&self) -> Result<()> {
        let store = self.passkeys.read().unwrap();
        let content = serde_json::to_string_pretty(&*store)?;
        self.write_with_lock(&self.passkeys_path(), &content)?;
        Ok(())
    }

    fn load_sessions(&self) -> Result<()> {
        let path = self.sessions_path();
        if path.exists() {
            let content = self.read_with_lock(&path)?;
            let mut store: SessionStore = serde_json::from_str(&content)?;

            // Clean up expired sessions on load
            let now = Utc::now();
            store.sessions.retain(|_, s| s.expires_at > now);

            *self.sessions.write().unwrap() = store;
            tracing::info!(
                "Loaded {} active sessions",
                self.sessions.read().unwrap().sessions.len()
            );
        }
        Ok(())
    }

    fn save_sessions(&self) -> Result<()> {
        let store = self.sessions.read().unwrap();
        let content = serde_json::to_string_pretty(&*store)?;
        self.write_with_lock(&self.sessions_path(), &content)?;
        Ok(())
    }

    /// Read file with exclusive lock
    fn read_with_lock(&self, path: &PathBuf) -> Result<String> {
        let file = File::open(path)?;
        file.lock_shared()?;
        let mut content = String::new();
        (&file).read_to_string(&mut content)?;
        file.unlock()?;
        Ok(content)
    }

    /// Write file with exclusive lock (atomic via temp file)
    fn write_with_lock(&self, path: &PathBuf, content: &str) -> Result<()> {
        let temp_path = path.with_extension("json.tmp");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&temp_path)?;
        file.lock_exclusive()?;
        (&file).write_all(content.as_bytes())?;
        file.sync_all()?;
        file.unlock()?;
        std::fs::rename(&temp_path, path)?;
        Ok(())
    }

    /// Reset all users, passkeys, and sessions (for recovery)
    pub fn reset_auth(&self) -> Result<()> {
        // Clear in-memory state
        {
            let mut users = self.users.write().unwrap();
            users.users.clear();
        }
        {
            let mut passkeys = self.passkeys.write().unwrap();
            passkeys.passkeys.clear();
        }
        {
            let mut sessions = self.sessions.write().unwrap();
            sessions.sessions.clear();
        }

        // Delete files
        let _ = std::fs::remove_file(self.users_path());
        let _ = std::fs::remove_file(self.passkeys_path());
        let _ = std::fs::remove_file(self.sessions_path());

        tracing::info!("Reset all users, passkeys, and sessions");
        Ok(())
    }
}

// --- Utility Functions ---

/// Generate a cryptographically secure random string
pub fn generate_random_string(len: usize) -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rng();
    (0..len)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

/// Hash a token/code for storage (we don't store raw tokens)
pub fn hash_token(token: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, result)
}
