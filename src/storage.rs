//! Persistent storage for users, passkeys, and sessions.

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

/// Storage for users, passkeys, and sessions
pub struct Storage {
    config_path: PathBuf,
    /// Registered users
    users: RwLock<UserStore>,
    /// User passkeys
    passkeys: RwLock<PasskeyStore>,
    /// Active sessions
    sessions: RwLock<SessionStore>,
    /// Runtime-managed API keys (actor-bound, hashed)
    api_keys: RwLock<ApiKeyStore>,
    /// WebAuthn challenge state (in-memory, short-lived)
    webauthn_challenges: RwLock<WebAuthnChallengeStore>,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ApiKeyStore {
    /// Maps key_hash -> stored key
    keys: HashMap<String, StoredApiKey>,
}

/// In-memory WebAuthn challenge state (not persisted)
#[derive(Default)]
struct WebAuthnChallengeStore {
    /// Maps challenge_id -> (state, created_at)
    registration: HashMap<String, (PasskeyRegistration, Instant)>,
    authentication: HashMap<String, (PasskeyAuthentication, Instant)>,
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

/// A runtime-managed API key.
///
/// The raw secret is never stored — only its hash — and lookups compare hashes
/// in constant time. `actor_uuid` binds the key to a registered principal (a
/// `StoredUser`) so `/validate` can emit `X-Auth-Actor` and `/login/key` can
/// mint a session for that principal. A key with no `actor_uuid` authenticates
/// by name only, matching the legacy config-key behavior, and cannot be
/// exchanged for a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredApiKey {
    pub key_hash: String,
    pub actor_uuid: Option<Uuid>,
    pub name: String,
    pub active: bool,
    pub created_at: DateTime<Utc>,
}

impl Storage {
    /// Create a new storage instance
    pub fn new(config_path: &str) -> Result<Self> {
        let config_path = PathBuf::from(config_path);
        std::fs::create_dir_all(&config_path)
            .with_context(|| format!("Failed to create config directory: {:?}", config_path))?;

        let storage = Self {
            config_path: config_path.clone(),
            users: RwLock::new(UserStore::default()),
            passkeys: RwLock::new(PasskeyStore::default()),
            sessions: RwLock::new(SessionStore::default()),
            api_keys: RwLock::new(ApiKeyStore::default()),
            webauthn_challenges: RwLock::new(WebAuthnChallengeStore::default()),
        };

        // Load persisted data
        storage.load_users()?;
        storage.load_passkeys()?;
        storage.load_sessions()?;
        storage.load_api_keys()?;

        // Cleanup expired sessions on startup
        storage.cleanup_expired_sessions();

        Ok(storage)
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

    /// Find a user by username (handle).
    pub fn find_user_by_username(&self, username: &str) -> Option<StoredUser> {
        self.users
            .read()
            .unwrap()
            .users
            .values()
            .find(|u| u.username == username)
            .cloned()
    }

    /// Create a guest user, bypassing the single-user setup gate.
    ///
    /// `create_user` hard-gates on an empty user store — passkey setup is
    /// single-user by design. Guests are additional login-capable principals
    /// minted out-of-band from the shell plane, so they need an insert that does
    /// not consult that gate. This is CLI-only and wired to no HTTP route: it
    /// must never widen the internet-facing self-claim surface that `/setup`
    /// guards.
    ///
    /// The handle becomes the user's username and is charset-restricted to ASCII
    /// letters, digits, and hyphens (autonomy/o:635).
    pub fn create_guest_user(&self, handle: &str) -> Result<StoredUser> {
        validate_handle_charset(handle)?;

        let user = StoredUser {
            id: Uuid::new_v4(),
            username: handle.to_string(),
            created_at: Utc::now(),
        };

        {
            let mut store = self.users.write().unwrap();
            if store.users.values().any(|u| u.username == handle) {
                anyhow::bail!("A user with handle '{}' already exists.", handle);
            }
            store.users.insert(user.id, user.clone());
        }
        self.save_users()?;

        tracing::info!("Created guest user: {} ({})", user.username, user.id);
        Ok(user)
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

    // --- API Key Management ---

    /// Issue a new runtime API key bound to an optional actor uuid.
    ///
    /// Returns the raw key string ONCE; only its hash is persisted, so the raw
    /// key cannot be recovered afterwards. The caller must deliver it securely.
    pub fn issue_api_key(&self, actor_uuid: Option<Uuid>, name: &str) -> Result<String> {
        let raw_key = generate_random_string(43);
        self.insert_api_key(&raw_key, name, actor_uuid)?;
        tracing::info!("Issued API key '{}' (actor: {:?})", name, actor_uuid);
        Ok(raw_key)
    }

    /// Insert a new active key record for a known raw secret.
    fn insert_api_key(&self, raw_key: &str, name: &str, actor_uuid: Option<Uuid>) -> Result<()> {
        let key_hash = hash_token(raw_key);
        let record = StoredApiKey {
            key_hash: key_hash.clone(),
            actor_uuid,
            name: name.to_string(),
            active: true,
            created_at: Utc::now(),
        };
        {
            let mut store = self.api_keys.write().unwrap();
            store.keys.insert(key_hash, record);
        }
        self.save_api_keys()?;
        Ok(())
    }

    /// Revoke a key by its name or its stored hash. Returns whether a matching
    /// active key was revoked.
    ///
    /// Revocation takes effect on the next `/validate` with no restart: the
    /// lookup path (`find_api_key_by_secret`) reloads keys from disk, so a revoke
    /// performed by a separate CLI process is honored immediately by a running
    /// server. This is the runtime-key-lifecycle guarantee.
    pub fn revoke_api_key(&self, identifier: &str) -> Result<bool> {
        // Reflect any keys issued/revoked by a concurrent CLI process first.
        self.load_api_keys()?;
        let revoked = {
            let mut store = self.api_keys.write().unwrap();
            let mut changed = false;
            for key in store.keys.values_mut() {
                if key.active && (key.name == identifier || key.key_hash == identifier) {
                    key.active = false;
                    changed = true;
                }
            }
            changed
        };
        if revoked {
            self.save_api_keys()?;
            tracing::info!("Revoked API key '{}'", identifier);
        }
        Ok(revoked)
    }

    /// Look up an active stored key by its raw secret, comparing hashes in
    /// constant time. Returns a clone of the matching active key, if any.
    ///
    /// Reloads keys from disk first: the CLI issue/revoke subcommands run as
    /// separate processes, so the read path must consult disk rather than a
    /// startup snapshot for a running server to honor them without a restart.
    pub fn find_api_key_by_secret(&self, raw_key: &str) -> Option<StoredApiKey> {
        let _ = self.load_api_keys();
        let candidate_hash = hash_token(raw_key);
        let store = self.api_keys.read().unwrap();
        let mut matched: Option<StoredApiKey> = None;
        for key in store.keys.values() {
            // Constant-time compare guards the hash even though it is already a
            // one-way digest of the secret — defense in depth on an auth
            // boundary. Does not early-exit on a match, so timing does not leak
            // which stored key (if any) matched.
            if key.active && constant_time_eq(key.key_hash.as_bytes(), candidate_hash.as_bytes()) {
                matched = Some(key.clone());
            }
        }
        matched
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
        store
            .registration
            .insert(challenge_id, (state, Instant::now()));
    }

    /// Consume registration challenge (returns and removes it)
    pub fn consume_registration_challenge(
        &self,
        challenge_id: &str,
    ) -> Option<PasskeyRegistration> {
        let mut store = self.webauthn_challenges.write().unwrap();
        store
            .registration
            .remove(challenge_id)
            .and_then(|(state, created)| {
                if created.elapsed() < Self::CHALLENGE_TTL {
                    Some(state)
                } else {
                    None
                }
            })
    }

    /// Store authentication challenge state
    pub fn store_authentication_challenge(
        &self,
        challenge_id: String,
        state: PasskeyAuthentication,
    ) {
        let mut store = self.webauthn_challenges.write().unwrap();
        // Clean up expired challenges
        store
            .authentication
            .retain(|_, (_, created)| created.elapsed() < Self::CHALLENGE_TTL);
        store
            .authentication
            .insert(challenge_id, (state, Instant::now()));
    }

    /// Consume authentication challenge (returns and removes it)
    pub fn consume_authentication_challenge(
        &self,
        challenge_id: &str,
    ) -> Option<PasskeyAuthentication> {
        let mut store = self.webauthn_challenges.write().unwrap();
        store
            .authentication
            .remove(challenge_id)
            .and_then(|(state, created)| {
                if created.elapsed() < Self::CHALLENGE_TTL {
                    Some(state)
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

    fn api_keys_path(&self) -> PathBuf {
        self.config_path.join("api_keys.json")
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

    fn load_api_keys(&self) -> Result<()> {
        let path = self.api_keys_path();
        if path.exists() {
            let content = self.read_with_lock(&path)?;
            let store: ApiKeyStore = serde_json::from_str(&content)?;
            *self.api_keys.write().unwrap() = store;
        }
        // No logging here: this runs on every bearer lookup (see
        // find_api_key_by_secret), so a per-call log line would be noise.
        Ok(())
    }

    fn save_api_keys(&self) -> Result<()> {
        let store = self.api_keys.read().unwrap();
        let content = serde_json::to_string_pretty(&*store)?;
        self.write_with_lock(&self.api_keys_path(), &content)?;
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

    /// Reset all users, passkeys, sessions, and API keys (for recovery).
    ///
    /// API keys are credentials too: leaving them behind after a reset would
    /// let a key still authenticate against a store that no longer has its
    /// principal, so recovery wipes them alongside users and sessions.
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
        {
            let mut api_keys = self.api_keys.write().unwrap();
            api_keys.keys.clear();
        }

        // Delete files
        let _ = std::fs::remove_file(self.users_path());
        let _ = std::fs::remove_file(self.passkeys_path());
        let _ = std::fs::remove_file(self.sessions_path());
        let _ = std::fs::remove_file(self.api_keys_path());

        tracing::info!("Reset all users, passkeys, sessions, and API keys");
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
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let result = hasher.finalize();
    base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, result)
}

/// Constant-time byte-slice equality. Returns false immediately on a length
/// mismatch — length is not secret here, both operands are fixed-width hashes —
/// but never short-circuits on content, so comparison time does not depend on
/// how many leading bytes match.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Validate that a handle contains only ASCII letters, digits, and hyphens
/// (autonomy/o:635). Rejects empty handles and any other character.
fn validate_handle_charset(handle: &str) -> Result<()> {
    if handle.is_empty() {
        anyhow::bail!("Handle must not be empty");
    }
    if !handle
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        anyhow::bail!(
            "Handle '{}' is invalid: only ASCII letters, digits, and hyphens are allowed",
            handle
        );
    }
    Ok(())
}
