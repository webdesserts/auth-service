//! Persistent storage for OAuth clients, tokens, and authorization codes

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::RwLock;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Storage for OAuth data
pub struct Storage {
    config_path: PathBuf,
    /// Registered OAuth clients
    clients: RwLock<ClientStore>,
    /// Active access tokens
    tokens: RwLock<TokenStore>,
    /// Pending authorization codes
    auth_codes: RwLock<AuthCodeStore>,
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
        };

        // Load persisted data
        storage.load_clients()?;
        storage.load_tokens()?;

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
