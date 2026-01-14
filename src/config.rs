//! Configuration loading and management

use std::collections::HashSet;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Main configuration for the auth service
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// API keys that can be used for authentication (alternative to OAuth)
    #[serde(default)]
    pub api_keys: Vec<ApiKey>,

    /// Allowed redirect URIs for OAuth clients
    #[serde(default = "default_allowed_redirects")]
    pub allowed_redirect_uris: HashSet<String>,

    /// Token configuration
    #[serde(default)]
    pub tokens: TokenConfig,

    /// WebAuthn configuration
    #[serde(default)]
    pub webauthn: WebAuthnConfig,

    /// Session configuration
    #[serde(default)]
    pub session: SessionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// The API key value (should be a secure random string)
    pub key: String,
    /// Human-readable name for this key
    pub name: String,
    /// Whether this key is active
    #[serde(default = "default_true")]
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenConfig {
    /// Access token lifetime in seconds (default: 1 hour)
    #[serde(default = "default_access_token_lifetime")]
    pub access_token_lifetime_secs: u64,

    /// Refresh token lifetime in seconds (default: 30 days)
    #[serde(default = "default_refresh_token_lifetime")]
    pub refresh_token_lifetime_secs: u64,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            access_token_lifetime_secs: default_access_token_lifetime(),
            refresh_token_lifetime_secs: default_refresh_token_lifetime(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnConfig {
    /// Relying party ID (domain name, e.g. "leda.webdesserts.com")
    #[serde(default = "default_rp_id")]
    pub rp_id: String,

    /// Relying party display name
    #[serde(default = "default_rp_name")]
    pub rp_name: String,

    /// Origin URL (if different from https://{rp_id})
    pub origin: Option<String>,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_id: default_rp_id(),
            rp_name: default_rp_name(),
            origin: None,
        }
    }
}

fn default_rp_id() -> String {
    "leda.webdesserts.com".to_string()
}

fn default_rp_name() -> String {
    "Obsidian Memory".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    /// Session lifetime in seconds (default: 30 days)
    #[serde(default = "default_session_lifetime")]
    pub session_lifetime_secs: u64,

    /// Cookie signing secret (32+ bytes, hex-encoded)
    /// If not set, a random key is generated at startup (sessions won't survive restarts)
    pub cookie_secret: Option<String>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            session_lifetime_secs: default_session_lifetime(),
            cookie_secret: None,
        }
    }
}

fn default_session_lifetime() -> u64 {
    30 * 24 * 3600 // 30 days
}

fn default_true() -> bool {
    true
}

fn default_access_token_lifetime() -> u64 {
    3600 // 1 hour
}

fn default_refresh_token_lifetime() -> u64 {
    30 * 24 * 3600 // 30 days
}

fn default_allowed_redirects() -> HashSet<String> {
    let mut set = HashSet::new();
    // Claude MCP OAuth callbacks
    set.insert("https://claude.ai/api/mcp/auth_callback".to_string());
    set.insert("https://claude.ai/callback".to_string());
    set.insert("https://claude.com/callback".to_string());
    set
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_keys: Vec::new(),
            allowed_redirect_uris: default_allowed_redirects(),
            tokens: TokenConfig::default(),
            webauthn: WebAuthnConfig::default(),
            session: SessionConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from the config directory
    pub fn load(config_path: &str) -> Result<Self> {
        let config_file = Path::new(config_path).join("config.json");

        if config_file.exists() {
            let content = std::fs::read_to_string(&config_file)
                .with_context(|| format!("Failed to read config file: {:?}", config_file))?;
            let config: Config = serde_json::from_str(&content)
                .with_context(|| "Failed to parse config.json")?;
            tracing::info!("Loaded configuration from {:?}", config_file);
            Ok(config)
        } else {
            tracing::info!(
                "No config file found at {:?}, using defaults",
                config_file
            );
            let config = Config::default();

            // Create config directory if it doesn't exist
            std::fs::create_dir_all(config_path)
                .with_context(|| format!("Failed to create config directory: {}", config_path))?;

            // Write default config for reference
            let content = serde_json::to_string_pretty(&config)?;
            std::fs::write(&config_file, content)
                .with_context(|| format!("Failed to write default config: {:?}", config_file))?;
            tracing::info!("Created default config at {:?}", config_file);

            Ok(config)
        }
    }

    /// Check if an API key is valid
    pub fn validate_api_key(&self, key: &str) -> bool {
        self.api_keys
            .iter()
            .any(|k| k.active && k.key == key)
    }

    /// Check if a redirect URI is allowed
    pub fn is_redirect_allowed(&self, uri: &str) -> bool {
        self.allowed_redirect_uris.contains(uri)
    }
}
