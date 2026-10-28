//! Configuration loading and management

use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use url::Url;

/// Main configuration for the auth service
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// API keys that can be used for authentication
    #[serde(default)]
    pub api_keys: Vec<ApiKey>,

    /// WebAuthn configuration
    #[serde(default)]
    pub webauthn: WebAuthnConfig,

    /// Session configuration
    #[serde(default)]
    pub session: SessionConfig,

    /// Browser-facing authentication policy. Explicit exact hosts only.
    #[serde(default)]
    pub auth: AuthConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Exact HTTPS destination hosts accepted for post-login redirects.
    /// The configured central origin host is always included by validation.
    #[serde(default)]
    pub return_hosts: Vec<String>,
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
pub struct WebAuthnConfig {
    /// Relying party ID (domain name). Defaults to the host from AUTH_PUBLIC_URL at startup.
    pub rp_id: Option<String>,

    /// Relying party display name
    #[serde(default = "default_rp_name")]
    pub rp_name: String,

    /// Origin URL (if different from https://{rp_id})
    pub origin: Option<String>,
}

impl Default for WebAuthnConfig {
    fn default() -> Self {
        Self {
            rp_id: None,
            rp_name: default_rp_name(),
            origin: None,
        }
    }
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

    /// Optional shared cookie domain, validated against the central origin host.
    #[serde(default)]
    pub cookie_domain: Option<String>,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            session_lifetime_secs: default_session_lifetime(),
            cookie_secret: None,
            cookie_domain: None,
        }
    }
}

fn default_session_lifetime() -> u64 {
    30 * 24 * 3600 // 30 days
}

fn default_true() -> bool {
    true
}

impl Config {
    /// Validate the browser auth policy against the configured central origin.
    pub fn validate(&self, public_url: &str) -> Result<()> {
        let central = self.central_origin(public_url)?;
        let public = Url::parse(public_url).context("invalid public URL")?;
        if public.scheme() != central.scheme()
            || public.host_str() != central.host_str()
            || public.port_or_known_default() != central.port_or_known_default()
        {
            bail!("AUTH_PUBLIC_URL and WebAuthn origin must share the central origin");
        }
        if let Some(domain) = &self.session.cookie_domain {
            let domain = domain.trim().trim_start_matches('.').to_ascii_lowercase();
            if domain.is_empty()
                || domain.ends_with('.')
                || domain.contains(['/', ':', '\\'])
                || domain.chars().any(|c| c.is_whitespace() || c.is_control())
            {
                bail!("invalid session cookie domain");
            }
            let host = central
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("central origin has no host"))?;
            if domain != host.to_ascii_lowercase() {
                bail!("session cookie domain must equal the central origin host");
            }
        }
        for host in &self.auth.return_hosts {
            validate_exact_host(host)?;
        }
        Ok(())
    }

    /// The canonical scheme/host origin used for login, WebAuthn and cookies.
    pub fn central_origin(&self, public_url: &str) -> Result<Url> {
        let source = match &self.webauthn.origin {
            Some(origin) => origin.as_str(),
            None => public_url,
        };
        let url = Url::parse(source).context("invalid central origin URL")?;
        if url.scheme() != "https" && url.scheme() != "http" {
            bail!("central origin must use http or https");
        }
        if url.host_str().is_none() {
            bail!("central origin must include a host");
        }
        if self.webauthn.origin.is_some() && url.path() != "/" && !url.path().is_empty() {
            bail!("central origin must not include a path");
        }
        let origin = url.origin().ascii_serialization();
        Url::parse(&origin).context("invalid canonical central origin")
    }

    /// Exact destination hosts allowed after login. The central host is implicit.
    pub fn allowed_return_hosts(&self, public_url: &str) -> Result<Vec<String>> {
        let central = self.central_origin(public_url)?;
        let mut hosts = vec![
            central
                .host_str()
                .expect("validated central host")
                .to_ascii_lowercase(),
        ];
        for host in &self.auth.return_hosts {
            let host = validate_exact_host(host)?;
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
        Ok(hosts)
    }

    /// Load configuration from the config directory
    pub fn load(config_path: &str) -> Result<Self> {
        let config_file = Path::new(config_path).join("config.json");

        if config_file.exists() {
            let content = std::fs::read_to_string(&config_file)
                .with_context(|| format!("Failed to read config file: {:?}", config_file))?;
            let config: Config =
                serde_json::from_str(&content).with_context(|| "Failed to parse config.json")?;
            tracing::info!("Loaded configuration from {:?}", config_file);
            Ok(config)
        } else {
            tracing::info!("No config file found at {:?}, using defaults", config_file);
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
}

fn validate_exact_host(host: &str) -> Result<String> {
    let host = host.trim().to_ascii_lowercase();
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.contains(['/', ':', '\\', '*', '@'])
        || host.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        bail!("invalid exact return host");
    }
    Ok(host)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_domain_must_equal_central_origin_host() {
        let mut config = Config::default();
        config.session.cookie_domain = Some("umbra.computer".to_string());
        assert!(config.validate("https://umbra.computer/auth").is_ok());
        config.session.cookie_domain = Some("example.com".to_string());
        assert!(config.validate("https://umbra.computer/auth").is_err());
        config.session.cookie_domain = Some(".umbra.computer".to_string());
        assert!(config.validate("https://umbra.computer/auth").is_ok());
    }

    #[test]
    fn return_hosts_are_exact_not_wildcards() {
        let mut config = Config::default();
        config.auth.return_hosts = vec!["cache-reuse-utils.review.umbra.computer".to_string()];
        assert!(config.validate("https://umbra.computer/auth").is_ok());
        config.auth.return_hosts = vec!["*.umbra.computer".to_string()];
        assert!(config.validate("https://umbra.computer/auth").is_err());
        config.auth.return_hosts = vec!["https://evil.example".to_string()];
        assert!(config.validate("https://umbra.computer/auth").is_err());
    }
}
