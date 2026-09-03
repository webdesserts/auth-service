//! API key authentication service for obsidian-memory
//!
//! Provides:
//! - API key validation
//! - Caddy forward_auth integration
//! - WebAuthn passkey authentication

mod config;
mod key_login;
mod passkey;
mod storage;
mod validation;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Router,
    routing::{get, post},
};
use clap::{Parser, Subcommand};
use tokio::signal;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;
use webauthn_rs::prelude::*;

use crate::config::Config;
use crate::storage::{Storage, StoredUser};

#[derive(Parser, Debug)]
#[command(name = "auth-service")]
#[command(about = "API key authentication service for obsidian-memory")]
struct Cli {
    /// Port to listen on
    #[arg(long, default_value_t = 3001, env = "AUTH_PORT")]
    port: u16,

    /// Address to bind to
    #[arg(long, default_value = "0.0.0.0", env = "AUTH_BIND")]
    bind: String,

    /// Path to config directory
    #[arg(long, default_value = "/config", env = "AUTH_CONFIG_PATH")]
    config_path: String,

    /// Public URL for this service (used for WebAuthn rp_id/origin derivation)
    #[arg(long, env = "AUTH_PUBLIC_URL")]
    public_url: Option<String>,

    /// Path prefix for URLs (e.g., "/auth" when mounted behind reverse proxy)
    #[arg(long, default_value = "", env = "AUTH_PATH_PREFIX")]
    path_prefix: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Reset all users, passkeys, sessions, and API keys (for recovery)
    Reset,
    /// Create a guest user (a login-capable principal) with a handle
    CreateGuest {
        /// Handle for the guest (ASCII letters, digits, hyphens only)
        #[arg(long)]
        handle: String,
    },
    /// Issue a runtime API key bound to a user; prints the raw key once
    IssueKey {
        /// User to bind the key to (uuid or handle)
        #[arg(long)]
        user: String,
        /// Human-readable name for the key
        #[arg(long)]
        name: String,
    },
    /// Revoke a runtime API key by its name or stored hash
    RevokeKey {
        /// Key name or stored hash to revoke
        identifier: String,
    },
}

/// Shared application state
pub struct AppState {
    pub config: Config,
    pub storage: Storage,
    pub public_url: String,
    pub path_prefix: String,
    pub webauthn: Webauthn,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "auth_service=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let cli = Cli::parse();

    // Load configuration
    let config = Config::load(&cli.config_path)?;

    let storage = Storage::new(&cli.config_path)?;

    // Handle subcommands
    match cli.command {
        Some(Command::Reset) => {
            tracing::info!("Resetting all users, passkeys, sessions, and API keys...");
            storage.reset_auth()?;
            tracing::info!("Reset complete. Please re-register with a passkey.");
            return Ok(());
        }
        Some(Command::CreateGuest { handle }) => {
            let user = storage.create_guest_user(&handle)?;
            println!(
                "Created guest user '{}' with uuid {}",
                user.username, user.id
            );
            return Ok(());
        }
        Some(Command::IssueKey { user, name }) => {
            let principal = resolve_user(&storage, &user)
                .ok_or_else(|| anyhow::anyhow!("No user found for '{}'", user))?;
            let raw_key = storage.issue_api_key(Some(principal.id), &name)?;
            println!(
                "Issued API key '{}' for user '{}' ({})",
                name, principal.username, principal.id
            );
            println!("{}", raw_key);
            println!("(store this now — it cannot be recovered)");
            return Ok(());
        }
        Some(Command::RevokeKey { identifier }) => {
            if storage.revoke_api_key(&identifier)? {
                println!("Revoked API key '{}'", identifier);
            } else {
                println!("No active API key matched '{}'", identifier);
            }
            return Ok(());
        }
        None => {}
    }

    // Migrate config-file api keys into runtime storage, then authenticate
    // solely from that hashed store (see validation::authenticate_bearer).
    migrate_config_keys(&storage, &config)?;

    // Require public_url for server mode
    let public_url = cli
        .public_url
        .ok_or_else(|| anyhow::anyhow!("--public-url is required (or set AUTH_PUBLIC_URL)"))?;

    // Initialize WebAuthn
    let webauthn = {
        let rp_id = config.webauthn.rp_id.clone().unwrap_or_else(|| {
            // Derive RP ID from public URL when not explicitly configured
            Url::parse(&public_url)
                .ok()
                .and_then(|u| u.host_str().map(|h| h.to_string()))
                .unwrap_or_else(|| "localhost".to_string())
        });
        let rp_origin = config
            .webauthn
            .origin
            .clone()
            .unwrap_or_else(|| format!("https://{}", rp_id));
        let rp_origin = Url::parse(&rp_origin)?;

        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)?.rp_name(&config.webauthn.rp_name);

        builder.build()?
    };

    let state = Arc::new(AppState {
        config,
        storage,
        public_url: public_url.clone(),
        path_prefix: cli.path_prefix,
        webauthn,
    });

    // Build router
    let app = Router::new()
        // Validation endpoint for Caddy forward_auth
        .route("/validate", get(validation::handler))
        // Passkey setup routes
        .route("/setup", get(passkey::setup::get_setup))
        .route(
            "/setup/register/start",
            post(passkey::setup::start_registration),
        )
        .route(
            "/setup/register/finish",
            post(passkey::setup::finish_registration),
        )
        // Passkey login routes
        .route("/login", get(passkey::login::get_login))
        .route("/login/auth/start", post(passkey::login::start_auth))
        .route("/login/auth/finish", post(passkey::login::finish_auth))
        .route("/logout", post(passkey::login::logout))
        // API key → session exchange (header-less guest floor)
        .route("/login/key", post(key_login::login_key))
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Parse bind address
    let addr: SocketAddr = format!("{}:{}", cli.bind, cli.port).parse()?;

    tracing::info!("Starting auth-service on {}", addr);
    tracing::info!("Public URL: {}", public_url);

    // Start server
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("Auth service shut down");
    Ok(())
}

/// Resolve a `--user` argument (a uuid or a handle) to a stored user.
fn resolve_user(storage: &Storage, user: &str) -> Option<StoredUser> {
    if let Ok(uuid) = Uuid::parse_str(user) {
        storage.get_user(uuid)
    } else {
        storage.find_user_by_username(user)
    }
}

/// Migrate config-file api keys into runtime storage (idempotent), so bearer
/// auth reads exclusively from the hashed key store. Active keys are seeded
/// preserving their exact string; inactive config keys are skipped (they never
/// authenticated). Config keys carry no known actor uuid at the auth-service
/// layer, so they migrate uuid-less and name-only — behavior identical to the
/// old config path, but now hashed.
fn migrate_config_keys(storage: &Storage, config: &Config) -> anyhow::Result<()> {
    for api_key in &config.api_keys {
        if api_key.active {
            storage.seed_api_key(&api_key.key, &api_key.name, None)?;
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    tracing::info!("Shutdown signal received");
}
