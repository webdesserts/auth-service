//! OAuth 2.1 + API key authentication service for obsidian-memory
//!
//! Provides:
//! - RFC 8414 OAuth metadata discovery
//! - RFC 7591 Dynamic Client Registration (manual implementation)
//! - Authorization code flow with PKCE
//! - Token exchange and refresh
//! - API key validation
//! - Caddy forward_auth integration
//! - WebAuthn passkey authentication

mod config;
mod oauth;
mod passkey;
mod storage;
mod validation;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use clap::{Parser, Subcommand};
use tokio::signal;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use webauthn_rs::prelude::*;

use crate::config::Config;
use crate::storage::Storage;

#[derive(Parser, Debug)]
#[command(name = "auth-service")]
#[command(about = "OAuth 2.1 authentication service for obsidian-memory")]
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

    /// Public URL for this service (used in OAuth metadata)
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
    /// Reset all users, passkeys, and sessions (for recovery)
    Reset,
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
    if let Some(Command::Reset) = cli.command {
        tracing::info!("Resetting all users, passkeys, and sessions...");
        storage.reset_auth()?;
        tracing::info!("Reset complete. Please re-register with a passkey.");
        return Ok(());
    }

    // Require public_url for server mode
    let public_url = cli.public_url.ok_or_else(|| {
        anyhow::anyhow!("--public-url is required (or set AUTH_PUBLIC_URL)")
    })?;

    // Initialize WebAuthn
    let webauthn = {
        let rp_id = config.webauthn.rp_id.clone();
        let rp_origin = config
            .webauthn
            .origin
            .clone()
            .unwrap_or_else(|| format!("https://{}", rp_id));
        let rp_origin = Url::parse(&rp_origin)?;

        let builder = WebauthnBuilder::new(&rp_id, &rp_origin)?
            .rp_name(&config.webauthn.rp_name);

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
        // OAuth metadata (RFC 8414)
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth::metadata::handler),
        )
        // Dynamic Client Registration (RFC 7591)
        .route("/register", post(oauth::registration::handler))
        // Authorization endpoint
        .route("/authorize", get(oauth::authorize::get_handler))
        .route("/authorize", post(oauth::authorize::post_handler))
        // Token endpoint
        .route("/token", post(oauth::token::handler))
        // Validation endpoint for Caddy forward_auth
        .route("/validate", get(validation::handler))
        // Passkey setup routes
        .route("/setup", get(passkey::setup::get_setup))
        .route("/setup/register/start", post(passkey::setup::start_registration))
        .route("/setup/register/finish", post(passkey::setup::finish_registration))
        // Passkey login routes
        .route("/login", get(passkey::login::get_login))
        .route("/login/auth/start", post(passkey::login::start_auth))
        .route("/login/auth/finish", post(passkey::login::finish_auth))
        .route("/logout", post(passkey::login::logout))
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
