//! OAuth 2.1 + API key authentication service for obsidian-memory
//!
//! Provides:
//! - RFC 8414 OAuth metadata discovery
//! - RFC 7591 Dynamic Client Registration (manual implementation)
//! - Authorization code flow with PKCE
//! - Token exchange and refresh
//! - API key validation
//! - Caddy forward_auth integration

mod config;
mod oauth;
mod storage;
mod validation;

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    routing::{get, post},
    Router,
};
use clap::Parser;
use tokio::signal;
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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
    public_url: String,
}

/// Shared application state
pub struct AppState {
    pub config: Config,
    pub storage: Storage,
    pub public_url: String,
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

    let state = Arc::new(AppState {
        config,
        storage,
        public_url: cli.public_url.clone(),
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
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Parse bind address
    let addr: SocketAddr = format!("{}:{}", cli.bind, cli.port).parse()?;

    tracing::info!("Starting auth-service on {}", addr);
    tracing::info!("Public URL: {}", cli.public_url);

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
