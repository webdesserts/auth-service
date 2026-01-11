# syntax=docker/dockerfile:1

# Build stage
FROM rust:latest AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for better layer caching
COPY Cargo.toml Cargo.lock ./
COPY crates/auth-service/Cargo.toml crates/auth-service/
COPY crates/mcp-server/Cargo.toml crates/mcp-server/
COPY crates/wiki-links/Cargo.toml crates/wiki-links/
COPY crates/obsidian-fs/Cargo.toml crates/obsidian-fs/
COPY crates/semantic-embeddings/Cargo.toml crates/semantic-embeddings/

# Create dummy source files for dependency compilation
RUN mkdir -p crates/auth-service/src && echo "fn main() {}" > crates/auth-service/src/main.rs \
    && mkdir -p crates/mcp-server/src && echo "fn main() {}" > crates/mcp-server/src/main.rs \
    && mkdir -p crates/wiki-links/src && echo "" > crates/wiki-links/src/lib.rs \
    && mkdir -p crates/obsidian-fs/src && echo "" > crates/obsidian-fs/src/lib.rs \
    && mkdir -p crates/semantic-embeddings/src && echo "" > crates/semantic-embeddings/src/lib.rs

# Build dependencies only (cached layer)
RUN cargo build --release -p auth-service 2>/dev/null || true

# Copy actual source code
COPY crates/auth-service/ crates/auth-service/

# Touch source file to invalidate the cache
RUN touch crates/auth-service/src/main.rs

# Build the actual binary
RUN cargo build --release -p auth-service

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user (UID 1000 for consistency)
RUN useradd -m -u 1000 auth

# Copy binary
COPY --from=builder /app/target/release/auth-service /usr/local/bin/

# Create config mount point
RUN mkdir -p /config && chown auth:auth /config

USER auth
WORKDIR /config

EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:3001/.well-known/oauth-authorization-server > /dev/null || exit 1

ENTRYPOINT ["auth-service"]
CMD ["--port", "3001", "--bind", "0.0.0.0", "--config-path", "/config"]
