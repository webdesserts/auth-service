# syntax=docker/dockerfile:1
#
# Source build for auth-service. See .dockerignore for exclusions.

FROM rust:bookworm AS builder

WORKDIR /build

COPY . .

RUN cargo build --release --locked

# --- Runtime layer ---
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/target/release/auth-service /usr/local/bin/auth-service

# Create non-root user (UID 1000)
RUN useradd -m -u 1000 auth

# Create config mount point
RUN mkdir -p /config && chown auth:auth /config

USER auth
WORKDIR /config

EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:3001/setup > /dev/null || exit 1

ENTRYPOINT ["auth-service"]
CMD ["--port", "3001", "--bind", "0.0.0.0", "--config-path", "/config"]