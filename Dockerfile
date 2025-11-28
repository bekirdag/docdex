# Dockerfile
# Container image for the Docdex MCP server.

########################
# 1) Build stage
########################
FROM rust:1.79-slim AS builder

# System dependencies for building
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifest files
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY . .

# Build the release binary
RUN cargo build --release

########################
# 2) Runtime stage
########################
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Non-root user for safety
RUN useradd -m -u 1000 docdex

WORKDIR /app

# Copy the compiled binary from the builder image
COPY --from=builder /app/target/release/docdexd /usr/local/bin/docdexd

# --- KEY FIX: Create a wrapper script to bridge Env Vars -> CLI Flags ---
# We use printf to ensure newlines are handled correctly.
RUN printf '#!/bin/sh\n\
\n\
# 1. Read Env Vars (provided by Smithery/Docker), default to sensible values if missing\n\
# We check both camelCase (Smithery default) and standard UPPERCASE just in case\n\
REPO="${repoPath:-${REPO_PATH:-.}}"\n\
LOG="${logLevel:-${LOG_LEVEL:-warn}}"\n\
MAX="${maxResults:-${MAX_RESULTS:-8}}"\n\
\n\
# 2. Log startup for debugging\n\
echo "Starting docdexd with: repo=$REPO, log=$LOG, max=$MAX"\n\
\n\
# 3. Exec into the actual binary so it takes over PID 1\n\
exec docdexd mcp --repo "$REPO" --log "$LOG" --max-results "$MAX"\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

USER docdex

# Point to our wrapper script instead of the binary directly
CMD ["/entrypoint.sh"]