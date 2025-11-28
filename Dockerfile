# Dockerfile
# Container image for the Docdex MCP server.

########################
# 1) Build stage
########################
# FIX 1: Use 'slim-bookworm' to match the runtime OS (prevents GLIBC error)
FROM rust:slim-bookworm AS builder

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

# Create the app directory
WORKDIR /app

# FIX 2: Change ownership of /app to the docdex user so it can write indexes
RUN chown docdex:docdex /app

# Copy the compiled binary
COPY --from=builder /app/target/release/docdexd /usr/local/bin/docdexd

# Create wrapper script (Env Vars -> CLI Flags)
RUN printf '#!/bin/sh\n\
\n\
# 1. Read Env Vars (provided by Smithery/Docker)\n\
REPO="${repoPath:-${REPO_PATH:-.}}"\n\
LOG="${logLevel:-${LOG_LEVEL:-warn}}"\n\
MAX="${maxResults:-${MAX_RESULTS:-8}}"\n\
\n\
# 2. Log startup\n\
echo "Starting docdexd with: repo=$REPO, log=$LOG, max=$MAX"\n\
\n\
# 3. Exec binary\n\
exec docdexd mcp --repo "$REPO" --log "$LOG" --max-results "$MAX"\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

USER docdex

# Point to wrapper script
ENTRYPOINT ["/entrypoint.sh"]