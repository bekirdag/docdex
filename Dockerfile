# Dockerfile
# Container image for the Docdex MCP server.
# Place this in the repository root (next to Cargo.toml).

########################
# 1) Build stage
########################
FROM rust:1.79-slim AS builder

# System dependencies for building (adjust if you know docdex needs more/less)
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy manifest files first for better caching
COPY Cargo.toml Cargo.lock ./
# If you have a workspace, you may want to COPY additional manifests here.

# Copy the rest of the source
COPY . .

# Build the release binary (docdexd)
# If the binary name ever changes, update "docdexd" here and in the COPY below.
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

USER docdex

# Default command: matches the smithery.yaml startCommand (can be overridden by Smithery).
CMD ["docdexd", "mcp", "--repo", ".", "--log", "warn", "--max-results", "8"]
