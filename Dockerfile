# Stage 1: Build the Docdex binary (Rust)
FROM rust:slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --release --locked

# Stage 2: Minimal runtime
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/docdexd /usr/local/bin/docdexd
ENTRYPOINT ["docdexd"]
