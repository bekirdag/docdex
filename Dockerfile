# Stage 1: Build the Docdex binary (Rust)
FROM rust:slim-bookworm AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY . .
RUN cargo build --release

# Stage 2: Runtime (Node.js + The Binary + Your Docs)
FROM node:20-bookworm-slim

# Install basics
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# A. Copy the compiled binary
COPY --from=builder /app/target/release/docdexd /usr/local/bin/docdexd

# B. Copy the Node.js adapter files (we will create these next)
COPY package.json server.js ./

# C. CRITICAL: Copy your entire repository into the container so it can be indexed
#    (We exclude .git and target via .dockerignore usually, but this copies source)
COPY . /source

# Install Node dependencies
RUN npm install

# Pre-build the index so startup is fast
RUN docdexd index --repo /source

ENV PORT=8080
CMD ["node", "server.js"]