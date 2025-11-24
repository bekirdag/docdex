# Docdex CLI (npm)

Docdex is a lightweight, local docs indexer/searcher. It builds and serves a per-repo index of your Markdown/text files—no external services, no uploads.

## Install
```bash
# Global install
npm i -g docdex

# One-off use
npx docdex --version
```

## Requirements
- Node.js >= 18
- Platforms: macOS (arm64, x64), Linux glibc (arm64, x64), Linux musl/Alpine (x64), Windows (x64). ARM64 Windows and Linux musl ARM64 can be added when artifacts are published.

## What this package does
- Provides a tiny JS launcher (`docdex`/`docdexd`).
- On install, downloads the prebuilt `docdexd` binary for your platform from the GitHub release that matches the npm package version, storing it under `dist/<platform>/docdexd`.

## What Docdex does
- Indexes Markdown/text files in your repo (tantivy-based) and stores the index locally.
- Serves search/snippet APIs over HTTP (`/search`, `/snippet`, `/healthz`) and via CLI commands.
- Watches files while serving to keep the index fresh.
- Hardened defaults: loopback bind, optional TLS/auth token, rate limits, strict state-dir perms.

## Quick usage
```bash
# Check version
docdex --version

# Build an index
docdexd index --repo /path/to/repo

# Serve HTTP API with live watching
docdexd serve --repo /path/to/repo --host 127.0.0.1 --port 46137 --log info

# Ad-hoc search via CLI (JSON)
docdexd query --repo /path/to/repo --query "otp flow" --limit 5
```

## Environment overrides (optional)
- `DOCDEX_DOWNLOAD_REPO` — `owner/repo` slug hosting release assets (defaults to the linked GitHub repo).
- `DOCDEX_DOWNLOAD_BASE` — custom base URL for release downloads (defaults to `https://github.com/<repo>/releases/download`).
- `DOCDEX_VERSION` — override version/tag to download (for testing).
- `DOCDEX_LIBC` — force `gnu` or `musl` on Linux if auto-detection is wrong.
- `DOCDEX_GITHUB_TOKEN` — token for authenticated GitHub downloads (avoids rate limits/private releases).

## Notes
- Release assets are expected to be named `docdexd-<platform>.tar.gz` with a matching `.sha256`.
- License: MIT (see `LICENSE`).
- Changelog: see `CHANGELOG.md`.
