# Docdex CLI (npm)

Docdex is a lightweight, local docs indexer/searcher. This package installs the `docdex` (alias `docdexd`) CLI via npm.

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

## What gets installed
- A tiny JS launcher (`docdex`/`docdexd`).
- On install, it downloads the prebuilt `docdexd` binary for your platform from the GitHub release that matches the npm package version and stores it under `dist/<platform>/docdexd`.

## Usage
```bash
docdex --version
docdexd serve --repo /path/to/repo --host 127.0.0.1 --port 46137
docdexd index --repo /path/to/repo
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
