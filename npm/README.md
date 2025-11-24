# Docdex (npm)

Install the Docdex CLI via npm:

```bash
npm i -g docdex
# or
npx docdex --version
```

Requirements:
- Node.js >= 18
- Supported platforms: macOS (arm64, x64), Linux glibc (arm64, x64). Musl (Alpine) is detected automatically when artifacts are available.

How it works:
- The package ships a small launcher (`docdex`/`docdexd`); `postinstall` downloads the correct `docdexd` binary for your platform from the GitHub release matching the npm package version.

Environment overrides (optional):
- `DOCDEX_DOWNLOAD_REPO` — `owner/repo` slug hosting release assets (required if `package.json` repository is still a placeholder).
- `DOCDEX_DOWNLOAD_BASE` — full base URL for release downloads (defaults to `https://github.com/<repo>/releases/download`).
- `DOCDEX_VERSION` — force a specific version/tag when testing.
- `DOCDEX_LIBC` — force `gnu` or `musl` on Linux if auto-detection is wrong.
- `DOCDEX_GITHUB_TOKEN` — token for authenticated GitHub downloads (avoids rate limits/private release issues).

Notes:
- Release assets are expected to be named `docdexd-<platform>.tar.gz` with a matching `.sha256`.
- License: MIT (see `LICENSE`).
- Changelog: see `CHANGELOG.md`.
