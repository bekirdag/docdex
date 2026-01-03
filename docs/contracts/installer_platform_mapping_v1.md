# Installer Platform Mapping Contract (v1)

Scope: canonical mapping from the Node.js runtime (`process.platform`, `process.arch`, and Linux libc)
to the Rust target triple used to name and select `docdexd` release assets. This mapping is the
single source of truth for npm postinstall selection, CLI resolution, and installer output.

Source of truth:
- `npm/lib/platform_matrix.js` (authoritative data)
- `npm/lib/platform.js` (detection + resolution logic)

## Inputs (runtime detection)

- OS: `process.platform` (`darwin`, `linux`, `win32`)
- CPU arch: `process.arch` (`x64`, `arm64`)
- Linux libc (only when `process.platform === "linux"`):
  - Override: `DOCDEX_LIBC=gnu|musl|glibc` (glibc is normalized to `gnu`)
  - Otherwise: detected by Node report + Alpine hints + ELF interpreter inspection
    (see `npm/lib/platform.js`)

## Outputs (used by installer + CLI)

- `platformKey`: stable platform identifier used in asset names and install paths.
- `targetTriple`: Rust target triple used by release manifests and fallback resolution.
- Expected asset name: `docdexd-<platformKey>.tar.gz`

## Published support (installer treats as supported)

These entries are marked `published: true` in `npm/lib/platform_matrix.js`.

| Node runtime | Linux libc | `platformKey` | Rust `targetTriple` | Expected release asset |
|---|---|---|---|---|
| `darwin/arm64` | n/a | `darwin-arm64` | `aarch64-apple-darwin` | `docdexd-darwin-arm64.tar.gz` |
| `darwin/x64` | n/a | `darwin-x64` | `x86_64-apple-darwin` | `docdexd-darwin-x64.tar.gz` |
| `linux/x64` | `gnu` | `linux-x64-gnu` | `x86_64-unknown-linux-gnu` | `docdexd-linux-x64-gnu.tar.gz` |
| `linux/x64` | `musl` | `linux-x64-musl` | `x86_64-unknown-linux-musl` | `docdexd-linux-x64-musl.tar.gz` |
| `linux/arm64` | `gnu` | `linux-arm64-gnu` | `aarch64-unknown-linux-gnu` | `docdexd-linux-arm64-gnu.tar.gz` |
| `win32/x64` | n/a | `win32-x64` | `x86_64-pc-windows-msvc` | `docdexd-win32-x64.tar.gz` |

## Recognized but not published (installer treats as unsupported)

These mappings exist in `npm/lib/platform_matrix.js` but are marked `published: false`.

| Node runtime | Linux libc | `platformKey` | Rust `targetTriple` | Expected asset (if/when published) |
|---|---|---|---|---|
| `linux/arm64` | `musl` | `linux-arm64-musl` | `aarch64-unknown-linux-musl` | `docdexd-linux-arm64-musl.tar.gz` |
| `win32/arm64` | n/a | `win32-arm64` | `aarch64-pc-windows-msvc` | `docdexd-win32-arm64.tar.gz` |

## Unsupported behavior (contract)

- If the runtime maps to a published entry, the installer resolves `platformKey` + `targetTriple`
  and downloads `docdexd-<platformKey>.tar.gz` for the npm package version.
- If the runtime maps to an unpublished entry or is unknown, the installer exits with
  `DOCDEX_UNSUPPORTED_PLATFORM` and does **not** download any asset.

## Related docs

- `docs/contracts/release_manifest_schema_v1.md`
- `docs/contracts/installer_error_contract_v1.md`
- `docs/ops/installer_supported_platforms.md`
- `docs/ops/installer_platform_audit.md`
