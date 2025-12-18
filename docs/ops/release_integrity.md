# Release Integrity (Checksums + Optional Signatures)

This repo publishes integrity metadata for `docdexd` GitHub Release assets so installers and humans can verify what was downloaded before running it.

## What is published (per release tag `vX.Y.Z`)

Release workflow: `.github/workflows/release.yml`

Integrity artifacts (GitHub Release assets):
- `docdex-release-manifest.json` — machine-readable mapping `{targetTriple -> asset.name + sha256}`.
- `docdex-release-manifest.json.sha256` — SHA-256 checksum file for the manifest itself.
- `SHA256SUMS` and `SHA256SUMS.txt` — consolidated SHA-256 checksums for released artifacts (installer fallback).
- `docdexd-<platformKey>.tar.gz.sha256` — per-asset checksum sidecar (legacy fallback).

Contract / schema:
- `docs/contracts/release_manifest_schema_v1.md`

## Installer behavior (npm postinstall)

Installer implementation:
- `npm/lib/install.js`

Behavior summary (deterministic):
- Prefer `docdex-release-manifest.json` to resolve the correct asset + expected SHA-256.
- If no usable manifest exists, fall back to `SHA256SUMS` / `SHA256SUMS.txt`, then `<asset>.sha256`.
- Download the selected archive and verify `sha256(archive)` before extracting.
- If integrity metadata is missing or verification fails, the installer aborts with a non-zero exit code and prints actionable remediation.

Error/exit-code contract:
- `docs/contracts/installer_error_contract_v1.md`
- `docs/ops/installer_error_codes.md`

## Signature policy (optional)

Current policy (this repo by default): checksums only (no signature verification by the npm installer).

If you require signatures in your own fork/environment, the recommended policy is:
- Sign the checksum bundle (`SHA256SUMS`) and publish the detached signature alongside the release.
- Distribute the verifying public key out-of-band and pin it (see “Public key distribution” below).

### Suggested artifacts (when enabled)

- `SHA256SUMS.asc` — detached signature for `SHA256SUMS` (ASCII-armored OpenPGP, `gpg --detach-sign --armor`).
- `docdex-release-signing-public-key.asc` — the OpenPGP public key used to verify signatures.

### Public key provenance + distribution

To make signature verification meaningful, verifiers need an authenticated copy of the public key.

Recommended distribution (pick at least one, ideally two):
- Commit the public key in-repo under version control (e.g. `docs/ops/docdex-release-signing-public-key.asc`) and reference it from docs.
- Attach the same public key to every GitHub Release as a release asset (e.g. `docdex-release-signing-public-key.asc`).

Recommended provenance:
- Generate the signing key in a controlled environment (hardware-backed if possible).
- Record key fingerprint(s), creation date, and rotation policy in the repo docs.
- Treat signing key material as a long-lived secret (do not generate in CI).

### Manual verification (example)

Assumes you have downloaded `SHA256SUMS`, `SHA256SUMS.asc`, and the pinned public key.

```bash
gpg --import docdex-release-signing-public-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
shasum -a 256 -c SHA256SUMS
```

