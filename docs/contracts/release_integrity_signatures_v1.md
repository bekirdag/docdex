# Release Integrity Signatures (v1)

Scope: optional detached signatures over **integrity metadata** release assets (e.g. `SHA256SUMS`, `docdex-release-manifest.json`) consumed by the npm installer (`npm/lib/install.js`).

Goal: if a release provides signatures for integrity metadata, the installer verifies those signatures **before trusting any checksums**.

## Published signature assets (per release)

When enabled, the release workflow uploads these GitHub Release assets:

- `SHA256SUMS.sig` — detached signature over `SHA256SUMS`
- `SHA256SUMS.txt.sig` — detached signature over `SHA256SUMS.txt`
- `docdex-release-manifest.json.sig` — detached signature over `docdex-release-manifest.json`

Signature filenames are deterministic: `<signedFilename>.sig`.

## Signature format

Each `.sig` file is UTF-8 text containing:

- base64-encoded Ed25519 signature bytes (64 bytes), optionally prefixed with `ed25519:`

The signature is computed over the **exact file bytes** of the signed artifact as uploaded to the release.

## Verifier key material (pinned)

The npm installer verifies signatures using a pinned Ed25519 public key:

- Default verifier key: `npm/lib/release_signing.js` (`DEFAULT_RELEASE_SIGNING_PUBLIC_KEY_PEM`)
- Fork override (testing/private releases): `DOCDEX_RELEASE_SIGNING_PUBLIC_KEY` (PEM-encoded public key)

Operational note: key rotation requires updating the pinned public key in the npm package and re-signing release metadata with the corresponding private key.

## Installer policy (deterministic)

Signature verification behavior is controlled by `DOCDEX_SIGNATURE_POLICY`:

- `optional` (default): if a `.sig` asset exists it **must** verify; if the signature is missing/unavailable the installer proceeds with checksum-only verification and emits a stable warning.
- `required`: the installer requires a valid `.sig` for the selected integrity metadata and fails closed when the signature is missing/unavailable/invalid.
- `disabled`: the installer does not attempt signature verification.

## Release generation (how signatures are produced)

- `scripts/generate_release_manifest.cjs` signs integrity metadata when `DOCDEX_RELEASE_SIGNING_PRIVATE_KEY` is set to a PEM-encoded Ed25519 private key.
- `.github/workflows/release.yml` uploads the `.sig` assets only when the `DOCDEX_RELEASE_SIGNING_PRIVATE_KEY` secret is configured.

