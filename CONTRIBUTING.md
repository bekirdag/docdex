# Contributing to Docdex

Thanks for your interest in improving Docdex! Here’s how to get started.

## Prereqs
- Rust toolchain (stable), Node.js >= 18, npm.
- On macOS/Linux, ensure you can build the Rust binary: `cargo test --locked --all`.

## Setup
```bash
git clone git@github.com:bekirdag/docdex.git
cd docdex
cargo test --locked --all
```

## Making changes
- Keep versions aligned across `Cargo.toml` and `npm/package.json` when releasing.
- Follow existing patterns; add comments only where the code isn’t obvious.
- For workflow edits, prefer tag-triggered releases; npm publishes via trusted publishing.

## Testing
- Run `cargo test --locked --all` before opening a PR.
- If you touch npm wrapper files, run `npm install --ignore-scripts` inside `npm/` and `npm pack --ignore-scripts` to sanity check.

## Releases
- Tag releases as `vX.Y.Z` from `main`; the release workflow builds binaries, uploads assets, and publishes to npm via OIDC.

## Reporting issues
- Include repro steps, expected/actual behavior, platform, and logs where possible.
