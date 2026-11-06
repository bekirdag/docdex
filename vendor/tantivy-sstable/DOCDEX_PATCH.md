# Compatibility backport

Source: crates.io tantivy-sstable 0.2.0 (package VCS identifier 7bbb30d0280532c0d7b4f044510382c6676d72cc). All Rust source files are unchanged. The only functional change is zstd 0.12 → 0.13, allowing patched zstd-safe/zstd-sys versions. Cargo.lock pins the audited resolution.

This retains Tantivy 0.21 and its existing index format; upgrading Tantivy to 0.27 would require a separate state migration and is outside this preservation-focused release. The upstream MIT license from Tantivy tag 0.21.1 is included (the package VCS identifier is not reachable through GitHub). Test reading an old index and reopening a new write with the previous binary before deployment.
