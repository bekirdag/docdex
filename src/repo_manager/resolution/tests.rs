use super::{normalize_repo_path, resolve_repo_root};
use tempfile::TempDir;

#[test]
fn normalize_repo_path_replaces_backslashes() {
    let path = std::path::Path::new("C:\\repo\\path");
    let normalized = normalize_repo_path(path);
    assert!(!normalized.contains('\\'));
}

#[test]
fn resolve_repo_root_returns_fingerprint() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let resolution = resolve_repo_root(temp.path());
    assert!(resolution.fingerprint.is_some());
    assert!(!resolution.normalized_path.is_empty());
    Ok(())
}
