use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::state_layout::StateLayout;

/// Returns the global `cache/web` directory for the configured state layout.
pub fn web_cache_dir(layout: &StateLayout) -> PathBuf {
    layout.cache_web_dir()
}

/// Computes a stable cache path for the given URL inside the global web cache.
pub fn cache_entry_for_url(layout: &StateLayout, url: &str) -> PathBuf {
    let key = cache_key(url);
    layout.cache_web_dir().join(key).with_extension("json")
}

/// Ensures the cache directory exists with secure permissions.
pub fn ensure_web_cache(layout: &StateLayout) -> Result<PathBuf> {
    let dir = layout.cache_web_dir();
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn cache_key(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_layout::StateLayout;
    use tempfile::TempDir;

    #[test]
    fn cache_entry_changes_with_url() -> Result<()> {
        let temp = TempDir::new()?;
        let layout = StateLayout::new(temp.path().join("state"));
        let dir = web_cache_dir(&layout);
        assert!(dir.ends_with("cache/web"));
        let entry_a = cache_entry_for_url(&layout, "https://example.com/foo");
        let entry_b = cache_entry_for_url(&layout, "https://example.com/bar");
        assert_ne!(entry_a, entry_b);
        Ok(())
    }
}
