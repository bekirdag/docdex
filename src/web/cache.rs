use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::config;
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

/// Returns the configured cache TTL, using env/config defaults when available.
pub fn cache_ttl() -> Duration {
    let ttl_secs = std::env::var("DOCDEX_WEB_CACHE_TTL_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .or_else(config_cache_ttl_secs)
        .unwrap_or(2_592_000);
    Duration::from_secs(ttl_secs)
}

/// Reads a cached entry if present and fresh; expires stale entries.
pub fn read_cache_entry(layout: &StateLayout, url: &str) -> Result<Option<Vec<u8>>> {
    read_cache_entry_with_ttl(layout, url, cache_ttl())
}

/// Reads a cached entry if present and fresh using the provided TTL.
pub fn read_cache_entry_with_ttl(
    layout: &StateLayout,
    url: &str,
    ttl: Duration,
) -> Result<Option<Vec<u8>>> {
    if ttl.is_zero() {
        return Ok(None);
    }
    let entry = cache_entry_for_url(layout, url);
    if !entry.exists() {
        return Ok(None);
    }
    if !cache_entry_is_fresh(&entry, ttl)? {
        let _ = std::fs::remove_file(&entry);
        return Ok(None);
    }
    let data = std::fs::read(&entry)
        .with_context(|| format!("read web cache entry {}", entry.display()))?;
    Ok(Some(data))
}

/// Writes a cache entry payload and returns the path.
pub fn write_cache_entry(layout: &StateLayout, url: &str, payload: &[u8]) -> Result<PathBuf> {
    let dir = ensure_web_cache(layout)?;
    let entry = cache_entry_for_url(layout, url);
    if let Some(parent) = entry.parent() {
        if parent != dir {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(&entry, payload)
        .with_context(|| format!("write web cache entry {}", entry.display()))?;
    Ok(entry)
}

/// Best-effort load of the global state layout for web caching.
pub fn cache_layout_from_config() -> Option<StateLayout> {
    let config = config::AppConfig::load_default().ok()?;
    let base_dir = config.core.global_state_dir?;
    let layout = StateLayout::new(base_dir);
    layout.ensure_global_dirs().ok()?;
    Some(layout)
}

fn cache_entry_is_fresh(path: &Path, ttl: Duration) -> Result<bool> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("stat web cache entry {}", path.display()))?;
    let modified = metadata
        .modified()
        .with_context(|| format!("read mtime for {}", path.display()))?;
    let age = SystemTime::now().duration_since(modified).unwrap_or_default();
    Ok(age <= ttl)
}

fn cache_key(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}

fn config_cache_ttl_secs() -> Option<u64> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(config.web.cache_ttl_secs)
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

    #[test]
    fn read_cache_entry_respects_ttl() -> Result<()> {
        let temp = TempDir::new()?;
        let layout = StateLayout::new(temp.path().join("state"));
        let url = "https://example.com/foo";
        write_cache_entry(&layout, url, b"payload")?;
        let fresh = read_cache_entry_with_ttl(&layout, url, Duration::from_secs(60))?;
        assert_eq!(fresh.as_deref(), Some(b"payload".as_slice()));
        let stale = read_cache_entry_with_ttl(&layout, url, Duration::from_secs(0))?;
        assert!(stale.is_none());
        Ok(())
    }
}
