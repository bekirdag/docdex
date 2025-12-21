use crate::repo_identity;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::env;
use std::path::{Path, PathBuf};

const DEFAULT_REPO_CACHE_SIZE: usize = 16;
const MAX_REPO_CACHE_SIZE: usize = 256;

#[derive(Clone, Debug)]
pub struct RepoResolution {
    pub repo_root: PathBuf,
    pub normalized_path: String,
    pub fingerprint: Option<String>,
}

#[derive(Debug)]
struct RepoCacheEntry {
    resolution: RepoResolution,
    last_access: u64,
}

#[derive(Debug)]
struct RepoResolutionCache {
    entries: BTreeMap<String, RepoCacheEntry>,
    max_entries: usize,
    access_clock: u64,
}

impl RepoResolutionCache {
    fn new(max_entries: usize) -> Self {
        Self {
            entries: BTreeMap::new(),
            max_entries: max_entries.max(1),
            access_clock: 0,
        }
    }

    fn resolve(&mut self, repo_root: &Path) -> RepoResolution {
        let canonical = repo_root
            .canonicalize()
            .unwrap_or_else(|_| repo_root.to_path_buf());
        let normalized = normalize_repo_path(&canonical);
        if let Some(entry) = self.entries.get_mut(&normalized) {
            entry.last_access = self.tick();
            return entry.resolution.clone();
        }
        if self.entries.len() >= self.max_entries {
            self.evict_one();
        }
        let fingerprint = repo_identity::repo_fingerprint_sha256(&canonical).ok();
        let resolution = RepoResolution {
            repo_root: canonical,
            normalized_path: normalized.clone(),
            fingerprint,
        };
        let entry = RepoCacheEntry {
            resolution: resolution.clone(),
            last_access: self.tick(),
        };
        self.entries.insert(normalized, entry);
        resolution
    }

    fn tick(&mut self) -> u64 {
        self.access_clock = self.access_clock.saturating_add(1);
        self.access_clock
    }

    fn evict_one(&mut self) {
        if self.entries.is_empty() {
            return;
        }
        let mut candidate_key: Option<String> = None;
        let mut candidate_access: u64 = u64::MAX;
        for (key, entry) in self.entries.iter() {
            let access = entry.last_access;
            let replace = match candidate_key.as_ref() {
                None => true,
                Some(current_key) => {
                    access < candidate_access || (access == candidate_access && key < current_key)
                }
            };
            if replace {
                candidate_key = Some(key.clone());
                candidate_access = access;
            }
        }
        if let Some(key) = candidate_key {
            self.entries.remove(&key);
        }
    }
}

fn normalize_repo_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn repo_cache_capacity() -> usize {
    let parsed = env::var("DOCDEX_REPO_CACHE_SIZE")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok());
    let mut capacity = parsed.unwrap_or(DEFAULT_REPO_CACHE_SIZE).max(1);
    if capacity > MAX_REPO_CACHE_SIZE {
        capacity = MAX_REPO_CACHE_SIZE;
    }
    capacity
}

static REPO_RESOLUTION_CACHE: Lazy<Mutex<RepoResolutionCache>> =
    Lazy::new(|| Mutex::new(RepoResolutionCache::new(repo_cache_capacity())));

pub fn resolve_repo_root(repo_root: &Path) -> RepoResolution {
    REPO_RESOLUTION_CACHE.lock().resolve(repo_root)
}
