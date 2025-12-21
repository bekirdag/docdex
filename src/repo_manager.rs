#![allow(dead_code)]

use crate::error::{
    repo_resolution_details, AppError, ERR_INVALID_ARGUMENT, ERR_MISSING_REPO_PATH,
    ERR_REPO_CAPACITY,
};
use anyhow::Result;
use parking_lot::Mutex;
use serde_json::json;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Clone)]
pub struct RepoHandleManager<H> {
    inner: Arc<RepoHandleManagerInner<H>>,
}

struct RepoHandleManagerInner<H> {
    max_open_repos: usize,
    open_fn: Box<dyn Fn(&Path) -> Result<H> + Send + Sync>,
    state: Mutex<RepoManagerState<H>>,
}

struct RepoManagerState<H> {
    entries: HashMap<String, RepoEntry<H>>,
    access_counter: u64,
    open_counter: u64,
}

struct RepoEntry<H> {
    repo_root: PathBuf,
    handle: Arc<H>,
    in_flight: usize,
    last_access: u64,
    open_seq: u64,
}

pub struct RepoLease<H> {
    repo_id: String,
    repo_root: PathBuf,
    handle: Arc<H>,
    manager: Arc<RepoHandleManagerInner<H>>,
}

impl<H> RepoHandleManager<H> {
    pub fn new(
        max_open_repos: usize,
        open_fn: impl Fn(&Path) -> Result<H> + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(RepoHandleManagerInner {
                max_open_repos: max_open_repos.max(1),
                open_fn: Box::new(open_fn),
                state: Mutex::new(RepoManagerState {
                    entries: HashMap::new(),
                    access_counter: 0,
                    open_counter: 0,
                }),
            }),
        }
    }

    pub fn acquire(&self, repo_root: &Path) -> Result<RepoLease<H>> {
        let (repo_root, repo_id) = resolve_repo_identity(repo_root)?;
        let mut state = self.inner.state.lock();
        state.access_counter = state.access_counter.saturating_add(1);
        let access = state.access_counter;

        if let Some(entry) = state.entries.get_mut(&repo_id) {
            entry.in_flight = entry.in_flight.saturating_add(1);
            entry.last_access = access;
            return Ok(RepoLease {
                repo_id,
                repo_root: entry.repo_root.clone(),
                handle: entry.handle.clone(),
                manager: self.inner.clone(),
            });
        }

        if state.entries.len() >= self.inner.max_open_repos {
            if let Some(evict_id) = pick_eviction_candidate(&state.entries) {
                state.entries.remove(&evict_id);
            } else {
                let in_flight_ids: Vec<String> = state
                    .entries
                    .iter()
                    .filter(|(_, entry)| entry.in_flight > 0)
                    .map(|(repo_id, _)| repo_id.clone())
                    .collect();
                let details = json!({
                    "maxOpenRepos": self.inner.max_open_repos,
                    "openRepos": state.entries.len(),
                    "inFlightRepos": in_flight_ids.len(),
                    "inFlightRepoIds": in_flight_ids,
                    "requestedRepoId": repo_id,
                    "requestedRepoRoot": repo_root.display().to_string(),
                    "evictionPolicy": "lru_inactive_only",
                });
                return Err(
                    AppError::new(
                        ERR_REPO_CAPACITY,
                        "repo capacity reached; all repos have in-flight operations",
                    )
                    .with_details(details)
                    .into(),
                );
            }
        }

        let handle = (self.inner.open_fn)(&repo_root)?;
        state.open_counter = state.open_counter.saturating_add(1);
        let open_seq = state.open_counter;
        let handle = Arc::new(handle);
        state.entries.insert(
            repo_id.clone(),
            RepoEntry {
                repo_root: repo_root.clone(),
                handle: handle.clone(),
                in_flight: 1,
                last_access: access,
                open_seq,
            },
        );
        Ok(RepoLease {
            repo_id,
            repo_root,
            handle,
            manager: self.inner.clone(),
        })
    }

    fn release(&self, repo_id: &str) {
        let mut state = self.inner.state.lock();
        if let Some(entry) = state.entries.get_mut(repo_id) {
            if entry.in_flight > 0 {
                entry.in_flight -= 1;
            }
        }
    }
}

impl<H> RepoLease<H> {
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    pub fn handle(&self) -> &H {
        &self.handle
    }
}

impl<H> std::ops::Deref for RepoLease<H> {
    type Target = H;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl<H> Drop for RepoLease<H> {
    fn drop(&mut self) {
        self.manager.release(&self.repo_id);
    }
}

fn resolve_repo_identity(repo_root: &Path) -> Result<(PathBuf, String)> {
    if !repo_root.exists() {
        return Err(
            AppError::new(ERR_MISSING_REPO_PATH, "repo path not found")
                .with_details(repo_resolution_details(
                    repo_root.to_string_lossy().replace('\\', "/"),
                    None,
                    None,
                    vec![
                        "Repo may have moved or been renamed.".to_string(),
                        "Re-run with the repo's current path.".to_string(),
                    ],
                ))
                .into(),
        );
    }
    if !repo_root.is_dir() {
        return Err(
            AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("repo root is not a directory: {}", repo_root.display()),
            )
            .into(),
        );
    }
    let canonical = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());
    let repo_id = crate::repo_identity::repo_fingerprint_sha256(&canonical).map_err(|err| {
        AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("failed to resolve repo fingerprint: {err}"),
        )
    })?;
    Ok((canonical, repo_id))
}

fn pick_eviction_candidate<H>(entries: &HashMap<String, RepoEntry<H>>) -> Option<String> {
    entries
        .iter()
        .filter(|(_, entry)| entry.in_flight == 0)
        .min_by(|(left_id, left), (right_id, right)| {
            let left_key = (left.last_access, left.open_seq, left_id.as_str());
            let right_key = (right.last_access, right.open_seq, right_id.as_str());
            left_key.cmp(&right_key)
        })
        .map(|(repo_id, _)| repo_id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[derive(Debug)]
    struct DummyHandle {
        _root: PathBuf,
    }

    fn create_repo(base: &Path, name: &str) -> Result<PathBuf> {
        let path = base.join(name);
        fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn open_dummy(root: &Path) -> Result<DummyHandle> {
        Ok(DummyHandle {
            _root: root.to_path_buf(),
        })
    }

    #[test]
    fn capacity_error_when_all_repos_in_flight() -> Result<()> {
        let base = TempDir::new()?;
        let repo_a = create_repo(base.path(), "repo-a")?;
        let repo_b = create_repo(base.path(), "repo-b")?;
        let repo_c = create_repo(base.path(), "repo-c")?;

        let manager = RepoHandleManager::new(2, open_dummy);
        let _lease_a = manager.acquire(&repo_a)?;
        let _lease_b = manager.acquire(&repo_b)?;

        let err = manager.acquire(&repo_c).unwrap_err();
        let app = err
            .downcast_ref::<AppError>()
            .expect("capacity errors should be AppError");
        assert_eq!(app.code, ERR_REPO_CAPACITY);
        let details = app.details.as_ref().expect("capacity error details");
        assert_eq!(
            details
                .get("maxOpenRepos")
                .and_then(|value| value.as_u64()),
            Some(2)
        );
        assert_eq!(
            details
                .get("inFlightRepos")
                .and_then(|value| value.as_u64()),
            Some(2)
        );
        assert_eq!(
            details
                .get("inFlightRepoIds")
                .and_then(|value| value.as_array())
                .map(|value| value.len()),
            Some(2)
        );
        Ok(())
    }

    #[test]
    fn eviction_skips_repos_with_in_flight_operations() -> Result<()> {
        let base = TempDir::new()?;
        let repo_a = create_repo(base.path(), "repo-a")?;
        let repo_b = create_repo(base.path(), "repo-b")?;
        let repo_c = create_repo(base.path(), "repo-c")?;

        let manager = RepoHandleManager::new(2, open_dummy);
        let lease_a = manager.acquire(&repo_a)?;
        let lease_b = manager.acquire(&repo_b)?;
        drop(lease_b);

        let _lease_c = manager.acquire(&repo_c)?;
        let id_a = crate::repo_identity::repo_fingerprint_sha256(&repo_a)?;
        let id_b = crate::repo_identity::repo_fingerprint_sha256(&repo_b)?;
        let id_c = crate::repo_identity::repo_fingerprint_sha256(&repo_c)?;

        let state = manager.inner.state.lock();
        assert!(state.entries.contains_key(&id_a));
        assert!(state.entries.contains_key(&id_c));
        assert!(!state.entries.contains_key(&id_b));
        drop(lease_a);
        Ok(())
    }
}
