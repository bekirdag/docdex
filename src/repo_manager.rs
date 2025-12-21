#![allow(dead_code)]

use std::cmp::Ordering;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoHandle {
    repo_id: String,
    generation: u64,
}

impl RepoHandle {
    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepoOpenError {
    CapExceeded { max_open: usize, in_flight: Vec<String> },
}

#[derive(Clone, Debug)]
struct RepoEntry {
    handle: RepoHandle,
    last_access: u64,
    in_flight: usize,
}

pub struct RepoHandleManager {
    max_open: usize,
    tick: u64,
    next_generation: u64,
    repos: BTreeMap<String, RepoEntry>,
}

impl RepoHandleManager {
    pub fn new(max_open: usize) -> Self {
        let max_open = max_open.max(1);
        Self {
            max_open,
            tick: 0,
            next_generation: 0,
            repos: BTreeMap::new(),
        }
    }

    pub fn open_count(&self) -> usize {
        self.repos.len()
    }

    pub fn is_open(&self, repo_id: &str) -> bool {
        self.repos.contains_key(repo_id)
    }

    pub fn acquire(&mut self, repo_id: &str) -> Result<RepoHandle, RepoOpenError> {
        if let Some(entry) = self.repos.get_mut(repo_id) {
            entry.in_flight += 1;
            entry.last_access = self.bump_tick();
            return Ok(entry.handle.clone());
        }

        if self.repos.len() >= self.max_open && !self.evict_one() {
            return Err(RepoOpenError::CapExceeded {
                max_open: self.max_open,
                in_flight: self.in_flight_repos(),
            });
        }

        let handle = RepoHandle {
            repo_id: repo_id.to_string(),
            generation: self.next_generation(),
        };
        let entry = RepoEntry {
            handle: handle.clone(),
            last_access: self.bump_tick(),
            in_flight: 1,
        };
        self.repos.insert(repo_id.to_string(), entry);
        Ok(handle)
    }

    pub fn release(&mut self, repo_id: &str) {
        if let Some(entry) = self.repos.get_mut(repo_id) {
            if entry.in_flight > 0 {
                entry.in_flight -= 1;
            }
        }
    }

    fn bump_tick(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    fn next_generation(&mut self) -> u64 {
        self.next_generation = self.next_generation.wrapping_add(1);
        self.next_generation
    }

    fn in_flight_repos(&self) -> Vec<String> {
        let mut repos: Vec<String> = self
            .repos
            .iter()
            .filter_map(|(repo_id, entry)| {
                if entry.in_flight > 0 {
                    Some(repo_id.clone())
                } else {
                    None
                }
            })
            .collect();
        repos.sort();
        repos
    }

    fn evict_one(&mut self) -> bool {
        let candidate = self
            .repos
            .iter()
            .filter(|(_, entry)| entry.in_flight == 0)
            .min_by(|(id_a, a), (id_b, b)| match a.last_access.cmp(&b.last_access) {
                Ordering::Equal => id_a.cmp(id_b),
                other => other,
            })
            .map(|(repo_id, _)| repo_id.clone());

        if let Some(repo_id) = candidate {
            self.repos.remove(&repo_id);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_and_release(manager: &mut RepoHandleManager, repo_id: &str) -> RepoHandle {
        let handle = manager.acquire(repo_id).expect("acquire repo");
        manager.release(repo_id);
        handle
    }

    #[test]
    fn lru_eviction_respects_access_order() {
        let mut manager = RepoHandleManager::new(2);

        open_and_release(&mut manager, "repo-a");
        open_and_release(&mut manager, "repo-b");
        open_and_release(&mut manager, "repo-a");

        assert_eq!(manager.open_count(), 2);
        assert!(manager.is_open("repo-a"));
        assert!(manager.is_open("repo-b"));

        manager
            .acquire("repo-c")
            .expect("acquire repo-c after eviction");
        manager.release("repo-c");

        assert_eq!(manager.open_count(), 2);
        assert!(manager.is_open("repo-a"));
        assert!(manager.is_open("repo-c"));
        assert!(!manager.is_open("repo-b"));
    }

    #[test]
    fn eviction_skips_inflight_repos() {
        let mut manager = RepoHandleManager::new(2);

        manager.acquire("repo-a").expect("acquire repo-a");
        manager.acquire("repo-b").expect("acquire repo-b");
        manager.release("repo-b");

        manager
            .acquire("repo-c")
            .expect("acquire repo-c with inflight repo-a");
        manager.release("repo-c");

        assert!(manager.is_open("repo-a"));
        assert!(manager.is_open("repo-c"));
        assert!(!manager.is_open("repo-b"));
        assert_eq!(
            manager.repos.get("repo-a").map(|entry| entry.in_flight),
            Some(1)
        );
        manager.release("repo-a");
    }

    #[test]
    fn cap_blocked_when_all_repos_inflight() {
        let mut manager = RepoHandleManager::new(2);

        manager.acquire("repo-a").expect("acquire repo-a");
        manager.acquire("repo-b").expect("acquire repo-b");

        let err = manager.acquire("repo-c").expect_err("cap should block");
        match err {
            RepoOpenError::CapExceeded { max_open, in_flight } => {
                assert_eq!(max_open, 2);
                assert_eq!(in_flight, vec!["repo-a".to_string(), "repo-b".to_string()]);
            }
        }

        assert_eq!(manager.open_count(), 2);
        assert!(manager.is_open("repo-a"));
        assert!(manager.is_open("repo-b"));
    }

    #[test]
    fn reopen_after_eviction_refreshes_generation() {
        let mut manager = RepoHandleManager::new(1);

        let first = open_and_release(&mut manager, "repo-a");
        open_and_release(&mut manager, "repo-b");

        let reopened = manager.acquire("repo-a").expect("reopen repo-a");
        assert_ne!(first.generation(), reopened.generation());
        manager.release("repo-a");

        assert_eq!(manager.open_count(), 1);
        assert!(manager.is_open("repo-a"));
    }
}
