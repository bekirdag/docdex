
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
