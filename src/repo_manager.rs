use std::cmp::Ordering;
use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoLruEntry {
    last_access: u64,
    open_seq: u64,
    in_use: u64,
    pinned: bool,
}

impl RepoLruEntry {
    pub fn last_access(&self) -> u64 {
        self.last_access
    }

    pub fn open_seq(&self) -> u64 {
        self.open_seq
    }

    pub fn in_use(&self) -> u64 {
        self.in_use
    }

    pub fn is_pinned(&self) -> bool {
        self.pinned
    }

    fn is_evictable(&self) -> bool {
        !self.pinned && self.in_use == 0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepoLruUpdate {
    Inserted,
    Touched,
}

#[derive(Debug, Default)]
pub struct RepoLru {
    entries: HashMap<String, RepoLruEntry>,
    access_clock: u64,
    open_clock: u64,
}

impl RepoLru {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn contains(&self, repo_id: &str) -> bool {
        self.entries.contains_key(repo_id)
    }

    pub fn insert(&mut self, repo_id: impl Into<String>) -> RepoLruUpdate {
        let repo_id = repo_id.into();
        let access = self.next_access();
        if let Some(entry) = self.entries.get_mut(repo_id.as_str()) {
            entry.last_access = access;
            return RepoLruUpdate::Touched;
        }
        let open_seq = self.next_open_seq();
        self.entries.insert(
            repo_id,
            RepoLruEntry {
                last_access: access,
                open_seq,
                in_use: 0,
                pinned: false,
            },
        );
        RepoLruUpdate::Inserted
    }

    pub fn touch(&mut self, repo_id: &str) -> bool {
        let Some(entry) = self.entries.get_mut(repo_id) else {
            return false;
        };
        entry.last_access = self.next_access();
        true
    }

    pub fn remove(&mut self, repo_id: &str) -> Option<RepoLruEntry> {
        self.entries.remove(repo_id)
    }

    pub fn set_pinned(&mut self, repo_id: &str, pinned: bool) -> bool {
        let Some(entry) = self.entries.get_mut(repo_id) else {
            return false;
        };
        entry.pinned = pinned;
        true
    }

    pub fn acquire(&mut self, repo_id: &str) -> bool {
        let Some(entry) = self.entries.get_mut(repo_id) else {
            return false;
        };
        entry.in_use = entry.in_use.saturating_add(1);
        entry.last_access = self.next_access();
        true
    }

    pub fn release(&mut self, repo_id: &str) -> bool {
        let Some(entry) = self.entries.get_mut(repo_id) else {
            return false;
        };
        if entry.in_use > 0 {
            entry.in_use -= 1;
        }
        true
    }

    pub fn eviction_candidate(&self) -> Option<String> {
        let mut best: Option<(&str, &RepoLruEntry)> = None;
        for (key, entry) in self.entries.iter().filter(|(_, entry)| entry.is_evictable()) {
            best = match best {
                None => Some((key.as_str(), entry)),
                Some((best_key, best_entry)) => {
                    if compare_entries(key, entry, best_key, best_entry) == Ordering::Less {
                        Some((key.as_str(), entry))
                    } else {
                        Some((best_key, best_entry))
                    }
                }
            };
        }
        best.map(|(key, _)| key.to_string())
    }

    pub fn evict_lru(&mut self) -> Option<(String, RepoLruEntry)> {
        let candidate = self.eviction_candidate()?;
        self.entries.remove_entry(candidate.as_str())
    }

    fn next_access(&mut self) -> u64 {
        self.access_clock = self.access_clock.saturating_add(1);
        self.access_clock
    }

    fn next_open_seq(&mut self) -> u64 {
        self.open_clock = self.open_clock.saturating_add(1);
        self.open_clock
    }
}

fn compare_entries(a_key: &str, a: &RepoLruEntry, b_key: &str, b: &RepoLruEntry) -> Ordering {
    a.last_access
        .cmp(&b.last_access)
        .then_with(|| a.open_seq.cmp(&b.open_seq))
        .then_with(|| a_key.cmp(b_key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lru_selects_oldest_access() {
        let mut lru = RepoLru::new();
        lru.insert("alpha");
        lru.insert("bravo");
        lru.touch("alpha");
        assert_eq!(lru.eviction_candidate().as_deref(), Some("bravo"));
    }

    #[test]
    fn lru_tiebreaks_by_open_seq_then_key() {
        let mut lru = RepoLru::new();
        lru.entries.insert(
            "b".to_string(),
            RepoLruEntry {
                last_access: 5,
                open_seq: 2,
                in_use: 0,
                pinned: false,
            },
        );
        lru.entries.insert(
            "a".to_string(),
            RepoLruEntry {
                last_access: 5,
                open_seq: 2,
                in_use: 0,
                pinned: false,
            },
        );
        assert_eq!(lru.eviction_candidate().as_deref(), Some("a"));
    }

    #[test]
    fn lru_skips_ineligible_entries() {
        let mut lru = RepoLru::new();
        lru.entries.insert(
            "alpha".to_string(),
            RepoLruEntry {
                last_access: 1,
                open_seq: 1,
                in_use: 1,
                pinned: false,
            },
        );
        lru.entries.insert(
            "bravo".to_string(),
            RepoLruEntry {
                last_access: 2,
                open_seq: 2,
                in_use: 0,
                pinned: true,
            },
        );
        assert!(lru.eviction_candidate().is_none());
        lru.entries.get_mut("alpha").unwrap().in_use = 0;
        assert_eq!(lru.eviction_candidate().as_deref(), Some("alpha"));
    }
}
