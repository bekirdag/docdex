//! Retention for the on-disk state directory.
//!
//! Docdex writes per-repository state under `<state>/repos/<state_key>/` and
//! never removes it. Indexing a throwaway checkout — a CI clone, a temp
//! directory in a test — leaves its symbol database, AST rows, and Tantivy
//! segments resident forever. On a long-lived machine the majority of entries
//! can be repositories that no longer exist.
//!
//! Two kinds of state are reclaimable:
//!
//! * **Orphaned** — the registry knows the repository, but its `canonical_path`
//!   is gone from disk.
//! * **Unregistered** — a state directory with no registry entry at all, left
//!   by an interrupted mount or a registry rewrite.
//!
//! Everything else is left alone. This module never deletes state for a
//! repository that still exists, and never touches the shared databases at the
//! state root, whose ownership is not expressed in the registry.

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Why a repository state directory is considered reclaimable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReclaimReason {
    /// Registered, but the repository path no longer exists.
    Orphaned,
    /// Present on disk with no registry entry.
    Unregistered,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReclaimCandidate {
    pub state_key: String,
    pub path: PathBuf,
    pub bytes: u64,
    pub reason: ReclaimReason,
    /// Repository path from the registry, when one was recorded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_path: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct StatePruneReport {
    pub live_repos: usize,
    pub live_bytes: u64,
    pub candidates: Vec<ReclaimCandidate>,
}

impl StatePruneReport {
    pub fn reclaimable_bytes(&self) -> u64 {
        self.candidates.iter().map(|entry| entry.bytes).sum()
    }

    pub fn orphaned(&self) -> usize {
        self.count(ReclaimReason::Orphaned)
    }

    pub fn unregistered(&self) -> usize {
        self.count(ReclaimReason::Unregistered)
    }

    fn count(&self, reason: ReclaimReason) -> usize {
        self.candidates
            .iter()
            .filter(|entry| entry.reason == reason)
            .count()
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct StatePruneOutcome {
    pub removed: usize,
    pub removed_bytes: u64,
    pub failed: Vec<String>,
}

/// Registry entry keyed by `state_key`, mapping to the repository path.
fn load_registry(state_base: &Path) -> HashMap<String, Option<String>> {
    let path = state_base.join("repos").join("repo_registry.json");
    let Ok(raw) = fs::read_to_string(&path) else {
        return HashMap::new();
    };
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) else {
        return HashMap::new();
    };
    let Some(repos) = parsed.get("repos").and_then(|value| value.as_object()) else {
        return HashMap::new();
    };
    let mut out = HashMap::new();
    for (key, entry) in repos {
        let state_key = entry
            .get("state_key")
            .and_then(|value| value.as_str())
            .unwrap_or(key.as_str())
            .to_string();
        let canonical = entry
            .get("canonical_path")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string());
        out.insert(state_key, canonical);
    }
    out
}

fn directory_size(path: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(entries) = fs::read_dir(&current) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                stack.push(entry.path());
            } else if let Ok(meta) = entry.metadata() {
                total = total.saturating_add(meta.len());
            }
        }
    }
    total
}

/// Classify every repository state directory without changing anything.
pub fn analyze(state_base: &Path) -> Result<StatePruneReport> {
    let repos_dir = state_base.join("repos");
    let registry = load_registry(state_base);
    let mut report = StatePruneReport::default();
    let Ok(entries) = fs::read_dir(&repos_dir) else {
        return Ok(report);
    };

    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if !file_type.is_dir() {
            continue;
        }
        let path = entry.path();
        let Some(state_key) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        let state_key = state_key.to_string();
        match registry.get(&state_key) {
            // Registered and the repository is still on disk: keep.
            Some(Some(repo_path)) if Path::new(repo_path).exists() => {
                report.live_repos += 1;
                report.live_bytes = report.live_bytes.saturating_add(directory_size(&path));
            }
            Some(repo_path) => {
                let bytes = directory_size(&path);
                report.candidates.push(ReclaimCandidate {
                    state_key,
                    path,
                    bytes,
                    reason: ReclaimReason::Orphaned,
                    repo_path: repo_path.clone(),
                });
            }
            None => {
                let bytes = directory_size(&path);
                report.candidates.push(ReclaimCandidate {
                    state_key,
                    path,
                    bytes,
                    reason: ReclaimReason::Unregistered,
                    repo_path: None,
                });
            }
        }
    }

    // Largest first, so a partial run reclaims the most space.
    report.candidates.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    Ok(report)
}

/// Remove the reclaimable directories identified by [`analyze`].
///
/// Each path is re-checked against the repos directory before deletion, so a
/// stale or hand-edited report cannot be used to delete outside it.
pub fn apply(state_base: &Path, report: &StatePruneReport) -> Result<StatePruneOutcome> {
    let repos_dir = state_base
        .join("repos")
        .canonicalize()
        .with_context(|| format!("resolve {}", state_base.join("repos").display()))?;
    let mut outcome = StatePruneOutcome::default();
    for candidate in &report.candidates {
        let Ok(resolved) = candidate.path.canonicalize() else {
            continue;
        };
        if resolved.parent() != Some(repos_dir.as_path()) {
            outcome.failed.push(format!(
                "{}: refusing to remove a path outside {}",
                candidate.path.display(),
                repos_dir.display()
            ));
            continue;
        }
        match fs::remove_dir_all(&resolved) {
            Ok(()) => {
                outcome.removed += 1;
                outcome.removed_bytes = outcome.removed_bytes.saturating_add(candidate.bytes);
            }
            Err(err) => outcome
                .failed
                .push(format!("{}: {err}", candidate.path.display())),
        }
    }
    Ok(outcome)
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[0])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct Fixture {
        _root: TempDir,
        state_base: PathBuf,
        repos: PathBuf,
    }

    fn fixture() -> Fixture {
        let root = TempDir::new().expect("temp dir");
        let state_base = root.path().join("state");
        let repos = state_base.join("repos");
        fs::create_dir_all(&repos).expect("create repos dir");
        Fixture {
            _root: root,
            state_base,
            repos,
        }
    }

    fn write_repo_state(repos: &Path, key: &str, bytes: usize) {
        let dir = repos.join(key);
        fs::create_dir_all(dir.join("index")).expect("create state dir");
        fs::write(dir.join("symbols.db"), vec![b'x'; bytes]).expect("write db");
    }

    fn write_registry(state_base: &Path, entries: &[(&str, Option<&str>)]) {
        let repos: serde_json::Map<String, serde_json::Value> = entries
            .iter()
            .map(|(key, path)| {
                let mut entry = serde_json::Map::new();
                entry.insert("state_key".into(), serde_json::json!(key));
                if let Some(path) = path {
                    entry.insert("canonical_path".into(), serde_json::json!(path));
                }
                ((*key).to_string(), serde_json::Value::Object(entry))
            })
            .collect();
        let payload = serde_json::json!({ "version": 1, "repos": repos });
        fs::write(
            state_base.join("repos").join("repo_registry.json"),
            serde_json::to_vec(&payload).expect("serialize registry"),
        )
        .expect("write registry");
    }

    #[test]
    fn classifies_live_orphaned_and_unregistered_state() {
        let fx = fixture();
        let live_repo = TempDir::new().expect("live repo");

        write_repo_state(&fx.repos, "live", 100);
        write_repo_state(&fx.repos, "orphaned", 200);
        write_repo_state(&fx.repos, "unregistered", 300);
        write_registry(
            &fx.state_base,
            &[
                ("live", Some(live_repo.path().to_str().expect("path"))),
                ("orphaned", Some("/definitely/not/here/anymore")),
            ],
        );

        let report = analyze(&fx.state_base).expect("analyze");

        assert_eq!(report.live_repos, 1);
        assert_eq!(report.orphaned(), 1);
        assert_eq!(report.unregistered(), 1);
        // Largest candidate first so a partial run reclaims the most space.
        assert_eq!(report.candidates[0].state_key, "unregistered");
        assert!(report.reclaimable_bytes() >= 500);
    }

    #[test]
    fn analyze_never_proposes_state_for_a_repo_that_still_exists() {
        let fx = fixture();
        let live_repo = TempDir::new().expect("live repo");
        write_repo_state(&fx.repos, "live", 128);
        write_registry(
            &fx.state_base,
            &[("live", Some(live_repo.path().to_str().expect("path")))],
        );

        let report = analyze(&fx.state_base).expect("analyze");

        assert!(report.candidates.is_empty());
        assert_eq!(report.live_repos, 1);
    }

    #[test]
    fn apply_removes_only_the_reclaimable_directories() {
        let fx = fixture();
        let live_repo = TempDir::new().expect("live repo");
        write_repo_state(&fx.repos, "live", 100);
        write_repo_state(&fx.repos, "orphaned", 200);
        write_registry(
            &fx.state_base,
            &[
                ("live", Some(live_repo.path().to_str().expect("path"))),
                ("orphaned", Some("/gone")),
            ],
        );

        let report = analyze(&fx.state_base).expect("analyze");
        let outcome = apply(&fx.state_base, &report).expect("apply");

        assert_eq!(outcome.removed, 1);
        assert!(outcome.failed.is_empty());
        assert!(fx.repos.join("live").exists(), "live state must survive");
        assert!(!fx.repos.join("orphaned").exists());
        // The registry itself is never removed.
        assert!(fx.repos.join("repo_registry.json").exists());
    }

    #[test]
    fn apply_refuses_paths_outside_the_repos_directory() {
        let fx = fixture();
        let outsider = fx.state_base.join("not-repos");
        fs::create_dir_all(&outsider).expect("create outsider");

        let report = StatePruneReport {
            live_repos: 0,
            live_bytes: 0,
            candidates: vec![ReclaimCandidate {
                state_key: "escape".to_string(),
                path: outsider.clone(),
                bytes: 0,
                reason: ReclaimReason::Unregistered,
                repo_path: None,
            }],
        };
        let outcome = apply(&fx.state_base, &report).expect("apply");

        assert_eq!(outcome.removed, 0);
        assert_eq!(outcome.failed.len(), 1);
        assert!(outsider.exists(), "path outside repos/ must survive");
    }

    #[test]
    fn missing_registry_treats_everything_as_unregistered() {
        let fx = fixture();
        write_repo_state(&fx.repos, "a", 10);
        write_repo_state(&fx.repos, "b", 20);

        let report = analyze(&fx.state_base).expect("analyze");

        assert_eq!(report.live_repos, 0);
        assert_eq!(report.unregistered(), 2);
    }

    #[test]
    fn formats_byte_counts_for_reporting() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1536), "1.5 KiB");
        assert_eq!(format_bytes(18_253_611_008), "17.0 GiB");
    }
}
