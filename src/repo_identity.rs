use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum RepoIdentityError {
    #[error("repo state metadata fingerprint mismatch (state_key={state_key}): expected {expected_fingerprint}, found {found_fingerprint}")]
    StateMetaFingerprintMismatch {
        state_key: String,
        expected_fingerprint: String,
        found_fingerprint: String,
    },
    #[error("canonical path `{canonical_path}` is already associated with a different repo fingerprint `{other_fingerprint}`")]
    CanonicalPathCollision {
        canonical_path: String,
        other_fingerprint: String,
    },
    #[error("repo fingerprint `{fingerprint}` is already mapped to state_key `{existing_state_key}`; refusing to remap to `{requested_state_key}`")]
    StateKeyConflict {
        fingerprint: String,
        existing_state_key: String,
        requested_state_key: String,
    },
    #[error("failed to persist repo registry at {path}: {source}")]
    PersistFailed {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[derive(Debug, Clone)]
pub struct RepoStateKeyResolution {
    pub state_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RepoRegistryFile {
    version: u32,
    repos: BTreeMap<String, RepoRegistryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepoRegistryEntry {
    state_key: String,
    canonical_path: String,
    #[serde(default)]
    prior_paths: Vec<String>,
    #[serde(default)]
    last_seen_at_epoch_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepoStateMetaV1 {
    version: u32,
    fingerprint_sha256: String,
    canonical_path: String,
    #[serde(default)]
    created_at_epoch_ms: i64,
    #[serde(default)]
    last_seen_at_epoch_ms: i64,
}

const REPO_REGISTRY_VERSION: u32 = 1;
const REPO_META_VERSION: u32 = 1;
const REPO_REGISTRY_FILENAME: &str = "repo_registry.json";
const REPO_META_FILENAME: &str = "repo_meta.json";

pub fn legacy_repo_id_for_root(repo_root: &Path) -> String {
    let normalized = normalize_path(repo_root);
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

pub fn repo_fingerprint_sha256(repo_root: &Path) -> Result<String> {
    let target = git_identity_target(repo_root);
    let payload = file_identity_payload(&target).with_context(|| {
        format!(
            "read filesystem identity for {}",
            target.to_string_lossy()
        )
    })?;
    Ok(hex::encode(Sha256::digest(payload.as_bytes())))
}

pub fn resolve_shared_state_key(repo_root: &Path, shared_base_dir: &Path) -> Result<RepoStateKeyResolution> {
    let fingerprint = repo_fingerprint_sha256(repo_root)?;
    let registry_path = repo_registry_path(shared_base_dir);
    let registry = load_registry(&registry_path)?;

    let mut state_key = if let Some(entry) = registry.repos.get(&fingerprint) {
        entry.state_key.clone()
    } else {
        fingerprint.clone()
    };

    // Back-compat: if registry doesn't know this repo yet, prefer existing on-disk state dirs.
    if !registry.repos.contains_key(&fingerprint) {
        let preferred = shared_repo_root_dir(shared_base_dir, &fingerprint);
        let legacy = legacy_repo_id_for_root(repo_root);
        let legacy_dir = shared_repo_root_dir(shared_base_dir, &legacy);
        if preferred.join("index").exists() {
            state_key = fingerprint.clone();
        } else if legacy_dir.join("index").exists() {
            state_key = legacy;
        } else {
            state_key = fingerprint.clone();
        }
    }

    // Fast-fail on explicit mismatches when metadata exists.
    validate_state_meta(shared_base_dir, &state_key, &fingerprint)?;

    Ok(RepoStateKeyResolution {
        state_key,
    })
}

pub fn resolve_shared_index_state_dir(repo_root: &Path, custom_state_dir: &Path) -> Result<PathBuf> {
    let (base_dir, maybe_scoped_key, scoped_has_index) =
        split_scoped_state_dir(custom_state_dir).unwrap_or_else(|| (custom_state_dir.to_path_buf(), None, false));

    let resolution = resolve_shared_state_key(repo_root, &base_dir)?;
    let expected = resolution.state_key.clone();

    if let Some(scoped_key) = maybe_scoped_key {
        if scoped_key == expected {
            if scoped_has_index {
                return Ok(custom_state_dir.to_path_buf());
            }
            return Ok(custom_state_dir.join("index"));
        }
    }

    Ok(shared_repo_root_dir(&base_dir, &expected).join("index"))
}

pub fn record_repo_opened(repo_root: &Path, index_state_dir: &Path) -> Result<()> {
    let Some((base_dir, state_key)) = base_dir_and_state_key_from_index_dir(index_state_dir) else {
        return Ok(());
    };

    let fingerprint = repo_fingerprint_sha256(repo_root)?;
    validate_state_meta(&base_dir, &state_key, &fingerprint)?;

    let canonical_path = normalize_path(repo_root);
    let now_ms = chrono::Utc::now().timestamp_millis();
    let registry_path = repo_registry_path(&base_dir);
    fs::create_dir_all(registry_path.parent().expect("registry parent"))
        .with_context(|| format!("create {}", registry_path.parent().unwrap().display()))?;

    let mut registry = load_registry(&registry_path)?;

    if let Some((other_fp, _)) = registry
        .repos
        .iter()
        .find(|(fp, entry)| fp.as_str() != fingerprint.as_str() && entry.canonical_path == canonical_path)
    {
        return Err(RepoIdentityError::CanonicalPathCollision {
            canonical_path,
            other_fingerprint: other_fp.to_string(),
        }
        .into());
    }

    let entry = registry.repos.entry(fingerprint.clone()).or_insert_with(|| RepoRegistryEntry {
        state_key: state_key.clone(),
        canonical_path: canonical_path.clone(),
        prior_paths: Vec::new(),
        last_seen_at_epoch_ms: now_ms,
    });

    if entry.state_key != state_key {
        return Err(RepoIdentityError::StateKeyConflict {
            fingerprint,
            existing_state_key: entry.state_key.clone(),
            requested_state_key: state_key,
        }
        .into());
    }

    if entry.canonical_path != canonical_path {
        if !entry.prior_paths.contains(&entry.canonical_path) {
            entry.prior_paths.push(entry.canonical_path.clone());
        }
        entry.canonical_path = canonical_path.clone();
    }
    entry.last_seen_at_epoch_ms = now_ms;

    write_repo_meta(&base_dir, &entry.state_key, &fingerprint, &canonical_path, now_ms)?;
    save_registry_atomic(&registry_path, &registry)?;

    Ok(())
}

pub fn validate_repo_state_dir(repo_root: &Path, index_state_dir: &Path) -> Result<()> {
    let Some((base_dir, state_key)) = base_dir_and_state_key_from_index_dir(index_state_dir) else {
        return Ok(());
    };
    let fingerprint = repo_fingerprint_sha256(repo_root)?;
    validate_state_meta(&base_dir, &state_key, &fingerprint)?;

    let registry_path = repo_registry_path(&base_dir);
    let registry = load_registry(&registry_path)?;
    if let Some(entry) = registry.repos.get(&fingerprint) {
        if entry.state_key != state_key {
            return Err(RepoIdentityError::StateKeyConflict {
                fingerprint: fingerprint.clone(),
                existing_state_key: entry.state_key.clone(),
                requested_state_key: state_key,
            }
            .into());
        }
    }

    let canonical_path = normalize_path(repo_root);
    if let Some((other_fp, _)) = registry
        .repos
        .iter()
        .find(|(fp, entry)| fp.as_str() != fingerprint.as_str() && entry.canonical_path == canonical_path)
    {
        return Err(RepoIdentityError::CanonicalPathCollision {
            canonical_path,
            other_fingerprint: other_fp.to_string(),
        }
        .into());
    }

    Ok(())
}

fn normalize_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
}

fn repo_registry_path(shared_base_dir: &Path) -> PathBuf {
    shared_base_dir.join("repos").join(REPO_REGISTRY_FILENAME)
}

fn shared_repo_root_dir(shared_base_dir: &Path, state_key: &str) -> PathBuf {
    shared_base_dir.join("repos").join(state_key)
}

fn repo_meta_path(shared_base_dir: &Path, state_key: &str) -> PathBuf {
    shared_repo_root_dir(shared_base_dir, state_key).join(REPO_META_FILENAME)
}

fn load_registry(path: &Path) -> Result<RepoRegistryFile> {
    let data = match fs::read_to_string(path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(RepoRegistryFile {
                version: REPO_REGISTRY_VERSION,
                repos: BTreeMap::new(),
            })
        }
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    let mut parsed: RepoRegistryFile = serde_json::from_str(&data).with_context(|| format!("parse {}", path.display()))?;
    if parsed.version == 0 {
        parsed.version = REPO_REGISTRY_VERSION;
    }
    Ok(parsed)
}

fn save_registry_atomic(path: &Path, registry: &RepoRegistryFile) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(registry).context("serialize repo registry")?;
    let tmp = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    fs::rename(&tmp, path).map_err(|err| RepoIdentityError::PersistFailed {
        path: path.to_path_buf(),
        source: err,
    })?;
    Ok(())
}

fn validate_state_meta(shared_base_dir: &Path, state_key: &str, expected_fingerprint: &str) -> Result<()> {
    let path = repo_meta_path(shared_base_dir, state_key);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err).with_context(|| format!("read {}", path.display())),
    };
    let parsed: RepoStateMetaV1 = serde_json::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    if parsed.fingerprint_sha256 != expected_fingerprint {
        return Err(RepoIdentityError::StateMetaFingerprintMismatch {
            state_key: state_key.to_string(),
            expected_fingerprint: expected_fingerprint.to_string(),
            found_fingerprint: parsed.fingerprint_sha256,
        }
        .into());
    }
    Ok(())
}

fn write_repo_meta(
    shared_base_dir: &Path,
    state_key: &str,
    fingerprint: &str,
    canonical_path: &str,
    now_ms: i64,
) -> Result<()> {
    let path = repo_meta_path(shared_base_dir, state_key);
    fs::create_dir_all(
        path.parent()
            .expect("repo meta parent"),
    )
    .with_context(|| format!("create {}", path.parent().unwrap().display()))?;

    let mut created_at = now_ms;
    if let Ok(raw) = fs::read_to_string(&path) {
        if let Ok(existing) = serde_json::from_str::<RepoStateMetaV1>(&raw) {
            if existing.version == REPO_META_VERSION && existing.fingerprint_sha256 == fingerprint {
                created_at = existing.created_at_epoch_ms.max(1);
            }
        }
    }

    let payload = RepoStateMetaV1 {
        version: REPO_META_VERSION,
        fingerprint_sha256: fingerprint.to_string(),
        canonical_path: canonical_path.to_string(),
        created_at_epoch_ms: created_at,
        last_seen_at_epoch_ms: now_ms,
    };
    let bytes = serde_json::to_vec_pretty(&payload).context("serialize repo meta")?;
    let tmp = path.with_extension(format!("tmp.{}", uuid::Uuid::new_v4()));
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    if path.exists() {
        let _ = fs::remove_file(&path);
    }
    fs::rename(&tmp, &path).with_context(|| format!("rename {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

fn base_dir_and_state_key_from_index_dir(index_state_dir: &Path) -> Option<(PathBuf, String)> {
    if index_state_dir.file_name().and_then(|s| s.to_str())? != "index" {
        return None;
    }
    let state_key_dir = index_state_dir.parent()?;
    let state_key = state_key_dir.file_name()?.to_string_lossy().to_string();
    let repos_dir = state_key_dir.parent()?;
    if repos_dir.file_name().and_then(|s| s.to_str())? != "repos" {
        return None;
    }
    let base_dir = repos_dir.parent()?.to_path_buf();
    Some((base_dir, state_key))
}

fn split_scoped_state_dir(custom_state_dir: &Path) -> Option<(PathBuf, Option<String>, bool)> {
    let name = custom_state_dir.file_name()?.to_string_lossy();
    if name == "index" {
        let state_key_dir = custom_state_dir.parent()?;
        let state_key = state_key_dir.file_name()?.to_string_lossy().to_string();
        let repos_dir = state_key_dir.parent()?;
        if repos_dir.file_name().and_then(|s| s.to_str())? != "repos" {
            return None;
        }
        let base_dir = repos_dir.parent()?.to_path_buf();
        return Some((base_dir, Some(state_key), true));
    }

    let state_key = name.to_string();
    let repos_dir = custom_state_dir.parent()?;
    if repos_dir.file_name().and_then(|s| s.to_str())? != "repos" {
        return None;
    }
    let base_dir = repos_dir.parent()?.to_path_buf();
    Some((base_dir, Some(state_key), false))
}

fn git_identity_target(repo_root: &Path) -> PathBuf {
    let dot_git = repo_root.join(".git");
    let Ok(meta) = fs::metadata(&dot_git) else {
        return repo_root.to_path_buf();
    };
    if meta.is_dir() {
        return dot_git;
    }
    if !meta.is_file() {
        return repo_root.to_path_buf();
    }
    let Ok(contents) = fs::read_to_string(&dot_git) else {
        return repo_root.to_path_buf();
    };
    let line = contents.lines().next().unwrap_or_default().trim();
    let Some(rest) = line.strip_prefix("gitdir:") else {
        return repo_root.to_path_buf();
    };
    let rest = rest.trim();
    if rest.is_empty() {
        return repo_root.to_path_buf();
    }
    let candidate = PathBuf::from(rest);
    if candidate.is_absolute() {
        return candidate;
    }
    repo_root.join(candidate)
}

fn file_identity_payload(path: &Path) -> Result<String> {
    let meta = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        return Ok(format!(
            "v1|unix|dev={}|ino={}|is_dir={}",
            meta.dev(),
            meta.ino(),
            meta.is_dir()
        ));
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let vsn = meta.volume_serial_number().unwrap_or(0);
        let file_index = meta.file_index().unwrap_or(0);
        return Ok(format!(
            "v1|windows|volume_serial_number={vsn}|file_index={file_index}|is_dir={}",
            meta.is_dir()
        ));
    }

    #[cfg(not(any(unix, windows)))]
    {
        let normalized = normalize_path(path);
        Ok(format!("v1|path|{}", normalized))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_git_repo(dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)?;
        fs::create_dir_all(dir.join(".git"))?;
        fs::write(dir.join("readme.md"), "# Repo\n")?;
        Ok(())
    }

    #[test]
    fn fingerprint_stable_across_rename_when_git_dir_preserved() -> Result<()> {
        let base = TempDir::new()?;
        let repo_a = base.path().join("repo-a");
        let repo_b = base.path().join("repo-b");
        create_git_repo(&repo_a)?;

        let fp1 = repo_fingerprint_sha256(&repo_a)?;
        fs::rename(&repo_a, &repo_b)?;
        let fp2 = repo_fingerprint_sha256(&repo_b)?;
        assert_eq!(fp1, fp2);
        Ok(())
    }

    #[test]
    fn registry_updates_canonical_path_and_keeps_state_key() -> Result<()> {
        let base = TempDir::new()?;
        let shared = base.path().join("state");
        fs::create_dir_all(shared.join("repos"))?;

        let repo_root = base.path().join("repo-a");
        create_git_repo(&repo_root)?;
        let fingerprint = repo_fingerprint_sha256(&repo_root)?;

        let resolution = resolve_shared_state_key(&repo_root, &shared)?;
        let state_key = resolution.state_key.clone();
        fs::create_dir_all(shared_repo_root_dir(&shared, &state_key).join("index"))?;

        record_repo_opened(&repo_root, &shared_repo_root_dir(&shared, &state_key).join("index"))?;
        let registry = load_registry(&repo_registry_path(&shared))?;
        assert!(registry.repos.contains_key(&fingerprint));
        assert_eq!(
            registry.repos.get(&fingerprint).unwrap().state_key,
            state_key
        );

        let moved = base.path().join("repo-moved");
        fs::rename(&repo_root, &moved)?;
        record_repo_opened(&moved, &shared_repo_root_dir(&shared, &state_key).join("index"))?;
        let registry2 = load_registry(&repo_registry_path(&shared))?;
        let entry = registry2.repos.get(&fingerprint).unwrap();
        assert_eq!(entry.state_key, state_key);
        assert_eq!(entry.canonical_path, normalize_path(&moved));
        assert!(!entry.prior_paths.is_empty());
        Ok(())
    }

    #[test]
    fn canonical_path_collision_is_rejected() -> Result<()> {
        let base = TempDir::new()?;
        let shared = base.path().join("state");
        fs::create_dir_all(shared.join("repos"))?;

        let repo_a = base.path().join("repo-a");
        let repo_b = base.path().join("repo-b");
        create_git_repo(&repo_a)?;
        create_git_repo(&repo_b)?;
        let fp_a = repo_fingerprint_sha256(&repo_a)?;

        let res_a = resolve_shared_state_key(&repo_a, &shared)?;
        let res_b = resolve_shared_state_key(&repo_b, &shared)?;

        let state_a = shared_repo_root_dir(&shared, &res_a.state_key).join("index");
        let state_b = shared_repo_root_dir(&shared, &res_b.state_key).join("index");
        fs::create_dir_all(&state_a)?;
        fs::create_dir_all(&state_b)?;

        record_repo_opened(&repo_a, &state_a)?;

        // Force collision by corrupting repo A's registry entry to claim repo B's canonical path.
        let mut registry = load_registry(&repo_registry_path(&shared))?;
        let entry_a = registry
            .repos
            .get_mut(&fp_a)
            .expect("repo A entry");
        entry_a.canonical_path = normalize_path(&repo_b);
        save_registry_atomic(&repo_registry_path(&shared), &registry)?;

        let err = record_repo_opened(&repo_b, &state_b).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("canonical path") && msg.contains("already associated"),
            "unexpected error: {msg}"
        );
        Ok(())
    }
}
