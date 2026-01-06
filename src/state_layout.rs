use anyhow::{anyhow, Result};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::warn;

use crate::error::{
    repo_resolution_details, AppError, ERR_INVALID_ARGUMENT, ERR_MISSING_REPO_PATH,
    ERR_REPO_STATE_MISMATCH,
};

#[derive(Debug, Clone)]
pub struct StateLayout {
    base_dir: PathBuf,
}

#[derive(Debug, Clone)]
pub struct StatePaths {
    layout: StateLayout,
    repo_root: PathBuf,
    index_dir: PathBuf,
    libs_index_dir: PathBuf,
    memory_path: PathBuf,
    symbols_dir: PathBuf,
    dag_path: PathBuf,
    fingerprint: String,
    state_key: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StatePathsDebug {
    pub fingerprint: String,
    pub state_key: String,
    pub base_dir: String,
    pub repo_state_root: String,
    pub index_dir: String,
    pub libs_index_dir: String,
    pub memory_path: String,
    pub symbols_dir: String,
    pub dag_path: String,
    pub cache_web_dir: String,
    pub cache_libs_dir: String,
    pub profiles_dir: String,
    pub profiles_sync_dir: String,
    pub browser_profiles_dir: String,
    pub locks_dir: String,
    pub logs_dir: String,
}

struct StateBaseResolution {
    base_dir: PathBuf,
    scoped_state_key: Option<String>,
}

impl StateLayout {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    pub fn base_dir(&self) -> &Path {
        &self.base_dir
    }

    pub fn repos_dir(&self) -> PathBuf {
        self.base_dir.join("repos")
    }

    pub fn cache_dir(&self) -> PathBuf {
        self.base_dir.join("cache")
    }

    pub fn cache_web_dir(&self) -> PathBuf {
        self.cache_dir().join("web")
    }

    pub fn cache_libs_dir(&self) -> PathBuf {
        self.cache_dir().join("libs")
    }

    pub fn locks_dir(&self) -> PathBuf {
        self.base_dir.join("locks")
    }

    pub fn logs_dir(&self) -> PathBuf {
        self.base_dir.join("logs")
    }

    pub fn profiles_dir(&self) -> PathBuf {
        self.base_dir.join("profiles")
    }

    pub fn profiles_sync_dir(&self) -> PathBuf {
        self.profiles_dir().join("sync")
    }

    pub fn browser_profiles_dir(&self) -> PathBuf {
        self.base_dir.join("browser_profiles")
    }

    pub fn ensure_global_dirs(&self) -> Result<()> {
        ensure_state_dir_secure(&self.base_dir)?;
        ensure_state_dir_secure(&self.repos_dir())?;
        ensure_state_dir_secure(&self.cache_dir())?;
        ensure_state_dir_secure(&self.cache_web_dir())?;
        ensure_state_dir_secure(&self.cache_libs_dir())?;
        ensure_state_dir_secure(&self.profiles_dir())?;
        ensure_state_dir_secure(&self.profiles_sync_dir())?;
        ensure_state_dir_secure(&self.browser_profiles_dir())?;
        ensure_state_dir_secure(&self.locks_dir())?;
        ensure_state_dir_secure(&self.logs_dir())?;
        Ok(())
    }
}

impl StatePaths {
    pub fn layout(&self) -> &StateLayout {
        &self.layout
    }

    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    pub fn index_dir(&self) -> &Path {
        &self.index_dir
    }

    pub fn libs_index_dir(&self) -> &Path {
        &self.libs_index_dir
    }

    pub fn memory_path(&self) -> &Path {
        &self.memory_path
    }

    pub fn symbols_dir(&self) -> &Path {
        &self.symbols_dir
    }

    pub fn dag_path(&self) -> &Path {
        &self.dag_path
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn state_key(&self) -> &str {
        &self.state_key
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        self.layout.ensure_global_dirs()?;
        ensure_state_dir_secure(&self.repo_root)?;
        Ok(())
    }

    pub fn debug_report(&self) -> StatePathsDebug {
        StatePathsDebug {
            fingerprint: self.fingerprint.clone(),
            state_key: self.state_key.clone(),
            base_dir: self.layout.base_dir.display().to_string(),
            repo_state_root: self.repo_root.display().to_string(),
            index_dir: self.index_dir.display().to_string(),
            libs_index_dir: self.libs_index_dir.display().to_string(),
            memory_path: self.memory_path.display().to_string(),
            symbols_dir: self.symbols_dir.display().to_string(),
            dag_path: self.dag_path.display().to_string(),
            cache_web_dir: self.layout.cache_web_dir().display().to_string(),
            cache_libs_dir: self.layout.cache_libs_dir().display().to_string(),
            profiles_dir: self.layout.profiles_dir().display().to_string(),
            profiles_sync_dir: self.layout.profiles_sync_dir().display().to_string(),
            browser_profiles_dir: self.layout.browser_profiles_dir().display().to_string(),
            locks_dir: self.layout.locks_dir().display().to_string(),
            logs_dir: self.layout.logs_dir().display().to_string(),
        }
    }
}

pub fn resolve_state_paths(
    repo_root: &Path,
    state_dir_override: Option<PathBuf>,
) -> Result<StatePaths> {
    let repo_root = canonical_repo_root(repo_root)?;
    let base_resolution = resolve_state_base(&repo_root, state_dir_override)?;

    let fingerprint = crate::repo_manager::repo_fingerprint_sha256(&repo_root)?;
    let state_key =
        crate::repo_manager::resolve_shared_state_key(&repo_root, &base_resolution.base_dir)?
            .state_key;

    if let Some(scoped_key) = base_resolution.scoped_state_key {
        if scoped_key != state_key {
            let hint = base_resolution
                .base_dir
                .join("repos")
                .join(&scoped_key)
                .join("index");
            let identity = crate::repo_manager::RepoIdentityError::StateKeyConflict {
                fingerprint: fingerprint.clone(),
                existing_state_key: scoped_key,
                requested_state_key: state_key.clone(),
            };
            return Err(
                repo_state_mismatch_error(&repo_root, Some(hint.as_path()), &identity).into(),
            );
        }
    }

    let layout = StateLayout::new(base_resolution.base_dir);
    let repo_state_root = layout.repos_dir().join(&state_key);
    Ok(StatePaths {
        layout,
        repo_root: repo_state_root.clone(),
        index_dir: repo_state_root.join("index"),
        libs_index_dir: repo_state_root.join("libs_index"),
        memory_path: repo_state_root.join("memory.db"),
        symbols_dir: repo_state_root.join("symbols.db"),
        dag_path: repo_state_root.join("dag.db"),
        fingerprint,
        state_key,
    })
}

pub(crate) fn resolve_state_paths_for_inspect(
    repo_root: &Path,
    state_dir_override: Option<PathBuf>,
) -> Result<StatePaths> {
    let repo_root = canonical_repo_root(repo_root)?;
    let base_resolution = resolve_state_base(&repo_root, state_dir_override)?;

    let fingerprint = crate::repo_manager::repo_fingerprint_sha256(&repo_root)?;
    let state_key = crate::repo_manager::resolve_shared_state_key_lenient(
        &repo_root,
        &base_resolution.base_dir,
    )?
    .state_key;

    let layout = StateLayout::new(base_resolution.base_dir);
    let repo_state_root = layout.repos_dir().join(&state_key);
    Ok(StatePaths {
        layout,
        repo_root: repo_state_root.clone(),
        index_dir: repo_state_root.join("index"),
        libs_index_dir: repo_state_root.join("libs_index"),
        memory_path: repo_state_root.join("memory.db"),
        symbols_dir: repo_state_root.join("symbols.db"),
        dag_path: repo_state_root.join("dag.db"),
        fingerprint,
        state_key,
    })
}

fn resolve_state_base(
    repo_root: &Path,
    state_dir_override: Option<PathBuf>,
) -> Result<StateBaseResolution> {
    let resolved = match state_dir_override {
        Some(custom) => {
            if custom.is_absolute() {
                custom
            } else {
                repo_root.join(custom)
            }
        }
        None => default_state_root()?,
    };

    if let Some((base_dir, scoped_key, _)) = crate::repo_manager::split_scoped_state_dir(&resolved)
    {
        return Ok(StateBaseResolution {
            base_dir,
            scoped_state_key: scoped_key,
        });
    }

    Ok(StateBaseResolution {
        base_dir: resolved,
        scoped_state_key: None,
    })
}

fn default_state_root() -> Result<PathBuf> {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
        .or_else(|| {
            let drive = std::env::var_os("HOMEDRIVE")?;
            let path = std::env::var_os("HOMEPATH")?;
            Some(PathBuf::from(drive).join(path))
        })
        .ok_or_else(|| anyhow!("HOME not set"))?;
    Ok(home.join(".docdex").join("state"))
}

fn canonical_repo_root(repo_root: &Path) -> Result<PathBuf> {
    if !repo_root.exists() {
        return Err(missing_repo_path_error(repo_root).into());
    }
    if !repo_root.is_dir() {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("repo root is not a directory: {}", repo_root.display()),
        )
        .into());
    }
    Ok(repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf()))
}

pub(crate) fn ensure_state_dir_secure(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;
        use std::os::unix::fs::PermissionsExt;

        let mut builder = DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder.create(path)?;
        let metadata = fs::metadata(path)?;
        let current = metadata.permissions().mode() & 0o777;
        if current != 0o700 {
            let mut perms = metadata.permissions();
            perms.set_mode(0o700);
            if let Err(err) = fs::set_permissions(path, perms) {
                let is_perm_err = err.kind() == std::io::ErrorKind::PermissionDenied
                    || err.raw_os_error() == Some(1);
                if is_perm_err && can_write_dir(path) {
                    warn!(
                        target: "docdexd",
                        error = %err,
                        "state dir permissions could not be tightened; continuing with existing perms"
                    );
                } else {
                    return Err(err.into());
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

fn can_write_dir(path: &Path) -> bool {
    let probe = path.join(format!(
        ".docdex-perm-check-{}",
        std::process::id()
    ));
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn normalize_for_error(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn known_canonical_path_from_repo_meta(index_state_dir: &Path) -> Option<String> {
    if index_state_dir.file_name().and_then(|s| s.to_str())? != "index" {
        return None;
    }
    let state_key_dir = index_state_dir.parent()?;
    let state_key = state_key_dir.file_name()?.to_string_lossy().to_string();
    let repos_dir = state_key_dir.parent()?;
    if repos_dir.file_name().and_then(|s| s.to_str())? != "repos" {
        return None;
    }
    let base_dir = repos_dir.parent()?;
    let registry_path = base_dir.join("repos").join("repo_registry.json");
    if let Ok(raw) = fs::read_to_string(&registry_path) {
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(repos) = parsed.get("repos").and_then(|v| v.as_object()) {
                for entry in repos.values() {
                    let entry_state_key = entry.get("state_key").and_then(|v| v.as_str())?;
                    if entry_state_key == state_key {
                        return entry
                            .get("canonical_path")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string());
                    }
                }
            }
        }
    }
    None
}

fn canonical_path_from_repo_meta(repo_root: &Path) -> Option<String> {
    let meta_path = repo_root.join("repo_meta.json");
    let raw = fs::read_to_string(&meta_path).ok()?;
    let parsed = serde_json::from_str::<serde_json::Value>(&raw).ok()?;
    parsed
        .get("canonical_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

pub(crate) fn missing_repo_path_error(repo_root: &Path) -> AppError {
    AppError::new(ERR_MISSING_REPO_PATH, "repo path not found").with_details(repo_resolution_details(
        normalize_for_error(repo_root),
        None,
        None,
        vec![
            "Repo may have moved or been renamed.".to_string(),
            "Re-run with the repo's current path.".to_string(),
            "If you previously indexed this repo, you may need to reindex after moving it: `docdexd index --repo <repo>`."
                .to_string(),
        ],
    ))
}

pub(crate) fn repo_state_mismatch_error(
    repo_root: &Path,
    index_state_dir: Option<&Path>,
    identity: &crate::repo_manager::RepoIdentityError,
) -> AppError {
    let attempted_fingerprint = crate::repo_manager::repo_fingerprint_sha256(repo_root).ok();
    let mut known_canonical_path = index_state_dir.and_then(known_canonical_path_from_repo_meta);
    if known_canonical_path.is_none() {
        known_canonical_path = canonical_path_from_repo_meta(repo_root);
    }
    if let crate::repo_manager::RepoIdentityError::CanonicalPathCollision {
        canonical_path, ..
    } = identity
    {
        known_canonical_path = Some(canonical_path.clone());
    }
    if let crate::repo_manager::RepoIdentityError::ReassociationRequired {
        registered_canonical_path,
        ..
    } = identity
    {
        known_canonical_path = Some(registered_canonical_path.clone());
    }
    AppError::new(
        ERR_REPO_STATE_MISMATCH,
        "repo state mismatch; refusing to associate this repo with the existing state directory",
    )
    .with_details(repo_resolution_details(
        normalize_for_error(repo_root),
        attempted_fingerprint,
        known_canonical_path,
        vec![
            "Repo may have moved or been renamed.".to_string(),
            "Verify you are using the correct `--repo` and `--state-dir` combination.".to_string(),
            "Run: `docdexd repo inspect --repo <repo> --state-dir <shared_state_dir>` to see the repo fingerprint and any known canonical/alias mappings.".to_string(),
            "To explicitly re-associate a moved repo to existing shared state, run: `docdexd repo reassociate --repo <new_path> --state-dir <shared_state_dir> --old-path <knownCanonicalPath>` (or `--fingerprint <attemptedFingerprint>`)."
                .to_string(),
            "Do not reuse a shared `--state-dir` across unrelated repos; choose a different state dir or clear the conflicting state."
                .to_string(),
        ],
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_repo(dir: &Path) -> Result<()> {
        fs::create_dir_all(dir)?;
        fs::create_dir_all(dir.join(".git"))?;
        Ok(())
    }

    #[test]
    fn resolves_paths_under_state_root() -> Result<()> {
        let repo = TempDir::new()?;
        create_repo(repo.path())?;
        let state_root = TempDir::new()?;

        let paths = resolve_state_paths(repo.path(), Some(state_root.path().to_path_buf()))?;
        let fingerprint = crate::repo_manager::repo_fingerprint_sha256(repo.path())?;
        let expected_index = state_root
            .path()
            .join("repos")
            .join(&fingerprint)
            .join("index");

        assert_eq!(paths.state_key(), fingerprint);
        assert_eq!(paths.index_dir(), expected_index);
        Ok(())
    }

    #[test]
    fn ensure_dirs_creates_global_and_repo_roots() -> Result<()> {
        let repo = TempDir::new()?;
        create_repo(repo.path())?;
        let state_root = TempDir::new()?;

        let paths = resolve_state_paths(repo.path(), Some(state_root.path().to_path_buf()))?;
        paths.ensure_dirs()?;

        assert!(paths.layout().base_dir().exists());
        assert!(paths.layout().cache_web_dir().exists());
        assert!(paths.layout().cache_libs_dir().exists());
        assert!(paths.layout().browser_profiles_dir().exists());
        assert!(paths.layout().locks_dir().exists());
        assert!(paths.layout().logs_dir().exists());
        assert!(paths.repo_root().exists());
        assert!(
            !paths.index_dir().exists(),
            "index dir should not be created during state root initialization"
        );
        Ok(())
    }

    #[test]
    fn scoped_override_mismatch_errors() -> Result<()> {
        let repo_a = TempDir::new()?;
        let repo_b = TempDir::new()?;
        create_repo(repo_a.path())?;
        create_repo(repo_b.path())?;
        let state_root = TempDir::new()?;

        let paths_a = resolve_state_paths(repo_a.path(), Some(state_root.path().to_path_buf()))?;
        let scoped = state_root
            .path()
            .join("repos")
            .join(paths_a.state_key())
            .join("index");
        let err = resolve_state_paths(repo_b.path(), Some(scoped)).unwrap_err();
        let app = err.downcast_ref::<AppError>().expect("expected AppError");
        assert_eq!(app.code, ERR_REPO_STATE_MISMATCH);
        Ok(())
    }
}
