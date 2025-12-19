<<<<<<< HEAD
use anyhow::{anyhow, Context, Result};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::fs::DirBuilder;
use std::path::{Path, PathBuf};

const GLOBAL_STATE_DIR_ENV: &str = "DOCDEX_GLOBAL_STATE_DIR";

#[derive(Debug, Clone)]
pub struct StatePaths {
    global_root: PathBuf,
}

impl StatePaths {
    pub fn new() -> Result<Self> {
        let global_root = resolve_global_state_root()?;
        Ok(Self { global_root })
    }

    pub fn from_root(global_root: PathBuf) -> Self {
        Self { global_root }
    }

    pub fn global_root(&self) -> &Path {
        &self.global_root
    }

    pub fn cache_root(&self) -> Result<PathBuf> {
        let path = self.global_root.join("cache");
        ensure_dir_secure(&path)?;
        Ok(path)
    }

    pub fn locks_root(&self) -> Result<PathBuf> {
        let path = self.global_root.join("locks");
        ensure_dir_secure(&path)?;
        Ok(path)
    }

    pub fn repo_cache_dir(&self, repo_root: &Path, cache_name: &str) -> Result<PathBuf> {
        let repo_key = repo_key(repo_root)?;
        let path = self.cache_root()?.join(cache_name).join(&repo_key);
        ensure_dir_secure(&path)?;
        self.assert_repo_scoped_cache_dir(cache_name, &path)?;
        Ok(path)
    }

    pub fn repo_lock_path(&self, repo_root: &Path, lock_name: &str) -> Result<PathBuf> {
        let repo_key = repo_key(repo_root)?;
        let locks_root = self.locks_root()?;
        Ok(locks_root.join(format!("{repo_key}-{lock_name}")))
    }

    pub fn assert_repo_scoped_cache_dir(&self, cache_name: &str, cache_dir: &Path) -> Result<()> {
        let cache_root = self.cache_root()?;
        if !cache_dir.starts_with(&cache_root) {
            return Ok(());
        }
        let rel = cache_dir
            .strip_prefix(&cache_root)
            .context("cache dir missing cache root prefix")?;
        let mut components = rel.components();
        let Some(cache_component) = components.next() else {
            return Err(anyhow!("cache dir missing cache name segment"));
        };
        if cache_component.as_os_str() != OsStr::new(cache_name) {
            return Err(anyhow!(
                "cache dir missing expected cache namespace: expected {cache_name}"
            ));
        }
        let Some(repo_component) = components.next() else {
            return Err(anyhow!("cache dir missing repo namespace segment"));
        };
        let repo_component = repo_component.as_os_str().to_string_lossy();
        if !repo_component.starts_with("repo-") {
            return Err(anyhow!(
                "cache dir missing repo scope prefix (expected repo-*)"
=======
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};
use tracing::warn;

const REPOS_DIRNAME: &str = "repos";
const REPO_REGISTRY_FILENAME: &str = "repo_registry.json";
const REPO_META_FILENAME: &str = "repo_meta.json";

#[derive(Clone, Debug)]
pub struct StatePaths {
    base_dir: PathBuf,
}

impl StatePaths {
    pub fn new(base_dir: PathBuf) -> Self {
        Self { base_dir }
    }

    pub fn repos_dir(&self) -> PathBuf {
        self.base_dir.join(REPOS_DIRNAME)
    }

    pub fn repo_root(&self, state_key: &str) -> PathBuf {
        self.repos_dir().join(state_key)
    }

    pub fn repo_index_dir(&self, state_key: &str) -> PathBuf {
        self.repo_root(state_key).join("index")
    }

    pub fn repo_meta_path(&self, state_key: &str) -> PathBuf {
        self.repo_root(state_key).join(REPO_META_FILENAME)
    }

    pub fn repo_registry_path(&self) -> PathBuf {
        self.repos_dir().join(REPO_REGISTRY_FILENAME)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepoStateLayout {
    Scoped,
    LegacyIndexDir,
}

#[derive(Clone, Debug)]
pub struct RepoStatePaths {
    base_dir: PathBuf,
    repo_state_dir: PathBuf,
    index_dir: PathBuf,
    layout: RepoStateLayout,
}

impl RepoStatePaths {
    pub fn scoped(base_dir: PathBuf, index_dir: PathBuf) -> Result<Self> {
        let repo_state_dir = index_dir.parent().unwrap_or(&index_dir).to_path_buf();
        let paths = Self {
            base_dir,
            repo_state_dir,
            index_dir,
            layout: RepoStateLayout::Scoped,
        };
        paths.validate_scoped()?;
        Ok(paths)
    }

    pub fn legacy(index_dir: PathBuf) -> Self {
        Self {
            base_dir: index_dir.clone(),
            repo_state_dir: index_dir.clone(),
            index_dir,
            layout: RepoStateLayout::LegacyIndexDir,
        }
    }

    pub fn repo_state_dir(&self) -> &Path {
        &self.repo_state_dir
    }

    pub fn index_dir(&self) -> &Path {
        &self.index_dir
    }

    pub fn log_if_unexpected(&self) {
        match self.layout {
            RepoStateLayout::LegacyIndexDir => {
                warn!(
                    target: "docdexd",
                    state_dir = %self.index_dir.display(),
                    "using legacy in-repo state dir; repo-scoped state root disabled"
                );
            }
            RepoStateLayout::Scoped => {
                let expected_repos_dir = self.base_dir.join(REPOS_DIRNAME);
                if !self.repo_state_dir.starts_with(&expected_repos_dir) {
                    warn!(
                        target: "docdexd",
                        repo_state_dir = %self.repo_state_dir.display(),
                        expected_repos_dir = %expected_repos_dir.display(),
                        "repo state dir is outside expected scoped repos directory"
                    );
                }
                if !self.index_dir.starts_with(&self.repo_state_dir) {
                    warn!(
                        target: "docdexd",
                        index_dir = %self.index_dir.display(),
                        repo_state_dir = %self.repo_state_dir.display(),
                        "index dir is outside repo state root"
                    );
                }
            }
        }
    }

    fn validate_scoped(&self) -> Result<()> {
        let expected_repos_dir = self.base_dir.join(REPOS_DIRNAME);
        if !self.repo_state_dir.starts_with(&expected_repos_dir) {
            warn!(
                target: "docdexd",
                repo_state_dir = %self.repo_state_dir.display(),
                expected_repos_dir = %expected_repos_dir.display(),
                "repo state dir is outside expected scoped repos directory"
            );
            return Err(anyhow!(
                "repo state dir {} is outside scoped base {}",
                self.repo_state_dir.display(),
                expected_repos_dir.display()
            ));
        }
        if !self.index_dir.starts_with(&self.repo_state_dir) {
            warn!(
                target: "docdexd",
                index_dir = %self.index_dir.display(),
                repo_state_dir = %self.repo_state_dir.display(),
                "index dir is outside repo state root"
            );
            return Err(anyhow!(
                "index dir {} is outside repo state root {}",
                self.index_dir.display(),
                self.repo_state_dir.display()
>>>>>>> mcoda/task/ops-01-us-03-t04
            ));
        }
        Ok(())
    }
}

<<<<<<< HEAD
fn resolve_global_state_root() -> Result<PathBuf> {
    if let Ok(value) = env::var(GLOBAL_STATE_DIR_ENV) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    let home = resolve_home_dir()
        .ok_or_else(|| anyhow!("unable to resolve home directory for global state paths"))?;
    Ok(home.join(".docdex").join("state"))
}

fn resolve_home_dir() -> Option<PathBuf> {
    if let Some(home) = env::var_os("HOME") {
        return Some(PathBuf::from(home));
    }
    if let Some(profile) = env::var_os("USERPROFILE") {
        return Some(PathBuf::from(profile));
    }
    match (env::var_os("HOMEDRIVE"), env::var_os("HOMEPATH")) {
        (Some(drive), Some(path)) => {
            let mut combined = PathBuf::from(drive);
            combined.push(path);
            Some(combined)
        }
        _ => None,
    }
}

fn repo_key(repo_root: &Path) -> Result<String> {
    let fingerprint = crate::repo_identity::repo_fingerprint_sha256(repo_root)?;
    Ok(format!("repo-{fingerprint}"))
}

fn ensure_dir_secure(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
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
            fs::set_permissions(path, perms)?;
        }
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::OpenOptions;
    use tempfile::TempDir;

    fn create_repo(dir: &Path) -> Result<()> {
        fs::create_dir_all(dir.join(".git"))?;
        Ok(())
    }

    #[test]
    fn repo_cache_dir_is_scoped() -> Result<()> {
        let temp = TempDir::new()?;
        let state_paths = StatePaths::from_root(temp.path().join("state"));
        let repo = TempDir::new()?;
        create_repo(repo.path())?;

        let cache_dir = state_paths.repo_cache_dir(repo.path(), "libs")?;
        let cache_root = state_paths.cache_root()?;
        assert!(cache_dir.starts_with(&cache_root));
        let rel = cache_dir.strip_prefix(&cache_root)?;
        let mut components = rel.components();
        assert_eq!(
            components.next().unwrap().as_os_str(),
            std::ffi::OsStr::new("libs")
        );
        assert!(components
            .next()
            .unwrap()
            .as_os_str()
            .to_string_lossy()
            .starts_with("repo-"));
        Ok(())
    }

    #[test]
    fn unscoped_cache_dir_is_rejected() -> Result<()> {
        let temp = TempDir::new()?;
        let state_paths = StatePaths::from_root(temp.path().join("state"));
        let cache_root = state_paths.cache_root()?;
        let unscoped = cache_root.join("libs");
        let err = state_paths.assert_repo_scoped_cache_dir("libs", &unscoped);
        assert!(err.is_err(), "expected unscoped cache dir to error");
        Ok(())
    }

    #[test]
    fn repo_lock_paths_do_not_collide() -> Result<()> {
        let temp = TempDir::new()?;
        let state_paths = StatePaths::from_root(temp.path().join("state"));
        let repo_a = TempDir::new()?;
        let repo_b = TempDir::new()?;
        create_repo(repo_a.path())?;
        create_repo(repo_b.path())?;

        let lock_a = state_paths.repo_lock_path(repo_a.path(), "browser.lock")?;
        let lock_b = state_paths.repo_lock_path(repo_b.path(), "browser.lock")?;
        assert_ne!(lock_a, lock_b);

        let _lock_a = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_a)?;
        let _lock_b = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_b)?;
        Ok(())
    }
=======
pub fn default_state_base_dir() -> Result<PathBuf> {
    let home = home_dir().ok_or_else(|| anyhow!("unable to resolve home directory for state dir"))?;
    Ok(home.join(".docdex").join("state"))
}

fn home_dir() -> Option<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        return Some(PathBuf::from(home));
    }
    if let Some(home) = std::env::var_os("USERPROFILE") {
        return Some(PathBuf::from(home));
    }
    let drive = std::env::var_os("HOMEDRIVE")?;
    let path = std::env::var_os("HOMEPATH")?;
    Some(PathBuf::from(drive).join(path))
>>>>>>> mcoda/task/ops-01-us-03-t04
}
