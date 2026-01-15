use anyhow::{anyhow, Result};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::warn;

const REPOS_DIRNAME: &str = "repos";
const REPO_REGISTRY_FILENAME: &str = "repo_registry.json";

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
            ));
        }
        Ok(())
    }
}

pub fn default_state_base_dir() -> Result<PathBuf> {
    let home =
        home_dir().ok_or_else(|| anyhow!("unable to resolve home directory for state dir"))?;
    Ok(home.join(".docdex").join("state"))
}

pub fn daemon_root_dir_from_state_base(state_base: &Path) -> Result<PathBuf> {
    let root = state_base.parent().ok_or_else(|| {
        anyhow!(
            "unable to resolve docdex state root from {}",
            state_base.display()
        )
    })?;
    Ok(root.join("daemon_root"))
}

pub fn ensure_daemon_root_dir(state_base: &Path) -> Result<PathBuf> {
    let root = state_base.parent().ok_or_else(|| {
        anyhow!(
            "unable to resolve docdex state root from {}",
            state_base.display()
        )
    })?;
    crate::state_layout::ensure_state_dir_secure(root)?;
    let daemon_root = root.join("daemon_root");
    fs::create_dir_all(&daemon_root).map_err(|err| {
        anyhow!(
            "failed to create daemon root {}: {err}",
            daemon_root.display()
        )
    })?;
    Ok(daemon_root)
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
}
