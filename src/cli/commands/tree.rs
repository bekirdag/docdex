use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

use crate::config::RepoArgs;
use crate::tree::{render_tree, TreeOptions};

pub(crate) async fn run(
    repo: RepoArgs,
    path: Option<PathBuf>,
    max_depth: Option<usize>,
    dirs_only: bool,
    include_hidden: bool,
    extra_excludes: Vec<String>,
) -> Result<()> {
    let repo_root = repo.repo_root();
    let tree_root = resolve_tree_root(&repo_root, path)?;
    let options = TreeOptions {
        max_depth,
        dirs_only,
        include_hidden,
        extra_excludes,
    };
    let output = render_tree(&tree_root, &options)?;
    print!("{}", output.tree);
    Ok(())
}

fn resolve_tree_root(repo_root: &Path, path: Option<PathBuf>) -> Result<PathBuf> {
    let repo_root = repo_root
        .canonicalize()
        .map_err(|err| anyhow!("resolve repo root {}: {err}", repo_root.display()))?;
    let candidate = match path {
        None => repo_root.clone(),
        Some(raw) => {
            if raw.as_os_str().is_empty() {
                return Err(anyhow!("path must not be empty"));
            }
            if raw.is_absolute() {
                raw
            } else {
                repo_root.join(raw)
            }
        }
    };
    let canonical = candidate
        .canonicalize()
        .map_err(|err| anyhow!("resolve tree path {}: {err}", candidate.display()))?;
    if !canonical.starts_with(&repo_root) {
        return Err(anyhow!("path must stay within repo root"));
    }
    Ok(canonical)
}
