use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub fn normalize_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
}

pub fn legacy_repo_id_for_root(repo_root: &Path) -> String {
    let normalized = normalize_path(repo_root);
    hex::encode(Sha256::digest(normalized.as_bytes()))
}

pub fn repo_fingerprint_sha256(repo_root: &Path) -> Result<String> {
    let registry =
        crate::state_paths::StatePaths::new(crate::state_paths::default_state_base_dir()?)
            .repo_registry_path();
    select_repo_fingerprint(repo_root, &registry)
}

// Preserve an established name-based identity only for its registered owner.
// New repositories are path-scoped: a basename is not a repository identity.
fn select_repo_fingerprint(repo_root: &Path, registry_path: &Path) -> Result<String> {
    let repo_root = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());
    let repo_name = repo_root
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| repo_root.to_string_lossy().to_string());
    let legacy = hex::encode(Sha256::digest(format!("v2|name|{}", repo_name).as_bytes()));
    let canonical = normalize_path(&repo_root);
    let registry: Option<serde_json::Value> = match fs::read(registry_path) {
        Ok(bytes) => Some(serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "parse repository identity registry {}",
                registry_path.display()
            )
        })?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error).context("read repository identity registry"),
    };
    if registry
        .as_ref()
        .and_then(|value| value.get("repos"))
        .and_then(|repos| repos.get(&legacy))
        .and_then(|entry| entry.get("canonical_path"))
        .and_then(|value| value.as_str())
        == Some(canonical.as_str())
    {
        return Ok(legacy);
    }
    Ok(hex::encode(Sha256::digest(
        format!("v3|path|{}", canonical).as_bytes(),
    )))
}

pub(crate) fn git_dir_for_repo(repo_root: &Path) -> Option<PathBuf> {
    let dot_git = repo_root.join(".git");
    let Ok(meta) = fs::metadata(&dot_git) else {
        return None;
    };
    if meta.is_dir() {
        return Some(dot_git);
    }
    if !meta.is_file() {
        return None;
    }
    let Ok(contents) = fs::read_to_string(&dot_git) else {
        return None;
    };
    let line = contents.lines().next().unwrap_or_default().trim();
    let Some(rest) = line.strip_prefix("gitdir:") else {
        return None;
    };
    let rest = rest.trim();
    if rest.is_empty() {
        return None;
    }
    let candidate = PathBuf::from(rest);
    if candidate.is_absolute() {
        return Some(candidate);
    }
    Some(repo_root.join(candidate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn same_basename_workspaces_have_distinct_stable_identities() -> Result<()> {
        let temp = TempDir::new()?;
        let a = temp.path().join("a/workspace");
        let b = temp.path().join("b/workspace");
        fs::create_dir_all(&a)?;
        fs::create_dir_all(&b)?;
        let registry = temp.path().join("registry.json");
        let first = select_repo_fingerprint(&a, &registry)?;
        assert_ne!(first, select_repo_fingerprint(&b, &registry)?);
        assert_eq!(first, select_repo_fingerprint(&a, &registry)?);
        Ok(())
    }

    #[test]
    fn legacy_identity_stays_with_registered_owner_only() -> Result<()> {
        let temp = TempDir::new()?;
        let a = temp.path().join("a/workspace");
        let b = temp.path().join("b/workspace");
        fs::create_dir_all(&a)?;
        fs::create_dir_all(&b)?;
        let registry = temp.path().join("registry.json");
        let legacy = hex::encode(Sha256::digest(b"v2|name|workspace"));
        fs::write(
            &registry,
            serde_json::to_vec(&serde_json::json!({
                "version":1,"repos":{legacy.clone():{"canonical_path":normalize_path(&a),"state_key":legacy}}
            }))?,
        )?;
        assert_eq!(select_repo_fingerprint(&a, &registry)?, legacy);
        assert_ne!(select_repo_fingerprint(&b, &registry)?, legacy);
        fs::write(&registry, b"malformed")?;
        assert!(select_repo_fingerprint(&a, &registry).is_err());
        Ok(())
    }

    #[test]
    fn normalize_path_resolves_realpath_when_symlinks_available() -> Result<()> {
        let temp = TempDir::new()?;
        let repo_root = temp.path().join("RepoRoot");
        fs::create_dir_all(&repo_root)?;
        let link_root = temp.path().join("repo-link");
        if let Err(err) = create_symlink_dir(&repo_root, &link_root) {
            eprintln!("skipping symlink normalization test: {err}");
            return Ok(());
        }

        let normalized_real = normalize_path(&repo_root);
        let normalized_link = normalize_path(&link_root);
        assert_eq!(normalized_real, normalized_link);
        Ok(())
    }

    #[test]
    fn normalize_path_case_normalizes_on_case_insensitive_fs() -> Result<()> {
        let temp = TempDir::new()?;
        let repo_root = temp.path().join("RepoCase");
        fs::create_dir_all(&repo_root)?;
        let alt_case = temp.path().join("repocase");

        let normalized_real = normalize_path(&repo_root);
        let normalized_alt = normalize_path(&alt_case);

        if alt_case.exists() {
            assert_eq!(normalized_real, normalized_alt);
        } else {
            assert_ne!(normalized_real, normalized_alt);
        }
        Ok(())
    }

    #[test]
    fn repo_fingerprint_stable_across_realpath_when_symlinks_available() -> Result<()> {
        let temp = TempDir::new()?;
        let repo_root = temp.path().join("RepoRoot");
        fs::create_dir_all(repo_root.join(".git"))?;
        let link_root = temp.path().join("repo-link");
        if let Err(err) = create_symlink_dir(&repo_root, &link_root) {
            eprintln!("skipping symlink fingerprint test: {err}");
            return Ok(());
        }

        let fingerprint_real = repo_fingerprint_sha256(&repo_root)?;
        let fingerprint_link = repo_fingerprint_sha256(&link_root)?;
        assert_eq!(fingerprint_real, fingerprint_link);
        Ok(())
    }

    #[test]
    fn repo_fingerprint_case_normalizes_on_case_insensitive_fs() -> Result<()> {
        let temp = TempDir::new()?;
        let repo_root = temp.path().join("RepoCase");
        fs::create_dir_all(repo_root.join(".git"))?;
        let alt_case = temp.path().join("repocase");

        if !alt_case.exists() {
            return Ok(());
        }

        let fingerprint_real = repo_fingerprint_sha256(&repo_root)?;
        let fingerprint_alt = repo_fingerprint_sha256(&alt_case)?;
        assert_eq!(fingerprint_real, fingerprint_alt);
        Ok(())
    }

    #[cfg(unix)]
    fn create_symlink_dir(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::unix::fs::symlink(target, link)
    }

    #[cfg(windows)]
    fn create_symlink_dir(target: &Path, link: &Path) -> std::io::Result<()> {
        std::os::windows::fs::symlink_dir(target, link)
    }

    #[cfg(not(any(unix, windows)))]
    fn create_symlink_dir(_target: &Path, _link: &Path) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "symlink creation unavailable",
        ))
    }
}
