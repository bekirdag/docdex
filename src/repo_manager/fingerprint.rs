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
    let target = git_identity_target(repo_root);
    let payload = file_identity_payload(&target)
        .with_context(|| format!("read filesystem identity for {}", target.to_string_lossy()))?;
    Ok(hex::encode(Sha256::digest(payload.as_bytes())))
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
        let normalized = normalize_path(path);
        return Ok(format!(
            "v1|windows|path={normalized}|is_dir={}",
            meta.is_dir(),
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
    use anyhow::Result;
    use std::fs;
    use tempfile::TempDir;

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
