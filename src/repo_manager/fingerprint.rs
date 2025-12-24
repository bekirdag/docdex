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
