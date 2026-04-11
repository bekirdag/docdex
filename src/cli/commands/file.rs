use anyhow::{Context, Result};
use serde_json::json;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

pub(crate) fn run(command: super::super::FileCommand) -> Result<()> {
    match command {
        super::super::FileCommand::EnsureNewline { repo, file } => {
            let repo_root = repo.repo_root();
            let canonical_root = repo_root
                .canonicalize()
                .with_context(|| format!("resolve repo root {}", repo_root.display()))?;
            let resolved = resolve_repo_path(&repo_root, &canonical_root, &file, false)?;
            let changed = ensure_newline_at_path(&resolved.abs)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "path": resolved.rel.display().to_string(),
                    "changed": changed,
                }))?
            );
        }
        super::super::FileCommand::Write {
            repo,
            file,
            content,
            stdin,
            create,
        } => {
            let repo_root = repo.repo_root();
            let canonical_root = repo_root
                .canonicalize()
                .with_context(|| format!("resolve repo root {}", repo_root.display()))?;
            let resolved = resolve_repo_path(&repo_root, &canonical_root, &file, create)?;
            let payload = resolve_write_payload(content, stdin)?;
            write_file(&resolved.abs, &payload, create)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "path": resolved.rel.display().to_string(),
                    "bytes": payload.len(),
                }))?
            );
        }
    }
    Ok(())
}

struct ResolvedPath {
    rel: PathBuf,
    abs: PathBuf,
}

fn resolve_repo_path(
    repo_root: &Path,
    canonical_root: &Path,
    file: &str,
    allow_missing: bool,
) -> Result<ResolvedPath> {
    let trimmed = file.trim();
    if trimmed.is_empty() {
        anyhow::bail!("file must not be empty");
    }
    let rel = normalize_rel_path(trimmed).ok_or_else(|| {
        anyhow::anyhow!("file must be repo-relative and not contain parent components")
    })?;
    let abs = repo_root.join(&rel);
    if abs.exists() {
        let canonical = abs
            .canonicalize()
            .with_context(|| format!("resolve path {}", rel.display()))?;
        if !canonical.starts_with(canonical_root) {
            anyhow::bail!("file must be under repo root");
        }
        if canonical.is_dir() {
            anyhow::bail!("file path resolves to a directory");
        }
    } else if allow_missing {
        let parent = abs
            .parent()
            .ok_or_else(|| anyhow::anyhow!("file must have a parent directory"))?;
        let canonical_parent = parent
            .canonicalize()
            .with_context(|| format!("resolve parent {}", parent.display()))?;
        if !canonical_parent.starts_with(canonical_root) {
            anyhow::bail!("file must be under repo root");
        }
    } else {
        anyhow::bail!("file does not exist");
    }
    Ok(ResolvedPath { rel, abs })
}

fn normalize_rel_path(input: &str) -> Option<PathBuf> {
    crate::path_utils::normalize_repo_relative_path_from_str(input)
}

fn ensure_newline_at_path(path: &Path) -> Result<bool> {
    let mut content =
        fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    if content.ends_with('\n') {
        return Ok(false);
    }
    content.push('\n');
    fs::write(path, content).with_context(|| format!("write {}", path.display()))?;
    Ok(true)
}

fn resolve_write_payload(content: Option<String>, stdin: bool) -> Result<String> {
    match (content, stdin) {
        (Some(_), true) => anyhow::bail!("use either --content or --stdin, not both"),
        (None, false) => anyhow::bail!("provide --content or --stdin"),
        (Some(value), false) => Ok(value),
        (None, true) => {
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .context("read stdin")?;
            Ok(buffer)
        }
    }
}

fn write_file(path: &Path, content: &str, create: bool) -> Result<()> {
    if path.exists() {
        if path.is_dir() {
            anyhow::bail!("file path resolves to a directory");
        }
    } else if !create {
        anyhow::bail!("file does not exist (pass --create to allow)");
    }
    fs::write(path, content).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ensure_newline_at_path, write_file};
    use anyhow::Result;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn ensure_newline_appends_if_missing() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("note.txt");
        fs::write(&path, "hello")?;
        let changed = ensure_newline_at_path(&path)?;
        assert!(changed);
        let content = fs::read_to_string(&path)?;
        assert_eq!(content, "hello\n");
        Ok(())
    }

    #[test]
    fn ensure_newline_noop_when_present() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("note.txt");
        fs::write(&path, "hello\n")?;
        let changed = ensure_newline_at_path(&path)?;
        assert!(!changed);
        let content = fs::read_to_string(&path)?;
        assert_eq!(content, "hello\n");
        Ok(())
    }

    #[test]
    fn write_file_respects_create_flag() -> Result<()> {
        let temp = TempDir::new()?;
        let path = temp.path().join("note.txt");
        let err = write_file(&path, "hi", false);
        assert!(err.is_err());
        write_file(&path, "hi", true)?;
        let content = fs::read_to_string(&path)?;
        assert_eq!(content, "hi");
        Ok(())
    }
}
