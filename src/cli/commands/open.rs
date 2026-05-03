use crate::config::RepoArgs;
use crate::max_size::OPEN_MAX_BYTES;
use anyhow::{Context, Result};
use serde_json::json;
use std::fs;
use std::path::PathBuf;

pub(crate) fn run(
    repo: RepoArgs,
    file: String,
    start: Option<usize>,
    end: Option<usize>,
    head: Option<usize>,
    clamp: bool,
) -> Result<()> {
    let repo_root = repo.repo_root();
    let repo_encryption = crate::config::AppConfig::load_default()
        .ok()
        .map(|config| config.repo_encryption)
        .unwrap_or_default();
    if repo_encryption.is_enabled() {
        if !repo_encryption.full_file_open_enabled {
            anyhow::bail!(
                "repository encryption full-file open is disabled by policy; use snippet/search access instead"
            );
        }
        let _key = repo_encryption.require_key()?;
    }
    let canonical_root = repo_root
        .canonicalize()
        .with_context(|| format!("resolve repo root {}", repo_root.display()))?;
    let trimmed = file.trim();
    if trimmed.is_empty() {
        anyhow::bail!("file must not be empty");
    }
    let rel_path = normalize_rel_path(trimmed).ok_or_else(|| {
        anyhow::anyhow!("file must be repo-relative and not contain parent components")
    })?;
    let abs_path = repo_root.join(&rel_path);
    let canonical = abs_path
        .canonicalize()
        .with_context(|| format!("resolve path {}", rel_path.display()))?;
    if !canonical.starts_with(&canonical_root) {
        anyhow::bail!("file must be under repo root");
    }
    let content =
        fs::read_to_string(&canonical).with_context(|| format!("read {}", rel_path.display()))?;
    if content.len() > OPEN_MAX_BYTES {
        anyhow::bail!(
            "file too large ({} bytes > {} limit)",
            content.len(),
            OPEN_MAX_BYTES
        );
    }
    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len();
    if total_lines == 0 {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "path": rel_path.display().to_string(),
                "start_line": 0,
                "end_line": 0,
                "total_lines": 0,
                "content": "",
                "repo_root": repo_root.display().to_string(),
                "project_root": repo_root.display().to_string(),
            }))?
        );
        return Ok(());
    }
    let (start_line, end_line) = resolve_open_range(total_lines, start, end, head, clamp)?;
    let start_idx = start_line.saturating_sub(1);
    let end_idx = end_line.saturating_sub(1);
    let slice = lines[start_idx..=end_idx].join("\n");
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "path": rel_path.display().to_string(),
            "start_line": start_line,
            "end_line": end_line,
            "total_lines": total_lines,
            "content": slice,
            "repo_root": repo_root.display().to_string(),
            "project_root": repo_root.display().to_string(),
        }))?
    );
    Ok(())
}

fn normalize_rel_path(input: &str) -> Option<PathBuf> {
    crate::path_utils::normalize_repo_relative_path_from_str(input)
}

fn resolve_open_range(
    total_lines: usize,
    start_line: Option<usize>,
    end_line: Option<usize>,
    head: Option<usize>,
    clamp: bool,
) -> Result<(usize, usize)> {
    let mut start = start_line.unwrap_or(1).max(1);
    let mut end = end_line.unwrap_or(total_lines);
    let mut clamp = clamp;

    if let Some(head) = head {
        start = 1;
        end = head.max(1);
        clamp = true;
    }

    if clamp {
        if total_lines == 0 {
            return Ok((0, 0));
        }
        if start > total_lines {
            start = total_lines;
        }
        if end > total_lines {
            end = total_lines;
        }
        if end < start {
            end = start;
        }
        return Ok((start, end));
    }

    if end < start || start > total_lines || end > total_lines {
        anyhow::bail!(
            "line range is invalid (start_line={}, end_line={}, total_lines={})",
            start,
            end,
            total_lines
        );
    }
    Ok((start, end))
}

#[cfg(test)]
mod tests {
    use super::resolve_open_range;

    #[test]
    fn resolve_open_range_clamps_when_requested() {
        let (start, end) = resolve_open_range(10, Some(1), Some(25), None, true).expect("range");
        assert_eq!((start, end), (1, 10));
    }

    #[test]
    fn resolve_open_range_head_sets_clamp() {
        let (start, end) = resolve_open_range(5, None, None, Some(20), false).expect("range");
        assert_eq!((start, end), (1, 5));
    }

    #[test]
    fn resolve_open_range_errors_without_clamp() {
        let err = resolve_open_range(5, Some(1), Some(10), None, false);
        assert!(err.is_err());
    }
}
