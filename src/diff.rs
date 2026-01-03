use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiffLineRange {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffFileChange {
    pub path: String,
    pub ranges: Vec<DiffLineRange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffMode {
    #[serde(alias = "working")]
    WorkingTree,
    Staged,
    Range,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffScope {
    WorkingTree,
    Staged,
    Range { base: String, head: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffRequest {
    pub scope: DiffScope,
    pub paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffOptions {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<DiffMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
}

impl DiffRequest {
    pub fn working_tree() -> Self {
        Self {
            scope: DiffScope::WorkingTree,
            paths: Vec::new(),
        }
    }

    pub fn staged() -> Self {
        Self {
            scope: DiffScope::Staged,
            paths: Vec::new(),
        }
    }

    pub fn range(base: impl Into<String>, head: impl Into<String>) -> Self {
        Self {
            scope: DiffScope::Range {
                base: base.into(),
                head: head.into(),
            },
            paths: Vec::new(),
        }
    }

    pub fn with_paths(mut self, paths: Vec<PathBuf>) -> Self {
        self.paths = paths;
        self
    }
}

pub fn resolve_diff_request(
    mode: Option<DiffMode>,
    base: Option<String>,
    head: Option<String>,
    paths: Vec<PathBuf>,
) -> Result<Option<DiffRequest>> {
    let has_inputs = mode.is_some() || base.is_some() || head.is_some() || !paths.is_empty();
    if !has_inputs {
        return Ok(None);
    }
    let resolved_mode = match mode {
        Some(value) => value,
        None if base.is_some() || head.is_some() => DiffMode::Range,
        None => DiffMode::WorkingTree,
    };
    let request = match resolved_mode {
        DiffMode::WorkingTree => {
            if base.is_some() || head.is_some() {
                return Err(anyhow!("diff base/head only valid with mode=range"));
            }
            DiffRequest::working_tree().with_paths(paths)
        }
        DiffMode::Staged => {
            if base.is_some() || head.is_some() {
                return Err(anyhow!("diff base/head only valid with mode=range"));
            }
            DiffRequest::staged().with_paths(paths)
        }
        DiffMode::Range => {
            let base = base.ok_or_else(|| anyhow!("diff base is required for mode=range"))?;
            let head = head.ok_or_else(|| anyhow!("diff head is required for mode=range"))?;
            DiffRequest::range(base, head).with_paths(paths)
        }
    };
    Ok(Some(request))
}

pub fn resolve_diff_request_from_options(
    options: Option<&DiffOptions>,
) -> Result<Option<DiffRequest>> {
    let Some(options) = options else {
        return Ok(None);
    };
    let paths = options
        .paths
        .iter()
        .map(|path| PathBuf::from(path))
        .collect::<Vec<_>>();
    resolve_diff_request(
        options.mode,
        options.base.clone(),
        options.head.clone(),
        paths,
    )
}

pub fn collect_git_diff(repo_root: &Path, request: &DiffRequest) -> Result<Vec<DiffFileChange>> {
    let output = run_git_diff(repo_root, request)?;
    Ok(parse_diff_output(&output))
}

fn run_git_diff(repo_root: &Path, request: &DiffRequest) -> Result<String> {
    let mut cmd = Command::new("git");
    cmd.current_dir(repo_root);
    cmd.arg("diff");
    cmd.arg("--no-color");
    cmd.arg("--no-ext-diff");
    cmd.arg("--unified=0");
    match &request.scope {
        DiffScope::WorkingTree => {}
        DiffScope::Staged => {
            cmd.arg("--staged");
        }
        DiffScope::Range { base, head } => {
            let base = base.trim();
            let head = head.trim();
            if base.is_empty() || head.is_empty() {
                return Err(anyhow!("diff range requires non-empty base and head"));
            }
            cmd.arg(format!("{base}..{head}"));
        }
    }

    let paths = normalize_paths(repo_root, &request.paths)?;
    if !paths.is_empty() {
        cmd.arg("--");
        cmd.args(paths);
    }

    let output = cmd.output().context("run git diff")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("git diff failed: {}", stderr.trim()));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn normalize_paths(repo_root: &Path, paths: &[PathBuf]) -> Result<Vec<String>> {
    let mut out = Vec::new();
    for raw in paths {
        let rel = if raw.is_absolute() {
            raw.strip_prefix(repo_root).map_err(|_| {
                anyhow!(
                    "diff path {} is outside repo root {}",
                    raw.display(),
                    repo_root.display()
                )
            })?
        } else {
            raw.as_path()
        };
        let normalized = normalize_rel_path(rel)?;
        out.push(normalized);
    }
    Ok(out)
}

fn normalize_rel_path(path: &Path) -> Result<String> {
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(part) => clean.push(part),
            _ => {
                return Err(anyhow!(
                    "diff path must be repo-relative without parent components"
                ))
            }
        }
    }
    let clean_str = clean.to_string_lossy().replace('\\', "/");
    if clean_str.is_empty() {
        return Err(anyhow!("diff path must not be empty"));
    }
    Ok(clean_str)
}

fn parse_diff_output(output: &str) -> Vec<DiffFileChange> {
    let mut files: BTreeMap<String, Vec<DiffLineRange>> = BTreeMap::new();
    let mut current_file: Option<String> = None;

    for line in output.lines() {
        if let Some(path) = parse_file_marker(line) {
            current_file = Some(path.clone());
            files.entry(path).or_default();
            continue;
        }
        if let Some(range) = parse_hunk_range(line) {
            if let Some(path) = current_file.as_ref() {
                files.entry(path.clone()).or_default().push(range);
            }
        }
    }

    files
        .into_iter()
        .map(|(path, ranges)| DiffFileChange {
            path,
            ranges: merge_ranges(ranges),
        })
        .collect()
}

fn parse_file_marker(line: &str) -> Option<String> {
    if !line.starts_with("+++ ") {
        return None;
    }
    let raw = line.trim_start_matches("+++ ").trim();
    if raw == "/dev/null" {
        return None;
    }
    let raw = raw.strip_prefix("b/").unwrap_or(raw);
    let raw = raw.strip_prefix("a/").unwrap_or(raw);
    let cleaned = unquote_path(raw);
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn unquote_path(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        let inner = &trimmed[1..trimmed.len() - 1];
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                if let Some(next) = chars.next() {
                    match next {
                        '\\' => out.push('\\'),
                        '"' => out.push('"'),
                        't' => out.push('\t'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        _ => out.push(next),
                    }
                } else {
                    out.push('\\');
                }
            } else {
                out.push(ch);
            }
        }
        return out;
    }
    trimmed.to_string()
}

fn parse_hunk_range(line: &str) -> Option<DiffLineRange> {
    if !line.starts_with("@@") {
        return None;
    }
    let plus_idx = line.find('+')?;
    let rest = &line[plus_idx + 1..];
    let end_idx = rest.find(' ')?;
    let spec = &rest[..end_idx];
    let mut parts = spec.split(',');
    let start: u32 = parts.next()?.parse().ok()?;
    let count: u32 = parts
        .next()
        .and_then(|value| value.parse().ok())
        .unwrap_or(1);
    if count == 0 {
        return None;
    }
    let end = start.saturating_add(count.saturating_sub(1));
    Some(DiffLineRange { start, end })
}

fn merge_ranges(mut ranges: Vec<DiffLineRange>) -> Vec<DiffLineRange> {
    if ranges.len() <= 1 {
        return ranges;
    }
    ranges.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.end.cmp(&b.end)));
    let mut merged: Vec<DiffLineRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(last) = merged.last_mut() {
            if range.start <= last.end.saturating_add(1) {
                last.end = last.end.max(range.end);
                continue;
            }
        }
        merged.push(range);
    }
    merged
}
