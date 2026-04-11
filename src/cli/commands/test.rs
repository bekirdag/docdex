use crate::config::RepoArgs;
use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Command;

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

pub(crate) fn run(command: super::super::TestCommand) -> Result<()> {
    match command {
        super::super::TestCommand::RunNode { repo, file, args } => {
            run_node(repo, file, args)?;
        }
    }
    Ok(())
}

fn run_node(repo: RepoArgs, file: String, args: Vec<String>) -> Result<()> {
    let repo_root = repo.repo_root();
    let canonical_root = repo_root
        .canonicalize()
        .with_context(|| format!("resolve repo root {}", repo_root.display()))?;
    let rel_path = normalize_rel_path(file.trim())
        .ok_or_else(|| anyhow::anyhow!("file must be repo-relative"))?;
    let abs_path = repo_root.join(&rel_path);
    let canonical = abs_path
        .canonicalize()
        .with_context(|| format!("resolve path {}", rel_path.display()))?;
    if !canonical.starts_with(&canonical_root) {
        anyhow::bail!("file must be under repo root");
    }
    if !canonical.exists() {
        anyhow::bail!("file does not exist: {}", rel_path.display());
    }

    let mut cmd = Command::new("node");
    cmd.arg(&canonical);
    for arg in flatten_args(args) {
        cmd.arg(arg);
    }
    cmd.current_dir(&repo_root);
    let status = cmd.status().context("run node")?;
    if status.success() {
        return Ok(());
    }
    if let Some(code) = status.code() {
        std::process::exit(code);
    }
    #[cfg(unix)]
    if let Some(signal) = status.signal() {
        eprintln!("node terminated by signal {signal}");
    }
    std::process::exit(1);
}

fn flatten_args(args: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for arg in args {
        let trimmed = arg.trim();
        if trimmed.is_empty() {
            continue;
        }
        out.extend(trimmed.split_whitespace().map(|value| value.to_string()));
    }
    out
}

fn normalize_rel_path(input: &str) -> Option<PathBuf> {
    crate::path_utils::normalize_repo_relative_path_from_str(input)
}
