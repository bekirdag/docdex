use super::{repo_hint_for_command, should_ensure_daemon, Command};
use crate::config::RepoArgs;
use std::path::PathBuf;
use tempfile::TempDir;

fn repo_args(path: PathBuf) -> RepoArgs {
    RepoArgs {
        repo: path,
        state_dir: None,
        exclude_prefix: Vec::new(),
        exclude_dir: Vec::new(),
        enable_symbol_extraction: true,
    }
}

#[test]
fn ensure_daemon_skips_help_only() {
    assert!(!should_ensure_daemon(&Command::HelpAll));
    assert!(should_ensure_daemon(&Command::Check));
}

#[test]
fn ensure_daemon_for_index_and_hint() {
    let temp = TempDir::new().expect("temp dir");
    let repo = repo_args(temp.path().to_path_buf());
    let cmd = Command::Index {
        repo: repo.clone(),
        libs_sources: None,
    };
    assert!(should_ensure_daemon(&cmd));
    let hint = repo_hint_for_command(&cmd).expect("repo hint");
    assert_eq!(hint, repo.repo_root());
}

#[test]
fn ensure_daemon_for_mcp_sets_repo_hint() {
    let temp = TempDir::new().expect("temp dir");
    let repo = repo_args(temp.path().to_path_buf());
    let cmd = Command::Mcp {
        repo: repo.clone(),
        log: "warn".to_string(),
        max_results: 8,
        rate_limit_per_min: 0,
        rate_limit_burst: 0,
        auth_token: None,
    };
    assert!(should_ensure_daemon(&cmd));
    let hint = repo_hint_for_command(&cmd).expect("repo hint");
    assert_eq!(hint, repo.repo_root());
}
