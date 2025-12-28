use docdexd::diff::{collect_git_diff, DiffRequest, DiffScope};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn run_git(repo_root: &Path, args: &[&str]) -> Result<(), Box<dyn Error>> {
    let status = Command::new("git")
        .current_dir(repo_root)
        .args(args)
        .status()?;
    if !status.success() {
        return Err(format!("git {:?} failed", args).into());
    }
    Ok(())
}

fn init_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    run_git(repo_root, &["init"])?;
    run_git(repo_root, &["config", "user.email", "test@example.com"])?;
    run_git(repo_root, &["config", "user.name", "Docdex Test"])?;
    Ok(())
}

#[test]
fn collect_git_diff_supports_scopes_and_paths() -> Result<(), Box<dyn Error>> {
    if !git_available() {
        eprintln!("skipping diff test: git not available");
        return Ok(());
    }

    let repo = TempDir::new()?;
    let repo_root = repo.path();
    init_repo(repo_root)?;

    let file_path = repo_root.join("file.txt");
    fs::write(&file_path, "one\ntwo\nthree\n")?;
    run_git(repo_root, &["add", "file.txt"])?;
    run_git(repo_root, &["commit", "-m", "initial"])?;

    fs::write(&file_path, "one\ntwo changed\nthree\n")?;

    let working_changes = collect_git_diff(
        repo_root,
        &DiffRequest::working_tree().with_paths(vec![Path::new("file.txt").into()]),
    )?;
    assert_eq!(working_changes.len(), 1);
    assert_eq!(working_changes[0].path, "file.txt");
    assert_eq!(working_changes[0].ranges.len(), 1);
    assert_eq!(working_changes[0].ranges[0].start, 2);
    assert_eq!(working_changes[0].ranges[0].end, 2);

    run_git(repo_root, &["add", "file.txt"])?;
    let staged_changes = collect_git_diff(repo_root, &DiffRequest::staged())?;
    assert_eq!(staged_changes.len(), 1);
    assert_eq!(staged_changes[0].path, "file.txt");

    run_git(repo_root, &["commit", "-m", "update"])?;
    let range_changes = collect_git_diff(
        repo_root,
        &DiffRequest {
            scope: DiffScope::Range {
                base: "HEAD~1".to_string(),
                head: "HEAD".to_string(),
            },
            paths: Vec::new(),
        },
    )?;
    assert_eq!(range_changes.len(), 1);
    assert_eq!(range_changes[0].path, "file.txt");

    Ok(())
}
