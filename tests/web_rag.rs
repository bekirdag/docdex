use assert_cmd::cargo::cargo_bin;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    cargo_bin("docdexd").to_path_buf()
}

fn write_fixture_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join("docs"))?;
    fs::write(
        repo_root.join("docs").join("note.md"),
        "# Notes\n\nWeb RAG fixtures.\n",
    )?;
    Ok(())
}

fn index_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy();
    let output = Command::new(docdex_bin())
        .args(["index", "--repo", repo_str.as_ref()])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd index failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

#[test]
fn web_rag_requires_repo_flag() -> Result<(), Box<dyn Error>> {
    let output = Command::new(docdex_bin()).arg("web-rag").output()?;
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    let lowered = stderr.to_lowercase();
    assert!(
        lowered.contains("--repo") || lowered.contains("repo"),
        "stderr should mention repo requirement: {stderr}"
    );
    assert!(
        lowered.contains("index"),
        "stderr should include indexing guidance: {stderr}"
    );
    Ok(())
}

#[test]
fn web_rag_rejects_unknown_repo() -> Result<(), Box<dyn Error>> {
    let indexed = TempDir::new()?;
    write_fixture_repo(indexed.path())?;
    index_repo(indexed.path())?;

    let unknown = TempDir::new()?;
    let unknown_repo = unknown.path().join("unindexed");
    fs::create_dir_all(&unknown_repo)?;

    let output = Command::new(docdex_bin())
        .args(["web-rag", "--repo", unknown_repo.to_string_lossy().as_ref()])
        .output()?;
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("docdexd index"),
        "stderr should direct user to index: {stderr}"
    );
    assert!(
        stderr.contains(unknown_repo.to_string_lossy().as_ref()),
        "stderr should include provided repo path"
    );
    assert!(
        !stderr.contains(indexed.path().to_string_lossy().as_ref()),
        "stderr should not leak other repos"
    );
    Ok(())
}

#[test]
fn web_rag_accepts_indexed_repo() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_fixture_repo(repo.path())?;
    index_repo(repo.path())?;

    let output = Command::new(docdex_bin())
        .args(["web-rag", "--repo", repo.path().to_string_lossy().as_ref()])
        .output()?;
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(repo.path().to_string_lossy().as_ref()),
        "stdout should mention the repo path"
    );
    Ok(())
}
