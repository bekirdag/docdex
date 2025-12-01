use assert_cmd::cargo::cargo_bin;
use serde_json::Value;
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

fn repo_arg(repo_root: &Path) -> String {
    repo_root.to_string_lossy().to_string()
}

fn parse_waterfall(stdout: &[u8]) -> Result<Value, Box<dyn Error>> {
    let payload: Value = serde_json::from_slice(stdout)?;
    Ok(payload)
}

#[test]
fn web_rag_requires_repo_flag() -> Result<(), Box<dyn Error>> {
    let output = Command::new(docdex_bin())
        .args(["web-rag", "--query", "ping"])
        .output()?;
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
    let unknown_repo_arg = repo_arg(&unknown_repo);

    let output = Command::new(docdex_bin())
        .args([
            "web-rag",
            "--repo",
            unknown_repo_arg.as_str(),
            "--query",
            "note",
        ])
        .output()?;
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("docdexd index"),
        "stderr should direct user to index: {stderr}"
    );
    assert!(
        stderr.contains(unknown_repo_arg.as_str()),
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
    let repo_arg = repo_arg(repo.path());

    let output = Command::new(docdex_bin())
        .args([
            "web-rag",
            "--repo",
            repo_arg.as_str(),
            "--query",
            "fixtures",
        ])
        .output()?;
    assert!(output.status.success());
    let payload = parse_waterfall(&output.stdout)?;
    let empty: Vec<Value> = Vec::new();
    let hits = payload
        .get("local")
        .and_then(|v| v.get("hits"))
        .and_then(|v| v.as_array())
        .unwrap_or(&empty);
    assert!(
        !hits.is_empty(),
        "local stage should return at least one hit"
    );
    Ok(())
}

#[test]
fn web_rag_applies_caps_and_budget() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_fixture_repo(repo.path())?;
    index_repo(repo.path())?;
    let repo_arg = repo_arg(repo.path());

    let output = Command::new(docdex_bin())
        .args([
            "web-rag",
            "--repo",
            repo_arg.as_str(),
            "--query",
            "fixtures",
            "--limit",
            "5",
            "--max-repo-hits",
            "1",
            "--max-tokens",
            "10",
            "--confidence-threshold",
            "0.0",
        ])
        .output()?;
    assert!(output.status.success());
    let payload = parse_waterfall(&output.stdout)?;
    let local = payload
        .get("local")
        .and_then(|v| v.as_object())
        .ok_or("local result missing")?;
    let hits = local
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("hits missing")?;
    assert!(
        hits.len() <= 1,
        "max_repo_hits should cap results; got {} hits",
        hits.len()
    );
    assert_eq!(
        local
            .get("effective_limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        1
    );
    let consumed = local
        .get("token_budget_consumed")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let budget = local
        .get("token_budget")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(budget >= consumed, "token budget should be honored");
    assert!(consumed <= 10, "token budget should not be exceeded");
    assert_eq!(
        payload
            .get("web")
            .and_then(|v| v.get("ran"))
            .and_then(|v| v.as_bool()),
        Some(false)
    );
    Ok(())
}

#[test]
fn web_rag_confidence_gates_web_stage() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_fixture_repo(repo.path())?;
    index_repo(repo.path())?;
    let repo_arg = repo_arg(repo.path());

    let mut base_args = vec![
        "web-rag",
        "--repo",
        repo_arg.as_str(),
        "--query",
        "fixtures",
        "--limit",
        "3",
        "--max-repo-hits",
        "3",
    ];

    let mut high_threshold = base_args.clone();
    high_threshold.extend_from_slice(&["--confidence-threshold", "0.99"]);
    let high = Command::new(docdex_bin()).args(&high_threshold).output()?;
    assert!(high.status.success());
    let high_payload = parse_waterfall(&high.stdout)?;
    let high_ran = high_payload
        .get("web")
        .and_then(|v| v.get("ran"))
        .and_then(|v| v.as_bool());
    assert_eq!(high_ran, Some(true));

    let mut low_threshold = base_args.clone();
    low_threshold.extend_from_slice(&["--confidence-threshold", "0.0"]);
    let low = Command::new(docdex_bin()).args(&low_threshold).output()?;
    assert!(low.status.success());
    let low_payload = parse_waterfall(&low.stdout)?;
    let low_ran = low_payload
        .get("web")
        .and_then(|v| v.get("ran"))
        .and_then(|v| v.as_bool());
    assert_eq!(low_ran, Some(false));

    let mut forced = base_args.clone();
    forced.extend_from_slice(&["--confidence-threshold", "0.0", "--force-web"]);
    let force_output = Command::new(docdex_bin()).args(&forced).output()?;
    assert!(force_output.status.success());
    let forced_payload = parse_waterfall(&force_output.stdout)?;
    let forced_ran = forced_payload
        .get("web")
        .and_then(|v| v.get("ran"))
        .and_then(|v| v.as_bool());
    let forced_flag = forced_payload
        .get("web")
        .and_then(|v| v.get("forced"))
        .and_then(|v| v.as_bool());
    assert_eq!(forced_ran, Some(true));
    assert_eq!(forced_flag, Some(true));
    Ok(())
}
