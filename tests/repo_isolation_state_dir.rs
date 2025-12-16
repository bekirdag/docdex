use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn run_docdex<I, S>(args: I) -> Result<Vec<u8>, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin())
        .env_remove("DOCDEX_ENABLE_SYMBOL_EXTRACTION")
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

fn write_repo(repo_root: &Path, filename: &str, token: &str) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root)?;
    fs::create_dir_all(repo_root.join(".git"))?;
    fs::write(
        repo_root.join(filename),
        format!(
            r#"
# Fixture

shared_term
{token}
"#
        ),
    )?;
    Ok(())
}

fn hits_from_query(stdout: &[u8]) -> Result<Vec<Value>, Box<dyn Error>> {
    let payload: Value = serde_json::from_slice(stdout)?;
    let hits = payload
        .get("hits")
        .and_then(|value| value.as_array())
        .ok_or("hits array missing")?;
    Ok(hits.to_vec())
}

#[test]
fn absolute_state_dir_is_repo_scoped_and_prevents_cross_repo_mixing() -> Result<(), Box<dyn Error>>
{
    let state_root = TempDir::new()?;
    let state_root = state_root.path().canonicalize()?;

    let repo_a = TempDir::new()?;
    let repo_b = TempDir::new()?;
    write_repo(repo_a.path(), "a-only.md", "repo_a_token")?;
    write_repo(repo_b.path(), "b-only.md", "repo_b_token")?;

    let repo_a_str = repo_a.path().to_string_lossy().to_string();
    let repo_b_str = repo_b.path().to_string_lossy().to_string();
    let state_root_str = state_root.to_string_lossy().to_string();

    run_docdex(["index", "--repo", repo_a_str.as_str(), "--state-dir", &state_root_str])?;
    run_docdex(["index", "--repo", repo_b_str.as_str(), "--state-dir", &state_root_str])?;

    let repos_dir = state_root.join("repos");
    let mut repo_dirs: Vec<PathBuf> = fs::read_dir(&repos_dir)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let file_type = entry.file_type().ok()?;
            if file_type.is_dir() { Some(path) } else { None }
        })
        .collect();
    repo_dirs.sort();
    assert_eq!(
        repo_dirs.len(),
        2,
        "expected exactly 2 repo state dirs under shared base state dir"
    );
    for dir in &repo_dirs {
        assert!(
            dir.join("index").exists(),
            "expected {dir} to contain index subdir",
            dir = dir.display()
        );
    }

    let out_a = run_docdex([
        "query",
        "--repo",
        repo_a_str.as_str(),
        "--state-dir",
        &state_root_str,
        "--query",
        "shared_term",
        "--limit",
        "10",
    ])?;
    let hits_a = hits_from_query(&out_a)?;
    assert!(
        hits_a.iter().all(|hit| hit
            .get("path")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .ends_with("a-only.md")),
        "repo A query must not return docs from repo B"
    );

    let out_b = run_docdex([
        "query",
        "--repo",
        repo_b_str.as_str(),
        "--state-dir",
        &state_root_str,
        "--query",
        "shared_term",
        "--limit",
        "10",
    ])?;
    let hits_b = hits_from_query(&out_b)?;
    assert!(
        hits_b.iter().all(|hit| hit
            .get("path")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .ends_with("b-only.md")),
        "repo B query must not return docs from repo A"
    );

    Ok(())
}

#[test]
fn moved_repo_reuses_existing_state_key_under_shared_state_dir() -> Result<(), Box<dyn Error>> {
    let state_root = TempDir::new()?;
    let state_root = state_root.path().canonicalize()?;

    let workspace = TempDir::new()?;
    let repo_a = workspace.path().join("repo-a");
    let repo_b = workspace.path().join("repo-moved");
    write_repo(&repo_a, "doc.md", "move_token")?;

    let state_root_str = state_root.to_string_lossy().to_string();
    let repo_a_str = repo_a.to_string_lossy().to_string();
    let repo_b_str = repo_b.to_string_lossy().to_string();
    run_docdex(["index", "--repo", repo_a_str.as_str(), "--state-dir", &state_root_str])?;

    let repos_dir = state_root.join("repos");
    let repo_dirs: Vec<PathBuf> = fs::read_dir(&repos_dir)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let file_type = entry.file_type().ok()?;
            if file_type.is_dir() { Some(path) } else { None }
        })
        .collect();
    assert_eq!(repo_dirs.len(), 1, "expected one repo state dir after first index");
    let state_key = repo_dirs[0]
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("state dir missing name")?
        .to_string();

    fs::rename(&repo_a, &repo_b)?;
    let moved_out = Command::new(docdex_bin())
        .env_remove("DOCDEX_ENABLE_SYMBOL_EXTRACTION")
        .args([
            "index",
            "--repo",
            repo_b_str.as_str(),
            "--state-dir",
            &state_root_str,
        ])
        .output()?;
    assert!(
        !moved_out.status.success(),
        "expected moved repo to fast-fail before explicit re-association"
    );
    let stderr = String::from_utf8_lossy(&moved_out.stderr);
    let json_line = stderr
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .ok_or("expected JSON error line in stderr")?;
    let err_payload: Value = serde_json::from_str(json_line.trim())?;
    assert_eq!(
        err_payload
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|v| v.as_str()),
        Some("repo_state_mismatch")
    );
    let steps = err_payload
        .get("error")
        .and_then(|e| e.get("details"))
        .and_then(|d| d.get("recoverySteps"))
        .and_then(|v| v.as_array())
        .ok_or("expected recoverySteps array")?;
    assert!(
        steps.iter().any(|v| v
            .as_str()
            .unwrap_or_default()
            .contains("repo reassociate")),
        "expected recoverySteps to mention `repo reassociate`; got: {err_payload}"
    );
    let known_canonical = err_payload
        .get("error")
        .and_then(|e| e.get("details"))
        .and_then(|d| d.get("knownCanonicalPath"))
        .and_then(|v| v.as_str())
        .ok_or("expected details.knownCanonicalPath")?
        .to_string();

    let reassociate_out = run_docdex([
        "repo",
        "reassociate",
        "--repo",
        repo_b_str.as_str(),
        "--state-dir",
        &state_root_str,
        "--old-path",
        known_canonical.as_str(),
    ])?;
    let reassociated: Value = serde_json::from_slice(&reassociate_out)?;
    assert_eq!(
        reassociated
            .get("canonical_path")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        repo_b
            .canonicalize()
            .unwrap_or_else(|_| repo_b.clone())
            .to_string_lossy()
            .replace('\\', "/")
    );

    run_docdex(["index", "--repo", repo_b_str.as_str(), "--state-dir", &state_root_str])?;

    let repo_dirs_after: Vec<PathBuf> = fs::read_dir(&repos_dir)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let file_type = entry.file_type().ok()?;
            if file_type.is_dir() { Some(path) } else { None }
        })
        .collect();
    assert_eq!(
        repo_dirs_after.len(),
        1,
        "expected repo move to reuse existing state dir (no new state key)"
    );
    let state_key_after = repo_dirs_after[0]
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("state dir missing name")?
        .to_string();
    assert_eq!(state_key_after, state_key);

    let registry_path = state_root.join("repos").join("repo_registry.json");
    let registry_raw = fs::read_to_string(&registry_path)?;
    let registry_json: Value = serde_json::from_str(&registry_raw)?;
    let repos = registry_json
        .get("repos")
        .and_then(|value| value.as_object())
        .ok_or("registry missing repos object")?;
    let entry = repos
        .values()
        .find(|value| {
            value
                .get("state_key")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                == state_key
        })
        .ok_or("registry entry missing for state_key")?;
    let canonical = entry
        .get("canonical_path")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let expected = repo_b
        .canonicalize()
        .unwrap_or_else(|_| repo_b.clone())
        .to_string_lossy()
        .replace('\\', "/");
    assert_eq!(canonical, expected, "expected registry canonical path to update after move");

    Ok(())
}
    let moved_out = Command::new(docdex_bin())
        .env_remove("DOCDEX_ENABLE_SYMBOL_EXTRACTION")
        .args([
            "index",
            "--repo",
            repo_b_str.as_str(),
            "--state-dir",
            &state_root_str,
        ])
        .output()?;
    assert!(
        !moved_out.status.success(),
        "expected moved repo to fast-fail before explicit re-association"
    );
    let stderr = String::from_utf8_lossy(&moved_out.stderr);
    let json_line = stderr
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .ok_or("expected JSON error line in stderr")?;
    let err_payload: Value = serde_json::from_str(json_line.trim())?;
    assert_eq!(
        err_payload
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|v| v.as_str()),
        Some("repo_state_mismatch")
    );
    let steps = err_payload
        .get("error")
        .and_then(|e| e.get("details"))
        .and_then(|d| d.get("recoverySteps"))
        .and_then(|v| v.as_array())
        .ok_or("expected recoverySteps array")?;
    assert!(
        steps.iter().any(|v| v
            .as_str()
            .unwrap_or_default()
            .contains("repo reassociate")),
        "expected recoverySteps to mention `repo reassociate`; got: {err_payload}"
    );
    let known_canonical = err_payload
        .get("error")
        .and_then(|e| e.get("details"))
        .and_then(|d| d.get("knownCanonicalPath"))
        .and_then(|v| v.as_str())
        .ok_or("expected details.knownCanonicalPath")?
        .to_string();

    let reassociate_out = run_docdex([
        "repo",
        "reassociate",
        "--repo",
        repo_b_str.as_str(),
        "--state-dir",
        &state_root_str,
        "--old-path",
        known_canonical.as_str(),
    ])?;
    let reassociated: Value = serde_json::from_slice(&reassociate_out)?;
    assert_eq!(
        reassociated
            .get("canonical_path")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        repo_b
            .canonicalize()
            .unwrap_or_else(|_| repo_b.clone())
            .to_string_lossy()
            .replace('\\', "/")
    );

