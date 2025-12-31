use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn normalize_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
}

fn run_docdex<I, S>(args: I) -> Result<Vec<u8>, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin()).env("DOCDEX_ENABLE_MEMORY", "0")
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

fn parse_error(stderr: &[u8]) -> Result<Value, Box<dyn Error>> {
    let raw = String::from_utf8_lossy(stderr);
    let json_line = raw
        .lines()
        .rev()
        .find(|line| line.trim_start().starts_with('{'))
        .ok_or("expected JSON error line in stderr")?;
    Ok(serde_json::from_str(json_line.trim())?)
}

fn registry_entry_for_path(
    state_root: &Path,
    canonical_path: &str,
) -> Result<(String, String), Box<dyn Error>> {
    let registry_path = state_root.join("repos").join("repo_registry.json");
    let registry_raw = fs::read_to_string(&registry_path)?;
    let registry_json: Value = serde_json::from_str(&registry_raw)?;
    let repos = registry_json
        .get("repos")
        .and_then(|value| value.as_object())
        .ok_or("registry missing repos object")?;
    for (fingerprint, entry) in repos {
        let canon = entry
            .get("canonical_path")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if canon == canonical_path {
            let state_key = entry
                .get("state_key")
                .and_then(|v| v.as_str())
                .ok_or("registry entry missing state_key")?;
            return Ok((fingerprint.clone(), state_key.to_string()));
        }
    }
    Err(format!("no registry entry found for canonical_path={canonical_path}").into())
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

    run_docdex([
        "index",
        "--repo",
        repo_a_str.as_str(),
        "--state-dir",
        &state_root_str,
    ])?;
    run_docdex([
        "index",
        "--repo",
        repo_b_str.as_str(),
        "--state-dir",
        &state_root_str,
    ])?;

    let repos_dir = state_root.join("repos");
    let mut repo_dirs: Vec<PathBuf> = fs::read_dir(&repos_dir)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let file_type = entry.file_type().ok()?;
            if file_type.is_dir() {
                Some(path)
            } else {
                None
            }
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
    run_docdex([
        "index",
        "--repo",
        repo_a_str.as_str(),
        "--state-dir",
        &state_root_str,
    ])?;

    let repos_dir = state_root.join("repos");
    let mut repo_dirs: Vec<PathBuf> = fs::read_dir(&repos_dir)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let file_type = entry.file_type().ok()?;
            if file_type.is_dir() {
                Some(path)
            } else {
                None
            }
        })
        .collect();
    repo_dirs.sort();
    assert_eq!(
        repo_dirs.len(),
        1,
        "expected one repo state dir after first index"
    );

    let canon_a = normalize_path(&repo_a);
    let (fp_a, state_key) = registry_entry_for_path(&state_root, &canon_a)?;

    fs::rename(&repo_a, &repo_b)?;
    let moved_out = Command::new(docdex_bin()).env("DOCDEX_ENABLE_MEMORY", "0")
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
    let err_payload = parse_error(&moved_out.stderr)?;
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
        steps
            .iter()
            .any(|v| v.as_str().unwrap_or_default().contains("repo reassociate")),
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
            .get("fingerprint")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        fp_a.as_str(),
        "expected reassociate diagnostics to include the repo fingerprint"
    );
    assert_eq!(
        reassociated
            .get("state_key")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        state_key.as_str(),
        "expected reassociate diagnostics to include the mapped state_key"
    );
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
    assert_eq!(
        reassociated
            .get("prior_canonical_path")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        known_canonical.as_str(),
        "expected reassociate to report the prior canonical path"
    );

    run_docdex([
        "index",
        "--repo",
        repo_b_str.as_str(),
        "--state-dir",
        &state_root_str,
    ])?;

    let repo_dirs_after: Vec<PathBuf> = fs::read_dir(&repos_dir)?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let path = entry.path();
            let file_type = entry.file_type().ok()?;
            if file_type.is_dir() {
                Some(path)
            } else {
                None
            }
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
    assert_eq!(
        canonical, expected,
        "expected registry canonical path to update after move"
    );

    Ok(())
}

#[test]
fn reassociate_fails_closed_when_fingerprint_mismatches() -> Result<(), Box<dyn Error>> {
    let state_root = TempDir::new()?;
    let state_root = state_root.path().canonicalize()?;
    let workspace = TempDir::new()?;

    let repo_a = workspace.path().join("repo-a");
    let repo_b = workspace.path().join("repo-b");
    write_repo(&repo_a, "a.md", "repo_a_token")?;
    write_repo(&repo_b, "b.md", "repo_b_token")?;

    let state_root_str = state_root.to_string_lossy().to_string();
    run_docdex([
        "index",
        "--repo",
        repo_a.to_string_lossy().as_ref(),
        "--state-dir",
        &state_root_str,
    ])?;

    let canon_a = normalize_path(&repo_a);
    let (fp_a, _state_key_a) = registry_entry_for_path(&state_root, &canon_a)?;

    let output = Command::new(docdex_bin()).env("DOCDEX_ENABLE_MEMORY", "0")
        .env_remove("DOCDEX_ENABLE_SYMBOL_EXTRACTION")
        .args([
            "repo",
            "reassociate",
            "--repo",
            repo_b.to_string_lossy().as_ref(),
            "--state-dir",
            &state_root_str,
            "--fingerprint",
            fp_a.as_str(),
        ])
        .output()?;
    assert!(
        !output.status.success(),
        "expected reassociate to fail when fingerprint does not match"
    );
    let payload = parse_error(&output.stderr)?;
    assert_eq!(
        payload
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|v| v.as_str()),
        Some("repo_state_mismatch")
    );
    let attempted = payload
        .get("error")
        .and_then(|e| e.get("details"))
        .and_then(|d| d.get("attemptedFingerprint"))
        .and_then(|v| v.as_str())
        .ok_or("expected details.attemptedFingerprint")?;
    assert_ne!(
        attempted,
        fp_a.as_str(),
        "attemptedFingerprint should reflect the new repo, not the target registry fingerprint"
    );

    // Registry should remain unchanged: no reassociation to repo-b.
    let registry_path = state_root.join("repos").join("repo_registry.json");
    let registry_raw = fs::read_to_string(&registry_path)?;
    let registry_json: Value = serde_json::from_str(&registry_raw)?;
    let repos = registry_json
        .get("repos")
        .and_then(|value| value.as_object())
        .ok_or("registry missing repos object")?;
    let entry = repos
        .get(&fp_a)
        .ok_or("expected registry entry for repo-a fingerprint")?;
    assert_eq!(
        entry
            .get("canonical_path")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        canon_a.as_str(),
        "failed reassociate must not modify canonical_path"
    );
    let canon_b = normalize_path(&repo_b);
    assert!(
        !repos.values().any(|v| v
            .get("canonical_path")
            .and_then(|p| p.as_str())
            .unwrap_or_default()
            == canon_b),
        "failed reassociate must not create a new registry entry"
    );

    Ok(())
}

#[test]
fn never_cross_associates_repo_requests_via_other_repo_scoped_state_dir(
) -> Result<(), Box<dyn Error>> {
    let state_root = TempDir::new()?;
    let state_root = state_root.path().canonicalize()?;

    let workspace = TempDir::new()?;
    let repo_a = workspace.path().join("repo-a");
    let repo_b = workspace.path().join("repo-b");
    write_repo(&repo_a, "a-only.md", "repo_a_token")?;
    write_repo(&repo_b, "b-only.md", "repo_b_token")?;

    let state_root_str = state_root.to_string_lossy().to_string();
    run_docdex([
        "index",
        "--repo",
        repo_b.to_string_lossy().as_ref(),
        "--state-dir",
        &state_root_str,
    ])?;

    let canon_b = normalize_path(&repo_b);
    let (_fp_b, state_key_b) = registry_entry_for_path(&state_root, &canon_b)?;
    let scoped_b_index = state_root
        .join("repos")
        .join(&state_key_b)
        .join("index")
        .to_string_lossy()
        .to_string();

    // Querying repo-a with repo-b's scoped state dir must not return repo-b hits.
    // Repo-a is unindexed, so the only safe outcome is a missing_index error.
    let output = Command::new(docdex_bin()).env("DOCDEX_ENABLE_MEMORY", "0")
        .env_remove("DOCDEX_ENABLE_SYMBOL_EXTRACTION")
        .args([
            "query",
            "--repo",
            repo_a.to_string_lossy().as_ref(),
            "--state-dir",
            scoped_b_index.as_str(),
            "--query",
            "shared_term",
            "--limit",
            "10",
        ])
        .output()?;
    assert!(
        !output.status.success(),
        "expected repo-a query to fail closed instead of using repo-b state"
    );
    let payload = parse_error(&output.stderr)?;
    assert_eq!(
        payload
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|v| v.as_str()),
        Some("missing_index"),
        "repo-a must not be served from repo-b state; expected missing_index"
    );

    Ok(())
}
