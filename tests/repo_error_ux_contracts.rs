use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn normalize_path(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/")
}

fn write_repo(repo_root: &Path, filename: &str, token: &str) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root)?;
    fs::create_dir_all(repo_root.join(".git"))?;
    fs::write(
        repo_root.join(filename),
        format!(
            r#"# Fixture

shared_term
{token}
"#
        ),
    )?;
    Ok(())
}

fn parse_error(stderr: &[u8]) -> Result<Value, Box<dyn Error>> {
    let raw = String::from_utf8_lossy(stderr);
    let trimmed = raw.trim();
    Ok(serde_json::from_str(trimmed)?)
}

#[test]
fn cli_missing_repo_path_includes_move_hint_and_details() -> Result<(), Box<dyn Error>> {
    let base = TempDir::new()?;
    let missing_repo = base.path().join("missing-repo");

    let output = Command::new(docdex_bin())
        .args([
            "query",
            "--repo",
            missing_repo.to_string_lossy().as_ref(),
            "--query",
            "shared_term",
            "--limit",
            "1",
        ])
        .output()?;

    assert!(!output.status.success(), "expected non-zero exit");
    let payload = parse_error(&output.stderr)?;
    assert_eq!(
        payload
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|v| v.as_str()),
        Some("missing_repo_path")
    );
    let details = payload
        .get("error")
        .and_then(|e| e.get("details"))
        .ok_or("expected error.details")?;
    let expected_norm = missing_repo.to_string_lossy().replace('\\', "/");
    assert_eq!(
        details.get("normalizedPath").and_then(|v| v.as_str()),
        Some(expected_norm.as_str())
    );
    let steps = details
        .get("recoverySteps")
        .and_then(|v| v.as_array())
        .ok_or("expected details.recoverySteps array")?;
    assert!(
        steps.iter().any(|v| v.as_str().unwrap_or_default().to_lowercase().contains("moved")),
        "expected recoverySteps to mention moved/renamed; got: {details}"
    );
    Ok(())
}

#[test]
fn cli_repo_state_mismatch_fast_fails_with_fingerprint_and_guidance() -> Result<(), Box<dyn Error>> {
    let workspace = TempDir::new()?;
    let state_root = TempDir::new()?;
    let state_root = state_root.path().canonicalize()?;
    let state_root_str = state_root.to_string_lossy().to_string();

    let repo_a = workspace.path().join("repo-a");
    let repo_b = workspace.path().join("repo-b");
    write_repo(&repo_a, "a.md", "repo_a_token")?;
    write_repo(&repo_b, "b.md", "repo_b_token")?;

    let out_a = Command::new(docdex_bin())
        .args([
            "index",
            "--repo",
            repo_a.to_string_lossy().as_ref(),
            "--state-dir",
            state_root_str.as_str(),
        ])
        .output()?;
    assert!(out_a.status.success(), "index repo-a failed: {:?}", out_a);

    let out_b = Command::new(docdex_bin())
        .args([
            "index",
            "--repo",
            repo_b.to_string_lossy().as_ref(),
            "--state-dir",
            state_root_str.as_str(),
        ])
        .output()?;
    assert!(out_b.status.success(), "index repo-b failed: {:?}", out_b);

    let registry_path = state_root.join("repos").join("repo_registry.json");
    let registry_raw = fs::read_to_string(&registry_path)?;
    let registry_json: Value = serde_json::from_str(&registry_raw)?;
    let repos = registry_json
        .get("repos")
        .and_then(|v| v.as_object())
        .ok_or("registry missing repos object")?;

    let canon_a = normalize_path(&repo_a);
    let canon_b = normalize_path(&repo_b);
    let mut fp_a: Option<String> = None;
    let mut fp_b: Option<String> = None;
    let mut state_key_b: Option<String> = None;
    for (fp, entry) in repos {
        let canonical_path = entry
            .get("canonical_path")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if canonical_path == canon_a {
            fp_a = Some(fp.to_string());
        }
        if canonical_path == canon_b {
            fp_b = Some(fp.to_string());
            state_key_b = entry
                .get("state_key")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
        }
    }
    let fp_a = fp_a.ok_or("missing repo-a fingerprint in registry")?;
    let fp_b = fp_b.ok_or("missing repo-b fingerprint in registry")?;
    let state_key_b = state_key_b.ok_or("missing repo-b state_key in registry")?;

    let meta_path_b = state_root
        .join("repos")
        .join(&state_key_b)
        .join("repo_meta.json");
    let mut meta_b: Value = serde_json::from_str(&fs::read_to_string(&meta_path_b)?)?;
    meta_b["fingerprint_sha256"] = Value::String(fp_a.clone());
    fs::write(&meta_path_b, serde_json::to_string_pretty(&meta_b)?)?;

    let query_out = Command::new(docdex_bin())
        .args([
            "query",
            "--repo",
            repo_b.to_string_lossy().as_ref(),
            "--state-dir",
            state_root_str.as_str(),
            "--query",
            "shared_term",
            "--limit",
            "1",
        ])
        .output()?;
    assert!(
        !query_out.status.success(),
        "expected repo_state_mismatch fast-fail; got success"
    );
    let payload = parse_error(&query_out.stderr)?;
    assert_eq!(
        payload
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|v| v.as_str()),
        Some("repo_state_mismatch")
    );
    let details = payload
        .get("error")
        .and_then(|e| e.get("details"))
        .ok_or("expected error.details")?;
    assert_eq!(
        details.get("attemptedFingerprint").and_then(|v| v.as_str()),
        Some(fp_b.as_str())
    );
    assert_eq!(
        details.get("knownCanonicalPath").and_then(|v| v.as_str()),
        Some(canon_b.as_str())
    );
    assert!(
        details
            .get("recoverySteps")
            .and_then(|v| v.as_array())
            .map(|v| !v.is_empty())
            .unwrap_or(false),
        "expected recoverySteps for repo_state_mismatch; got: {details}"
    );

    Ok(())
}

#[test]
<<<<<<< HEAD
fn cli_repo_state_meta_drift_fails_closed() -> Result<(), Box<dyn Error>> {
    let workspace = TempDir::new()?;
    let state_root = TempDir::new()?;
    let state_root = state_root.path().canonicalize()?;
    let state_root_str = state_root.to_string_lossy().to_string();

    let repo_a = workspace.path().join("repo-a");
    write_repo(&repo_a, "a.md", "repo_a_token")?;

    let out_a = Command::new(docdex_bin())
        .args([
            "index",
            "--repo",
            repo_a.to_string_lossy().as_ref(),
            "--state-dir",
            state_root_str.as_str(),
        ])
        .output()?;
    assert!(out_a.status.success(), "index repo-a failed: {:?}", out_a);

    let repos_dir = state_root.join("repos");
    let mut repo_dir: Option<PathBuf> = None;
    for entry in fs::read_dir(&repos_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            repo_dir = Some(entry.path());
            break;
        }
    }
    let repo_dir = repo_dir.ok_or("expected repo state directory")?;
    let meta_path = repo_dir.join("repo_meta.json");
    let raw_meta = fs::read_to_string(&meta_path)?;
    let mut meta: Value = serde_json::from_str(&raw_meta)?;
    let original = meta
        .get("fingerprint_sha256")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let drifted = if original == "deadbeef" {
        "badbeef".to_string()
    } else {
        "deadbeef".to_string()
    };
    let obj = meta.as_object_mut().ok_or("repo meta must be an object")?;
    obj.insert("fingerprint_sha256".to_string(), Value::String(drifted));
    fs::write(&meta_path, serde_json::to_string_pretty(&meta)?)?;
=======
fn cli_missing_index_returns_actionable_hint() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path(), "a.md", "missing_index_token")?;
>>>>>>> mcoda/task/bck-05-us-08-t09

    let output = Command::new(docdex_bin())
        .args([
            "query",
            "--repo",
<<<<<<< HEAD
            repo_a.to_string_lossy().as_ref(),
            "--state-dir",
            state_root_str.as_str(),
=======
            repo.path().to_string_lossy().as_ref(),
>>>>>>> mcoda/task/bck-05-us-08-t09
            "--query",
            "shared_term",
            "--limit",
            "1",
        ])
        .output()?;
<<<<<<< HEAD
    assert!(
        !output.status.success(),
        "expected repo query to fail closed on meta drift"
    );
=======

    assert!(!output.status.success(), "expected non-zero exit");
>>>>>>> mcoda/task/bck-05-us-08-t09
    let payload = parse_error(&output.stderr)?;
    assert_eq!(
        payload
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|v| v.as_str()),
<<<<<<< HEAD
        Some("repo_state_mismatch")
=======
        Some("missing_index")
    );
    let message = payload
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        message.contains("docdexd index"),
        "expected missing_index message to include index hint; got: {message}"
>>>>>>> mcoda/task/bck-05-us-08-t09
    );
    let details = payload
        .get("error")
        .and_then(|e| e.get("details"))
        .ok_or("expected error.details")?;
<<<<<<< HEAD
    assert!(
        details
            .get("attemptedFingerprint")
            .and_then(|v| v.as_str())
            .is_some(),
        "expected attemptedFingerprint on repo_state_mismatch"
    );
    assert!(
        details
            .get("knownCanonicalPath")
            .and_then(|v| v.as_str())
            .is_some(),
        "expected knownCanonicalPath on repo_state_mismatch"
    );
    assert!(
        details
            .get("recoverySteps")
            .and_then(|v| v.as_array())
            .is_some(),
        "expected recoverySteps array on repo_state_mismatch"
    );

=======
    let steps = details
        .get("recoverySteps")
        .and_then(|v| v.as_array())
        .ok_or("expected details.recoverySteps array")?;
    assert!(
        steps
            .iter()
            .any(|v| v.as_str().unwrap_or_default().contains("docdexd index")),
        "expected recoverySteps to mention docdexd index; got: {details}"
    );
>>>>>>> mcoda/task/bck-05-us-08-t09
    Ok(())
}

#[test]
<<<<<<< HEAD
fn cli_repo_state_meta_drift_fails_closed() -> Result<(), Box<dyn Error>> {
    let workspace = TempDir::new()?;
    let state_root = TempDir::new()?;
    let state_root = state_root.path().canonicalize()?;
    let state_root_str = state_root.to_string_lossy().to_string();

    let repo_a = workspace.path().join("repo-a");
    write_repo(&repo_a, "a.md", "repo_a_token")?;

    let out_a = Command::new(docdex_bin())
        .args([
            "index",
            "--repo",
            repo_a.to_string_lossy().as_ref(),
            "--state-dir",
            state_root_str.as_str(),
        ])
        .output()?;
    assert!(out_a.status.success(), "index repo-a failed: {:?}", out_a);

    let repos_dir = state_root.join("repos");
    let mut repo_dir: Option<PathBuf> = None;
    for entry in fs::read_dir(&repos_dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            repo_dir = Some(entry.path());
            break;
        }
    }
    let repo_dir = repo_dir.ok_or("expected repo state directory")?;
    let meta_path = repo_dir.join("repo_meta.json");
    let raw_meta = fs::read_to_string(&meta_path)?;
    let mut meta: Value = serde_json::from_str(&raw_meta)?;
    let original = meta
        .get("fingerprint_sha256")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let drifted = if original == "deadbeef" {
        "badbeef".to_string()
    } else {
        "deadbeef".to_string()
    };
    let obj = meta.as_object_mut().ok_or("repo meta must be an object")?;
    obj.insert("fingerprint_sha256".to_string(), Value::String(drifted));
    fs::write(&meta_path, serde_json::to_string_pretty(&meta)?)?;
=======
fn cli_stale_index_returns_actionable_hint() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path(), "a.md", "stale_index_token")?;

    let repo_str = repo.path().to_string_lossy().to_string();
    let index_out = Command::new(docdex_bin())
        .args(["index", "--repo", repo_str.as_str()])
        .output()?;
    assert!(index_out.status.success(), "index failed: {:?}", index_out);

    let state_path = repo
        .path()
        .join(".docdex")
        .join("index")
        .join("index_state.json");
    let mut state: Value = serde_json::from_str(&fs::read_to_string(&state_path)?)?;
    state["status"] = Value::String("stale".to_string());
    fs::write(&state_path, serde_json::to_string_pretty(&state)?)?;
>>>>>>> mcoda/task/bck-05-us-08-t09

    let output = Command::new(docdex_bin())
        .args([
            "query",
            "--repo",
<<<<<<< HEAD
            repo_a.to_string_lossy().as_ref(),
            "--state-dir",
            state_root_str.as_str(),
=======
            repo_str.as_str(),
>>>>>>> mcoda/task/bck-05-us-08-t09
            "--query",
            "shared_term",
            "--limit",
            "1",
        ])
        .output()?;
<<<<<<< HEAD
    assert!(
        !output.status.success(),
        "expected repo query to fail closed on meta drift"
    );
=======

    assert!(!output.status.success(), "expected non-zero exit");
>>>>>>> mcoda/task/bck-05-us-08-t09
    let payload = parse_error(&output.stderr)?;
    assert_eq!(
        payload
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|v| v.as_str()),
<<<<<<< HEAD
        Some("repo_state_mismatch")
=======
        Some("stale_index")
    );
    let message = payload
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        message.contains("docdexd index"),
        "expected stale_index message to include index hint; got: {message}"
>>>>>>> mcoda/task/bck-05-us-08-t09
    );
    let details = payload
        .get("error")
        .and_then(|e| e.get("details"))
        .ok_or("expected error.details")?;
<<<<<<< HEAD
    assert!(
        details
            .get("attemptedFingerprint")
            .and_then(|v| v.as_str())
            .is_some(),
        "expected attemptedFingerprint on repo_state_mismatch"
    );
    assert!(
        details
            .get("knownCanonicalPath")
            .and_then(|v| v.as_str())
            .is_some(),
        "expected knownCanonicalPath on repo_state_mismatch"
    );
    assert!(
        details
            .get("recoverySteps")
            .and_then(|v| v.as_array())
            .is_some(),
        "expected recoverySteps array on repo_state_mismatch"
    );

=======
    let steps = details
        .get("recoverySteps")
        .and_then(|v| v.as_array())
        .ok_or("expected details.recoverySteps array")?;
    assert!(
        steps
            .iter()
            .any(|v| v.as_str().unwrap_or_default().contains("docdexd index")),
        "expected recoverySteps to mention docdexd index; got: {details}"
    );
>>>>>>> mcoda/task/bck-05-us-08-t09
    Ok(())
}
