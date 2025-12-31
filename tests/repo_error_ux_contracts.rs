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

    let output = Command::new(docdex_bin()).env("DOCDEX_ENABLE_MEMORY", "0")
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
        steps.iter().any(|v| v
            .as_str()
            .unwrap_or_default()
            .to_lowercase()
            .contains("moved")),
        "expected recoverySteps to mention moved/renamed; got: {details}"
    );
    Ok(())
}

#[test]
fn cli_repo_state_mismatch_fast_fails_with_fingerprint_and_guidance() -> Result<(), Box<dyn Error>>
{
    let workspace = TempDir::new()?;
    let state_root = TempDir::new()?;
    let state_root = state_root.path().canonicalize()?;
    let state_root_str = state_root.to_string_lossy().to_string();

    let repo_a = workspace.path().join("repo-a");
    let repo_b = workspace.path().join("repo-b");
    write_repo(&repo_a, "a.md", "repo_a_token")?;
    write_repo(&repo_b, "b.md", "repo_b_token")?;

    let out_a = Command::new(docdex_bin()).env("DOCDEX_ENABLE_MEMORY", "0")
        .args([
            "index",
            "--repo",
            repo_a.to_string_lossy().as_ref(),
            "--state-dir",
            state_root_str.as_str(),
        ])
        .output()?;
    assert!(out_a.status.success(), "index repo-a failed: {:?}", out_a);

    let out_b = Command::new(docdex_bin()).env("DOCDEX_ENABLE_MEMORY", "0")
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
        }
    }
    let fp_a = fp_a.ok_or("missing repo-a fingerprint in registry")?;
    let fp_b = fp_b.ok_or("missing repo-b fingerprint in registry")?;

    let meta_path_b = repo_b.join("repo_meta.json");
    let mut meta_b: Value = serde_json::from_str(&fs::read_to_string(&meta_path_b)?)?;
    meta_b["fingerprint_sha256"] = Value::String(fp_a.clone());
    fs::write(&meta_path_b, serde_json::to_string_pretty(&meta_b)?)?;

    let query_out = Command::new(docdex_bin()).env("DOCDEX_ENABLE_MEMORY", "0")
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
