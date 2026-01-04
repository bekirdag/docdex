mod common;

use common::docdex_bin;
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join("docs"))?;
    fs::write(repo_root.join("docs").join("readme.md"), "# Repo\n")?;
    Ok(())
}

#[test]
fn cli_state_dir_override_scopes_index() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_base = TempDir::new()?;

    let output = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args([
            "index",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--state-dir",
            state_base.path().to_string_lossy().as_ref(),
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd index failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }

    let inspect_out = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args([
            "repo",
            "inspect",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--state-dir",
            state_base.path().to_string_lossy().as_ref(),
        ])
        .output()?;
    if !inspect_out.status.success() {
        return Err(format!(
            "docdexd repo inspect failed: {}",
            String::from_utf8_lossy(&inspect_out.stderr)
        )
        .into());
    }
    let payload: Value = serde_json::from_slice(&inspect_out.stdout)?;
    let resolved = payload
        .get("resolvedIndexStateDir")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let base = state_base.path().to_string_lossy();
    assert!(
        resolved.starts_with(base.as_ref()),
        "expected {resolved} to start with {base}"
    );
    Ok(())
}
