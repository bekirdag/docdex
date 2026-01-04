use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tantivy::schema::{Schema, STORED, TEXT};
use tantivy::{doc, Index};
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    std::env::set_var("DOCDEX_WEB_ENABLED", "0");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn inspect_repo_state(state_root: &Path, repo_root: &Path) -> Result<Value, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let state_root_str = state_root.to_string_lossy().to_string();
    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args([
            "repo",
            "inspect",
            "--repo",
            repo_str.as_str(),
            "--state-dir",
            state_root_str.as_str(),
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd repo inspect exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn resolve_index_dir(state_root: &Path, repo_root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let payload = inspect_repo_state(state_root, repo_root)?;
    let resolved = payload
        .get("resolvedIndexStateDir")
        .and_then(|value| value.as_str())
        .ok_or("missing resolvedIndexStateDir")?;
    Ok(PathBuf::from(resolved))
}

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root)?;
    fs::write(repo_root.join("doc.md"), "# Fixture\n\nSCHEMA_TOKEN\n")?;
    Ok(())
}

fn create_incompatible_index(index_dir: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(index_dir)?;
    let mut builder = Schema::builder();
    let title = builder.add_text_field("legacy_title", TEXT | STORED);
    let schema = builder.build();
    let index = Index::create_in_dir(index_dir, schema)?;
    let mut writer = index.writer(15_000_000)?;
    writer.add_document(doc!(title => "legacy"))?;
    writer.commit()?;
    Ok(())
}

fn parse_error(stderr: &[u8]) -> Result<Value, Box<dyn Error>> {
    let raw = String::from_utf8_lossy(stderr);
    let trimmed = raw.trim();
    Ok(serde_json::from_str(trimmed)?)
}

#[test]
fn cli_query_reports_schema_mismatch() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let index_dir = resolve_index_dir(state_root.path(), repo.path())?;
    create_incompatible_index(&index_dir)?;

    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root.path())
        .args([
            "query",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--query",
            "SCHEMA_TOKEN",
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
        Some("stale_index")
    );
    assert!(
        payload
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .contains("schema mismatch"),
        "expected schema mismatch message; got: {payload}"
    );
    Ok(())
}

#[test]
fn reindex_does_not_clobber_incompatible_schema() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let index_dir = resolve_index_dir(state_root.path(), repo.path())?;
    create_incompatible_index(&index_dir)?;
    let meta_path = index_dir.join("meta.json");
    let before = fs::read_to_string(&meta_path)?;

    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root.path())
        .args(["index", "--repo", repo.path().to_string_lossy().as_ref()])
        .output()?;
    assert!(!output.status.success(), "expected non-zero exit");
    let payload = parse_error(&output.stderr)?;
    assert_eq!(
        payload
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(|v| v.as_str()),
        Some("stale_index")
    );

    let after = fs::read_to_string(&meta_path)?;
    assert!(after.contains("legacy_title"));
    assert_eq!(
        before, after,
        "expected schema metadata to remain unchanged"
    );
    Ok(())
}
