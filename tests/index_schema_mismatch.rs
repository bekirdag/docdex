use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tantivy::schema::{Schema, STORED, TEXT};
use tantivy::{doc, Index};
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
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
    let mut writer = index.writer(5_000_000)?;
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
    let index_dir = repo.path().join(".docdex").join("index");
    create_incompatible_index(&index_dir)?;

    let output = Command::new(docdex_bin())
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
    let index_dir = repo.path().join(".docdex").join("index");
    create_incompatible_index(&index_dir)?;
    let meta_path = index_dir.join("meta.json");
    let before = fs::read_to_string(&meta_path)?;

    let output = Command::new(docdex_bin())
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
