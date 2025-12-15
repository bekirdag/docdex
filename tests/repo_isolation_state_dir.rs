use serde_json::Value;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn repo_id_for_root(repo_root: &Path) -> String {
    let normalized = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf())
        .to_string_lossy()
        .replace('\\', "/");
    hex::encode(Sha256::digest(normalized.as_bytes()))
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

    let repo_a_id = repo_id_for_root(repo_a.path());
    let repo_b_id = repo_id_for_root(repo_b.path());
    assert!(
        state_root
            .join("repos")
            .join(&repo_a_id)
            .join("index")
            .exists(),
        "expected repo A state dir to exist under base state dir"
    );
    assert!(
        state_root
            .join("repos")
            .join(&repo_b_id)
            .join("index")
            .exists(),
        "expected repo B state dir to exist under base state dir"
    );

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
