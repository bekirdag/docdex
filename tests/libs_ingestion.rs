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

fn run_docdex<I, S>(state_root: &Path, args: I) -> Result<Vec<u8>, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin())
        .env_remove("DOCDEX_ENABLE_SYMBOL_EXTRACTION")
        .env("DOCDEX_STATE_DIR", state_root)
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

fn setup_repo() -> Result<TempDir, Box<dyn Error>> {
    let repo = TempDir::new()?;
    fs::write(
        repo.path().join("readme.md"),
        "# Repo Doc\n\nThis is a repository document.\n",
    )?;
    Ok(repo)
}

fn write_lib_doc(repo_root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    write_lib_doc_with_body(
        repo_root,
        "# Serde\n\nLIBS_ONLY_TERM_123 appears only in library docs.\n",
    )
}

fn write_lib_doc_with_body(repo_root: &Path, body: &str) -> Result<PathBuf, Box<dyn Error>> {
    let path = repo_root.join("vendor").join("serde").join("README.md");
    fs::create_dir_all(path.parent().expect("parent"))?;
    fs::write(&path, body)?;
    Ok(path)
}

#[test]
fn libs_ingestion_is_partial_and_searchable() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let repo_str = repo_root.to_string_lossy().to_string();

    let lib_doc = write_lib_doc(repo_root)?;
    let invalid_path = repo_root.join("vendor").join("missing").join("README.md");

    let sources_path = repo_root.join("libs_sources.json");
    let sources = serde_json::json!({
        "sources": [
            {
                "library": "serde",
                "version": "1.0.0",
                "source": "local_file",
                "path": lib_doc.display().to_string(),
                "title": "Serde"
            },
            {
                "library": "missing-lib",
                "version": "0.0.0",
                "source": "local_file",
                "path": invalid_path.display().to_string()
            }
        ]
    });
    fs::write(&sources_path, serde_json::to_string_pretty(&sources)?)?;

    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let ingest_out = run_docdex(
        state_root.path(),
        [
            "libs-ingest",
            "--repo",
            repo_str.as_str(),
            "--sources",
            sources_path.to_string_lossy().as_ref(),
        ],
    )?;
    let ingest_payload: Value = serde_json::from_slice(&ingest_out)?;
    assert_eq!(
        ingest_payload
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "partial_success"
    );
    assert_eq!(
        ingest_payload
            .get("succeeded_sources")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        1
    );
    assert_eq!(
        ingest_payload
            .get("failed_sources")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        1
    );

    let query_out = run_docdex(
        state_root.path(),
        [
            "query",
            "--repo",
            repo_str.as_str(),
            "--query",
            "LIBS_ONLY_TERM_123",
            "--limit",
            "5",
        ],
    )?;
    let query_payload: Value = serde_json::from_slice(&query_out)?;
    let hits = query_payload
        .get("hits")
        .and_then(|value| value.as_array())
        .expect("hits array missing");
    assert!(
        !hits.is_empty(),
        "expected at least one search hit from libs index"
    );
    let any_libs_hit = hits.iter().any(|hit| {
        hit.get("doc_id")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .starts_with("libs:")
            || hit
                .get("rel_path")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .starts_with("libs/")
    });
    assert!(any_libs_hit, "expected at least one libs:* hit");

    let repo_only_out = run_docdex(
        state_root.path(),
        [
            "query",
            "--repo",
            repo_str.as_str(),
            "--repo-only",
            "--query",
            "LIBS_ONLY_TERM_123",
            "--limit",
            "5",
        ],
    )?;
    let repo_only_payload: Value = serde_json::from_slice(&repo_only_out)?;
    let repo_only_hits = repo_only_payload
        .get("hits")
        .and_then(|value| value.as_array())
        .expect("hits array missing");
    assert!(
        repo_only_hits.is_empty(),
        "expected repo-only query to ignore libs index hits"
    );

    Ok(())
}

#[test]
fn repo_hits_precede_libs_hits_in_query() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let repo_str = repo_root.to_string_lossy().to_string();

    let docs_dir = repo_root.join("docs");
    fs::create_dir_all(&docs_dir)?;
    fs::write(
        docs_dir.join("priority.md"),
        "# Priority\n\nSHARED_TERM_456 appears in repo docs.\n",
    )?;
    let lib_doc = write_lib_doc_with_body(
        repo_root,
        "# Serde\n\nSHARED_TERM_456 appears in library docs too.\n",
    )?;

    let sources_path = repo_root.join("libs_sources.json");
    let sources = serde_json::json!({
        "sources": [
            {
                "library": "serde",
                "version": "1.0.0",
                "source": "local_file",
                "path": lib_doc.display().to_string(),
                "title": "Serde"
            }
        ]
    });
    fs::write(&sources_path, serde_json::to_string_pretty(&sources)?)?;

    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    run_docdex(
        state_root.path(),
        [
            "libs-ingest",
            "--repo",
            repo_str.as_str(),
            "--sources",
            sources_path.to_string_lossy().as_ref(),
        ],
    )?;

    let query_out = run_docdex(
        state_root.path(),
        [
            "query",
            "--repo",
            repo_str.as_str(),
            "--query",
            "SHARED_TERM_456",
            "--limit",
            "5",
        ],
    )?;
    let query_payload: Value = serde_json::from_slice(&query_out)?;
    let hits = query_payload
        .get("hits")
        .and_then(|value| value.as_array())
        .expect("hits array missing");
    assert!(
        !hits.is_empty(),
        "expected hits for shared term query"
    );

    let mut first_lib_idx = None;
    let mut last_repo_idx = None;
    for (idx, hit) in hits.iter().enumerate() {
        let doc_id = hit.get("doc_id").and_then(|v| v.as_str()).unwrap_or_default();
        let rel_path = hit
            .get("rel_path")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let is_libs = doc_id.starts_with("libs:") || rel_path.starts_with("libs/");
        if is_libs {
            if first_lib_idx.is_none() {
                first_lib_idx = Some(idx);
            }
        } else {
            last_repo_idx = Some(idx);
        }
    }

    assert!(
        first_lib_idx.is_some(),
        "expected at least one libs hit: {}",
        serde_json::to_string_pretty(&query_payload).unwrap_or_default()
    );
    assert!(
        last_repo_idx.is_some(),
        "expected at least one repo hit: {}",
        serde_json::to_string_pretty(&query_payload).unwrap_or_default()
    );
    assert!(
        first_lib_idx.unwrap() > last_repo_idx.unwrap(),
        "expected repo hits before libs hits: {}",
        serde_json::to_string_pretty(&query_payload).unwrap_or_default()
    );

    Ok(())
}
