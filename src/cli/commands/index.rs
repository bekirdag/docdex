use crate::cli::http_client::CliHttpClient;
use crate::config::{self, RepoArgs};
use crate::index;
use crate::indexer;
use crate::util;
use anyhow::Result;
use reqwest::Method;
use std::path::PathBuf;
use tracing::info;

pub async fn run_index(repo: RepoArgs, libs_sources: Option<PathBuf>) -> Result<()> {
    if !crate::cli::cli_local_mode() {
        return run_index_via_http(repo, libs_sources).await;
    }
    let _ = config::AppConfig::load_default()?;
    let repo_root = repo.repo_root();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("info")?;
    info!("Rebuilding index for {}", repo_root.display());
    let options = match libs_sources.as_ref() {
        Some(path) => indexer::IndexingOptions::from_sources_path(path)?,
        None => indexer::IndexingOptions::none(),
    };
    let _ = indexer::reindex_repo(repo_root, index_config, options).await?;
    Ok(())
}

pub async fn run_ingest(repo: RepoArgs, file: PathBuf) -> Result<()> {
    if !crate::cli::cli_local_mode() {
        return run_ingest_via_http(repo, file).await;
    }
    let _ = config::AppConfig::load_default()?;
    let repo_root = repo.repo_root();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("warn")?;
    let _ = indexer::ingest_file(repo_root, index_config, file).await?;
    Ok(())
}

async fn run_index_via_http(repo: RepoArgs, libs_sources: Option<PathBuf>) -> Result<()> {
    let repo_root = repo.repo_root();
    let client = CliHttpClient::new()?;
    let payload = serde_json::json!({
        "libs_sources": libs_sources.as_ref().map(|path| path.to_string_lossy().to_string())
    });
    let mut req = client
        .request(Method::POST, "/v1/index/rebuild")
        .json(&payload);
    req = client.with_repo(req, &repo_root)?;
    let resp = req.send().await?;
    emit_json_or_error(resp, "index rebuild").await?;
    Ok(())
}

async fn run_ingest_via_http(repo: RepoArgs, file: PathBuf) -> Result<()> {
    let repo_root = repo.repo_root();
    let client = CliHttpClient::new()?;
    let payload = serde_json::json!({
        "file": file.to_string_lossy().to_string(),
    });
    let mut req = client
        .request(Method::POST, "/v1/index/ingest")
        .json(&payload);
    req = client.with_repo(req, &repo_root)?;
    let resp = req.send().await?;
    emit_json_or_error(resp, "index ingest").await?;
    Ok(())
}

async fn emit_json_or_error(resp: reqwest::Response, label: &str) -> Result<()> {
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("docdexd {} failed ({}): {}", label, status, text);
    }
    let value: serde_json::Value = serde_json::from_str(&text)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
