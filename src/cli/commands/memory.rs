use crate::cli::http_client::CliHttpClient;
use crate::config::{self, RepoArgs};
use crate::error;
use crate::index;
use crate::memory;
use crate::ollama;
use crate::repo_manager;
use crate::util;
use anyhow::Result;
use reqwest::Method;

pub async fn run_store(
    repo: RepoArgs,
    text: String,
    metadata: Option<String>,
    embedding_base_url: Option<String>,
    ollama_base_url: String,
    embedding_model: String,
    embedding_timeout_ms: u64,
) -> Result<()> {
    if !crate::cli::cli_local_mode() {
        return run_store_via_http(repo, text, metadata).await;
    }
    let config = config::AppConfig::load_default()?;
    let provider = config.llm.provider.trim();
    if !provider.eq_ignore_ascii_case("ollama") {
        return Err(error::StartupError::new(
            "startup_config_invalid",
            format!("unsupported llm provider `{provider}`; only ollama is supported"),
        )
        .with_hint("Set [llm].provider = \"ollama\" in ~/.docdex/config.toml.")
        .into());
    }
    let repo_root = repo.repo_root();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("warn")?;
    index::ensure_state_dir_secure(index_config.state_dir())?;

    let timeout = std::time::Duration::from_millis(embedding_timeout_ms);
    let embedding_base_url = embedding_base_url.unwrap_or(ollama_base_url);
    let embedder = ollama::OllamaEmbedder::new(embedding_base_url, embedding_model, timeout)?;
    let embedding = embedder.embed(&text).await?;
    let user_metadata = match metadata {
        None => None,
        Some(raw) => Some(
            serde_json::from_str::<serde_json::Value>(&raw).map_err(|err| {
                error::AppError::new(
                    error::ERR_INVALID_ARGUMENT,
                    format!("invalid --metadata JSON: {err}"),
                )
            })?,
        ),
    };
    let metadata =
        memory::inject_embedding_metadata(user_metadata, embedder.provider(), embedder.model());
    let repo_id = repo_manager::repo_fingerprint_sha256(&repo_root)?;
    let metadata = memory::inject_repo_metadata(metadata, &repo_id);
    let store = memory::MemoryStore::new(index_config.state_dir());
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis() as i64;
    let text_owned = text.clone();
    let stored = tokio::task::spawn_blocking(move || {
        store.store(&text_owned, &embedding, metadata, created_at)
    })
    .await??;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "id": stored.0.to_string(),
            "created_at": stored.1
        }))?
    );
    Ok(())
}

pub async fn run_recall(
    repo: RepoArgs,
    query: String,
    top_k: usize,
    embedding_base_url: Option<String>,
    ollama_base_url: String,
    embedding_model: String,
    embedding_timeout_ms: u64,
) -> Result<()> {
    if !crate::cli::cli_local_mode() {
        return run_recall_via_http(repo, query, top_k).await;
    }
    let config = config::AppConfig::load_default()?;
    let provider = config.llm.provider.trim();
    if !provider.eq_ignore_ascii_case("ollama") {
        return Err(error::StartupError::new(
            "startup_config_invalid",
            format!("unsupported llm provider `{provider}`; only ollama is supported"),
        )
        .with_hint("Set [llm].provider = \"ollama\" in ~/.docdex/config.toml.")
        .into());
    }
    let repo_root = repo.repo_root();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("warn")?;
    index::ensure_state_dir_secure(index_config.state_dir())?;

    let timeout = std::time::Duration::from_millis(embedding_timeout_ms);
    let embedding_base_url = embedding_base_url.unwrap_or(ollama_base_url);
    let embedder = ollama::OllamaEmbedder::new(embedding_base_url, embedding_model, timeout)?;
    let embedding = embedder.embed(&query).await?;
    let store = memory::MemoryStore::new(index_config.state_dir());
    let top_k = top_k.max(1).min(50);
    let results = tokio::task::spawn_blocking(move || store.recall(&embedding, top_k)).await??;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "results": results.into_iter().map(|item| {
                serde_json::json!({
                    "content": item.content,
                    "score": item.score,
                    "metadata": item.metadata
                })
            }).collect::<Vec<_>>()
        }))?
    );
    Ok(())
}

async fn run_store_via_http(repo: RepoArgs, text: String, metadata: Option<String>) -> Result<()> {
    let repo_root = repo.repo_root();
    let user_metadata = match metadata {
        None => None,
        Some(raw) => Some(
            serde_json::from_str::<serde_json::Value>(&raw).map_err(|err| {
                error::AppError::new(
                    error::ERR_INVALID_ARGUMENT,
                    format!("invalid --metadata JSON: {err}"),
                )
            })?,
        ),
    };
    let payload = serde_json::json!({
        "text": text,
        "metadata": user_metadata,
    });
    let client = CliHttpClient::new()?;
    client.ensure_repo(&repo_root).await?;
    let mut req = client
        .request(Method::POST, "/v1/memory/store")
        .json(&payload);
    req = client.with_repo(req, &repo_root)?;
    let resp = req.send().await?;
    emit_json_or_error(resp, "memory store").await?;
    Ok(())
}

async fn run_recall_via_http(repo: RepoArgs, query: String, top_k: usize) -> Result<()> {
    let repo_root = repo.repo_root();
    let payload = serde_json::json!({
        "query": query,
        "top_k": top_k,
    });
    let client = CliHttpClient::new()?;
    client.ensure_repo(&repo_root).await?;
    let mut req = client
        .request(Method::POST, "/v1/memory/recall")
        .json(&payload);
    req = client.with_repo(req, &repo_root)?;
    let resp = req.send().await?;
    emit_json_or_error(resp, "memory recall").await?;
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
