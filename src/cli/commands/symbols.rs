use crate::cli::http_client::CliHttpClient;
use crate::config::RepoArgs;
use crate::error::{AppError, ERR_REPO_ENCRYPTION_UNSUPPORTED};
use crate::index;
use crate::repo_encryption::RepoEncryptionConfig;
use crate::symbols::SymbolsStore;
use crate::util;
use anyhow::Result;
use reqwest::Method;

pub async fn run_status(repo: RepoArgs) -> Result<()> {
    if !crate::cli::cli_local_mode() {
        return run_status_via_http(repo).await;
    }
    let repo_root = repo.repo_root();
    let repo_encryption = crate::config::AppConfig::load_default()
        .ok()
        .map(|config| config.repo_encryption)
        .unwrap_or_default();
    ensure_symbols_allowed(&repo_encryption)?;
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("warn")?;
    index::ensure_state_dir_secure(index_config.state_dir())?;

    let store = SymbolsStore::new(&repo_root, index_config.state_dir())?;
    let status = store.parser_status()?;
    println!("{}", serde_json::to_string_pretty(&status)?);
    Ok(())
}

fn ensure_symbols_allowed(repo_encryption: &RepoEncryptionConfig) -> Result<()> {
    if repo_encryption.is_enabled() {
        return Err(AppError::new(
            ERR_REPO_ENCRYPTION_UNSUPPORTED,
            "symbol extraction is disabled when repository encryption is enabled",
        )
        .into());
    }
    Ok(())
}

async fn run_status_via_http(repo: RepoArgs) -> Result<()> {
    let repo_root = repo.repo_root();
    let client = CliHttpClient::new()?;
    client.ensure_repo(&repo_root).await?;
    let mut req = client.request(Method::GET, "/v1/symbols/status");
    req = client.with_repo(req, &repo_root)?;
    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("docdexd symbols status failed ({}): {}", status, text);
    }
    let value: serde_json::Value = serde_json::from_str(&text)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
