use crate::config;
use crate::repo_manager;
use anyhow::{anyhow, Result};
use reqwest::{Client, Method, RequestBuilder};
use std::path::Path;
use std::time::Duration;

const REPO_ID_HEADER: &str = "x-docdex-repo-id";

pub(crate) struct CliHttpClient {
    client: Client,
    base_url: String,
    auth_token: Option<String>,
}

impl CliHttpClient {
    pub(crate) fn new() -> Result<Self> {
        let base_url = resolve_base_url()?;
        let auth_token = env_non_empty("DOCDEX_AUTH_TOKEN");
        let timeout_ms = env_u64("DOCDEX_HTTP_TIMEOUT_MS").unwrap_or(30_000);
        let client = Client::builder()
            .timeout(Duration::from_millis(timeout_ms.max(1)))
            .build()?;
        Ok(Self {
            client,
            base_url,
            auth_token,
        })
    }

    pub(crate) fn new_streaming() -> Result<Self> {
        let base_url = resolve_base_url()?;
        let auth_token = env_non_empty("DOCDEX_AUTH_TOKEN");
        let client = Client::builder().build()?;
        Ok(Self {
            client,
            base_url,
            auth_token,
        })
    }

    pub(crate) fn request(&self, method: Method, path: &str) -> RequestBuilder {
        let url = format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let mut req = self.client.request(method, url);
        if let Some(token) = self.auth_token.as_ref() {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        req
    }

    pub(crate) fn with_repo(
        &self,
        req: RequestBuilder,
        repo_root: &Path,
    ) -> Result<RequestBuilder> {
        let repo_id = repo_manager::repo_fingerprint_sha256(repo_root)?;
        Ok(req.header(REPO_ID_HEADER, repo_id))
    }
}

fn resolve_base_url() -> Result<String> {
    if let Some(raw) = env_non_empty("DOCDEX_HTTP_BASE_URL") {
        return Ok(normalize_base_url(&raw));
    }
    let config = config::AppConfig::load_default()?;
    let bind_addr = config.server.http_bind_addr.trim();
    if bind_addr.is_empty() {
        return Err(anyhow!(
            "server.http_bind_addr is empty; set it in ~/.docdex/config.toml"
        ));
    }
    Ok(normalize_base_url(bind_addr))
}

fn normalize_base_url(raw: &str) -> String {
    if raw.contains("://") {
        raw.trim().to_string()
    } else {
        format!("http://{}", raw.trim())
    }
}

fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_u64(key: &str) -> Option<u64> {
    env_non_empty(key)?.parse::<u64>().ok()
}

#[cfg(test)]
mod tests;
