use crate::config::LlmConfig;
use crate::error::{
    AppError, ERR_EMBEDDING_FAILED, ERR_EMBEDDING_MODEL_NOT_FOUND, ERR_EMBEDDING_TIMEOUT,
    ERR_INVALID_ARGUMENT,
};
use crate::llm::local_library::{
    resolve_local_default_selection, LocalDefaultCandidate, LocalDefaultCandidateKind,
    LocalLlmProvider, LocalModelLibrary,
};
use crate::ollama::OllamaClient;
use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::{json, Value};
use std::time::Duration;
use url::Url;

pub const DEFAULT_OLLAMA_EMBEDDING_BASE_URL: &str = "http://127.0.0.1:11434";
pub const DEFAULT_REPO_EMBEDDING_MODEL: &str = "nomic-embed-text";
pub const DEFAULT_PROFILE_EMBEDDING_MODEL: &str = "nomic-embed-text-v1.5";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmbeddingTarget {
    pub provider: String,
    pub base_url: String,
    pub model: String,
    pub source: String,
}

impl EmbeddingTarget {
    pub fn new(
        provider: impl Into<String>,
        base_url: impl Into<String>,
        model: impl Into<String>,
        source: impl Into<String>,
    ) -> Result<Self> {
        let provider = normalize_embedding_provider(&provider.into());
        let base_url = base_url.into().trim().trim_end_matches('/').to_string();
        let model = model.into().trim().to_string();
        let source = source.into().trim().to_string();
        if provider.is_empty() {
            return Err(AppError::new(
                ERR_EMBEDDING_FAILED,
                "embedding provider is not configured",
            )
            .into());
        }
        if base_url.is_empty() {
            return Err(AppError::new(
                ERR_EMBEDDING_FAILED,
                "embedding base URL is not configured",
            )
            .into());
        }
        if model.is_empty() {
            return Err(
                AppError::new(ERR_EMBEDDING_FAILED, "embedding model is not configured").into(),
            );
        }
        Ok(Self {
            provider,
            base_url,
            model,
            source,
        })
    }

    pub fn ollama(
        base_url: impl Into<String>,
        model: impl Into<String>,
        source: impl Into<String>,
    ) -> Result<Self> {
        Self::new("ollama", base_url, model, source)
    }

    pub fn provider_is_ollama(&self) -> bool {
        provider_is_ollama(&self.provider)
    }
}

#[derive(Debug, Clone)]
pub struct EmbeddingTargetHints {
    pub provider: Option<String>,
    pub base_url: Option<String>,
    pub model: Option<String>,
    pub legacy_ollama_base_url: Option<String>,
    pub base_url_explicit: bool,
    pub model_explicit: bool,
    pub default_model: String,
    pub source_label: String,
}

impl EmbeddingTargetHints {
    pub fn repo() -> Self {
        Self {
            provider: None,
            base_url: None,
            model: None,
            legacy_ollama_base_url: None,
            base_url_explicit: false,
            model_explicit: false,
            default_model: DEFAULT_REPO_EMBEDDING_MODEL.to_string(),
            source_label: "repo-memory".to_string(),
        }
    }

    pub fn profile() -> Self {
        Self {
            default_model: DEFAULT_PROFILE_EMBEDDING_MODEL.to_string(),
            source_label: "profile-memory".to_string(),
            ..Self::repo()
        }
    }

    pub fn explicit_provider(mut self, provider: Option<String>) -> Self {
        self.provider = trim_option(provider);
        self
    }

    pub fn explicit_base_url(mut self, base_url: Option<String>, explicit: bool) -> Self {
        self.base_url = trim_option(base_url);
        self.base_url_explicit = explicit;
        self
    }

    pub fn explicit_model(mut self, model: Option<String>, explicit: bool) -> Self {
        self.model = trim_option(model);
        self.model_explicit = explicit;
        self
    }

    pub fn legacy_ollama_base_url(mut self, base_url: Option<String>) -> Self {
        self.legacy_ollama_base_url = trim_option(base_url);
        self
    }
}

#[derive(Clone)]
pub struct EmbeddingEmbedder {
    target: EmbeddingTarget,
    client: EmbeddingClient,
    timeout: Duration,
}

#[derive(Clone)]
enum EmbeddingClient {
    Ollama(OllamaClient),
    OpenAiCompatible {
        http: Client,
        embeddings_url: String,
    },
}

impl EmbeddingEmbedder {
    pub fn new(base_url: String, model: String, timeout: Duration) -> Result<Self> {
        let target = EmbeddingTarget::ollama(base_url, model, "legacy-ollama")?;
        Self::with_target(target, timeout)
    }

    pub fn with_provider(
        provider: String,
        base_url: String,
        model: String,
        timeout: Duration,
    ) -> Result<Self> {
        let target = EmbeddingTarget::new(provider, base_url, model, "explicit-provider")?;
        Self::with_target(target, timeout)
    }

    pub fn with_target(target: EmbeddingTarget, timeout: Duration) -> Result<Self> {
        let client = if target.provider_is_ollama() {
            EmbeddingClient::Ollama(OllamaClient::new(target.base_url.clone())?)
        } else {
            let mut builder = Client::builder();
            if !timeout.is_zero() {
                builder = builder.timeout(timeout);
            }
            EmbeddingClient::OpenAiCompatible {
                http: builder.build().context("build embedding HTTP client")?,
                embeddings_url: openai_embeddings_url(&target.base_url)?,
            }
        };
        Ok(Self {
            target,
            client,
            timeout,
        })
    }

    pub fn provider(&self) -> &str {
        &self.target.provider
    }

    pub fn model(&self) -> &str {
        &self.target.model
    }

    pub fn base_url(&self) -> &str {
        &self.target.base_url
    }

    pub fn target(&self) -> &EmbeddingTarget {
        &self.target
    }

    pub async fn embed(&self, prompt: &str) -> Result<Vec<f32>> {
        match &self.client {
            EmbeddingClient::Ollama(client) => {
                client.embed(&self.target.model, prompt, self.timeout).await
            }
            EmbeddingClient::OpenAiCompatible {
                http,
                embeddings_url,
            } => {
                embed_openai_compatible(
                    http,
                    embeddings_url,
                    &self.target.provider,
                    &self.target.model,
                    prompt,
                )
                .await
            }
        }
    }
}

pub fn resolve_embedding_target(
    llm_config: &LlmConfig,
    library: Option<&LocalModelLibrary>,
    hints: EmbeddingTargetHints,
) -> Result<EmbeddingTarget> {
    let provider_hint = hints
        .provider
        .as_deref()
        .map(normalize_embedding_provider)
        .filter(|value| !value.is_empty());
    let model_hint = hints
        .model
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let base_url_hint = hints
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());
    let legacy_ollama_base_url = hints
        .legacy_ollama_base_url
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty());

    let library_targets = library_embedding_targets(library, llm_config);
    let selected_library_target = library_targets.first().cloned();
    let config_provider = normalize_embedding_provider(&llm_config.provider);
    let config_base_url = non_empty(&llm_config.base_url);
    let config_model = non_empty(&llm_config.embedding_model);
    let default_model = hints.default_model.trim();

    if provider_hint.is_some() || hints.base_url_explicit || hints.model_explicit {
        let provider = provider_hint
            .clone()
            .or_else(|| {
                if !config_provider.is_empty() {
                    Some(config_provider.clone())
                } else {
                    selected_library_target
                        .as_ref()
                        .map(|target| target.provider.clone())
                }
            })
            .unwrap_or_else(|| "ollama".to_string());
        let base_url = base_url_hint
            .or_else(|| {
                if provider_is_ollama(&provider) {
                    legacy_ollama_base_url
                } else {
                    config_base_url
                }
            })
            .or_else(|| {
                selected_library_target
                    .as_ref()
                    .map(|target| target.base_url.as_str())
            })
            .or(config_base_url)
            .unwrap_or(DEFAULT_OLLAMA_EMBEDDING_BASE_URL);
        let model = model_hint
            .or_else(|| {
                selected_library_target
                    .as_ref()
                    .map(|target| target.model.as_str())
            })
            .or(config_model)
            .unwrap_or(default_model);
        return EmbeddingTarget::new(
            provider,
            base_url,
            model,
            format!("{}:explicit", hints.source_label),
        );
    }

    if config_provider_explicit(&config_provider) {
        let base_url = config_base_url.unwrap_or(DEFAULT_OLLAMA_EMBEDDING_BASE_URL);
        let model = model_hint.or(config_model).unwrap_or(default_model);
        return EmbeddingTarget::new(
            config_provider,
            base_url,
            model,
            format!("{}:config-provider", hints.source_label),
        );
    }

    if let Some(target) = selected_library_target {
        return Ok(target);
    }

    if config_ollama_override(config_base_url, config_model, default_model) {
        return EmbeddingTarget::new(
            config_provider,
            config_base_url.unwrap_or(DEFAULT_OLLAMA_EMBEDDING_BASE_URL),
            config_model.unwrap_or(default_model),
            format!("{}:config", hints.source_label),
        );
    }

    EmbeddingTarget::ollama(
        legacy_ollama_base_url.unwrap_or(DEFAULT_OLLAMA_EMBEDDING_BASE_URL),
        model_hint.or(config_model).unwrap_or(default_model),
        format!("{}:ollama-fallback", hints.source_label),
    )
}

pub fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

pub fn env_present(key: &str) -> bool {
    std::env::var_os(key).is_some()
}

pub fn normalize_embedding_provider(provider: &str) -> String {
    let normalized = provider
        .trim()
        .to_ascii_lowercase()
        .replace('_', "-")
        .replace(' ', "-");
    if normalized.is_empty() {
        return String::new();
    }
    if matches!(
        normalized.as_str(),
        "openai" | "openai-compatible" | "openai-compatible-local"
    ) {
        return LocalLlmProvider::CustomOpenAiCompatible
            .as_str()
            .to_string();
    }
    LocalLlmProvider::from_mcoda_runner_kind(&normalized)
        .map(|provider| provider.as_str().to_string())
        .unwrap_or(normalized)
}

fn provider_is_ollama(provider: &str) -> bool {
    normalize_embedding_provider(provider) == LocalLlmProvider::Ollama.as_str()
}

fn config_provider_explicit(provider: &str) -> bool {
    !provider.trim().is_empty() && !provider_is_ollama(provider)
}

fn config_ollama_override(
    config_base_url: Option<&str>,
    config_model: Option<&str>,
    default_model: &str,
) -> bool {
    config_base_url
        .is_some_and(|base_url| base_url.trim_end_matches('/') != DEFAULT_OLLAMA_EMBEDDING_BASE_URL)
        || config_model.is_some_and(|model| model != default_model)
}

fn library_embedding_targets(
    library: Option<&LocalModelLibrary>,
    llm_config: &LlmConfig,
) -> Vec<EmbeddingTarget> {
    let Some(library) = library else {
        return Vec::new();
    };
    let embedding_defaults = if library.defaults.embedding.selected.is_some()
        || !library.defaults.embedding.candidates.is_empty()
    {
        library.defaults.embedding.clone()
    } else {
        resolve_local_default_selection(library, llm_config).embedding
    };
    embedding_defaults
        .candidates
        .iter()
        .filter_map(default_candidate_target)
        .collect()
}

fn default_candidate_target(candidate: &LocalDefaultCandidate) -> Option<EmbeddingTarget> {
    if candidate.kind == LocalDefaultCandidateKind::OllamaSetupFallback {
        return None;
    }
    let provider = candidate.provider.as_ref()?;
    let model = candidate
        .raw_model
        .as_deref()
        .or(candidate.model.as_deref())?;
    let base_url = candidate.base_url.as_deref().or_else(|| {
        if *provider == LocalLlmProvider::Ollama {
            Some(DEFAULT_OLLAMA_EMBEDDING_BASE_URL)
        } else {
            None
        }
    })?;
    EmbeddingTarget::new(
        provider.as_str(),
        base_url,
        model,
        format!(
            "local-library:{:?}:{}",
            candidate.kind,
            candidate.reason.as_deref().unwrap_or("embedding default")
        ),
    )
    .ok()
}

fn openai_embeddings_url(base_url: &str) -> Result<String> {
    let mut url =
        Url::parse(base_url).with_context(|| format!("parse embedding URL {base_url}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(AppError::new(
            ERR_EMBEDDING_FAILED,
            "OpenAI-compatible embedding base URL must use http or https",
        )
        .into());
    }
    let path = url.path().trim_end_matches('/');
    let next_path = if path.ends_with("/embeddings") {
        path.to_string()
    } else if path.ends_with("/v1") {
        format!("{path}/embeddings")
    } else if path.is_empty() || path == "/" {
        "/v1/embeddings".to_string()
    } else {
        format!("{path}/v1/embeddings")
    };
    url.set_path(&next_path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

async fn embed_openai_compatible(
    http: &Client,
    embeddings_url: &str,
    provider: &str,
    model: &str,
    prompt: &str,
) -> Result<Vec<f32>> {
    let model = model.trim();
    if model.is_empty() {
        return Err(
            AppError::new(ERR_EMBEDDING_FAILED, "embedding model is not configured").into(),
        );
    }
    if prompt.trim().is_empty() {
        return Err(AppError::new(ERR_INVALID_ARGUMENT, "prompt must not be empty").into());
    }

    let payload = json!({
        "model": model,
        "input": prompt,
    });
    let response = http
        .post(embeddings_url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| {
            if err.is_timeout() {
                AppError::new(
                    ERR_EMBEDDING_TIMEOUT,
                    format!("{provider} embedding request timed out"),
                )
            } else {
                AppError::new(
                    ERR_EMBEDDING_FAILED,
                    format!("{provider} embedding request failed: {err}"),
                )
            }
        })?;
    let status = response.status();
    let body = response.bytes().await.map_err(|err| {
        AppError::new(
            ERR_EMBEDDING_FAILED,
            format!("{provider} embedding response read failed: {err}"),
        )
    })?;
    if !status.is_success() {
        let body_text = String::from_utf8_lossy(&body);
        let lowered = body_text.to_ascii_lowercase();
        if lowered.contains("model")
            && (lowered.contains("not found")
                || lowered.contains("does not exist")
                || lowered.contains("not loaded"))
        {
            return Err(AppError::new(
                ERR_EMBEDDING_MODEL_NOT_FOUND,
                format!("{provider} embedding model not found: {model}"),
            )
            .into());
        }
        if status.as_u16() == 404 {
            return Err(AppError::new(
                ERR_EMBEDDING_FAILED,
                format!(
                    "{provider} embeddings endpoint not found; check embedding provider/base URL"
                ),
            )
            .into());
        }
        return Err(AppError::new(
            ERR_EMBEDDING_FAILED,
            format!(
                "{provider} embedding request failed (status {})",
                status.as_u16()
            ),
        )
        .into());
    }

    let value: Value = serde_json::from_slice(&body).map_err(|err| {
        AppError::new(
            ERR_EMBEDDING_FAILED,
            format!("{provider} embedding response was not valid JSON: {err}"),
        )
    })?;
    if let Some(error) = value.get("error") {
        let lowered = error.to_string().to_ascii_lowercase();
        if lowered.contains("model")
            && (lowered.contains("not found")
                || lowered.contains("does not exist")
                || lowered.contains("not loaded"))
        {
            return Err(AppError::new(
                ERR_EMBEDDING_MODEL_NOT_FOUND,
                format!("{provider} embedding model not found: {model}"),
            )
            .into());
        }
        return Err(AppError::new(
            ERR_EMBEDDING_FAILED,
            format!("{provider} embedding request returned an error"),
        )
        .into());
    }

    let embedding_value = value
        .pointer("/data/0/embedding")
        .or_else(|| value.get("embedding"))
        .ok_or_else(|| {
            AppError::new(
                ERR_EMBEDDING_FAILED,
                format!("{provider} embedding response did not include an embedding"),
            )
        })?;
    let embedding = parse_embedding_array(embedding_value).ok_or_else(|| {
        AppError::new(
            ERR_EMBEDDING_FAILED,
            format!("{provider} embedding response contained invalid embedding values"),
        )
    })?;
    if embedding.is_empty() {
        return Err(AppError::new(
            ERR_EMBEDDING_FAILED,
            format!("{provider} returned empty embedding"),
        )
        .into());
    }
    Ok(embedding)
}

fn parse_embedding_array(value: &Value) -> Option<Vec<f32>> {
    let array = value.as_array()?;
    let mut out = Vec::with_capacity(array.len());
    for item in array {
        out.push(item.as_f64()? as f32);
    }
    Some(out)
}

fn non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn trim_option(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::local_library::{
        LocalCapabilityFlags, LocalLibrarySourceType, LocalServiceEntry, LocalServiceHealth,
        LocalServiceModelEntry,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn embedding_service(
        provider: LocalLlmProvider,
        base_url: &str,
        model: &str,
    ) -> LocalServiceEntry {
        LocalServiceEntry {
            service_id: format!("{}:{base_url}", provider.as_str()),
            provider,
            source_type: LocalLibrarySourceType::LocalProcess,
            base_url: Some(base_url.to_string()),
            health: LocalServiceHealth::Healthy,
            models: vec![LocalServiceModelEntry {
                name: model.to_string(),
                raw_name: Some(model.to_string()),
                capability_flags: LocalCapabilityFlags {
                    embedding: true,
                    ..LocalCapabilityFlags::default()
                },
                ..LocalServiceModelEntry::default()
            }],
            ..LocalServiceEntry::default()
        }
    }

    #[test]
    fn openai_url_resolution_appends_embeddings_endpoint() -> Result<()> {
        assert_eq!(
            openai_embeddings_url("http://127.0.0.1:8000")?,
            "http://127.0.0.1:8000/v1/embeddings"
        );
        assert_eq!(
            openai_embeddings_url("http://127.0.0.1:8000/v1")?,
            "http://127.0.0.1:8000/v1/embeddings"
        );
        assert_eq!(
            openai_embeddings_url("http://127.0.0.1:8000/v1/embeddings")?,
            "http://127.0.0.1:8000/v1/embeddings"
        );
        Ok(())
    }

    #[test]
    fn resolver_prefers_phase_five_embedding_default_without_explicit_hints() -> Result<()> {
        let mut library = LocalModelLibrary {
            services: vec![embedding_service(
                LocalLlmProvider::Vllm,
                "http://127.0.0.1:8000",
                "bge-m3",
            )],
            ..LocalModelLibrary::default()
        };
        library.defaults = resolve_local_default_selection(&library, &LlmConfig::default());
        let target = resolve_embedding_target(
            &LlmConfig::default(),
            Some(&library),
            EmbeddingTargetHints::repo(),
        )?;

        assert_eq!(target.provider, "vllm");
        assert_eq!(target.base_url, "http://127.0.0.1:8000");
        assert_eq!(target.model, "bge-m3");
        Ok(())
    }

    #[test]
    fn resolver_honors_explicit_provider_base_and_model() -> Result<()> {
        let hints = EmbeddingTargetHints::repo()
            .explicit_provider(Some("llama-cpp".to_string()))
            .explicit_base_url(Some("http://127.0.0.1:8080/v1".to_string()), true)
            .explicit_model(Some("qwen-embed".to_string()), true);
        let target = resolve_embedding_target(&LlmConfig::default(), None, hints)?;
        assert_eq!(target.provider, "llama-cpp");
        assert_eq!(target.base_url, "http://127.0.0.1:8080/v1");
        assert_eq!(target.model, "qwen-embed");
        Ok(())
    }

    #[test]
    fn resolver_keeps_ollama_fallback_when_no_library_target_exists() -> Result<()> {
        let target =
            resolve_embedding_target(&LlmConfig::default(), None, EmbeddingTargetHints::repo())?;
        assert_eq!(target.provider, "ollama");
        assert_eq!(target.base_url, DEFAULT_OLLAMA_EMBEDDING_BASE_URL);
        assert_eq!(target.model, DEFAULT_REPO_EMBEDDING_MODEL);
        Ok(())
    }

    #[tokio::test]
    async fn openai_compatible_embedder_posts_and_parses_embedding() -> Result<()> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept embedding request");
            let mut buf = vec![0_u8; 4096];
            let n = socket.read(&mut buf).await.expect("read embedding request");
            let request = String::from_utf8_lossy(&buf[..n]);
            assert!(request.starts_with("POST /v1/embeddings HTTP/1.1"));
            assert!(request.contains("\"model\":\"bge-m3\""));
            assert!(request.contains("\"input\":\"hello\""));
            let body = r#"{"data":[{"embedding":[0.1,0.2,0.3]}]}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write embedding response");
        });
        let target = EmbeddingTarget::new("vllm", format!("http://{addr}"), "bge-m3", "test")?;
        let embedder = EmbeddingEmbedder::with_target(target, Duration::from_secs(2))?;
        let embedding = embedder.embed("hello").await?;

        assert_eq!(embedding, vec![0.1, 0.2, 0.3]);
        server.await?;
        Ok(())
    }
}
