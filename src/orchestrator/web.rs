use crate::config;
use crate::index::Hit;
use crate::index::Indexer;
use crate::libs::LibsIndexer;
use crate::ollama::OllamaClient;
use crate::search;
use crate::tier2::{Tier2Unavailable, Tier2UnavailableReason};
use crate::max_size::truncate_utf8_chars;
use crate::util;
use crate::web::cache;
use crate::web::ddg::{DdgDiscovery, WebDiscoveryResponse, WebDiscoveryResult};
use crate::web::normalize::{dedupe_urls, unwrap_ddg_redirect};
use crate::web::WebConfig;
use ammonia::Builder as HtmlCleaner;
use serde::{Deserialize, Serialize};
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::path::Path;
use which::which;

const DEFAULT_WEB_TRIGGER_THRESHOLD: f32 = 0.45;
const MAX_WEB_DOC_CHARS: usize = 2000;
const MAX_WEB_SUMMARY_INPUT_CHARS: usize = 1600;
const MAX_WEB_SUMMARY_TOKENS: u32 = 256;
const WEB_SUMMARY_TIMEOUT_MS: u64 = 15_000;

#[derive(Clone, Debug)]
pub struct WebGateConfig {
    pub enabled: bool,
    pub trigger_threshold: f32,
    pub browser_hint: Option<String>,
    pub browser_available: bool,
}

impl WebGateConfig {
    pub fn from_env() -> Self {
        let enabled = env_boolish("DOCDEX_WEB_ENABLED").unwrap_or(false);
        let trigger_threshold = env_f32("DOCDEX_WEB_TRIGGER_THRESHOLD")
            .or_else(config_web_trigger_threshold)
            .unwrap_or(DEFAULT_WEB_TRIGGER_THRESHOLD);
        let trigger_threshold = trigger_threshold.clamp(0.0, 1.0);
        let browser_hint = env_string("DOCDEX_WEB_BROWSER");
        let browser_available = resolve_browser_available(browser_hint.as_deref());
        Self {
            enabled,
            trigger_threshold,
            browser_hint,
            browser_available,
        }
    }

    pub fn should_attempt(&self, top_score_normalized: Option<f32>, force_web: bool) -> bool {
        if force_web {
            return true;
        }
        top_score_normalized.map_or(true, |score| score < self.trigger_threshold)
    }
}

pub(crate) fn build_gate_meta(
    gate: &WebGateConfig,
    top_score: Option<f32>,
    top_score_normalized: Option<f32>,
    force_web: bool,
) -> WebGateMeta {
    WebGateMeta {
        enabled: gate.enabled,
        forced: force_web,
        threshold: gate.trigger_threshold,
        top_score,
        top_score_normalized,
        top_score_normalized_camel: top_score_normalized,
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebDiscoveryStatusCode {
    Skipped,
    Disabled,
    Unavailable,
    Served,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebGateMeta {
    pub enabled: bool,
    pub forced: bool,
    pub threshold: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_score: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_score_normalized: Option<f32>,
    #[serde(rename = "topScoreNormalized", skip_serializing_if = "Option::is_none")]
    pub top_score_normalized_camel: Option<f32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebDiscoveryStatus {
    pub status: WebDiscoveryStatusCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<Tier2Unavailable>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovery: Option<WebDiscoveryResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fetches: Option<Vec<WebFetchResult>>,
    pub gate: WebGateMeta,
}

pub fn web_context_from_status(status: &WebDiscoveryStatus) -> Option<Vec<WebFetchResult>> {
    let fetches = status.fetches.as_ref()?;
    let mut items = Vec::new();
    for item in fetches {
        let content = item
            .ai_digested_content
            .as_ref()
            .or(item.content.as_ref());
        let Some(content) = content else {
            continue;
        };
        if content.trim().is_empty() {
            continue;
        }
        let mut cloned = item.clone();
        cloned.error = None;
        items.push(cloned);
    }
    if items.is_empty() {
        None
    } else {
        Some(items)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct WebFetchResult {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fetched_at_epoch_ms: Option<u128>,
    pub cached: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_digested_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WebFetchCacheEntry {
    url: String,
    status: u16,
    fetched_at_epoch_ms: u128,
    content: String,
    #[serde(default)]
    ai_digested_content: Option<String>,
}

#[derive(Clone)]
struct WebSummaryClient {
    client: OllamaClient,
    model: String,
    max_tokens: u32,
    timeout: Duration,
}

impl WebSummaryClient {
    async fn summarize(&self, query: &str, content: &str) -> Option<String> {
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return None;
        }
        let prompt = build_summary_prompt(query, trimmed);
        match self
            .client
            .generate(&self.model, &prompt, self.max_tokens, self.timeout)
            .await
        {
            Ok(text) => {
                let cleaned = clean_summary_text(&text);
                if cleaned.is_empty() {
                    None
                } else {
                    Some(cleaned)
                }
            }
            Err(_) => None,
        }
    }
}

fn load_web_summary_client() -> Option<WebSummaryClient> {
    let config = load_llm_config()?;
    if !config.provider.trim().eq_ignore_ascii_case("ollama") {
        return None;
    }
    let base_url = config.base_url.trim();
    let model = config.default_model.trim();
    if base_url.is_empty() || model.is_empty() {
        return None;
    }
    let max_tokens = config.max_answer_tokens.min(MAX_WEB_SUMMARY_TOKENS);
    let client = OllamaClient::new(base_url.to_string()).ok()?;
    Some(WebSummaryClient {
        client,
        model: model.to_string(),
        max_tokens,
        timeout: Duration::from_millis(WEB_SUMMARY_TIMEOUT_MS),
    })
}

fn load_llm_config() -> Option<config::LlmConfig> {
    let path = config::default_config_path().ok();
    let mut config = if let Some(path) = path {
        if path.exists() {
            config::load_config_from_path(&path).ok()?
        } else {
            let mut config = config::AppConfig::default();
            config.apply_defaults().ok()?;
            config
        }
    } else {
        let mut config = config::AppConfig::default();
        config.apply_defaults().ok()?;
        config
    };
    config.apply_defaults().ok()?;
    Some(config.llm)
}

fn build_summary_prompt(query: &str, content: &str) -> String {
    let (snippet, _) = truncate_utf8_chars(content, MAX_WEB_SUMMARY_INPUT_CHARS);
    let query = query.trim();
    if query.is_empty() {
        format!(
            "Summarize the following web page in 2-3 sentences. Focus on the key factual details.\n\nContent:\n{}",
            snippet
        )
    } else {
        format!(
            "Summarize the following web page in 2-3 sentences. Focus on facts relevant to the question: \"{}\".\n\nContent:\n{}",
            query, snippet
        )
    }
}

fn clean_summary_text(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[derive(Debug, Clone, Serialize)]
pub struct WebResearchResponse {
    pub completion: String,
    pub hits: Vec<Hit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_score: Option<f32>,
    #[serde(rename = "topScore", skip_serializing_if = "Option::is_none")]
    pub top_score_camel: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_score_normalized: Option<f32>,
    #[serde(rename = "topScoreNormalized", skip_serializing_if = "Option::is_none")]
    pub top_score_normalized_camel: Option<f32>,
    #[serde(rename = "webDiscovery")]
    pub web_discovery: WebDiscoveryStatus,
}

pub async fn run_web_research(
    request_id: &str,
    indexer: &Indexer,
    libs_indexer: Option<&LibsIndexer>,
    query: &str,
    limit: usize,
    force_web: bool,
    gate: &WebGateConfig,
) -> Result<WebResearchResponse, anyhow::Error> {
    let query = query.trim();
    let search_response = search::run_query(indexer, libs_indexer, query, limit).await?;
    let top_score = search_response.top_score;
    let top_score_normalized = search_response.top_score_normalized;
    let hits = search_response.hits;
    let completion = build_completion(query, &hits);
    let web_discovery = if !gate.enabled {
        let unavailable = Tier2Unavailable::new(
            Tier2UnavailableReason::Disabled,
            "web discovery is disabled",
        )
        .with_correlation_id(request_id);
        WebDiscoveryStatus {
            status: WebDiscoveryStatusCode::Disabled,
            reason: Some("disabled".to_string()),
            message: Some(unavailable.message.clone()),
            unavailable: Some(unavailable),
            discovery: None,
            fetches: None,
            gate: build_gate_meta(gate, top_score, top_score_normalized, force_web),
        }
    } else if !gate.should_attempt(top_score_normalized, force_web) {
        WebDiscoveryStatus {
            status: WebDiscoveryStatusCode::Skipped,
            reason: Some("confidence_above_threshold".to_string()),
            message: Some("web discovery skipped by confidence gate".to_string()),
            unavailable: None,
            discovery: None,
            fetches: None,
            gate: build_gate_meta(gate, top_score, top_score_normalized, force_web),
        }
    } else {
        run_web_discovery(
            request_id,
            gate,
            query,
            limit,
            top_score,
            top_score_normalized,
            force_web,
        )
        .await
    };
    Ok(WebResearchResponse {
        completion,
        hits,
        top_score,
        top_score_camel: top_score,
        top_score_normalized,
        top_score_normalized_camel: top_score_normalized,
        web_discovery,
    })
}

pub(crate) fn evaluate_gate_status(
    request_id: &str,
    gate: &WebGateConfig,
    top_score: Option<f32>,
    top_score_normalized: Option<f32>,
    force_web: bool,
) -> WebDiscoveryStatus {
    let gate_meta = build_gate_meta(gate, top_score, top_score_normalized, force_web);

    if !gate.enabled {
        let unavailable = Tier2Unavailable::new(
            Tier2UnavailableReason::Disabled,
            "web discovery is disabled",
        )
        .with_correlation_id(request_id);
        return WebDiscoveryStatus {
            status: WebDiscoveryStatusCode::Disabled,
            reason: Some("disabled".to_string()),
            message: Some(unavailable.message.clone()),
            unavailable: Some(unavailable),
            discovery: None,
            fetches: None,
            gate: gate_meta,
        };
    }

    if !gate.should_attempt(top_score_normalized, force_web) {
        return WebDiscoveryStatus {
            status: WebDiscoveryStatusCode::Skipped,
            reason: Some("confidence_above_threshold".to_string()),
            message: Some("web discovery skipped by confidence gate".to_string()),
            unavailable: None,
            discovery: None,
            fetches: None,
            gate: gate_meta,
        };
    }

    if !gate.browser_available {
        let message = match gate.browser_hint.as_deref() {
            Some(hint) => format!("web browser not available: {hint}"),
            None => "web browser not available".to_string(),
        };
        let unavailable =
            Tier2Unavailable::new(Tier2UnavailableReason::StartupFailed, message.clone())
                .with_correlation_id(request_id);
        return WebDiscoveryStatus {
            status: WebDiscoveryStatusCode::Unavailable,
            reason: Some("missing_dependency".to_string()),
            message: Some(message),
            unavailable: Some(unavailable),
            discovery: None,
            fetches: None,
            gate: gate_meta,
        };
    }

    let unavailable = Tier2Unavailable::new(
        Tier2UnavailableReason::StartupFailed,
        "web discovery is not configured",
    )
    .with_correlation_id(request_id);
    WebDiscoveryStatus {
        status: WebDiscoveryStatusCode::Unavailable,
        reason: Some("not_configured".to_string()),
        message: Some(unavailable.message.clone()),
        unavailable: Some(unavailable),
        discovery: None,
        fetches: None,
        gate: gate_meta,
    }
}

async fn run_web_discovery(
    request_id: &str,
    gate: &WebGateConfig,
    query: &str,
    limit: usize,
    top_score: Option<f32>,
    top_score_normalized: Option<f32>,
    force_web: bool,
) -> WebDiscoveryStatus {
    let config = WebConfig::from_env();
    if !config.enabled {
        let unavailable = Tier2Unavailable::new(
            Tier2UnavailableReason::Disabled,
            "web discovery is disabled",
        )
        .with_correlation_id(request_id);
        return WebDiscoveryStatus {
            status: WebDiscoveryStatusCode::Disabled,
            reason: Some("disabled".to_string()),
            message: Some(unavailable.message.clone()),
            unavailable: Some(unavailable),
            discovery: None,
            fetches: None,
            gate: build_gate_meta(gate, top_score, top_score_normalized, force_web),
        };
    }

    let discovery = match DdgDiscovery::new(config.clone()) {
        Ok(discovery) => discovery,
        Err(err) => {
            let unavailable = Tier2Unavailable::new(
                Tier2UnavailableReason::StartupFailed,
                format!("web discovery init failed: {err}"),
            )
            .with_correlation_id(request_id);
            return WebDiscoveryStatus {
                status: WebDiscoveryStatusCode::Unavailable,
                reason: Some("discovery_init_failed".to_string()),
                message: Some(unavailable.message.clone()),
                unavailable: Some(unavailable),
                discovery: None,
                fetches: None,
                gate: build_gate_meta(gate, top_score, top_score_normalized, force_web),
            };
        }
    };

    match discovery.discover(query, limit).await {
        Ok(response) => {
            let (discovery_response, urls) = normalize_discovery_response(response, &config);
            let fetches = fetch_web_documents(query, &urls, &config).await;
            let message = if gate.browser_available {
                None
            } else {
                Some("web discovery complete; browser unavailable for fetch".to_string())
            };
            WebDiscoveryStatus {
                status: WebDiscoveryStatusCode::Served,
                reason: Some("discovery".to_string()),
                message,
                unavailable: None,
                discovery: Some(discovery_response),
                fetches: if fetches.is_empty() { None } else { Some(fetches) },
                gate: build_gate_meta(gate, top_score, top_score_normalized, force_web),
            }
        }
        Err(err) => {
            let unavailable = Tier2Unavailable::new(
                Tier2UnavailableReason::StartupFailed,
                format!("web discovery failed: {err}"),
            )
            .with_correlation_id(request_id);
            WebDiscoveryStatus {
                status: WebDiscoveryStatusCode::Unavailable,
                reason: Some("discovery_failed".to_string()),
                message: Some(unavailable.message.clone()),
                unavailable: Some(unavailable),
                discovery: None,
                fetches: None,
                gate: build_gate_meta(gate, top_score, top_score_normalized, force_web),
            }
        }
    }
}

fn normalize_discovery_response(
    response: WebDiscoveryResponse,
    config: &WebConfig,
) -> (WebDiscoveryResponse, Vec<String>) {
    let mut urls = Vec::with_capacity(response.results.len());
    for result in response.results {
        let raw = result.url;
        let unwrapped = unwrap_ddg_redirect(&raw).unwrap_or(raw);
        urls.push(unwrapped);
    }
    let mut urls = dedupe_urls(urls);
    urls.retain(|value| is_allowed_url(value, &config.blocklist));
    let results = urls
        .iter()
        .map(|url| WebDiscoveryResult { url: url.clone() })
        .collect();
    (
        WebDiscoveryResponse {
            provider: response.provider,
            query: response.query,
            results,
        },
        urls,
    )
}

fn is_allowed_url(raw: &str, blocklist: &[String]) -> bool {
    let url = match url::Url::parse(raw) {
        Ok(url) => url,
        Err(_) => return false,
    };
    let host = match url.host_str() {
        Some(host) => host.trim().to_ascii_lowercase(),
        None => return false,
    };
    if host.is_empty() {
        return false;
    }
    for entry in blocklist {
        let trimmed = entry.trim().trim_start_matches('.').to_ascii_lowercase();
        if trimmed.is_empty() {
            continue;
        }
        if host == trimmed || host.ends_with(&format!(".{trimmed}")) {
            return false;
        }
    }
    true
}

async fn fetch_web_documents(query: &str, urls: &[String], config: &WebConfig) -> Vec<WebFetchResult> {
    if urls.is_empty() {
        return Vec::new();
    }
    let layout = cache::cache_layout_from_config();
    let summary_client = load_web_summary_client();
    let client = match reqwest::Client::builder()
        .user_agent(config.user_agent.clone())
        .timeout(config.request_timeout)
        .build()
    {
        Ok(client) => client,
        Err(err) => {
            return vec![WebFetchResult {
                url: String::new(),
                status: None,
                fetched_at_epoch_ms: None,
                cached: false,
                content: None,
                ai_digested_content: None,
                error: Some(format!("web fetch client init failed: {err}")),
            }];
        }
    };

    let mut results = Vec::new();
    for raw in urls {
        let url = match url::Url::parse(raw) {
            Ok(url) => url,
            Err(err) => {
                results.push(WebFetchResult {
                    url: raw.to_string(),
                    status: None,
                    fetched_at_epoch_ms: None,
                    cached: false,
                    content: None,
                    ai_digested_content: None,
                    error: Some(format!("invalid url: {err}")),
                });
                continue;
            }
        };
        let cache_key = url.as_str();
        if let Some(layout) = layout.as_ref() {
            if let Ok(Some(payload)) =
                cache::read_cache_entry_with_ttl(layout, cache_key, config.cache_ttl)
            {
                if let Ok(mut entry) = serde_json::from_slice::<WebFetchCacheEntry>(&payload) {
                    if entry.ai_digested_content.is_none() {
                        if let Some(summary_client) = summary_client.as_ref() {
                            entry.ai_digested_content =
                                summary_client.summarize(query, &entry.content).await;
                            if entry.ai_digested_content.is_some()
                                && config.cache_ttl.as_secs() > 0
                            {
                                if let Ok(payload) = serde_json::to_vec(&entry) {
                                    let _ =
                                        cache::write_cache_entry(layout, cache_key, &payload);
                                }
                            }
                        }
                    }
                    results.push(WebFetchResult {
                        url: entry.url,
                        status: Some(entry.status),
                        fetched_at_epoch_ms: Some(entry.fetched_at_epoch_ms),
                        cached: true,
                        content: Some(entry.content),
                        ai_digested_content: entry.ai_digested_content,
                        error: None,
                    });
                    continue;
                }
            }
        }

        crate::web::fetch::enforce_domain_delay(&url, config.fetch_delay).await;
        let fetched_at_epoch_ms = now_epoch_ms();
        match client.get(url.clone()).send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                match resp.text().await {
                    Ok(body) => {
                        let cleaned = clean_web_text(&body);
                        let (content, _) = truncate_utf8_chars(&cleaned, MAX_WEB_DOC_CHARS);
                        let ai_digested_content = if let Some(summary_client) = summary_client.as_ref() {
                            summary_client.summarize(query, &content).await
                        } else {
                            None
                        };
                        if let Some(layout) = layout.as_ref() {
                            if config.cache_ttl.as_secs() > 0 {
                                let entry = WebFetchCacheEntry {
                                    url: url.to_string(),
                                    status,
                                    fetched_at_epoch_ms,
                                    content: content.clone(),
                                    ai_digested_content: ai_digested_content.clone(),
                                };
                                if let Ok(payload) = serde_json::to_vec(&entry) {
                                    let _ = cache::write_cache_entry(layout, cache_key, &payload);
                                }
                            }
                        }
                        results.push(WebFetchResult {
                            url: url.to_string(),
                            status: Some(status),
                            fetched_at_epoch_ms: Some(fetched_at_epoch_ms),
                            cached: false,
                            content: Some(content),
                            ai_digested_content,
                            error: None,
                        });
                    }
                    Err(err) => results.push(WebFetchResult {
                        url: url.to_string(),
                        status: Some(status),
                        fetched_at_epoch_ms: Some(fetched_at_epoch_ms),
                        cached: false,
                        content: None,
                        ai_digested_content: None,
                        error: Some(format!("read body failed: {err}")),
                    }),
                }
            }
            Err(err) => results.push(WebFetchResult {
                url: url.to_string(),
                status: None,
                fetched_at_epoch_ms: Some(fetched_at_epoch_ms),
                cached: false,
                content: None,
                ai_digested_content: None,
                error: Some(format!("request failed: {err}")),
            }),
        }
    }
    results
}

fn clean_web_text(html: &str) -> String {
    let cleaned = HtmlCleaner::default()
        .tags(std::collections::HashSet::new())
        .clean(html)
        .to_string();
    cleaned.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn build_completion(query: &str, hits: &[Hit]) -> String {
    let trimmed = query.trim();
    if hits.is_empty() {
        if trimmed.is_empty() {
            return "No local documents matched the query.".to_string();
        }
        return format!("No local documents matched query: {}", trimmed);
    }

    let mut lines = Vec::new();
    if !trimmed.is_empty() {
        lines.push(format!("Local matches for query: {}", trimmed));
    } else {
        lines.push("Local matches:".to_string());
    }
    for hit in hits.iter().take(3) {
        let summary = hit.summary.trim();
        if summary.is_empty() {
            lines.push(format!("- {}", hit.rel_path));
        } else {
            lines.push(format!("- {}: {}", hit.rel_path, summary));
        }
    }
    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_attempt_accounts_for_threshold_and_force_web() {
        let gate = WebGateConfig {
            enabled: true,
            trigger_threshold: 0.5,
            browser_hint: None,
            browser_available: true,
        };

        assert!(gate.should_attempt(Some(0.3), false));
        assert!(!gate.should_attempt(Some(0.8), false));
        assert!(gate.should_attempt(Some(0.8), true));
        assert!(gate.should_attempt(None, false));
    }

    #[test]
    fn evaluate_gate_status_skips_when_confident() {
        let gate = WebGateConfig {
            enabled: true,
            trigger_threshold: 0.45,
            browser_hint: None,
            browser_available: true,
        };
        let status = evaluate_gate_status("req", &gate, Some(0.8), Some(0.8), false);
        assert_eq!(status.status, WebDiscoveryStatusCode::Skipped);
        assert_eq!(status.reason.as_deref(), Some("confidence_above_threshold"));
    }

    #[test]
    fn evaluate_gate_status_reports_unavailable_without_browser() {
        let gate = WebGateConfig {
            enabled: true,
            trigger_threshold: 0.45,
            browser_hint: Some("chrome".to_string()),
            browser_available: false,
        };
        let status = evaluate_gate_status("req", &gate, Some(0.1), Some(0.1), false);
        assert_eq!(status.status, WebDiscoveryStatusCode::Unavailable);
        assert_eq!(status.reason.as_deref(), Some("missing_dependency"));
        assert!(status.message.as_deref().unwrap().contains("chrome"));
    }
}

fn env_boolish(key: &str) -> Option<bool> {
    let raw = env::var(key).ok()?;
    let trimmed = raw.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "1" | "true" | "t" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "f" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

fn env_f32(key: &str) -> Option<f32> {
    let raw = env::var(key).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<f32>().ok()
}

fn env_string(key: &str) -> Option<String> {
    let raw = env::var(key).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn config_web_trigger_threshold() -> Option<f32> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(config.search.web_trigger_threshold)
}

pub(crate) fn resolve_browser_available(hint: Option<&str>) -> bool {
    if let Some(path) = hint {
        if Path::new(path).is_file() {
            return true;
        }
        if which(path).is_ok() {
            return true;
        }
        return false;
    }

    util::detect_chrome_binary().is_some()
}
