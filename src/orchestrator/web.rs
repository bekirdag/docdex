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
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::path::Path;
use which::which;

const DEFAULT_WEB_TRIGGER_THRESHOLD: f32 = 0.45;
const DEFAULT_WEB_MIN_MATCH_RATIO: f32 = 0.2;
const DEFAULT_LOCAL_RELEVANCE_THRESHOLD: f32 = 0.6;
const MAX_WEB_DOC_CHARS: usize = 2000;
const MAX_WEB_SUMMARY_INPUT_CHARS: usize = 1600;
const MAX_WEB_SUMMARY_TOKENS: u32 = 256;
const WEB_SUMMARY_TIMEOUT_MS: u64 = 15_000;

const MAX_MATCH_HITS: usize = 3;
const LOCAL_RELEVANCE_TIMEOUT_MS: u64 = 8_000;
const LOCAL_RELEVANCE_MAX_TOKENS: u32 = 96;
const MAX_LOCAL_RELEVANCE_INPUT_CHARS: usize = 800;
const WEB_BATCH_SIZE: usize = 10;
const WEB_MAX_BATCHES: usize = 2;
const MAX_CODE_BLOCKS: usize = 4;
const MAX_CODE_BLOCK_CHARS: usize = 1800;

static STOPWORDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    [
        "a", "an", "and", "are", "as", "at", "be", "by", "do", "does", "for", "from",
        "how", "i", "if", "in", "is", "it", "of", "on", "or", "the", "to", "use",
        "using", "was", "we", "what", "when", "where", "who", "why", "with", "you",
        "your",
        "css", "html", "javascript", "js", "plain", "simple",
    ]
    .into_iter()
    .collect()
});

static CODE_BLOCK_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"(?is)<pre[^>]*>(.*?)</pre>").expect("valid code block regex")
});

static TAG_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"(?is)<[^>]+>").expect("valid tag regex")
});

#[derive(Clone, Debug)]
pub struct WebGateConfig {
    pub enabled: bool,
    pub trigger_threshold: f32,
    pub min_local_match_ratio: f32,
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
        let min_local_match_ratio = env_f32("DOCDEX_WEB_MIN_MATCH_RATIO")
            .or_else(config_web_min_match_ratio)
            .unwrap_or(DEFAULT_WEB_MIN_MATCH_RATIO)
            .clamp(0.0, 1.0);
        let browser_hint = env_string("DOCDEX_WEB_BROWSER");
        let browser_available = resolve_browser_available(browser_hint.as_deref());
        Self {
            enabled,
            trigger_threshold,
            min_local_match_ratio,
            browser_hint,
            browser_available,
        }
    }

    pub fn should_attempt(
        &self,
        top_score_normalized: Option<f32>,
        local_match_ratio: Option<f32>,
        force_web: bool,
    ) -> bool {
        if force_web {
            return true;
        }
        if let Some(local_match_ratio) = local_match_ratio {
            if local_match_ratio < self.min_local_match_ratio {
                return true;
            }
        }
        top_score_normalized.map_or(true, |score| score < self.trigger_threshold)
    }
}

pub(crate) fn build_gate_meta(
    gate: &WebGateConfig,
    top_score: Option<f32>,
    top_score_normalized: Option<f32>,
    local_match_ratio: Option<f32>,
    force_web: bool,
) -> WebGateMeta {
    WebGateMeta {
        enabled: gate.enabled,
        forced: force_web,
        threshold: gate.trigger_threshold,
        top_score,
        top_score_normalized,
        top_score_normalized_camel: top_score_normalized,
        local_match_ratio,
        local_match_ratio_camel: local_match_ratio,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_match_ratio: Option<f32>,
    #[serde(rename = "localMatchRatio", skip_serializing_if = "Option::is_none")]
    pub local_match_ratio_camel: Option<f32>,
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
    pub ai_digested_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relevance_score: Option<f32>,
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
    code_blocks: Vec<String>,
}

#[derive(Clone)]
struct WebSummaryClient {
    client: OllamaClient,
    model: String,
    max_tokens: u32,
    timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct WebEvalResponse {
    relevant: bool,
    score: f32,
    kind: String,
    output: String,
}

struct WebEvalOutput {
    relevance_score: f32,
    kind: String,
    output: String,
}

#[derive(Clone)]
struct LocalRelevanceClient {
    client: OllamaClient,
    model: String,
    max_tokens: u32,
    timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct LocalRelevanceResponse {
    relevant: bool,
    score: f32,
}

impl WebSummaryClient {
    async fn evaluate(
        &self,
        query: &str,
        content: &str,
        code_blocks: &[String],
    ) -> Option<WebEvalOutput> {
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return None;
        }
        let prompt = build_summary_prompt(query, trimmed, code_blocks);
        let result = self
            .client
            .generate(&self.model, &prompt, self.max_tokens, self.timeout)
            .await
            .ok()?;
        let parsed: WebEvalResponse = parse_json_response(&result)?;
        let relevant = parsed.relevant;
        let score = parsed.score.clamp(0.0, 1.0);
        let kind = parsed.kind.trim().to_ascii_lowercase();
        let output = if kind == "code" {
            clean_code_text(&parsed.output)
        } else {
            clean_summary_text(&parsed.output)
        };
        if !relevant || output.is_empty() {
            return None;
        }
        let kind = if kind == "code" { "code" } else { "summary" };
        Some(WebEvalOutput {
            relevance_score: score,
            kind: kind.to_string(),
            output,
        })
    }
}

impl LocalRelevanceClient {
    async fn evaluate(&self, query: &str, hit: &Hit) -> Option<LocalRelevanceResponse> {
        let prompt = build_local_relevance_prompt(query, hit);
        let result = self
            .client
            .generate(&self.model, &prompt, self.max_tokens, self.timeout)
            .await
            .ok()?;
        let parsed: LocalRelevanceResponse = parse_json_response(&result)?;
        let score = parsed.score.clamp(0.0, 1.0);
        Some(LocalRelevanceResponse {
            relevant: parsed.relevant,
            score,
        })
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

fn load_local_relevance_client() -> Option<LocalRelevanceClient> {
    let config = load_llm_config()?;
    if !config.provider.trim().eq_ignore_ascii_case("ollama") {
        return None;
    }
    let base_url = config.base_url.trim();
    let model = config.default_model.trim();
    if base_url.is_empty() || model.is_empty() {
        return None;
    }
    let max_tokens = config.max_answer_tokens.min(LOCAL_RELEVANCE_MAX_TOKENS);
    let client = OllamaClient::new(base_url.to_string()).ok()?;
    Some(LocalRelevanceClient {
        client,
        model: model.to_string(),
        max_tokens,
        timeout: Duration::from_millis(LOCAL_RELEVANCE_TIMEOUT_MS),
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

fn build_summary_prompt(query: &str, content: &str, code_blocks: &[String]) -> String {
    let (snippet, _) = truncate_utf8_chars(content, MAX_WEB_SUMMARY_INPUT_CHARS);
    let query = query.trim();
    let mut prompt = String::new();
    if query.is_empty() {
        prompt.push_str("User query: <empty>\n\n");
    } else {
        prompt.push_str("User query:\n");
        prompt.push_str(query);
        prompt.push_str("\n\n");
    }
    prompt.push_str("Here is what I found online.\n");
    prompt.push_str(
        "First: does it answer the question or is it helpful for this query?\n",
    );
    prompt.push_str("Second: if relevant, reformat it so an agent can consume it easily.\n");
    prompt.push_str("\nPage text (cleaned):\n");
    prompt.push_str(&snippet);
    prompt.push_str("\n\n");
    if code_blocks.is_empty() {
        prompt.push_str("Code blocks (verbatim): <none>\n");
    } else {
        prompt.push_str("Code blocks (verbatim):\n");
        for (idx, block) in code_blocks.iter().enumerate() {
            prompt.push_str(&format!("[code {}]\n{}\n[/code {}]\n", idx + 1, block, idx + 1));
        }
    }
    prompt.push_str(
        "\nInstructions:\n- Decide if the page is relevant to the query.\n- If relevant and the query asks for code/example, output ONLY the code from the provided code blocks. Do not add or rewrite code.\n- If relevant and not code-focused, output 2-4 bullet points with key facts.\n- If irrelevant or no relevant code exists, set relevant=false and output empty string.\n\nReturn JSON ONLY in this shape:\n{\"relevant\":true|false,\"score\":0..1,\"kind\":\"summary\"|\"code\",\"output\":\"...\"}\n",
    );
    prompt
}

fn build_local_relevance_prompt(query: &str, hit: &Hit) -> String {
    let query = query.trim();
    let summary = hit.summary.trim();
    let snippet = hit.snippet.trim();
    let (summary_trimmed, _) = truncate_utf8_chars(summary, MAX_LOCAL_RELEVANCE_INPUT_CHARS);
    let (snippet_trimmed, _) = truncate_utf8_chars(snippet, MAX_LOCAL_RELEVANCE_INPUT_CHARS);
    let mut prompt = String::new();
    if query.is_empty() {
        prompt.push_str("User query: <empty>\n\n");
    } else {
        prompt.push_str("User query:\n");
        prompt.push_str(query);
        prompt.push_str("\n\n");
    }
    prompt.push_str("Local result:\n");
    prompt.push_str("Path: ");
    prompt.push_str(&hit.rel_path);
    prompt.push('\n');
    if !summary_trimmed.is_empty() {
        prompt.push_str("Summary:\n");
        prompt.push_str(&summary_trimmed);
        prompt.push('\n');
    }
    if !snippet_trimmed.is_empty() {
        prompt.push_str("Snippet:\n");
        prompt.push_str(&snippet_trimmed);
        prompt.push('\n');
    }
    prompt.push_str(
        "\nInstructions:\n- Decide if the local result is relevant to the query.\n- Ignore matches that only share generic terms like language names or common words.\n- If unsure, mark irrelevant.\n\nReturn JSON ONLY in this shape:\n{\"relevant\":true|false,\"score\":0..1}\n",
    );
    prompt
}

fn clean_summary_text(text: &str) -> String {
    let mut lines = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        lines.push(trimmed.to_string());
    }
    lines.join("\n")
}

fn clean_code_text(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.starts_with("```") {
        let mut lines = trimmed.lines();
        lines.next();
        let mut body: Vec<&str> = lines.collect();
        if body.last().map(|line| line.trim()) == Some("```") {
            body.pop();
        }
        return body.join("\n").trim().to_string();
    }
    trimmed.to_string()
}

fn parse_json_response<T: serde::de::DeserializeOwned>(text: &str) -> Option<T> {
    let trimmed = text.trim();
    if let Ok(parsed) = serde_json::from_str::<T>(trimmed) {
        return Some(parsed);
    }
    let start = trimmed.find('{')?;
    let end = trimmed.rfind('}')?;
    if end <= start {
        return None;
    }
    serde_json::from_str::<T>(&trimmed[start..=end]).ok()
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
    let hits =
        filter_local_hits_with_llm(query, search_response.hits, top_score_normalized).await;
    let local_match_ratio = local_match_ratio(query, &hits);
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
            gate: build_gate_meta(
                gate,
                top_score,
                top_score_normalized,
                local_match_ratio,
                force_web,
            ),
        }
    } else if !gate.should_attempt(top_score_normalized, local_match_ratio, force_web) {
        WebDiscoveryStatus {
            status: WebDiscoveryStatusCode::Skipped,
            reason: Some("confidence_above_threshold".to_string()),
            message: Some("web discovery skipped by confidence gate".to_string()),
            unavailable: None,
            discovery: None,
            fetches: None,
            gate: build_gate_meta(
                gate,
                top_score,
                top_score_normalized,
                local_match_ratio,
                force_web,
            ),
        }
    } else {
        run_web_discovery(
            request_id,
            gate,
            query,
            limit,
            top_score,
            top_score_normalized,
            local_match_ratio,
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

pub(crate) async fn filter_local_hits_with_llm(
    query: &str,
    hits: Vec<Hit>,
    top_score_normalized: Option<f32>,
) -> Vec<Hit> {
    if hits.is_empty() {
        return hits;
    }
    if query.trim().is_empty() {
        return hits;
    }
    let threshold = resolve_local_relevance_threshold();
    let Some(score) = top_score_normalized else {
        return hits;
    };
    if score >= threshold {
        return hits;
    }
    let Some(client) = load_local_relevance_client() else {
        return hits;
    };
    let mut filtered = Vec::new();
    for hit in hits {
        match client.evaluate(query, &hit).await {
            Some(response) if response.relevant => filtered.push(hit),
            Some(_) => {}
            None => filtered.push(hit),
        }
    }
    filtered
}

pub(crate) fn evaluate_gate_status(
    request_id: &str,
    gate: &WebGateConfig,
    top_score: Option<f32>,
    top_score_normalized: Option<f32>,
    local_match_ratio: Option<f32>,
    force_web: bool,
) -> WebDiscoveryStatus {
    let gate_meta = build_gate_meta(
        gate,
        top_score,
        top_score_normalized,
        local_match_ratio,
        force_web,
    );

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

    if !gate.should_attempt(top_score_normalized, local_match_ratio, force_web) {
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
    local_match_ratio: Option<f32>,
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
            gate: build_gate_meta(
                gate,
                top_score,
                top_score_normalized,
                local_match_ratio,
                force_web,
            ),
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
                gate: build_gate_meta(
                    gate,
                    top_score,
                    top_score_normalized,
                    local_match_ratio,
                    force_web,
                ),
            };
        }
    };

    let discovery_limit = limit.max(WEB_BATCH_SIZE * WEB_MAX_BATCHES);
    match discovery.discover(query, discovery_limit).await {
        Ok(response) => {
            let (discovery_response, urls) =
                normalize_discovery_response(response, &config, limit);
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
                gate: build_gate_meta(
                    gate,
                    top_score,
                    top_score_normalized,
                    local_match_ratio,
                    force_web,
                ),
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
                gate: build_gate_meta(
                    gate,
                    top_score,
                    top_score_normalized,
                    local_match_ratio,
                    force_web,
                ),
            }
        }
    }
}

fn normalize_discovery_response(
    response: WebDiscoveryResponse,
    config: &WebConfig,
    limit: usize,
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
        .take(limit)
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
                ai_digested_kind: None,
                relevance_score: None,
                error: Some(format!("web fetch client init failed: {err}")),
            }];
        }
    };

    for batch in urls.chunks(WEB_BATCH_SIZE).take(WEB_MAX_BATCHES) {
        let mut batch_results = Vec::new();
        for raw in batch {
            let url = match url::Url::parse(raw) {
                Ok(url) => url,
                Err(_) => continue,
            };
            let cache_key = url.as_str();
            let mut cached = false;
            let mut fetched_at_epoch_ms = None;
            let mut status = None;
            let mut content: Option<String> = None;
            let mut code_blocks: Vec<String> = Vec::new();

            if let Some(layout) = layout.as_ref() {
                if let Ok(Some(payload)) =
                    cache::read_cache_entry_with_ttl(layout, cache_key, config.cache_ttl)
                {
                    if let Ok(entry) = serde_json::from_slice::<WebFetchCacheEntry>(&payload) {
                        cached = true;
                        fetched_at_epoch_ms = Some(entry.fetched_at_epoch_ms);
                        status = Some(entry.status);
                        content = Some(entry.content);
                        code_blocks = entry.code_blocks;
                    }
                }
            }

            if content.is_none() {
                crate::web::fetch::enforce_domain_delay(&url, config.fetch_delay).await;
                fetched_at_epoch_ms = Some(now_epoch_ms());
                match client.get(url.clone()).send().await {
                    Ok(resp) => {
                        status = Some(resp.status().as_u16());
                        match resp.text().await {
                            Ok(body) => {
                                code_blocks = extract_code_blocks(&body);
                                let cleaned = clean_web_text(&body);
                                let (trimmed, _) = truncate_utf8_chars(&cleaned, MAX_WEB_DOC_CHARS);
                                content = Some(trimmed);
                            }
                            Err(_) => continue,
                        }
                    }
                    Err(_) => continue,
                }
            }

            let Some(content_text) = content.as_ref() else {
                continue;
            };

            let evaluation = if let Some(summary_client) = summary_client.as_ref() {
                summary_client.evaluate(query, content_text, &code_blocks).await
            } else {
                Some(WebEvalOutput {
                    relevance_score: 0.0,
                    kind: "summary".to_string(),
                    output: content_text.clone(),
                })
            };

            let Some(evaluation) = evaluation else {
                continue;
            };

            if !cached {
                if let Some(layout) = layout.as_ref() {
                    if config.cache_ttl.as_secs() > 0 {
                        if let Some(status) = status {
                            if let Some(fetched_at_epoch_ms) = fetched_at_epoch_ms {
                                let entry = WebFetchCacheEntry {
                                    url: url.to_string(),
                                    status,
                                    fetched_at_epoch_ms,
                                    content: content_text.clone(),
                                    code_blocks: code_blocks.clone(),
                                };
                                if let Ok(payload) = serde_json::to_vec(&entry) {
                                    let _ = cache::write_cache_entry(layout, cache_key, &payload);
                                }
                            }
                        }
                    }
                }
            }

            batch_results.push(WebFetchResult {
                url: url.to_string(),
                status,
                fetched_at_epoch_ms,
                cached,
                content: Some(content_text.clone()),
                ai_digested_content: Some(evaluation.output),
                ai_digested_kind: Some(evaluation.kind),
                relevance_score: Some(evaluation.relevance_score),
                error: None,
            });
        }

        if !batch_results.is_empty() {
            batch_results.sort_by(|a, b| {
                b.relevance_score
                    .unwrap_or(0.0)
                    .partial_cmp(&a.relevance_score.unwrap_or(0.0))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            return batch_results;
        }
    }

    Vec::new()
}

fn clean_web_text(html: &str) -> String {
    let cleaned = HtmlCleaner::default()
        .tags(std::collections::HashSet::new())
        .clean(html)
        .to_string();
    cleaned.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_code_blocks(html: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    for caps in CODE_BLOCK_RE.captures_iter(html) {
        let raw = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let stripped = TAG_RE.replace_all(raw, "");
        let unescaped = html_unescape_text(stripped.as_ref());
        let normalized = unescaped.replace("\r\n", "\n");
        let trimmed = normalized.trim();
        if trimmed.is_empty() {
            continue;
        }
        let (snippet, _) = truncate_utf8_chars(trimmed, MAX_CODE_BLOCK_CHARS);
        blocks.push(snippet);
        if blocks.len() >= MAX_CODE_BLOCKS {
            break;
        }
    }
    blocks
}

fn html_unescape_text(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
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

pub(crate) fn local_match_ratio(query: &str, hits: &[Hit]) -> Option<f32> {
    let query_tokens = tokenize_terms(query);
    if query_tokens.is_empty() {
        return None;
    }
    let query_len = query_tokens.len();
    let min_required = if query_len >= 3 { 2 } else { 1 };

    let mut best_ratio = 0.0f32;
    let mut best_matches = 0usize;
    for hit in hits.iter().take(MAX_MATCH_HITS) {
        let mut hit_tokens = HashSet::new();
        collect_tokens(&hit.summary, &mut hit_tokens);
        collect_tokens(&hit.snippet, &mut hit_tokens);
        if hit_tokens.is_empty() {
            continue;
        }
        let matched = query_tokens
            .iter()
            .filter(|token| hit_tokens.contains(*token))
            .count();
        let ratio = matched as f32 / query_len as f32;
        if ratio > best_ratio {
            best_ratio = ratio;
            best_matches = matched;
        }
    }

    if best_matches < min_required {
        return Some(0.0);
    }
    Some(best_ratio)
}

fn tokenize_terms(text: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut buf = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            buf.push(ch.to_ascii_lowercase());
        } else if !buf.is_empty() {
            push_token(&mut tokens, &mut buf);
        }
    }
    if !buf.is_empty() {
        push_token(&mut tokens, &mut buf);
    }
    tokens
}

fn collect_tokens(text: &str, out: &mut HashSet<String>) {
    let mut buf = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            buf.push(ch.to_ascii_lowercase());
        } else if !buf.is_empty() {
            if should_keep_token(&buf) {
                out.insert(buf.clone());
            }
            buf.clear();
        }
    }
    if !buf.is_empty() {
        if should_keep_token(&buf) {
            out.insert(buf.clone());
        }
    }
}

fn push_token(tokens: &mut Vec<String>, buf: &mut String) {
    if should_keep_token(buf) {
        tokens.push(buf.clone());
    }
    buf.clear();
}

fn should_keep_token(token: &str) -> bool {
    let token = token.trim();
    if token.len() < 2 {
        return false;
    }
    !STOPWORDS.contains(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_attempt_accounts_for_threshold_and_force_web() {
        let gate = WebGateConfig {
            enabled: true,
            trigger_threshold: 0.5,
            min_local_match_ratio: 0.2,
            browser_hint: None,
            browser_available: true,
        };

        assert!(gate.should_attempt(Some(0.3), None, false));
        assert!(!gate.should_attempt(Some(0.8), Some(0.6), false));
        assert!(gate.should_attempt(Some(0.8), Some(0.1), false));
        assert!(gate.should_attempt(Some(0.8), None, true));
        assert!(gate.should_attempt(None, None, false));
    }

    #[test]
    fn evaluate_gate_status_skips_when_confident() {
        let gate = WebGateConfig {
            enabled: true,
            trigger_threshold: 0.45,
            min_local_match_ratio: 0.2,
            browser_hint: None,
            browser_available: true,
        };
        let status = evaluate_gate_status("req", &gate, Some(0.8), Some(0.8), Some(0.9), false);
        assert_eq!(status.status, WebDiscoveryStatusCode::Skipped);
        assert_eq!(status.reason.as_deref(), Some("confidence_above_threshold"));
    }

    #[test]
    fn evaluate_gate_status_reports_unavailable_without_browser() {
        let gate = WebGateConfig {
            enabled: true,
            trigger_threshold: 0.45,
            min_local_match_ratio: 0.2,
            browser_hint: Some("chrome".to_string()),
            browser_available: false,
        };
        let status = evaluate_gate_status("req", &gate, Some(0.1), Some(0.1), None, false);
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

fn config_web_min_match_ratio() -> Option<f32> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(config.search.web_min_match_ratio)
}

fn config_local_relevance_threshold() -> Option<f32> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(config.search.local_relevance_threshold)
}

fn resolve_local_relevance_threshold() -> f32 {
    env_f32("DOCDEX_LOCAL_RELEVANCE_THRESHOLD")
        .or_else(config_local_relevance_threshold)
        .unwrap_or(DEFAULT_LOCAL_RELEVANCE_THRESHOLD)
        .clamp(0.0, 1.0)
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
