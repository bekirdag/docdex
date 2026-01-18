use crate::config;
use crate::index::Hit;
use crate::index::Indexer;
use crate::libs::LibsIndexer;
use crate::llm::adapter::{resolve_agent_adapter, LlmClient, LlmCompletion, LlmFuture};
use crate::max_size::truncate_utf8_chars;
use crate::mcoda::registry::McodaRegistry;
use crate::ollama::OllamaClient;
use crate::search;
use crate::state_layout::StateLayout;
use crate::tier2::{Tier2Unavailable, Tier2UnavailableReason};
use crate::util;
use crate::web::cache;
use crate::web::chrome::ChromeFetchResult;
use crate::web::ddg::{DdgDiscovery, WebDiscoveryResponse, WebDiscoveryResult};
use crate::web::normalize::{dedupe_urls, unwrap_ddg_redirect};
use crate::web::readability::extract_readable_text;
use crate::web::scraper::ScraperEngine;
use crate::web::status::fetch_status;
use crate::web::WebConfig;
use anyhow::{anyhow, Context};
use once_cell::sync::Lazy;
use reqwest::header::{HeaderValue, ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::env;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Semaphore;
use tracing::{info, warn};
use url::Url;

const DEFAULT_WEB_TRIGGER_THRESHOLD: f32 = 0.7;
const DEFAULT_WEB_MIN_MATCH_RATIO: f32 = 0.2;
const DEFAULT_LOCAL_RELEVANCE_THRESHOLD: f32 = 0.7;
const MAX_WEB_SUMMARY_TOKENS: u32 = 256;
const WEB_SUMMARY_TIMEOUT_MS: u64 = 15_000;
const DEFAULT_WEB_SUMMARY_INPUT_MAX_CHARS: usize = 6000;
const MAX_QUERY_CATEGORY_TOKENS: u32 = 48;
const QUERY_CATEGORY_TIMEOUT_MS: u64 = 4_000;
const WEB_CONTEXT_MIN_RELEVANCE_SCORE: f32 = 0.2;
const WEB_HTML2TEXT_WRAP_COLS: usize = 120;

const MAX_MATCH_HITS: usize = 3;
const LOCAL_RELEVANCE_TIMEOUT_MS: u64 = 8_000;
const LOCAL_RELEVANCE_MAX_TOKENS: u32 = 96;
const MAX_LOCAL_RELEVANCE_INPUT_CHARS: usize = 800;
const WEB_BATCH_SIZE: usize = 10;
const WEB_MAX_BATCHES: usize = 2;
const WEB_FETCH_BUDGET_DEFAULT_MS: u64 = 45_000;
const WEB_FETCH_BUDGET_MIN_MS: u64 = 5_000;
const WEB_FETCH_MIN_REMAINING_MS: u64 = 1_000;
const WEB_DIRECT_FETCH_MAX_BYTES_DEFAULT: usize = 1_500_000;
const MAX_CODE_BLOCKS: usize = 4;
const MAX_CODE_BLOCK_CHARS: usize = 1800;
const WEB_GOOD_RELEVANCE_SCORE: f32 = 0.7;
const WEB_DISCOVERY_MULTIPLIER: usize = 4;
const WEB_DISCOVERY_MIN_RESULTS: usize = 4;
const WEB_DISCOVERY_MAX_QUERY_TOKENS: usize = 6;
const WEB_MIN_CONTENT_CHARS: usize = 200;
const WEB_MIN_CONTENT_WORDS: usize = 30;
const WEB_MAX_RESULTS_PER_DOMAIN: usize = 2;
const WEB_QUALITY_FAIL_THRESHOLD: u32 = 3;
const WEB_QUALITY_BLOCK_THRESHOLD: u32 = 2;
const WEB_QUALITY_CHALLENGE_THRESHOLD: u32 = 1;
const WEB_QUALITY_COOLDOWN_SECS: u64 = 600;
const WEB_QUALITY_TTL_SECS: u64 = 86_400;

static WEB_LLM_SEMAPHORE: Lazy<Semaphore> =
    Lazy::new(|| Semaphore::new(resolve_web_llm_concurrency()));

const COMMON_STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "by", "do", "does", "for", "from", "how", "i", "if",
    "in", "is", "it", "of", "on", "or", "the", "to", "use", "using", "was", "we", "what", "when",
    "where", "who", "why", "with", "you", "your",
];

const MATCH_STOPWORDS_EXTRA: &[&str] = &["add", "append", "build", "create", "insert", "make"];

const MATCH_STOPWORDS_GENERIC: &[&str] = &[
    "code",
    "sample",
    "samples",
    "example",
    "examples",
    "snippet",
    "snippets",
    "tutorial",
    "tutorials",
    "guide",
    "guides",
    "docs",
    "documentation",
    "reference",
    "references",
];

const DOMAIN_STOPWORDS: &[&str] = &[
    "code",
    "sample",
    "samples",
    "example",
    "examples",
    "tutorial",
    "tutorials",
    "guide",
    "guides",
    "docs",
    "documentation",
    "reference",
    "references",
    "overview",
    "intro",
    "introduction",
    "getting",
    "started",
    "learn",
    "learning",
];

static STOPWORDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    COMMON_STOPWORDS
        .iter()
        .chain(DOMAIN_STOPWORDS.iter())
        .copied()
        .collect()
});

static MATCH_STOPWORDS: Lazy<HashSet<&'static str>> = Lazy::new(|| {
    COMMON_STOPWORDS
        .iter()
        .chain(MATCH_STOPWORDS_EXTRA.iter())
        .chain(MATCH_STOPWORDS_GENERIC.iter())
        .copied()
        .collect()
});

#[derive(Clone, Copy)]
struct CachedQueryCategory {
    category: QueryCategory,
    source: QueryCategorySource,
}

static QUERY_CATEGORY_CACHE: Lazy<Mutex<HashMap<String, CachedQueryCategory>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

static ANSI_ESCAPE_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"\x1b\[[0-9;]*[A-Za-z]").expect("valid ansi escape regex"));

static HEADING_JOIN_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"([a-z0-9])#([A-Za-z])").expect("valid heading join regex"));

static TAG_ATTR_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"(<[A-Za-z]+)([a-z]{2,})(=)").expect("valid tag attr join regex")
});

static TLD_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"\.(com|org|net|io|dev|co|us|uk|edu|gov)([A-Z])")
        .expect("valid tld join regex")
});

static LOWER_UPPER_JOIN_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"([a-z])([A-Z])").expect("valid lower upper join regex"));

static AND_JOIN_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"([a-z])and([A-Z])").expect("valid and join regex"));

static AND_LOWER_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"([a-z]{3,})and([a-z]{3,})").expect("valid and lower join regex")
});

static CAPITAL_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"([A-Z][a-z]{2,})([A-Z][a-z]{2,})").expect("valid capital join regex")
});

static BRACKET_LEFT_JOIN_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"([A-Za-z])\[").expect("valid bracket left join regex"));

static BRACKET_RIGHT_JOIN_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"\]([A-Za-z])").expect("valid bracket right join regex"));

static LOWER_JOIN_STOPWORD_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"([A-Za-z]{3,})(and|of|in|to|with|by|as|for|from|its|is)([A-Za-z]{3,})")
        .expect("valid lower join stopword regex")
});

static TITLE_AND_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"([A-Z][a-z]{2,})and(\s+[a-z]{3,})").expect("valid title and join regex")
});

static PREFIX_COMMON_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r"(?i)\b(the|a|an|of|in|to|with|by|as|its|is)(capital|largest|city|population|area|state|country|province|district|region|union|metropolitan|inhabitants|limit|limits|river|county|kingdom|republic)",
    )
    .expect("valid prefix common join regex")
});

static LONG_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"([a-z]{5,})(within|into|over|under|between|across)([a-z]{3,})")
        .expect("valid long join regex")
});

static PUNCT_JOIN_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"([.!?])([A-Z])").expect("valid punctuation join regex"));

static COMMA_JOIN_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"([,])([A-Za-z])").expect("valid comma join regex"));

static COLON_JOIN_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"([:;])([A-Za-z])").expect("valid colon join regex"));

static WORD_METHOD_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"([A-Za-z]{2,})([a-z]{2,}\()").expect("valid word method join regex")
});

static PAREN_WORD_JOIN_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"(\))([A-Za-z])").expect("valid paren word join regex"));

static LABEL_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(
        r"(?i)\b(example|syntax|description|parameters|returns?|usage|notes)([A-Za-z])",
    )
    .expect("valid label join regex")
});

static CODE_KEYWORD_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"\b(const|let|var|function|return|class|struct|enum)([A-Za-z_])")
        .expect("valid code keyword join regex")
});

static ALLCAPS_JOIN_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"([a-z])([A-Z]{2,})").expect("valid allcaps join regex"));

static CAMEL_BREAK_RE: Lazy<regex::Regex> =
    Lazy::new(|| regex::Regex::new(r"([a-z])([A-Z])").expect("valid camel break regex"));

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
        let browser_hint = env_string("DOCDEX_WEB_BROWSER").or_else(config_web_browser_path);
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
        use_match_ratio: bool,
    ) -> bool {
        if force_web {
            return true;
        }
        if use_match_ratio {
            if let Some(local_match_ratio) = local_match_ratio {
                if local_match_ratio < self.min_local_match_ratio {
                    return true;
                }
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

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug: Option<Vec<String>>,
    pub gate: WebGateMeta,
}

pub fn web_context_from_status(status: &WebDiscoveryStatus) -> Option<Vec<WebFetchResult>> {
    let fetches = status.fetches.as_ref()?;
    let mut items = Vec::new();
    for item in fetches {
        if item
            .relevance_score
            .map_or(false, |score| score < WEB_CONTEXT_MIN_RELEVANCE_SCORE)
        {
            continue;
        }
        let content = item.ai_digested_content.as_ref().or(item.content.as_ref());
        let Some(content) = content else {
            continue;
        };
        if content.trim().is_empty() {
            continue;
        }
        let mut cloned = item.clone();
        cloned.error = None;
        cloned.debug = None;
        cloned.debug_html = None;
        cloned.debug_dom_text = None;
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
    pub debug_html: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug_dom_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WebFetchCacheEntry {
    url: String,
    status: Option<u16>,
    fetched_at_epoch_ms: u128,
    content: String,
    #[serde(default)]
    code_blocks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WebSummaryCacheEntry {
    query_hash: String,
    content_hash: String,
    relevance_score: f32,
    kind: String,
    output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct WebPhraseCacheEntry {
    query_hash: String,
    fetched_at_epoch_ms: u128,
    ai_digested_kind: String,
    ai_digested_content: String,
    #[serde(default)]
    url: String,
    #[serde(default)]
    relevance_score: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DomainQualityEntry {
    host: String,
    fail_count: u32,
    blocked_count: u32,
    challenge_count: u32,
    last_failure_epoch_ms: u64,
    cooldown_until_epoch_ms: u64,
}

#[derive(Debug, Clone, Copy)]
enum DomainFailureKind {
    Fetch,
    Blocked,
    Challenge,
}

struct OllamaPromptClient {
    client: OllamaClient,
    model: String,
    adapter: String,
}

impl LlmClient for OllamaPromptClient {
    fn generate<'a>(
        &'a self,
        prompt: &'a str,
        max_tokens: u32,
        timeout: Duration,
    ) -> LlmFuture<'a> {
        Box::pin(async move {
            let output = self
                .client
                .generate(&self.model, prompt, max_tokens, timeout)
                .await
                .context("ollama generate")?;
            Ok(LlmCompletion {
                output,
                adapter: self.adapter.clone(),
                model: Some(self.model.clone()),
                metadata: None,
            })
        })
    }
}

#[derive(Clone)]
struct QueryCategoryClient {
    client: Arc<dyn LlmClient>,
    max_tokens: u32,
    timeout: Duration,
}

#[derive(Clone)]
struct WebSummaryClient {
    client: Arc<dyn LlmClient>,
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

#[derive(Debug, Deserialize)]
struct QueryCategoryResponse {
    category: String,
}

struct WebEvalOutput {
    relevance_score: f32,
    kind: String,
    output: String,
}

#[derive(Clone)]
struct LocalRelevanceClient {
    client: Arc<dyn LlmClient>,
    max_tokens: u32,
    timeout: Duration,
}

#[derive(Debug, Deserialize)]
struct LocalRelevanceResponse {
    relevant: bool,
    score: f32,
}

const WEB_SUMMARY_INSTRUCTIONS: &str = include_str!("../../prompts/web_summary_instructions.txt");
const QUERY_CATEGORY_INSTRUCTIONS: &str =
    include_str!("../../prompts/query_category_instructions.txt");
const LOCAL_RELEVANCE_INSTRUCTIONS: &str =
    include_str!("../../prompts/local_relevance_instructions.txt");

impl WebSummaryClient {
    async fn evaluate(
        &self,
        query: &str,
        category: QueryCategory,
        content: &str,
        code_blocks: &[String],
    ) -> Option<WebEvalOutput> {
        let trimmed = content.trim();
        if trimmed.is_empty() {
            return None;
        }
        let intent = detect_query_intent(query);
        let allow_code = (matches!(intent, QueryIntent::Code)
            || matches!(category, QueryCategory::CodeExample))
            && !code_blocks.is_empty();
        let prompt = build_summary_prompt(query, category, trimmed, code_blocks);
        let _permit = WEB_LLM_SEMAPHORE.acquire().await.ok();
        let result = self
            .client
            .generate(&prompt, self.max_tokens, self.timeout)
            .await
            .ok()?;
        let output = result.output;
        let parsed: WebEvalResponse = match parse_json_response(&output) {
            Some(parsed) => parsed,
            None => {
                if let Some(parsed) = parse_web_eval_response_lenient(&output) {
                    parsed
                } else {
                    let raw = output.trim();
                    if raw.is_empty() {
                        return None;
                    }
                    if looks_like_web_eval_metadata(raw) {
                        return None;
                    }
                    let kind = if allow_code && looks_like_code_output(raw) {
                        "code"
                    } else {
                        "summary"
                    };
                    let output = if kind == "code" {
                        clean_code_text(raw)
                    } else {
                        clean_summary_text(raw)
                    };
                    if output.is_empty() {
                        return None;
                    }
                    return Some(WebEvalOutput {
                        relevance_score: 0.4,
                        kind: kind.to_string(),
                        output,
                    });
                }
            }
        };
        let relevant = parsed.relevant;
        let score = parsed.score.clamp(0.0, 1.0);
        let mut kind = parsed.kind.trim().to_ascii_lowercase();
        if kind == "code" && !allow_code {
            kind = "summary".to_string();
        }
        let output = if kind == "code" {
            let cleaned = clean_code_text(&parsed.output);
            format_md_code(&cleaned)
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
        let _permit = WEB_LLM_SEMAPHORE.acquire().await.ok();
        let result = self
            .client
            .generate(&prompt, self.max_tokens, self.timeout)
            .await
            .ok()?;
        let parsed: LocalRelevanceResponse = parse_json_response(&result.output)?;
        let score = parsed.score.clamp(0.0, 1.0);
        Some(LocalRelevanceResponse {
            relevant: parsed.relevant,
            score,
        })
    }
}

impl QueryCategoryClient {
    async fn evaluate(&self, query: &str) -> Option<QueryCategory> {
        let prompt = build_query_category_prompt(query);
        let _permit = WEB_LLM_SEMAPHORE.acquire().await.ok();
        let result = self
            .client
            .generate(&prompt, self.max_tokens, self.timeout)
            .await
            .ok()?;
        let parsed: QueryCategoryResponse = parse_json_response(&result.output)?;
        parse_query_category(&parsed.category)
    }
}

fn load_query_category_client(
    model_override: Option<&str>,
    llm_agent: Option<&str>,
) -> Option<QueryCategoryClient> {
    let client = load_llm_client(model_override, llm_agent)?;
    let max_tokens = load_llm_config(model_override)
        .map(|config| config.max_answer_tokens.min(MAX_QUERY_CATEGORY_TOKENS))
        .unwrap_or(MAX_QUERY_CATEGORY_TOKENS);
    Some(QueryCategoryClient {
        client,
        max_tokens,
        timeout: Duration::from_millis(QUERY_CATEGORY_TIMEOUT_MS),
    })
}

fn load_web_summary_client(
    model_override: Option<&str>,
    llm_agent: Option<&str>,
) -> Option<WebSummaryClient> {
    let client = load_llm_client(model_override, llm_agent)?;
    let max_tokens = load_llm_config(model_override)
        .map(|config| config.max_answer_tokens.min(MAX_WEB_SUMMARY_TOKENS))
        .unwrap_or(MAX_WEB_SUMMARY_TOKENS);
    Some(WebSummaryClient {
        client,
        max_tokens,
        timeout: Duration::from_millis(WEB_SUMMARY_TIMEOUT_MS),
    })
}

fn load_local_relevance_client(
    model_override: Option<&str>,
    llm_agent: Option<&str>,
) -> Option<LocalRelevanceClient> {
    let client = load_llm_client(model_override, llm_agent)?;
    let max_tokens = load_llm_config(model_override)
        .map(|config| config.max_answer_tokens.min(LOCAL_RELEVANCE_MAX_TOKENS))
        .unwrap_or(LOCAL_RELEVANCE_MAX_TOKENS);
    Some(LocalRelevanceClient {
        client,
        max_tokens,
        timeout: Duration::from_millis(LOCAL_RELEVANCE_TIMEOUT_MS),
    })
}

fn load_llm_config(model_override: Option<&str>) -> Option<config::LlmConfig> {
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
    if let Some(model_override) = model_override {
        let trimmed = model_override.trim();
        if !trimmed.is_empty() {
            config.llm.default_model = trimmed.to_string();
        }
    }
    Some(config.llm)
}

fn load_llm_client(
    model_override: Option<&str>,
    llm_agent: Option<&str>,
) -> Option<Arc<dyn LlmClient>> {
    if let Some(agent_id) = llm_agent {
        let registry = match McodaRegistry::load_default() {
            Ok(Some(registry)) => registry,
            Ok(None) => {
                warn!("mcoda registry not found; skipping agent {agent_id}");
                return None;
            }
            Err(err) => {
                warn!("failed to load mcoda registry: {err}");
                return None;
            }
        };
        let agent = registry
            .agent_by_id(agent_id)
            .or_else(|| registry.agent_by_slug(agent_id));
        let agent = match agent {
            Some(agent) => agent,
            None => {
                warn!("mcoda agent not found: {agent_id}");
                return None;
            }
        };
        match resolve_agent_adapter(agent) {
            Ok(adapter) => return Some(Arc::new(adapter)),
            Err(err) => {
                warn!("failed to resolve mcoda agent {agent_id}: {err}");
                return None;
            }
        }
    }

    let config = load_llm_config(model_override)?;
    if !config.provider.trim().eq_ignore_ascii_case("ollama") {
        return None;
    }
    let base_url = config.base_url.trim();
    let model = config.default_model.trim();
    if base_url.is_empty() || model.is_empty() {
        return None;
    }
    let client = OllamaClient::new(base_url.to_string()).ok()?;
    let adapter = OllamaPromptClient {
        client,
        model: model.to_string(),
        adapter: "ollama".to_string(),
    };
    Some(Arc::new(adapter))
}

fn build_summary_prompt(
    query: &str,
    category: QueryCategory,
    content: &str,
    code_blocks: &[String],
) -> String {
    let snippet = truncate_summary_input(content);
    let query = query.trim();
    let mut prompt = String::new();
    prompt.push_str("Here is what I found online.\n");
    prompt.push_str("The answer to the user query is in the page text below.\n");
    prompt.push_str("The text below is the main content with headers/menus removed.\n");
    prompt.push_str("\nPage text (cleaned):\n");
    prompt.push_str(&snippet);
    prompt.push_str("\n\n");
    if code_blocks.is_empty() {
        prompt.push_str("Code blocks (verbatim): <none>\n");
    } else {
        prompt.push_str("Code blocks (verbatim):\n");
        for (idx, block) in code_blocks.iter().enumerate() {
            prompt.push_str(&format!(
                "[code {}]\n{}\n[/code {}]\n",
                idx + 1,
                block,
                idx + 1
            ));
        }
    }
    prompt.push_str("\nUser query:\n");
    if query.is_empty() {
        prompt.push_str("<empty>");
    } else {
        prompt.push_str(query);
    }
    prompt.push_str("\n\nQuery category: ");
    prompt.push_str(category.as_str());
    prompt.push('\n');
    prompt.push_str(WEB_SUMMARY_INSTRUCTIONS);
    prompt
}

fn build_query_category_prompt(query: &str) -> String {
    let query = query.trim();
    let mut prompt = String::new();
    if query.is_empty() {
        prompt.push_str("User query: <empty>\n\n");
    } else {
        prompt.push_str("User query:\n");
        prompt.push_str(query);
        prompt.push_str("\n\n");
    }
    prompt.push_str(QUERY_CATEGORY_INSTRUCTIONS);
    prompt
}

fn build_local_relevance_prompt(query: &str, hit: &Hit) -> String {
    let query = query.trim();
    let intent = detect_query_intent(query);
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
    match intent {
        QueryIntent::Code => {
            prompt.push_str("Query intent: code example/snippet\n");
        }
        QueryIntent::Definition => {
            prompt.push_str("Query intent: documentation/summary\n");
        }
        QueryIntent::General => {
            prompt.push_str("Query intent: general\n");
        }
    }
    prompt.push('\n');
    prompt.push_str(LOCAL_RELEVANCE_INSTRUCTIONS);
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
        let joined = body.join("\n");
        return sanitize_code_block_text(&joined);
    }
    sanitize_code_block_text(trimmed)
}

fn sanitize_code_block_text(text: &str) -> String {
    let mut cleaned = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if is_code_marker_line(trimmed) {
            continue;
        }
        let stripped = strip_copy_prefix(trimmed);
        if stripped.is_empty() {
            continue;
        }
        cleaned.push(stripped.to_string());
    }
    cleaned.join("\n").trim().to_string()
}

fn is_code_marker_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.starts_with("[code ") || lower.starts_with("[/code ") || lower == "```"
}

fn strip_copy_prefix(line: &str) -> &str {
    let lower = line.to_ascii_lowercase();
    let prefixes = ["copy code", "copycode", "textcopy", "copy"];
    for prefix in prefixes {
        if lower.starts_with(prefix) {
            return line[prefix.len()..].trim_start();
        }
    }
    line
}

fn format_md_output(kind: &str, output: &str) -> String {
    match kind {
        "code" => format_md_code(&clean_code_text(output)),
        _ => clean_summary_text(output),
    }
}

fn format_md_code(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.contains("```") {
        return trimmed.to_string();
    }
    format!("```\n{}\n```", trimmed)
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
    let slice = &trimmed[start..=end];
    if let Ok(parsed) = serde_json::from_str::<T>(slice) {
        return Some(parsed);
    }
    let fixed = escape_unescaped_json_newlines(slice);
    serde_json::from_str::<T>(&fixed).ok()
}

fn parse_web_eval_response_lenient(raw: &str) -> Option<WebEvalResponse> {
    let output = extract_loose_output_field(raw)?;
    let kind = extract_loose_string_field(raw, "kind")
        .or_else(|| extract_loose_string_field(raw, "type"))
        .unwrap_or_else(|| "summary".to_string())
        .to_ascii_lowercase();
    let relevant = extract_loose_bool_field(raw, "relevant").unwrap_or(true);
    let score = extract_loose_float_field(raw, "score").unwrap_or(0.5);
    Some(WebEvalResponse {
        relevant,
        score,
        kind,
        output,
    })
}

fn looks_like_web_eval_metadata(raw: &str) -> bool {
    let lower = raw.to_ascii_lowercase();
    let has_relevant = lower.contains("\"relevant\"");
    let has_score = lower.contains("\"score\"");
    let has_kind = lower.contains("\"kind\"") || lower.contains("\"type\"");
    let has_output = lower.contains("\"output\"");
    if has_relevant && has_score && has_kind && !has_output {
        return true;
    }
    lower.contains("```json") && has_relevant && has_score
}

fn extract_loose_output_field(raw: &str) -> Option<String> {
    let lower = raw.to_ascii_lowercase();
    let key = "\"output\"";
    let key_pos = lower.find(key)?;
    let after_key = &raw[key_pos + key.len()..];
    let colon_pos = after_key.find(':')?;
    let mut idx = key_pos + key.len() + colon_pos + 1;
    let bytes = raw.as_bytes();
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    if idx >= bytes.len() {
        return None;
    }
    if bytes[idx] == b'"' {
        idx += 1;
        let end = raw.rfind('"')?;
        if end <= idx {
            return None;
        }
        return Some(raw[idx..end].to_string());
    }
    let trimmed = raw[idx..].trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn extract_loose_string_field(raw: &str, field: &str) -> Option<String> {
    let lower = raw.to_ascii_lowercase();
    let key = format!("\"{}\"", field);
    let key_pos = lower.find(&key)?;
    let after_key = &raw[key_pos + key.len()..];
    let colon_pos = after_key.find(':')?;
    let mut idx = key_pos + key.len() + colon_pos + 1;
    let bytes = raw.as_bytes();
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    if idx >= bytes.len() {
        return None;
    }
    if bytes[idx] == b'"' {
        idx += 1;
        let rest = &raw[idx..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    None
}

fn extract_loose_bool_field(raw: &str, field: &str) -> Option<bool> {
    let lower = raw.to_ascii_lowercase();
    let key = format!("\"{}\"", field);
    let key_pos = lower.find(&key)?;
    let after_key = &lower[key_pos + key.len()..];
    let colon_pos = after_key.find(':')?;
    let mut idx = key_pos + key.len() + colon_pos + 1;
    let bytes = lower.as_bytes();
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    if lower[idx..].starts_with("true") {
        return Some(true);
    }
    if lower[idx..].starts_with("false") {
        return Some(false);
    }
    None
}

fn extract_loose_float_field(raw: &str, field: &str) -> Option<f32> {
    let lower = raw.to_ascii_lowercase();
    let key = format!("\"{}\"", field);
    let key_pos = lower.find(&key)?;
    let after_key = &lower[key_pos + key.len()..];
    let colon_pos = after_key.find(':')?;
    let mut idx = key_pos + key.len() + colon_pos + 1;
    let bytes = lower.as_bytes();
    while idx < bytes.len() && bytes[idx].is_ascii_whitespace() {
        idx += 1;
    }
    let rest = &lower[idx..];
    let mut end = 0usize;
    for (i, ch) in rest.char_indices() {
        if ch.is_ascii_digit() || ch == '.' {
            end = i + ch.len_utf8();
        } else if end > 0 {
            break;
        } else if ch == '-' {
            end = i + ch.len_utf8();
        } else if ch.is_ascii_whitespace() {
            continue;
        } else {
            break;
        }
    }
    if end == 0 {
        return None;
    }
    rest[..end].trim().parse::<f32>().ok()
}

fn escape_unescaped_json_newlines(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut escaped = false;
    for ch in text.chars() {
        if in_string {
            if escaped {
                out.push(ch);
                escaped = false;
                continue;
            }
            if ch == '\\' {
                out.push(ch);
                escaped = true;
                continue;
            }
            if ch == '"' {
                out.push(ch);
                in_string = false;
                continue;
            }
            match ch {
                '\n' => {
                    out.push_str("\\n");
                    continue;
                }
                '\r' => {
                    out.push_str("\\r");
                    continue;
                }
                '\t' => {
                    out.push_str("\\t");
                    continue;
                }
                _ => {}
            }
            out.push(ch);
        } else {
            if ch == '"' {
                in_string = true;
            }
            out.push(ch);
        }
    }
    out
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
    web_limit: Option<usize>,
    force_web: bool,
    gate: &WebGateConfig,
    llm_filter_local_results: bool,
    skip_local_search: bool,
    disable_web_cache: bool,
    llm_model: Option<&str>,
    llm_agent: Option<&str>,
) -> Result<WebResearchResponse, anyhow::Error> {
    let query = query.trim();
    let intent = detect_query_intent(query);
    let (hits, top_score, top_score_normalized, local_match_ratio) = if skip_local_search {
        (Vec::new(), None, None, None)
    } else {
        let search_response = search::run_query(
            indexer,
            libs_indexer,
            query,
            limit,
            search::RankingSurface::Search,
        )
        .await?;
        let original_top_score_normalized = search_response.top_score_normalized;
        let mut hits = filter_local_hits_with_llm(
            query,
            intent,
            search_response.hits,
            original_top_score_normalized,
            llm_filter_local_results,
            llm_model,
            llm_agent,
        )
        .await;
        let mut top_score = hits.first().map(|hit| hit.score);
        let mut top_score_normalized = top_score.map(search::normalize_score);
        let mut local_match_ratio = local_match_ratio(query, &hits);
        if matches!(intent, QueryIntent::Code) && local_match_ratio == Some(0.0) {
            hits.clear();
            top_score = None;
            top_score_normalized = None;
            local_match_ratio = Some(0.0);
        }
        (hits, top_score, top_score_normalized, local_match_ratio)
    };
    let completion = build_completion(query, &hits);
    let web_limit = resolve_web_limit(web_limit, limit);
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
            debug: None,
            gate: build_gate_meta(
                gate,
                top_score,
                top_score_normalized,
                local_match_ratio,
                force_web,
            ),
        }
    } else if !gate.should_attempt(
        top_score_normalized,
        local_match_ratio,
        force_web,
        llm_filter_local_results,
    ) {
        WebDiscoveryStatus {
            status: WebDiscoveryStatusCode::Skipped,
            reason: Some("confidence_above_threshold".to_string()),
            message: Some("web discovery skipped by confidence gate".to_string()),
            unavailable: None,
            discovery: None,
            fetches: None,
            debug: None,
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
            web_limit,
            top_score,
            top_score_normalized,
            local_match_ratio,
            force_web,
            disable_web_cache,
            llm_model,
            llm_agent,
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
    intent: QueryIntent,
    hits: Vec<Hit>,
    top_score_normalized: Option<f32>,
    use_llm: bool,
    llm_model: Option<&str>,
    llm_agent: Option<&str>,
) -> Vec<Hit> {
    if hits.is_empty() {
        return hits;
    }
    if query.trim().is_empty() {
        return hits;
    }
    let query_tokens = tokenize_terms_for_match(query);
    if query_tokens.is_empty() {
        if matches!(intent, QueryIntent::Code) {
            return Vec::new();
        }
        return hits;
    }
    let query_len = query_tokens.len();
    let min_required = min_required_matches(query_len);
    let min_ratio = min_overlap_ratio_for_intent(intent, query_len);
    let code_intent = matches!(intent, QueryIntent::Code);
    let threshold = resolve_local_relevance_threshold();
    let client = if use_llm {
        load_local_relevance_client(llm_model, llm_agent)
    } else {
        None
    };
    if !code_intent {
        if let (Some(score), None) = (top_score_normalized, client.as_ref()) {
            if score >= threshold {
                return hits;
            }
        }
    }
    let Some(client) = client else {
        let mut filtered = Vec::new();
        for hit in hits {
            let Some((matched, ratio)) = hit_match_stats(&query_tokens, query_len, &hit) else {
                continue;
            };
            let overlap_ok = matched >= min_required && min_ratio.map_or(true, |min| ratio >= min);
            let has_code = hit_has_code_markers(&hit);
            let specific_match = hit_matches_specific_token(&query_tokens, &hit);
            if code_intent {
                if !overlap_ok || !has_code || !specific_match {
                    continue;
                }
            } else if !overlap_ok {
                continue;
            }
            let mut adjusted = hit;
            if code_intent {
                apply_code_intent_penalty(&mut adjusted, has_code);
            }
            filtered.push(adjusted);
        }
        filtered.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        return filtered;
    };
    let all_hits = hits;
    let mut filtered = Vec::new();
    let mut llm_responses = 0usize;
    let mut llm_failures = 0usize;
    for hit in &all_hits {
        match client.evaluate(query, hit).await {
            Some(response) => {
                llm_responses += 1;
                if !response.relevant {
                    continue;
                }
                let Some((matched, ratio)) = hit_match_stats(&query_tokens, query_len, hit) else {
                    continue;
                };
                let overlap_ok =
                    matched >= min_required && min_ratio.map_or(true, |min| ratio >= min);
                let has_code = hit_has_code_markers(hit);
                let specific_match = hit_matches_specific_token(&query_tokens, hit);
                if code_intent {
                    if !overlap_ok || !has_code || !specific_match {
                        continue;
                    }
                } else if !overlap_ok {
                    continue;
                }
                let mut adjusted = hit.clone();
                if code_intent {
                    apply_code_intent_penalty(&mut adjusted, has_code);
                }
                filtered.push(adjusted);
            }
            None => {
                llm_failures += 1;
            }
        }
    }
    if llm_responses == 0 && llm_failures > 0 {
        let mut fallback = Vec::new();
        for hit in all_hits {
            let Some((matched, ratio)) = hit_match_stats(&query_tokens, query_len, &hit) else {
                continue;
            };
            let overlap_ok = matched >= min_required && min_ratio.map_or(true, |min| ratio >= min);
            let has_code = hit_has_code_markers(&hit);
            let specific_match = hit_matches_specific_token(&query_tokens, &hit);
            if code_intent {
                if !overlap_ok || !has_code || !specific_match {
                    continue;
                }
            } else if !overlap_ok {
                continue;
            }
            let mut adjusted = hit;
            if code_intent {
                apply_code_intent_penalty(&mut adjusted, has_code);
            }
            fallback.push(adjusted);
        }
        fallback.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        return fallback;
    }
    filtered.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    if !filtered.is_empty() {
        return filtered;
    }
    let mut fallback = Vec::new();
    for hit in &all_hits {
        let Some((matched, ratio)) = hit_match_stats(&query_tokens, query_len, hit) else {
            continue;
        };
        let overlap_ok = matched >= min_required && min_ratio.map_or(true, |min| ratio >= min);
        let has_code = hit_has_code_markers(hit);
        let specific_match = hit_matches_specific_token(&query_tokens, hit);
        if code_intent {
            if !overlap_ok || !has_code || !specific_match {
                continue;
            }
        } else if !overlap_ok {
            continue;
        }
        let mut adjusted = hit.clone();
        if code_intent {
            apply_code_intent_penalty(&mut adjusted, has_code);
        }
        fallback.push(adjusted);
    }
    fallback.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    if !fallback.is_empty() {
        return fallback;
    }
    if code_intent {
        return Vec::new();
    }
    all_hits
}

pub(crate) fn evaluate_gate_status(
    request_id: &str,
    gate: &WebGateConfig,
    top_score: Option<f32>,
    top_score_normalized: Option<f32>,
    local_match_ratio: Option<f32>,
    force_web: bool,
    use_match_ratio: bool,
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
            debug: None,
            gate: gate_meta,
        };
    }

    if !gate.should_attempt(
        top_score_normalized,
        local_match_ratio,
        force_web,
        use_match_ratio,
    ) {
        return WebDiscoveryStatus {
            status: WebDiscoveryStatusCode::Skipped,
            reason: Some("confidence_above_threshold".to_string()),
            message: Some("web discovery skipped by confidence gate".to_string()),
            unavailable: None,
            discovery: None,
            fetches: None,
            debug: None,
            gate: gate_meta,
        };
    }

    if !gate.browser_available {
        let message = match gate.browser_hint.as_deref() {
            Some(hint) => format!("web browser not available: {hint}; run `docdexd browser setup`"),
            None => "web browser not available; run `docdexd browser setup`".to_string(),
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
            debug: None,
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
        debug: None,
        gate: gate_meta,
    }
}

async fn run_web_discovery(
    request_id: &str,
    gate: &WebGateConfig,
    query: &str,
    web_limit: usize,
    top_score: Option<f32>,
    top_score_normalized: Option<f32>,
    local_match_ratio: Option<f32>,
    force_web: bool,
    disable_web_cache: bool,
    llm_model: Option<&str>,
    llm_agent: Option<&str>,
) -> WebDiscoveryStatus {
    let config = WebConfig::from_env();
    let mut config = config;
    let cache_enabled = !disable_web_cache && !config.cache_ttl.is_zero();
    if !cache_enabled {
        config.cache_ttl = Duration::ZERO;
    }
    let cache_key = WebCacheKey {
        query,
        web_limit,
        force_web,
        llm_model: normalize_cache_opt(llm_model),
        llm_agent: normalize_cache_opt(llm_agent),
    };
    let query_hash = phrase_cache_hash(&cache_key);
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
            debug: None,
            gate: build_gate_meta(
                gate,
                top_score,
                top_score_normalized,
                local_match_ratio,
                force_web,
            ),
        };
    }

    if cache_enabled && !query.trim().is_empty() {
        if let Some(layout) = cache::cache_layout_from_config() {
            if let Some(entry) = read_phrase_cache(&layout, &query_hash, config.cache_ttl) {
                if entry.url.trim().is_empty() {
                    // Ignore legacy phrase cache entries without a source URL.
                } else {
                    let result = WebFetchResult {
                        url: entry.url.clone(),
                        status: None,
                        fetched_at_epoch_ms: Some(entry.fetched_at_epoch_ms),
                        cached: true,
                        content: None,
                        ai_digested_content: Some(entry.ai_digested_content),
                        ai_digested_kind: Some(entry.ai_digested_kind),
                        relevance_score: Some(entry.relevance_score.unwrap_or(1.0)),
                        debug_html: None,
                        debug_dom_text: None,
                        error: None,
                        debug: None,
                    };
                    return WebDiscoveryStatus {
                        status: WebDiscoveryStatusCode::Served,
                        reason: Some("phrase_cache".to_string()),
                        message: Some("web discovery served from exact phrase cache".to_string()),
                        unavailable: None,
                        discovery: None,
                        fetches: Some(vec![result]),
                        debug: None,
                        gate: build_gate_meta(
                            gate,
                            top_score,
                            top_score_normalized,
                            local_match_ratio,
                            force_web,
                        ),
                    };
                }
            }
        }
    }

    if !gate.browser_available {
        let message = match gate.browser_hint.as_deref() {
            Some(hint) => format!("web browser not available: {hint}; run `docdexd browser setup`"),
            None => "web browser not available; run `docdexd browser setup`".to_string(),
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
            debug: None,
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
                debug: None,
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

    let debug_enabled = env_boolish("DOCDEX_WEB_DEBUG").unwrap_or(false);
    let (query_category, category_source) =
        classify_query_category(query, llm_model, llm_agent).await;

    let mut discovery_limit = (web_limit * WEB_DISCOVERY_MULTIPLIER)
        .max(web_limit)
        .max(WEB_DISCOVERY_MIN_RESULTS);
    discovery_limit = discovery_limit.min(config.max_results.max(web_limit));
    match discovery.discover(query, discovery_limit).await {
        Ok(response) => {
            let mut debug = Vec::new();
            if debug_enabled {
                debug.push(format!(
                    "query_category: {} ({})",
                    query_category.as_str(),
                    category_source.as_str()
                ));
            }
            let (mut discovery_response, mut urls) =
                normalize_discovery_response(response, &config, web_limit, query_category);
            if urls.is_empty() {
                debug.push(format!(
                    "discovery returned empty results for query: {}",
                    query
                ));
                if let Some(fallback_query) = simplify_discovery_query(query) {
                    if !fallback_query.eq_ignore_ascii_case(query) {
                        match discovery.discover(&fallback_query, discovery_limit).await {
                            Ok(fallback_response) => {
                                let normalized = normalize_discovery_response(
                                    fallback_response,
                                    &config,
                                    web_limit,
                                    query_category,
                                );
                                discovery_response = normalized.0;
                                urls = normalized.1;
                                debug.push(format!("fallback discovery query: {}", fallback_query));
                                if urls.is_empty() {
                                    debug.push(
                                        "fallback discovery returned empty results".to_string(),
                                    );
                                }
                            }
                            Err(err) => {
                                debug.push(format!("fallback discovery failed: {err}"));
                            }
                        }
                    }
                }
            }
            if urls.is_empty() {
                debug.push(format!(
                    "discovery query used: {}",
                    discovery_response.query
                ));
                return WebDiscoveryStatus {
                    status: WebDiscoveryStatusCode::Unavailable,
                    reason: Some("discovery_empty".to_string()),
                    message: Some("web discovery returned empty results".to_string()),
                    unavailable: None,
                    discovery: Some(discovery_response),
                    fetches: None,
                    debug: Some(debug),
                    gate: build_gate_meta(
                        gate,
                        top_score,
                        top_score_normalized,
                        local_match_ratio,
                        force_web,
                    ),
                };
            }
            discovery_response.results = urls
                .iter()
                .take(web_limit)
                .map(|url| WebDiscoveryResult { url: url.clone() })
                .collect();
            let fetches = fetch_web_documents(
                query,
                &query_hash,
                &urls,
                &config,
                web_limit,
                query_category,
                gate.trigger_threshold,
                llm_model,
                llm_agent,
            )
            .await;
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
                fetches: if fetches.is_empty() {
                    None
                } else {
                    Some(fetches)
                },
                debug: if debug.is_empty() { None } else { Some(debug) },
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
                debug: None,
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
    query_category: QueryCategory,
) -> (WebDiscoveryResponse, Vec<String>) {
    let mut urls = Vec::with_capacity(response.results.len());
    for result in response.results {
        let raw = result.url;
        let unwrapped = unwrap_ddg_redirect(&raw).unwrap_or(raw);
        urls.push(unwrapped);
    }
    let mut urls = dedupe_urls(urls);
    urls.retain(|value| is_allowed_url(value, &config.blocklist));
    urls.retain(|value| !is_tracking_url(value));
    sort_urls_for_category(&mut urls, query_category);
    let urls = enforce_domain_diversity(urls, WEB_MAX_RESULTS_PER_DOMAIN);
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

fn simplify_discovery_query(query: &str) -> Option<String> {
    let tokens = tokenize_terms(query);
    if tokens.is_empty() {
        return None;
    }
    let mut seen = HashSet::new();
    let mut kept = Vec::new();
    for token in tokens {
        if seen.insert(token.clone()) {
            kept.push(token);
        }
        if kept.len() >= WEB_DISCOVERY_MAX_QUERY_TOKENS {
            break;
        }
    }
    let simplified = kept.join(" ");
    let simplified = simplified.trim();
    if simplified.is_empty() {
        return None;
    }
    if simplified.eq_ignore_ascii_case(query.trim()) {
        return None;
    }
    Some(simplified.to_string())
}

fn enforce_domain_diversity(urls: Vec<String>, max_per_domain: usize) -> Vec<String> {
    if max_per_domain == 0 {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut counts = std::collections::HashMap::new();
    for url in urls {
        let host = match url::Url::parse(&url) {
            Ok(parsed) => parsed
                .host_str()
                .map(|value| value.trim().to_ascii_lowercase()),
            Err(_) => None,
        };
        let Some(host) = host else {
            continue;
        };
        if host.is_empty() {
            continue;
        }
        let entry = counts.entry(host).or_insert(0usize);
        if *entry >= max_per_domain {
            continue;
        }
        *entry += 1;
        out.push(url);
    }
    out
}

fn sort_urls_for_category(urls: &mut Vec<String>, category: QueryCategory) {
    if urls.len() < 2 || matches!(category, QueryCategory::General) {
        return;
    }
    let mut scored = Vec::with_capacity(urls.len());
    for (idx, url) in urls.iter().enumerate() {
        let score = score_url_for_category(url, category);
        scored.push((score, idx, url.clone()));
    }
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    *urls = scored.into_iter().map(|(_, _, url)| url).collect();
}

fn score_url_for_category(url: &str, category: QueryCategory) -> i32 {
    let url_lc = url.trim().to_ascii_lowercase();
    let parsed = url::Url::parse(&url_lc).ok();
    let host = parsed
        .as_ref()
        .and_then(|item| item.host_str())
        .unwrap_or("");
    let mut score = 0;
    match category {
        QueryCategory::CodeExample => {
            if url_contains_any(
                host,
                &[
                    "github.com",
                    "gitlab.com",
                    "bitbucket.org",
                    "gist.github.com",
                ],
            ) {
                score += 6;
            }
            if url_contains_any(
                &url_lc,
                &[
                    "example",
                    "examples",
                    "sample",
                    "snippet",
                    "code",
                    "repository",
                    "repo",
                ],
            ) {
                score += 3;
            }
            if url_contains_any(&url_lc, &["docs", "reference"]) {
                score -= 1;
            }
            if url_contains_any(&url_lc, &["blog", "news"]) {
                score -= 1;
            }
        }
        QueryCategory::ApiReference => {
            if url_contains_any(host, &["docs.", "developer.", "api."]) {
                score += 3;
            }
            if url_contains_any(&url_lc, &["/docs", "/reference", "/api", "sdk"]) {
                score += 2;
            }
            if url_contains_any(host, &["github.com", "gitlab.com"]) {
                score -= 1;
            }
        }
        QueryCategory::HowToGuide => {
            if url_contains_any(
                &url_lc,
                &[
                    "how-to",
                    "howto",
                    "tutorial",
                    "guide",
                    "walkthrough",
                    "getting-started",
                ],
            ) {
                score += 3;
            }
            if url_contains_any(&url_lc, &["blog", "learn", "academy"]) {
                score += 1;
            }
        }
        QueryCategory::ConceptDefinition => {
            if url_contains_any(
                &url_lc,
                &["overview", "introduction", "what-is", "concept", "glossary"],
            ) {
                score += 3;
            }
            if url_contains_any(&url_lc, &["docs", "reference"]) {
                score += 1;
            }
        }
        QueryCategory::Troubleshooting => {
            if url_contains_any(
                host,
                &["stackoverflow.com", "serverfault.com", "superuser.com"],
            ) {
                score += 4;
            }
            if url_contains_any(&url_lc, &["issue", "issues", "error", "fix", "debug"]) {
                score += 2;
            }
            if url_contains_any(&url_lc, &["github.com/issues", "gitlab.com/issues"]) {
                score += 2;
            }
        }
        QueryCategory::SpecStandard => {
            if url_contains_any(
                host,
                &["eips.ethereum.org", "rfc-editor.org", "ietf.org", "w3.org"],
            ) {
                score += 5;
            }
            if url_contains_any(&url_lc, &["spec", "standard", "eip-", "erc-", "rfc"]) {
                score += 2;
            }
        }
        QueryCategory::ComparisonOpinion => {
            if url_contains_any(
                &url_lc,
                &[
                    "compare",
                    "comparison",
                    "-vs-",
                    "/vs/",
                    "versus",
                    "best",
                    "top",
                ],
            ) {
                score += 3;
            }
            if url_contains_any(&url_lc, &["review", "pros", "cons", "alternatives"]) {
                score += 2;
            }
        }
        QueryCategory::NewsRelease => {
            if url_contains_any(
                &url_lc,
                &[
                    "blog",
                    "news",
                    "release",
                    "changelog",
                    "announcement",
                    "press",
                ],
            ) {
                score += 3;
            }
            if url_contains_any(&url_lc, &["/blog", "/news"]) {
                score += 1;
            }
        }
        QueryCategory::General => {}
    }
    score
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

fn url_contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn is_tracking_url(raw: &str) -> bool {
    let url = match url::Url::parse(raw) {
        Ok(url) => url,
        Err(_) => return true,
    };
    let host = url.host_str().unwrap_or("").trim().to_ascii_lowercase();
    if host.is_empty() {
        return true;
    }
    if let Some(query) = url.query() {
        if query.len() > 4 {
            for (_, value) in url.query_pairs() {
                let val = value.trim();
                if val.is_empty() {
                    continue;
                }
                let val_lc = val.to_ascii_lowercase();
                if val_lc.starts_with("http://")
                    || val_lc.starts_with("https://")
                    || val_lc.contains("http%3a")
                    || val_lc.contains("https%3a")
                {
                    return true;
                }
            }
        }
    }
    false
}

fn domain_quality_key(host: &str) -> String {
    format!("quality:{host}")
}

fn read_domain_quality(layout: &StateLayout, host: &str) -> Option<DomainQualityEntry> {
    let key = domain_quality_key(host);
    let ttl = Duration::from_secs(WEB_QUALITY_TTL_SECS);
    let payload = cache::read_cache_entry_with_ttl(layout, &key, ttl).ok()??;
    serde_json::from_slice(&payload).ok()
}

fn write_domain_quality(layout: &StateLayout, entry: &DomainQualityEntry) {
    if let Ok(payload) = serde_json::to_vec(entry) {
        let _ = cache::write_cache_entry(layout, &domain_quality_key(&entry.host), &payload);
    }
}

fn domain_in_cooldown(layout: &StateLayout, host: &str, now_ms: u64) -> Option<u64> {
    let entry = read_domain_quality(layout, host)?;
    if entry.cooldown_until_epoch_ms > now_ms {
        Some(entry.cooldown_until_epoch_ms)
    } else {
        None
    }
}

fn record_domain_failure(
    layout: Option<&StateLayout>,
    host: &str,
    kind: DomainFailureKind,
    now_ms: u64,
) {
    let layout = match layout {
        Some(layout) => layout,
        None => return,
    };
    let mut entry = read_domain_quality(layout, host).unwrap_or(DomainQualityEntry {
        host: host.to_string(),
        fail_count: 0,
        blocked_count: 0,
        challenge_count: 0,
        last_failure_epoch_ms: now_ms,
        cooldown_until_epoch_ms: 0,
    });
    match kind {
        DomainFailureKind::Fetch => {
            entry.fail_count = entry.fail_count.saturating_add(1);
        }
        DomainFailureKind::Blocked => {
            entry.blocked_count = entry.blocked_count.saturating_add(1);
        }
        DomainFailureKind::Challenge => {
            entry.challenge_count = entry.challenge_count.saturating_add(1);
        }
    }
    entry.last_failure_epoch_ms = now_ms;
    if entry.fail_count >= WEB_QUALITY_FAIL_THRESHOLD
        || entry.blocked_count >= WEB_QUALITY_BLOCK_THRESHOLD
        || entry.challenge_count >= WEB_QUALITY_CHALLENGE_THRESHOLD
    {
        entry.cooldown_until_epoch_ms = now_ms.saturating_add(WEB_QUALITY_COOLDOWN_SECS * 1000);
    }
    write_domain_quality(layout, &entry);
}

fn record_domain_success(layout: Option<&StateLayout>, host: &str) {
    let layout = match layout {
        Some(layout) => layout,
        None => return,
    };
    let mut entry = read_domain_quality(layout, host).unwrap_or(DomainQualityEntry {
        host: host.to_string(),
        fail_count: 0,
        blocked_count: 0,
        challenge_count: 0,
        last_failure_epoch_ms: 0,
        cooldown_until_epoch_ms: 0,
    });
    entry.fail_count = 0;
    entry.blocked_count = 0;
    entry.challenge_count = 0;
    entry.cooldown_until_epoch_ms = 0;
    write_domain_quality(layout, &entry);
}

fn classify_status_failure(status: Option<u16>) -> Option<DomainFailureKind> {
    match status {
        Some(401 | 403 | 429 | 451) => Some(DomainFailureKind::Blocked),
        Some(code) if code >= 500 => Some(DomainFailureKind::Fetch),
        Some(404 | 408) => Some(DomainFailureKind::Fetch),
        Some(code) if code >= 400 => Some(DomainFailureKind::Blocked),
        _ => None,
    }
}

fn hash_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

#[derive(Serialize)]
struct WebCacheKey<'a> {
    query: &'a str,
    web_limit: usize,
    force_web: bool,
    llm_model: Option<&'a str>,
    llm_agent: Option<&'a str>,
}

fn normalize_cache_opt(value: Option<&str>) -> Option<&str> {
    value.and_then(|raw| {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn phrase_cache_key(query_hash: &str) -> String {
    format!("phrase:{query_hash}")
}

fn phrase_cache_hash(key: &WebCacheKey<'_>) -> String {
    let payload = serde_json::to_string(key).unwrap_or_default();
    hash_text(&payload)
}

fn summary_cache_key(query_hash: &str, content_hash: &str) -> String {
    format!("summary:{query_hash}:{content_hash}")
}

fn summary_cache_entry(
    query_hash: &str,
    content_text: &str,
    code_blocks: &[String],
) -> (String, String) {
    let mut content_input = String::new();
    content_input.push_str(content_text);
    if !code_blocks.is_empty() {
        content_input.push_str("\n\n");
        content_input.push_str(&code_blocks.join("\n\n"));
    }
    let content_hash = hash_text(&content_input);
    (query_hash.to_string(), content_hash)
}

fn read_phrase_cache(
    layout: &StateLayout,
    query_hash: &str,
    ttl: Duration,
) -> Option<WebPhraseCacheEntry> {
    let key = phrase_cache_key(query_hash);
    let payload = cache::read_cache_entry_with_ttl(layout, &key, ttl).ok()??;
    serde_json::from_slice::<WebPhraseCacheEntry>(&payload).ok()
}

fn write_phrase_cache(layout: &StateLayout, query_hash: &str, entry: &WebPhraseCacheEntry) {
    if let Ok(payload) = serde_json::to_vec(entry) {
        let _ = cache::write_cache_entry(layout, &phrase_cache_key(query_hash), &payload);
    }
}

fn read_summary_cache(
    layout: &StateLayout,
    query_hash: &str,
    content_hash: &str,
    ttl: Duration,
) -> Option<WebEvalOutput> {
    if ttl.is_zero() {
        return None;
    }
    let key = summary_cache_key(query_hash, content_hash);
    let payload = cache::read_cache_entry_with_ttl(layout, &key, ttl).ok()??;
    let entry: WebSummaryCacheEntry = serde_json::from_slice(&payload).ok()?;
    if entry.query_hash != query_hash || entry.content_hash != content_hash {
        return None;
    }
    if entry.output.trim().is_empty() {
        return None;
    }
    Some(WebEvalOutput {
        relevance_score: entry.relevance_score.clamp(0.0, 1.0),
        kind: entry.kind,
        output: entry.output,
    })
}

fn write_summary_cache(
    layout: &StateLayout,
    query_hash: &str,
    content_hash: &str,
    evaluation: &WebEvalOutput,
) {
    let entry = WebSummaryCacheEntry {
        query_hash: query_hash.to_string(),
        content_hash: content_hash.to_string(),
        relevance_score: evaluation.relevance_score.clamp(0.0, 1.0),
        kind: evaluation.kind.clone(),
        output: evaluation.output.clone(),
    };
    if let Ok(payload) = serde_json::to_vec(&entry) {
        let _ = cache::write_cache_entry(
            layout,
            &summary_cache_key(query_hash, content_hash),
            &payload,
        );
    }
}

async fn fetch_web_documents(
    query: &str,
    query_hash: &str,
    urls: &[String],
    config: &WebConfig,
    target_count: usize,
    query_category: QueryCategory,
    early_stop_score: f32,
    llm_model: Option<&str>,
    llm_agent: Option<&str>,
) -> Vec<WebFetchResult> {
    if urls.is_empty() {
        return Vec::new();
    }
    let desired_count = target_count.max(1);
    let max_urls = resolve_fetch_url_limit(desired_count, urls.len());
    let urls = &urls[..max_urls];
    let direct_max_bytes = resolve_direct_fetch_max_bytes();
    let fetch_budget = resolve_web_fetch_budget(config, desired_count);
    let deadline = fetch_budget.map(|budget| Instant::now() + budget);
    let remaining_budget = |deadline: Option<Instant>| -> Option<Duration> {
        deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()))
    };
    let layout = cache::cache_layout_from_config();
    let summary_client = load_web_summary_client(llm_model, llm_agent);
    let debug_enabled = env_boolish("DOCDEX_WEB_DEBUG").unwrap_or(false);
    let early_stop_score = early_stop_score.clamp(0.0, 1.0);
    let scraper = match ScraperEngine::from_web_config(config) {
        Ok(scraper) => scraper,
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
                debug_html: None,
                debug_dom_text: None,
                error: Some(err.to_string()),
                debug: None,
            }];
        }
    };
    let boilerplate_phrases = &config.boilerplate_phrases;

    let mut all_results = Vec::new();
    let mut good_count = 0usize;
    let mut last_good: Option<WebFetchResult> = None;
    let mut budget_exhausted = false;
    'batch_loop: for batch in urls.chunks(WEB_BATCH_SIZE).take(WEB_MAX_BATCHES) {
        let mut batch_results = Vec::new();
        let mut early_stop_now = false;
        macro_rules! push_result {
            ($result:expr) => {{
                batch_results.push($result);
                if let Some(item) = batch_results.last() {
                    if early_stop_now {
                        all_results.clear();
                        all_results.push(item.clone());
                        break 'batch_loop;
                    }
                    if item.relevance_score.unwrap_or(0.0) >= WEB_GOOD_RELEVANCE_SCORE {
                        good_count += 1;
                        last_good = Some(item.clone());
                    }
                }
                if good_count >= desired_count {
                    if desired_count == 1 {
                        all_results.clear();
                        if let Some(best) = last_good.take() {
                            all_results.push(best);
                        }
                    } else {
                        all_results.extend(batch_results);
                    }
                    break 'batch_loop;
                }
            }};
        }
        for raw in batch {
            if let Some(remaining) = remaining_budget(deadline) {
                if remaining <= Duration::from_millis(WEB_FETCH_MIN_REMAINING_MS) {
                    if debug_enabled {
                        info!("web fetch budget exhausted; returning partial results");
                    }
                    budget_exhausted = true;
                    break;
                }
            }
            let url = match url::Url::parse(raw) {
                Ok(url) => url,
                Err(_) => continue,
            };
            if debug_enabled {
                info!("web fetch start url={}", url.as_str());
            }
            let host = match url.host_str() {
                Some(host) => host.trim().to_ascii_lowercase(),
                None => continue,
            };
            let cache_key = url.as_str();
            let mut cached = false;
            let mut fetched_at_epoch_ms = None;
            let mut status: Option<u16> = None;
            let mut content: Option<String> = None;
            let mut content_error: Option<String> = None;
            let mut skip_summary = false;
            let mut code_blocks: Vec<String> = Vec::new();
            let mut quality_scale = 1.0f32;
            let mut debug_notes: Vec<String> = Vec::new();
            let mut debug_html: Option<String> = None;
            let mut debug_dom_text: Option<String> = None;
            let intent = resolve_query_intent(query, query_category);

            if let Some(layout) = layout.as_ref() {
                if let Ok(Some(payload)) =
                    cache::read_cache_entry_with_ttl(layout, cache_key, config.cache_ttl)
                {
                    if let Ok(entry) = serde_json::from_slice::<WebFetchCacheEntry>(&payload) {
                        cached = true;
                        fetched_at_epoch_ms = Some(entry.fetched_at_epoch_ms);
                        status = entry.status;
                        content = Some(normalize_text_spacing(&entry.content));
                        code_blocks = entry.code_blocks;
                        tighten_code_blocks_for_category(query_category, &mut code_blocks);
                        if debug_enabled {
                            info!("web fetch cache hit url={}", url.as_str());
                        }
                    }
                }
            }

            if content.is_none() {
                let now_ms = now_epoch_ms_u64();
                if let Some(layout) = layout.as_ref() {
                    if let Some(until_ms) = domain_in_cooldown(layout, &host, now_ms) {
                        if debug_enabled {
                            info!(
                                "web fetch skipped cooldown url={} until={}",
                                url.as_str(),
                                until_ms
                            );
                        }
                        push_result!(WebFetchResult {
                            url: url.to_string(),
                            status: None,
                            fetched_at_epoch_ms: None,
                            cached: false,
                            content: None,
                            ai_digested_content: None,
                            ai_digested_kind: None,
                            relevance_score: None,
                            debug_html: debug_html.clone(),
                            debug_dom_text: debug_dom_text.clone(),
                            error: Some(format!(
                                "web fetch skipped for host cooldown until {until_ms}"
                            )),
                            debug: None,
                        });
                        continue;
                    }
                }
                crate::web::fetch::enforce_domain_delay(&url, config.fetch_delay).await;
                fetched_at_epoch_ms = Some(now_epoch_ms());
                let status_timeout = match remaining_budget(deadline) {
                    Some(remaining) => config.request_timeout.min(remaining),
                    None => config.request_timeout,
                };
                if status_timeout <= Duration::from_millis(WEB_FETCH_MIN_REMAINING_MS) {
                    budget_exhausted = true;
                    break;
                }
                let status_probe = fetch_status(&url, &config.user_agent, status_timeout).await;
                if should_skip_status(status_probe) {
                    if debug_enabled {
                        info!(
                            "web fetch skipped preflight url={} status={:?}",
                            url.as_str(),
                            status_probe
                        );
                    }
                    push_result!(WebFetchResult {
                        url: url.to_string(),
                        status: status_probe,
                        fetched_at_epoch_ms,
                        cached: false,
                        content: None,
                        ai_digested_content: None,
                        ai_digested_kind: None,
                        relevance_score: None,
                        debug_html: debug_html.clone(),
                        debug_dom_text: debug_dom_text.clone(),
                        error: Some("web fetch skipped due to preflight status".to_string()),
                        debug: None,
                    });
                    continue;
                }
                let dom_timeout = match remaining_budget(deadline) {
                    Some(remaining) => config.page_load_timeout.min(remaining),
                    None => config.page_load_timeout,
                };
                if dom_timeout <= Duration::from_millis(WEB_FETCH_MIN_REMAINING_MS) {
                    budget_exhausted = true;
                    break;
                }
                let mut dom_result = if deadline.is_some() {
                    match tokio::time::timeout(dom_timeout, scraper.fetch_dom(&url)).await {
                        Ok(result) => result,
                        Err(_) => Err(anyhow!("web fetch timed out")),
                    }
                } else {
                    scraper.fetch_dom(&url).await
                };
                if dom_result.is_err() {
                    let direct_timeout = match remaining_budget(deadline) {
                        Some(remaining) => config.request_timeout.min(remaining),
                        None => config.request_timeout,
                    };
                    if direct_timeout > Duration::from_millis(WEB_FETCH_MIN_REMAINING_MS) {
                        if let Ok(direct_result) = fetch_dom_direct(
                            &url,
                            &config.user_agent,
                            direct_timeout,
                            direct_max_bytes,
                        )
                        .await
                        {
                            dom_result = Ok(direct_result);
                        }
                    }
                }
                match dom_result {
                    Ok(fetch_result) => {
                        status = fetch_result.status.or(status_probe);
                        let html = fetch_result.html;
                        let readable_opt = extract_readable_text(&html, &url);
                        if debug_enabled {
                            info!("web fetch dom ok url={} status={:?}", url.as_str(), status);
                        }
                        if debug_enabled {
                            debug_html = Some(truncate_debug_html(&html));
                            if let Some(readable) = readable_opt.as_ref() {
                                debug_dom_text = Some(truncate_debug_text(readable));
                            }
                        }
                        if debug_enabled {
                            if let Some(final_url) = fetch_result.final_url.as_ref() {
                                if final_url == "about:blank" {
                                    debug_notes.push(
                                        "browser navigation stayed on about:blank".to_string(),
                                    );
                                }
                            } else {
                                debug_notes.push("browser final_url missing".to_string());
                            }
                        }
                        code_blocks = extract_code_blocks(&html);
                        let ad_markers = count_ad_markers(&html);
                        let formatted_html = format_html_text(&html);
                        if debug_enabled {
                            if readable_opt.is_some() {
                                debug_notes.push("used readability content".to_string());
                            } else if !formatted_html.trim().is_empty() {
                                debug_notes.push("readability failed; using html2text".to_string());
                            } else {
                                debug_notes
                                    .push("readability failed; using html tag strip".to_string());
                            }
                        }
                        let mut readable = if let Some(readable) = readable_opt {
                            readable
                        } else if !formatted_html.trim().is_empty() {
                            formatted_html
                        } else {
                            clean_web_text(&html)
                        };
                        readable = normalize_text_spacing(&readable);
                        if is_cookie_wall(&html, &readable) {
                            record_domain_failure(
                                layout.as_ref(),
                                &host,
                                DomainFailureKind::Challenge,
                                now_ms,
                            );
                            if debug_enabled {
                                debug_notes.push("cookie wall detected".to_string());
                                info!("web fetch blocked by cookie wall url={}", url.as_str());
                            }
                            push_result!(WebFetchResult {
                                url: url.to_string(),
                                status,
                                fetched_at_epoch_ms,
                                cached: false,
                                content: None,
                                ai_digested_content: None,
                                ai_digested_kind: None,
                                relevance_score: None,
                                debug_html: debug_html.clone(),
                                debug_dom_text: debug_dom_text.clone(),
                                error: Some("web fetch blocked by cookie wall".to_string()),
                                debug: if debug_enabled && !debug_notes.is_empty() {
                                    Some(debug_notes.clone())
                                } else {
                                    None
                                },
                            });
                            continue;
                        }
                        if is_js_challenge(&html, &readable) {
                            record_domain_failure(
                                layout.as_ref(),
                                &host,
                                DomainFailureKind::Challenge,
                                now_ms,
                            );
                            if debug_enabled {
                                debug_notes.push(
                                    "js challenge detected (multiple signals + short text)"
                                        .to_string(),
                                );
                                info!("web fetch blocked by js challenge url={}", url.as_str());
                            }
                            push_result!(WebFetchResult {
                                url: url.to_string(),
                                status,
                                fetched_at_epoch_ms,
                                cached: false,
                                content: None,
                                ai_digested_content: None,
                                ai_digested_kind: None,
                                relevance_score: None,
                                debug_html: debug_html.clone(),
                                debug_dom_text: debug_dom_text.clone(),
                                error: Some("web fetch blocked by JS challenge".to_string()),
                                debug: if debug_enabled && !debug_notes.is_empty() {
                                    Some(debug_notes.clone())
                                } else {
                                    None
                                },
                            });
                            continue;
                        }
                        let banner_result = strip_banner_lines(&readable);
                        if banner_result.removed_lines > 0 && debug_enabled {
                            debug_notes.push(format!(
                                "banner lines removed: {}/{}",
                                banner_result.removed_lines, banner_result.total_lines
                            ));
                        }
                        let banner_only = is_banner_only(&banner_result);
                        let mut readable = banner_result.filtered;
                        if banner_only {
                            if debug_enabled {
                                debug_notes.push("content appears to be banner-only".to_string());
                            }
                            content_error = Some("banner-only".to_string());
                            content = None;
                        } else {
                            if debug_enabled && readable.trim().is_empty() {
                                debug_notes
                                    .push("text extraction empty after fallback".to_string());
                            }
                            let boiler_ratio = boilerplate_ratio(&readable, boilerplate_phrases);
                            let mut penalty = quality_penalty(boiler_ratio, ad_markers);
                            if penalty == 0.0
                                && matches!(intent, QueryIntent::Code)
                                && !code_blocks.is_empty()
                            {
                                penalty = 0.35;
                                if debug_enabled {
                                    debug_notes.push(
                                        "boilerplate penalty softened due to code blocks"
                                            .to_string(),
                                    );
                                }
                            }
                            if penalty == 0.0 {
                                if debug_enabled {
                                    info!("web fetch skipped boilerplate url={}", url.as_str());
                                }
                                push_result!(WebFetchResult {
                                    url: url.to_string(),
                                    status: status_probe,
                                    fetched_at_epoch_ms,
                                    cached: false,
                                    content: None,
                                    ai_digested_content: None,
                                    ai_digested_kind: None,
                                    relevance_score: None,
                                    debug_html: debug_html.clone(),
                                    debug_dom_text: debug_dom_text.clone(),
                                    error: Some(
                                        "web fetch skipped due to boilerplate noise".to_string()
                                    ),
                                    debug: None,
                                });
                                continue;
                            }
                            quality_scale = penalty;
                            let filtered =
                                filter_boilerplate_text(query, &readable, boilerplate_phrases);
                            readable = if filtered.trim().is_empty() {
                                readable
                            } else {
                                filtered
                            };
                            if matches!(intent, QueryIntent::Code) && code_blocks.is_empty() {
                                let fallback_blocks = extract_probable_code_blocks(&readable);
                                if !fallback_blocks.is_empty() {
                                    if debug_enabled {
                                        debug_notes.push(format!(
                                            "code fallback extracted {} block(s)",
                                            fallback_blocks.len()
                                        ));
                                    }
                                    code_blocks = fallback_blocks;
                                }
                            }
                            tighten_code_blocks_for_category(query_category, &mut code_blocks);
                            let trimmed = truncate_content_output(&readable);
                            if trimmed.trim().is_empty() {
                                if debug_enabled {
                                    debug_notes
                                        .push("extracted text empty after cleanup".to_string());
                                }
                                content = None;
                            } else {
                                let char_count = trimmed.chars().count();
                                let word_count = trimmed.split_whitespace().count();
                                let allow_short =
                                    matches!(intent, QueryIntent::Code) && !code_blocks.is_empty();
                                if !allow_short
                                    && char_count < WEB_MIN_CONTENT_CHARS
                                    && word_count < WEB_MIN_CONTENT_WORDS
                                {
                                    skip_summary = true;
                                    content_error = Some("low_content".to_string());
                                    if debug_enabled {
                                        debug_notes.push(format!(
                                            "low content: {char_count} chars, {word_count} words"
                                        ));
                                    }
                                }
                                content = Some(trimmed);
                            }
                        }
                    }
                    Err(err) => {
                        let failure_kind = classify_status_failure(status_probe)
                            .unwrap_or(DomainFailureKind::Fetch);
                        record_domain_failure(layout.as_ref(), &host, failure_kind, now_ms);
                        if debug_enabled {
                            info!(
                                "web fetch failed url={} status={:?} err={}",
                                url.as_str(),
                                status_probe,
                                err
                            );
                        }
                        push_result!(WebFetchResult {
                            url: url.to_string(),
                            status: status_probe,
                            fetched_at_epoch_ms,
                            cached: false,
                            content: None,
                            ai_digested_content: None,
                            ai_digested_kind: None,
                            relevance_score: None,
                            debug_html: debug_html.clone(),
                            debug_dom_text: debug_dom_text.clone(),
                            error: Some(format!("web fetch failed: {err}")),
                            debug: None,
                        });
                        continue;
                    }
                };
            }

            let Some(content_text) = content.as_ref() else {
                let empty_error = content_error
                    .clone()
                    .unwrap_or_else(|| "content empty".to_string());
                push_result!(WebFetchResult {
                    url: url.to_string(),
                    status,
                    fetched_at_epoch_ms,
                    cached,
                    content: Some(String::new()),
                    ai_digested_content: None,
                    ai_digested_kind: None,
                    relevance_score: Some(0.0),
                    debug_html: debug_html.clone(),
                    debug_dom_text: debug_dom_text.clone(),
                    error: Some(empty_error),
                    debug: if debug_enabled && !debug_notes.is_empty() {
                        Some(debug_notes.clone())
                    } else {
                        None
                    },
                });
                continue;
            };

            if !skip_summary {
                let char_count = content_text.chars().count();
                let word_count = content_text.split_whitespace().count();
                let allow_short = matches!(intent, QueryIntent::Code) && !code_blocks.is_empty();
                if !allow_short
                    && char_count < WEB_MIN_CONTENT_CHARS
                    && word_count < WEB_MIN_CONTENT_WORDS
                {
                    skip_summary = true;
                    content_error = Some("low_content".to_string());
                    if debug_enabled {
                        debug_notes.push(format!(
                            "low content (post-cache): {char_count} chars, {word_count} words"
                        ));
                    }
                }
            }

            if !skip_summary {
                if let Some(remaining) = remaining_budget(deadline) {
                    if remaining <= Duration::from_millis(WEB_SUMMARY_TIMEOUT_MS / 2) {
                        skip_summary = true;
                        content_error = Some("summary_budget_exhausted".to_string());
                        if debug_enabled {
                            debug_notes.push("summary skipped (budget)".to_string());
                        }
                    }
                }
            }

            if skip_summary {
                let error = content_error
                    .clone()
                    .unwrap_or_else(|| "low_content".to_string());
                push_result!(WebFetchResult {
                    url: url.to_string(),
                    status,
                    fetched_at_epoch_ms,
                    cached,
                    content: Some(content_text.clone()),
                    ai_digested_content: None,
                    ai_digested_kind: None,
                    relevance_score: Some(0.0),
                    debug_html: debug_html.clone(),
                    debug_dom_text: debug_dom_text.clone(),
                    error: Some(error),
                    debug: if debug_enabled && !debug_notes.is_empty() {
                        Some(debug_notes.clone())
                    } else {
                        None
                    },
                });
                continue;
            }

            let allow_code_summary = matches!(intent, QueryIntent::Code)
                || matches!(query_category, QueryCategory::CodeExample);
            let summary_blocks: Vec<String> = if allow_code_summary {
                code_blocks.clone()
            } else {
                Vec::new()
            };
            let (summary_query_hash, content_hash) =
                summary_cache_entry(query_hash, content_text, &summary_blocks);
            let cached_summary = layout.as_ref().and_then(|layout| {
                read_summary_cache(layout, &summary_query_hash, &content_hash, config.cache_ttl)
            });
            let used_cached_summary = cached_summary.is_some();
            let llm_available = summary_client.is_some();
            let evaluation = if let Some(summary) = cached_summary {
                Some(summary)
            } else if let Some(summary_client) = summary_client.as_ref() {
                if let Some(remaining) = remaining_budget(deadline) {
                    match tokio::time::timeout(
                        remaining,
                        summary_client.evaluate(
                            query,
                            query_category,
                            content_text,
                            &summary_blocks,
                        ),
                    )
                    .await
                    {
                        Ok(result) => result,
                        Err(_) => None,
                    }
                } else {
                    summary_client
                        .evaluate(query, query_category, content_text, &summary_blocks)
                        .await
                }
            } else {
                None
            };

            let evaluation = match evaluation {
                Some(value) => value,
                None => {
                    let wants_code = matches!(intent, QueryIntent::Code)
                        || matches!(query_category, QueryCategory::CodeExample);
                    if wants_code && !code_blocks.is_empty() {
                        let selected = select_best_code_block(query, &code_blocks)
                            .unwrap_or_else(|| code_blocks.join("\n\n"));
                        WebEvalOutput {
                            relevance_score: 0.5,
                            kind: "code".to_string(),
                            output: selected,
                        }
                    } else {
                        WebEvalOutput {
                            relevance_score: 0.0,
                            kind: "summary".to_string(),
                            output: if llm_available {
                                String::new()
                            } else {
                                clean_summary_text(content_text)
                            },
                        }
                    }
                }
            };
            let formatted_output = format_md_output(&evaluation.kind, &evaluation.output);
            let mut ai_kind = evaluation.kind.clone();
            let mut summary_error = None;
            let mut ai_digested_content = if formatted_output.trim().is_empty() {
                None
            } else {
                Some(formatted_output)
            };
            if ai_kind == "code" {
                if let Some(output) = ai_digested_content.as_ref() {
                    if !looks_like_code_output(output) {
                        ai_digested_content = None;
                    }
                } else {
                    ai_digested_content = None;
                }
            }
            if ai_digested_content.is_none() {
                if matches!(intent, QueryIntent::Code) && !code_blocks.is_empty() {
                    let selected = select_best_code_block(query, &code_blocks)
                        .unwrap_or_else(|| code_blocks.join("\n\n"));
                    let fallback_code = format_md_output("code", &selected);
                    if !fallback_code.trim().is_empty() {
                        ai_kind = "code".to_string();
                        ai_digested_content = Some(fallback_code);
                    }
                }
            }
            if ai_digested_content.is_none() {
                let fallback = clean_summary_text(content_text);
                if !fallback.trim().is_empty() {
                    ai_kind = "summary".to_string();
                    ai_digested_content = Some(fallback);
                } else {
                    summary_error = Some("summary empty".to_string());
                }
            }
            let ai_digested_kind = ai_digested_content.as_ref().map(|_| ai_kind.clone());
            let debug = if debug_enabled && !debug_notes.is_empty() {
                Some(debug_notes.clone())
            } else {
                None
            };

            if !cached {
                if let Some(layout) = layout.as_ref() {
                    if config.cache_ttl.as_secs() > 0 {
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

            if !used_cached_summary {
                if let Some(layout) = layout.as_ref() {
                    if config.cache_ttl.as_secs() > 0 {
                        write_summary_cache(
                            layout,
                            &summary_query_hash,
                            &content_hash,
                            &evaluation,
                        );
                    }
                }
            }

            let match_stats = web_match_stats(query, content_text, &code_blocks);
            let mut relevance_score =
                (blend_relevance_score(evaluation.relevance_score, &match_stats) * quality_scale)
                    .clamp(0.0, 1.0);
            if matches!(intent, QueryIntent::Code) {
                let code_score = code_block_score(&code_blocks);
                if code_score > 0.0 {
                    relevance_score = (relevance_score + (0.15 * code_score)).clamp(0.0, 1.0);
                    if ai_kind == "code" {
                        relevance_score = (relevance_score + 0.05).clamp(0.0, 1.0);
                    }
                } else if ai_kind != "code" {
                    relevance_score = (relevance_score * 0.8).clamp(0.0, 1.0);
                }
            } else if matches!(intent, QueryIntent::Definition) {
                if ai_kind == "summary" {
                    relevance_score = (relevance_score + 0.05).clamp(0.0, 1.0);
                } else {
                    relevance_score = (relevance_score * 0.8).clamp(0.0, 1.0);
                }
            } else if ai_kind == "code" {
                relevance_score = (relevance_score * 0.9).clamp(0.0, 1.0);
            }
            let category_multiplier =
                category_relevance_multiplier(query_category, &url, &code_blocks, &ai_kind);
            relevance_score = (relevance_score * category_multiplier).clamp(0.0, 1.0);
            let has_content = ai_digested_content
                .as_ref()
                .map(|value| !value.trim().is_empty())
                .unwrap_or(false)
                || !content_text.trim().is_empty();
            early_stop_now = should_stop_early(
                desired_count,
                relevance_score,
                &match_stats,
                query_category,
                &ai_kind,
                has_content,
                early_stop_score,
            );
            if debug_enabled && early_stop_now {
                info!(
                    "web fetch early stop url={} score={:.3}",
                    url.as_str(),
                    relevance_score
                );
            }
            record_domain_success(layout.as_ref(), &host);
            push_result!(WebFetchResult {
                url: url.to_string(),
                status,
                fetched_at_epoch_ms,
                cached,
                content: Some(content_text.clone()),
                ai_digested_content,
                ai_digested_kind,
                relevance_score: Some(relevance_score),
                debug_html,
                debug_dom_text,
                error: summary_error,
                debug,
            });
        }

        if !batch_results.is_empty() {
            all_results.extend(batch_results);
            if good_count >= desired_count {
                break;
            }
        }
        if budget_exhausted {
            break;
        }
    }

    if all_results.is_empty() {
        return Vec::new();
    }
    all_results.sort_by(|a, b| {
        b.relevance_score
            .unwrap_or(0.0)
            .partial_cmp(&a.relevance_score.unwrap_or(0.0))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    if let Some(best) = all_results.first() {
        if !config.cache_ttl.is_zero() && !query.trim().is_empty() {
            if let (Some(content), Some(kind)) = (
                best.ai_digested_content.as_ref(),
                best.ai_digested_kind.as_ref(),
            ) {
                if let Some(layout) = cache::cache_layout_from_config() {
                    let fetched_at_epoch_ms = best.fetched_at_epoch_ms.unwrap_or_else(now_epoch_ms);
                    let entry = WebPhraseCacheEntry {
                        query_hash: query_hash.to_string(),
                        fetched_at_epoch_ms,
                        ai_digested_kind: kind.clone(),
                        ai_digested_content: content.clone(),
                        url: best.url.clone(),
                        relevance_score: best.relevance_score,
                    };
                    write_phrase_cache(&layout, query_hash, &entry);
                }
            }
        }
        if best.relevance_score.unwrap_or(0.0) >= early_stop_score {
            all_results.truncate(1);
            return all_results;
        }
    }
    if all_results.len() > desired_count {
        all_results.truncate(desired_count);
    }
    all_results
}

async fn fetch_dom_direct(
    url: &Url,
    user_agent: &str,
    timeout: Duration,
    max_bytes: usize,
) -> Result<ChromeFetchResult, anyhow::Error> {
    if timeout.is_zero() {
        return Err(anyhow!("direct fetch timeout is zero"));
    }
    let client = reqwest::Client::builder()
        .user_agent(user_agent.to_string())
        .timeout(timeout)
        .build()
        .context("build direct fetch client")?;
    let resp = client
        .get(url.clone())
        .header(
            ACCEPT,
            HeaderValue::from_static(
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            ),
        )
        .header(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"))
        .send()
        .await
        .context("direct fetch request failed")?;
    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow!("direct fetch failed with status {status}"));
    }
    let content_type = resp
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let content_type_lc = content_type.to_ascii_lowercase();
    if !content_type_lc.is_empty()
        && !content_type_lc.contains("html")
        && !content_type_lc.starts_with("text/")
    {
        return Err(anyhow!(
            "direct fetch unsupported content-type {content_type}"
        ));
    }
    if let Some(len) = resp.content_length() {
        if len as usize > max_bytes {
            return Err(anyhow!(
                "direct fetch content-length {len} exceeds max {max_bytes}"
            ));
        }
    }
    let final_url = resp.url().to_string();
    let bytes = resp.bytes().await.context("read direct fetch body")?;
    if bytes.len() > max_bytes {
        return Err(anyhow!(
            "direct fetch body size {} exceeds max {max_bytes}",
            bytes.len()
        ));
    }
    let html = String::from_utf8_lossy(&bytes).to_string();
    if html.trim().is_empty() {
        return Err(anyhow!("direct fetch returned empty body"));
    }
    Ok(ChromeFetchResult {
        html,
        inner_text: None,
        text_content: None,
        status: Some(status.as_u16()),
        final_url: Some(final_url),
    })
}

fn clean_web_text(html: &str) -> String {
    let cleaned = format_html_text(html);
    normalize_text_spacing(&cleaned)
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn format_html_text(html: &str) -> String {
    let cleaned = ammonia::clean(html);
    if cleaned.trim().is_empty() {
        return String::new();
    }
    html2text::from_read(cleaned.as_bytes(), WEB_HTML2TEXT_WRAP_COLS).unwrap_or_default()
}

fn truncate_debug_html(html: &str) -> String {
    let limit = env_usize("DOCDEX_WEB_DEBUG_HTML_MAX_CHARS").unwrap_or(0);
    if limit == 0 {
        return html.to_string();
    }
    let (snippet, _) = truncate_utf8_chars(html, limit.max(1));
    snippet
}

fn truncate_debug_text(text: &str) -> String {
    let limit = env_usize("DOCDEX_WEB_DEBUG_TEXT_MAX_CHARS").unwrap_or(0);
    if limit == 0 {
        return text.to_string();
    }
    let (snippet, _) = truncate_utf8_chars(text, limit.max(1));
    snippet
}

fn truncate_summary_input(text: &str) -> String {
    let limit = env_usize("DOCDEX_WEB_SUMMARY_INPUT_MAX_CHARS")
        .unwrap_or(DEFAULT_WEB_SUMMARY_INPUT_MAX_CHARS);
    if limit == 0 {
        return text.to_string();
    }
    let (snippet, _) = truncate_utf8_chars(text, limit.max(1));
    snippet
}

fn truncate_content_output(text: &str) -> String {
    let limit = env_usize("DOCDEX_WEB_CONTENT_MAX_CHARS").unwrap_or(0);
    if limit == 0 {
        return text.to_string();
    }
    let (snippet, _) = truncate_utf8_chars(text, limit.max(1));
    snippet
}

fn normalize_text_spacing(text: &str) -> String {
    let mut lines = Vec::new();
    for line in text.lines() {
        let stripped = ANSI_ESCAPE_RE.replace_all(line, "");
        let trimmed = strip_invisible_chars(stripped.as_ref()).trim().to_string();
        let trimmed = trimmed.as_str();
        if trimmed.is_empty() {
            lines.push(String::new());
            continue;
        }
        let mut updated = trimmed.to_string();
        updated = TAG_ATTR_JOIN_RE
            .replace_all(&updated, "$1 $2$3")
            .to_string();
        updated = HEADING_JOIN_RE.replace_all(&updated, "$1\n#$2").to_string();
        updated = COLON_JOIN_RE.replace_all(&updated, "$1 $2").to_string();
        updated = COMMA_JOIN_RE.replace_all(&updated, "$1 $2").to_string();
        updated = LABEL_JOIN_RE.replace_all(&updated, "$1 $2").to_string();
        updated = TLD_JOIN_RE.replace_all(&updated, ".$1 $2").to_string();
        updated = BRACKET_LEFT_JOIN_RE
            .replace_all(&updated, "$1 [")
            .to_string();
        updated = BRACKET_RIGHT_JOIN_RE
            .replace_all(&updated, "] $1")
            .to_string();
        updated = LOWER_JOIN_STOPWORD_RE
            .replace_all(&updated, "$1 $2 $3")
            .to_string();
        updated = TITLE_AND_JOIN_RE
            .replace_all(&updated, "$1 and$2")
            .to_string();
        updated = AND_JOIN_RE.replace_all(&updated, "$1 and $2").to_string();
        updated = AND_LOWER_JOIN_RE
            .replace_all(&updated, "$1 and $2")
            .to_string();
        updated = PREFIX_COMMON_JOIN_RE
            .replace_all(&updated, "$1 $2")
            .to_string();
        updated = LONG_JOIN_RE.replace_all(&updated, "$1 $2 $3").to_string();
        updated = LOWER_UPPER_JOIN_RE
            .replace_all(&updated, "$1 $2")
            .to_string();
        updated = CAPITAL_JOIN_RE.replace_all(&updated, "$1 $2").to_string();
        updated = WORD_METHOD_JOIN_RE
            .replace_all(&updated, "$1 $2")
            .to_string();
        updated = PAREN_WORD_JOIN_RE
            .replace_all(&updated, "$1 $2")
            .to_string();
        updated = PUNCT_JOIN_RE.replace_all(&updated, "$1 $2").to_string();
        updated = ALLCAPS_JOIN_RE.replace_all(&updated, "$1 $2").to_string();
        updated = CAMEL_BREAK_RE.replace_all(&updated, "$1 $2").to_string();
        if looks_codeish(&updated) {
            updated = CODE_KEYWORD_JOIN_RE
                .replace_all(&updated, "$1 $2")
                .to_string();
        }
        let normalized = updated.split_whitespace().collect::<Vec<_>>().join(" ");
        if is_strict_code_line(trimmed) {
            lines.push(trimmed.to_string());
        } else {
            let fixed = if looks_codeish(&updated) {
                normalized
            } else {
                rejoin_split_words(&normalized)
            };
            lines.push(fixed);
        }
    }
    lines.join("\n")
}

fn strip_invisible_chars(text: &str) -> String {
    text.replace('\u{200B}', "")
        .replace('\u{200C}', "")
        .replace('\u{200D}', "")
        .replace('\u{FEFF}', "")
        .replace('\u{00AD}', "")
}

fn rejoin_split_words(line: &str) -> String {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 3 {
        return line.to_string();
    }
    let mut out: Vec<String> = Vec::with_capacity(tokens.len());
    let mut i = 0usize;
    while i < tokens.len() {
        if i + 2 < tokens.len() {
            let prev = tokens[i];
            let mid = tokens[i + 1];
            let next = tokens[i + 2];
            if should_rejoin_split(prev, mid, next) {
                out.push(format!("{prev}{mid}{next}"));
                i += 3;
                continue;
            }
        }
        out.push(tokens[i].to_string());
        i += 1;
    }
    out.join(" ")
}

fn should_rejoin_split(prev: &str, mid: &str, next: &str) -> bool {
    if prev.len() < 3 || next.len() < 3 || mid.len() > 2 {
        return false;
    }
    if !(is_lower_word_token(prev) && is_lower_word_token(mid) && is_lower_word_token(next)) {
        return false;
    }
    if is_common_stopword(prev) || is_common_stopword(next) {
        return false;
    }
    let combined_len = prev.len() + mid.len() + next.len();
    combined_len >= 8
}

fn is_lower_word_token(token: &str) -> bool {
    !token.is_empty() && token.chars().all(|ch| ch.is_ascii_lowercase())
}

fn is_common_stopword(token: &str) -> bool {
    matches!(
        token,
        "the"
            | "and"
            | "of"
            | "in"
            | "to"
            | "for"
            | "by"
            | "with"
            | "as"
            | "on"
            | "at"
            | "from"
            | "is"
            | "are"
            | "was"
            | "were"
            | "be"
            | "been"
            | "it"
            | "its"
            | "this"
            | "that"
            | "these"
            | "those"
            | "a"
            | "an"
            | "or"
            | "but"
            | "if"
            | "than"
            | "then"
            | "so"
            | "while"
            | "when"
    )
}

fn looks_codeish(text: &str) -> bool {
    text.contains('=')
        || text.contains(';')
        || text.contains('{')
        || text.contains('}')
        || text.contains("()")
        || text.contains("=>")
        || text.contains("->")
}

fn is_probable_code_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.starts_with("```") {
        return true;
    }
    if trimmed.starts_with("//") {
        return true;
    }
    if trimmed.starts_with("/**") || trimmed.starts_with("///") || trimmed.starts_with("/*") {
        return true;
    }
    let symbols = ['{', '}', ';', '=', '<', '>', '[', ']', '(', ')'];
    let symbol_hits = trimmed.chars().filter(|ch| symbols.contains(ch)).count();
    let leading_ws = line.len().saturating_sub(line.trim_start().len());
    if symbol_hits >= 2 {
        return true;
    }
    if leading_ws >= 2 && symbol_hits >= 1 {
        return true;
    }
    trimmed.contains("::") || trimmed.contains("->") || trimmed.contains("=>")
}

fn is_strict_code_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.starts_with("```") || trimmed.starts_with("#!") {
        return true;
    }
    let symbols = ['{', '}', ';', '=', '<', '>', '[', ']', '(', ')'];
    let symbol_hits = trimmed.chars().filter(|ch| symbols.contains(ch)).count();
    let hard_symbols = ['{', '}', ';', '=', '<', '>'];
    let hard_hits = trimmed
        .chars()
        .filter(|ch| hard_symbols.contains(ch))
        .count();
    let len = trimmed.len();
    if hard_hits >= 1 && symbol_hits >= 3 {
        return true;
    }
    if (symbol_hits >= 6 && len <= 120) || (symbol_hits >= 4 && len <= 60) {
        return true;
    }
    trimmed.contains("::") || trimmed.contains("->") || trimmed.contains("=>")
}

fn extract_code_blocks(html: &str) -> Vec<String> {
    let formatted = format_html_text(html);
    extract_probable_code_blocks(&formatted)
}

fn extract_probable_code_blocks(text: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut seen = HashSet::new();
    let mut current = Vec::new();
    let mut code_lines = 0usize;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !current.is_empty() {
                if code_lines >= 2 || block_has_code_shape(&current) {
                    let joined = current.join("\n");
                    push_code_block(&mut blocks, &mut seen, &joined, true);
                    if blocks.len() >= MAX_CODE_BLOCKS {
                        return blocks;
                    }
                }
                current.clear();
                code_lines = 0;
            }
            continue;
        }
        if is_probable_code_line(trimmed) {
            code_lines += 1;
            current.push(trimmed.to_string());
        } else if !current.is_empty() {
            if code_lines >= 2 || block_has_code_shape(&current) {
                let joined = current.join("\n");
                push_code_block(&mut blocks, &mut seen, &joined, true);
                if blocks.len() >= MAX_CODE_BLOCKS {
                    return blocks;
                }
            }
            current.clear();
            code_lines = 0;
        }
    }
    if !current.is_empty() && (code_lines >= 2 || block_has_code_shape(&current)) {
        let joined = current.join("\n");
        push_code_block(&mut blocks, &mut seen, &joined, true);
        if blocks.len() >= MAX_CODE_BLOCKS {
            return blocks;
        }
    }
    blocks
}

fn block_has_code_shape(lines: &[String]) -> bool {
    let mut symbol_hits = 0usize;
    let mut total_chars = 0usize;
    let mut indented = 0usize;
    for line in lines {
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        total_chars += trimmed.len();
        if line.len() > trimmed.len() + 1 {
            indented += 1;
        }
        for ch in trimmed.chars() {
            if matches!(
                ch,
                '{' | '}' | ';' | '=' | '<' | '>' | '[' | ']' | '(' | ')' | ':' | ','
            ) {
                symbol_hits += 1;
            }
        }
    }
    if total_chars == 0 {
        return false;
    }
    let symbol_ratio = symbol_hits as f32 / total_chars as f32;
    if indented >= 2 && symbol_hits >= 3 {
        return true;
    }
    symbol_ratio >= 0.06 && total_chars >= 80
}

fn push_code_block(
    blocks: &mut Vec<String>,
    seen: &mut HashSet<String>,
    raw: &str,
    require_blocklike: bool,
) {
    let unescaped = html_unescape_text(raw);
    let normalized = unescaped.replace("\r\n", "\n");
    let trimmed = normalized.trim();
    if trimmed.is_empty() {
        return;
    }
    let cleaned = sanitize_code_block_text(trimmed);
    if cleaned.is_empty() {
        return;
    }
    if is_tiny_code_fragment(&cleaned) {
        return;
    }
    if require_blocklike && !is_probable_code_block(&cleaned) {
        return;
    }
    let lowered = cleaned.to_ascii_lowercase();
    let key = normalize_text_key(&lowered);
    if key.is_empty() || !seen.insert(key) {
        return;
    }
    let (snippet, _) = truncate_utf8_chars(&cleaned, MAX_CODE_BLOCK_CHARS);
    blocks.push(snippet);
}

fn normalize_text_key(line: &str) -> String {
    let mut out = String::new();
    let mut last_space = false;
    for ch in line.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_space = false;
        } else if !last_space {
            out.push(' ');
            last_space = true;
        }
    }
    out.trim().to_string()
}

fn is_probable_code_block(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.contains('\n') {
        return true;
    }
    if is_tiny_code_fragment(trimmed) {
        return false;
    }
    if trimmed.len() >= 80 {
        return true;
    }
    let code_symbols = ['{', '}', ';', '=', '>', '<', '(', ')', '[', ']', ':'];
    let mut symbol_hits = 0usize;
    for ch in trimmed.chars() {
        if code_symbols.contains(&ch) {
            symbol_hits += 1;
            if symbol_hits >= 2 && trimmed.len() >= 30 {
                return true;
            }
        }
    }
    false
}

fn is_tiny_code_fragment(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return true;
    }
    if trimmed.contains('\n') {
        return false;
    }
    let len = trimmed.len();
    if len < 12 {
        return true;
    }
    let has_statement_markers = trimmed.contains(';')
        || trimmed.contains('=')
        || trimmed.contains('{')
        || trimmed.contains('}')
        || trimmed.contains("=>")
        || trimmed.contains("->");
    if has_statement_markers {
        return false;
    }
    let token_count = trimmed.split_whitespace().count();
    if token_count >= 2 && len >= 40 {
        return false;
    }
    let mut all_ident = true;
    for ch in trimmed.chars() {
        if ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                '.' | '_' | '<' | '>' | ':' | '(' | ')' | '[' | ']' | '#' | '?' | '!' | ','
            )
        {
            continue;
        }
        all_ident = false;
        break;
    }
    if all_ident && len < 60 {
        return true;
    }
    token_count <= 1 && len < 60
}

fn tighten_code_blocks_for_category(category: QueryCategory, blocks: &mut Vec<String>) {
    if !matches!(category, QueryCategory::CodeExample) {
        return;
    }
    let filtered: Vec<String> = blocks
        .iter()
        .filter(|block| is_strong_code_sample(block))
        .cloned()
        .collect();
    if filtered.is_empty() {
        blocks.clear();
    } else {
        *blocks = filtered;
    }
}

fn is_strong_code_sample(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.contains('\n') {
        return true;
    }
    if trimmed.len() < 18 {
        return false;
    }
    if trimmed.contains("=>") || trimmed.contains("->") {
        return true;
    }
    if trimmed.contains(';') || trimmed.contains('=') {
        return true;
    }
    let symbol_hits = trimmed
        .chars()
        .filter(|ch| ['{', '}', '[', ']', '(', ')', ':', ','].contains(ch))
        .count();
    if symbol_hits >= 2 && trimmed.len() >= 30 {
        return true;
    }
    trimmed.contains(' ') && trimmed.contains('(') && trimmed.contains(')')
}

fn html_unescape_text(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&nbsp;", " ")
        .replace("&#160;", " ")
        .replace("&#xA0;", " ")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn now_epoch_ms_u64() -> u64 {
    now_epoch_ms().try_into().unwrap_or(u64::MAX)
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
    let query_tokens = tokenize_terms_for_match(query);
    if query_tokens.is_empty() {
        return None;
    }
    let query_len = query_tokens.len();
    let min_required = min_required_matches(query_len);

    let mut best_ratio = 0.0f32;
    let mut best_matches = 0usize;
    for hit in hits.iter().take(MAX_MATCH_HITS) {
        if let Some((matched, ratio)) = hit_match_stats(&query_tokens, query_len, hit) {
            if ratio > best_ratio {
                best_ratio = ratio;
                best_matches = matched;
            }
        }
    }

    if best_matches < min_required {
        return Some(0.0);
    }
    Some(best_ratio)
}

fn hit_match_stats(query_tokens: &[String], query_len: usize, hit: &Hit) -> Option<(usize, f32)> {
    if query_tokens.is_empty() {
        return None;
    }
    let mut hit_tokens = HashSet::new();
    collect_match_tokens(&hit.summary, &mut hit_tokens);
    collect_match_tokens(&hit.snippet, &mut hit_tokens);
    if hit_tokens.is_empty() {
        return None;
    }
    let matched = query_tokens
        .iter()
        .filter(|token| hit_tokens.contains(*token))
        .count();
    let ratio = matched as f32 / query_len as f32;
    Some((matched, ratio))
}

fn min_required_matches(query_len: usize) -> usize {
    if query_len >= 3 {
        2
    } else {
        1
    }
}

fn tokenize_terms(text: &str) -> Vec<String> {
    tokenize_terms_with_filter(text, should_keep_token)
}

fn tokenize_terms_for_match(text: &str) -> Vec<String> {
    tokenize_terms_with_filter(text, should_keep_match_token)
}

fn tokenize_terms_with_filter(text: &str, keep: fn(&str) -> bool) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut buf = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            buf.push(ch.to_ascii_lowercase());
        } else if !buf.is_empty() {
            push_token_with_filter(&mut tokens, &mut buf, keep);
        }
    }
    if !buf.is_empty() {
        push_token_with_filter(&mut tokens, &mut buf, keep);
    }
    tokens
}

fn collect_tokens(text: &str, out: &mut HashSet<String>) {
    collect_tokens_with_filter(text, out, should_keep_token);
}

fn collect_match_tokens(text: &str, out: &mut HashSet<String>) {
    collect_tokens_with_filter(text, out, should_keep_match_token);
}

fn collect_tokens_with_filter(text: &str, out: &mut HashSet<String>, keep: fn(&str) -> bool) {
    let mut buf = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() {
            buf.push(ch.to_ascii_lowercase());
        } else if !buf.is_empty() {
            if keep(&buf) {
                out.insert(buf.clone());
            }
            buf.clear();
        }
    }
    if !buf.is_empty() && keep(&buf) {
        out.insert(buf.clone());
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum QueryIntent {
    Code,
    Definition,
    General,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QueryCategory {
    CodeExample,
    ApiReference,
    HowToGuide,
    ConceptDefinition,
    Troubleshooting,
    SpecStandard,
    ComparisonOpinion,
    NewsRelease,
    General,
}

#[derive(Debug, Clone, Copy)]
enum QueryCategorySource {
    Llm,
    Heuristic,
}

impl QueryCategory {
    fn as_str(self) -> &'static str {
        match self {
            QueryCategory::CodeExample => "code_example",
            QueryCategory::ApiReference => "api_reference",
            QueryCategory::HowToGuide => "how_to_guide",
            QueryCategory::ConceptDefinition => "concept_definition",
            QueryCategory::Troubleshooting => "troubleshooting",
            QueryCategory::SpecStandard => "spec_standard",
            QueryCategory::ComparisonOpinion => "comparison_opinion",
            QueryCategory::NewsRelease => "news_release",
            QueryCategory::General => "general",
        }
    }
}

impl QueryCategorySource {
    fn as_str(self) -> &'static str {
        match self {
            QueryCategorySource::Llm => "llm",
            QueryCategorySource::Heuristic => "heuristic",
        }
    }
}

pub(crate) fn detect_query_intent(query: &str) -> QueryIntent {
    let query_lc = query.trim().to_ascii_lowercase();
    if query_lc.is_empty() {
        return QueryIntent::General;
    }
    let tokens = tokenize_terms_with_filter(&query_lc, should_keep_category_token);
    let code_intent = tokens.iter().any(|token| {
        matches!(
            token.as_str(),
            "code"
                | "example"
                | "examples"
                | "sample"
                | "snippet"
                | "snippets"
                | "implement"
                | "implementation"
                | "tutorial"
                | "demo"
                | "template"
                | "boilerplate"
        )
    }) || query_lc.contains("how to ");
    if code_intent {
        return QueryIntent::Code;
    }
    let doc_tokens = tokenize_terms_for_match(&query_lc);
    let doc_intent = doc_tokens.iter().any(|token| {
        matches!(
            token.as_str(),
            "doc"
                | "docs"
                | "documentation"
                | "reference"
                | "references"
                | "manual"
                | "guide"
                | "guides"
                | "api"
        )
    });
    if doc_intent {
        return QueryIntent::Definition;
    }
    let definition_intent = tokens.iter().any(|token| {
        matches!(
            token.as_str(),
            "define" | "definition" | "meaning" | "explain" | "overview" | "concept" | "what"
        )
    }) || query_lc.starts_with("what is ")
        || query_lc.starts_with("what's ");
    if definition_intent {
        return QueryIntent::Definition;
    }
    QueryIntent::General
}

fn resolve_query_intent(query: &str, category: QueryCategory) -> QueryIntent {
    match category {
        QueryCategory::CodeExample => QueryIntent::Code,
        QueryCategory::ApiReference
        | QueryCategory::ConceptDefinition
        | QueryCategory::SpecStandard => QueryIntent::Definition,
        _ => detect_query_intent(query),
    }
}

fn parse_query_category(value: &str) -> Option<QueryCategory> {
    let normalized = value.trim().to_ascii_lowercase();
    let category = match normalized.as_str() {
        "code_example" | "code" | "example" | "code-sample" | "code_sample" => {
            QueryCategory::CodeExample
        }
        "api_reference" | "api" | "reference" | "documentation" => QueryCategory::ApiReference,
        "how_to_guide" | "how-to" | "how_to" | "guide" | "tutorial" => QueryCategory::HowToGuide,
        "concept_definition" | "definition" | "concept" | "overview" => {
            QueryCategory::ConceptDefinition
        }
        "troubleshooting" | "debugging" | "error" | "issue" => QueryCategory::Troubleshooting,
        "spec_standard" | "spec" | "standard" | "rfc" => QueryCategory::SpecStandard,
        "comparison_opinion" | "comparison" | "compare" | "opinion" => {
            QueryCategory::ComparisonOpinion
        }
        "news_release" | "news" | "release" | "announcement" => QueryCategory::NewsRelease,
        "general" | "other" | "unknown" => QueryCategory::General,
        _ => return None,
    };
    Some(category)
}

fn detect_query_category_heuristic(query: &str) -> QueryCategory {
    let query_lc = query.trim().to_ascii_lowercase();
    if query_lc.is_empty() {
        return QueryCategory::General;
    }
    let tokens = tokenize_terms_with_filter(&query_lc, should_keep_category_token);
    if cfg!(test)
        && std::env::var("DOCDEX_DEBUG_QUERY_CATEGORY")
            .map(|value| value.trim() == "1")
            .unwrap_or(false)
    {
        eprintln!("[web] category tokens={tokens:?}");
    }
    let has_token = |values: &[&str]| tokens.iter().any(|token| values.contains(&token.as_str()));
    let has_phrase = |phrase: &str| query_lc.contains(phrase);

    if has_token(&[
        "error",
        "issue",
        "issues",
        "bug",
        "bugs",
        "debug",
        "debugging",
        "fix",
        "fixed",
        "failure",
        "failed",
        "panic",
        "exception",
        "stacktrace",
        "stack",
        "trace",
    ]) {
        return QueryCategory::Troubleshooting;
    }

    if has_token(&[
        "spec",
        "specs",
        "standard",
        "standards",
        "rfc",
        "eip",
        "eips",
        "erc",
        "ercs",
        "draft",
    ]) {
        return QueryCategory::SpecStandard;
    }

    if has_token(&[
        "code",
        "example",
        "examples",
        "sample",
        "samples",
        "snippet",
        "snippets",
        "implementation",
        "template",
        "boilerplate",
    ]) {
        return QueryCategory::CodeExample;
    }

    if has_phrase("how to ") || has_phrase("how-to") || has_phrase("getting started") {
        return QueryCategory::HowToGuide;
    }
    if has_token(&[
        "how",
        "guide",
        "guides",
        "tutorial",
        "tutorials",
        "walkthrough",
    ]) {
        return QueryCategory::HowToGuide;
    }

    if has_token(&[
        "api",
        "reference",
        "docs",
        "documentation",
        "sdk",
        "endpoint",
        "schema",
    ]) {
        return QueryCategory::ApiReference;
    }

    if has_token(&[
        "vs",
        "versus",
        "compare",
        "comparison",
        "best",
        "top",
        "pros",
        "cons",
        "alternatives",
    ]) {
        return QueryCategory::ComparisonOpinion;
    }

    if has_token(&[
        "release",
        "releases",
        "changelog",
        "announcement",
        "news",
        "roadmap",
        "version",
    ]) {
        return QueryCategory::NewsRelease;
    }

    if has_phrase("what is ")
        || has_phrase("what's ")
        || has_token(&[
            "define",
            "definition",
            "meaning",
            "overview",
            "concept",
            "intro",
        ])
    {
        return QueryCategory::ConceptDefinition;
    }

    QueryCategory::General
}

async fn classify_query_category(
    query: &str,
    llm_model: Option<&str>,
    llm_agent: Option<&str>,
) -> (QueryCategory, QueryCategorySource) {
    let query_key = query.trim().to_ascii_lowercase();
    if query_key.is_empty() {
        return (QueryCategory::General, QueryCategorySource::Heuristic);
    }
    if let Ok(cache) = QUERY_CATEGORY_CACHE.lock() {
        if let Some(cached) = cache.get(&query_key).copied() {
            return (cached.category, cached.source);
        }
    }
    let heuristic = detect_query_category_heuristic(query);
    let Some(client) = load_query_category_client(llm_model, llm_agent) else {
        let source = QueryCategorySource::Heuristic;
        if let Ok(mut cache) = QUERY_CATEGORY_CACHE.lock() {
            cache.insert(
                query_key,
                CachedQueryCategory {
                    category: heuristic,
                    source,
                },
            );
        }
        return (heuristic, source);
    };
    let intent = detect_query_intent(query);
    let (mut category, mut source) = match client.evaluate(query).await {
        Some(category) => (category, QueryCategorySource::Llm),
        None => (heuristic, QueryCategorySource::Heuristic),
    };
    if matches!(category, QueryCategory::CodeExample)
        && !matches!(intent, QueryIntent::Code)
        && !matches!(heuristic, QueryCategory::CodeExample)
    {
        category = heuristic;
        source = QueryCategorySource::Heuristic;
    }
    if let Ok(mut cache) = QUERY_CATEGORY_CACHE.lock() {
        cache.insert(query_key, CachedQueryCategory { category, source });
    }
    (category, source)
}

fn code_block_score(blocks: &[String]) -> f32 {
    if blocks.is_empty() {
        return 0.0;
    }
    let mut total_chars = 0usize;
    let mut total_lines = 0usize;
    for block in blocks.iter().take(3) {
        total_chars += block.len();
        total_lines += block.lines().count();
    }
    let char_score = (total_chars as f32 / 800.0).clamp(0.0, 1.0);
    let line_score = (total_lines as f32 / 20.0).clamp(0.0, 1.0);
    (0.6 * line_score + 0.4 * char_score).clamp(0.0, 1.0)
}

fn score_code_block(block: &str) -> f32 {
    let total_chars = block.len();
    let total_lines = block.lines().count();
    let char_score = (total_chars as f32 / 800.0).clamp(0.0, 1.0);
    let line_score = (total_lines as f32 / 24.0).clamp(0.0, 1.0);
    (0.6 * line_score + 0.4 * char_score).clamp(0.0, 1.0)
}

fn select_best_code_block(query: &str, blocks: &[String]) -> Option<String> {
    if blocks.is_empty() {
        return None;
    }
    let mut candidates: Vec<&str> = Vec::new();
    for block in blocks {
        if is_viable_code_block(block) {
            candidates.push(block.as_str());
        }
    }
    let source: Vec<&str> = if candidates.is_empty() {
        blocks.iter().map(|b| b.as_str()).collect()
    } else {
        candidates
    };
    let tokens = tokenize_terms(&query.to_ascii_lowercase());
    let token_count = tokens.len();
    let mut best_score = -1.0f32;
    let mut best_block: Option<&str> = None;
    for block in source {
        let lowered = block.to_ascii_lowercase();
        let mut matched = 0usize;
        if token_count > 0 {
            for token in &tokens {
                if token.len() < 3 {
                    continue;
                }
                if lowered.contains(token) {
                    matched += 1;
                }
            }
        }
        let overlap = if token_count == 0 {
            0.0
        } else {
            matched as f32 / token_count as f32
        };
        let base = score_code_block(block);
        let line_count = block.lines().count();
        let length_factor = if line_count > 140 {
            0.8
        } else if line_count > 80 {
            0.9
        } else {
            1.0
        };
        let mut symbol_hits = 0usize;
        let mut total_chars = 0usize;
        let mut indented = 0usize;
        for line in block.lines() {
            let trimmed = line.trim_end();
            if trimmed.is_empty() {
                continue;
            }
            total_chars += trimmed.len();
            if line.len() > trimmed.len() + 1 {
                indented += 1;
            }
            for ch in trimmed.chars() {
                if matches!(
                    ch,
                    '{' | '}' | ';' | '=' | '<' | '>' | '[' | ']' | '(' | ')' | ':' | ','
                ) {
                    symbol_hits += 1;
                }
            }
        }
        let symbol_ratio = if total_chars == 0 {
            0.0
        } else {
            symbol_hits as f32 / total_chars as f32
        };
        let indent_ratio = if line_count == 0 {
            0.0
        } else {
            indented as f32 / line_count as f32
        };
        let structure_bonus = ((symbol_ratio * 1.4) + (indent_ratio * 0.6)).clamp(0.0, 1.0) * 0.2;
        let score = if token_count == 0 {
            base * length_factor + structure_bonus
        } else {
            (0.6 * overlap + 0.4 * base) * length_factor + structure_bonus
        };
        if score > best_score {
            best_score = score;
            best_block = Some(block);
        }
    }
    best_block.map(|value| value.to_string())
}

fn looks_like_code_output(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    if is_probable_code_block(trimmed) {
        return true;
    }
    let mut symbol_hits = 0usize;
    let mut total = 0usize;
    let mut indented = 0usize;
    for line in trimmed.lines().take(60) {
        if line.trim().is_empty() {
            continue;
        }
        total += line.len();
        if line.len() > line.trim_start().len() + 1 {
            indented += 1;
        }
        for ch in line.chars() {
            if matches!(
                ch,
                '{' | '}' | ';' | '=' | '<' | '>' | '[' | ']' | '(' | ')' | ':' | ','
            ) {
                symbol_hits += 1;
            }
        }
    }
    if total > 0 {
        let ratio = symbol_hits as f32 / total as f32;
        if ratio >= 0.08 && total >= 40 {
            return true;
        }
        if indented >= 3 {
            return true;
        }
    }
    let mut code_lines = 0usize;
    let mut total_lines = 0usize;
    for line in trimmed.lines().take(20) {
        if line.trim().is_empty() {
            continue;
        }
        total_lines += 1;
        if is_probable_code_line(line) {
            code_lines += 1;
        }
    }
    total_lines > 0 && (code_lines * 2 >= total_lines)
}

fn is_viable_code_block(block: &str) -> bool {
    let line_count = block.lines().count();
    if line_count < 4 {
        return false;
    }
    let mut code_lines = 0usize;
    let mut symbol_hits = 0usize;
    let mut total_chars = 0usize;
    let mut indented = 0usize;
    for line in block.lines() {
        let trimmed = line.trim_end();
        if trimmed.is_empty() {
            continue;
        }
        total_chars += trimmed.len();
        if line.len() > trimmed.len() + 1 {
            indented += 1;
        }
        if is_probable_code_line(trimmed) {
            code_lines += 1;
        }
        for ch in trimmed.chars() {
            if matches!(
                ch,
                '{' | '}' | ';' | '=' | '<' | '>' | '[' | ']' | '(' | ')' | ':' | ','
            ) {
                symbol_hits += 1;
            }
        }
    }
    if code_lines * 2 >= line_count {
        return true;
    }
    if total_chars == 0 {
        return false;
    }
    let symbol_ratio = symbol_hits as f32 / total_chars as f32;
    if indented >= 2 && symbol_hits >= 3 {
        return true;
    }
    symbol_ratio >= 0.06 && total_chars >= 120
}

fn filter_boilerplate_text(_query: &str, text: &str, phrases: &[String]) -> String {
    let mut kept = Vec::new();
    let mut seen = HashSet::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        if is_boilerplate_line(trimmed, &lower, phrases) {
            continue;
        }
        let key = normalize_text_key(trimmed);
        if !key.is_empty() && !seen.insert(key) {
            continue;
        }
        kept.push(trimmed.to_string());
    }
    kept.join("\n")
}

#[derive(Debug, Clone)]
struct BannerFilterResult {
    filtered: String,
    removed_lines: usize,
    total_lines: usize,
}

fn strip_banner_lines(text: &str) -> BannerFilterResult {
    let mut kept = Vec::new();
    let mut removed = 0usize;
    let mut total = 0usize;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        total += 1;
        if is_banner_line(trimmed) {
            removed += 1;
            continue;
        }
        kept.push(trimmed);
    }
    BannerFilterResult {
        filtered: kept.join("\n"),
        removed_lines: removed,
        total_lines: total,
    }
}

fn is_banner_only(result: &BannerFilterResult) -> bool {
    if result.total_lines == 0 {
        return false;
    }
    let remaining_lines = result.total_lines.saturating_sub(result.removed_lines);
    if remaining_lines == 0 {
        return true;
    }
    let remaining = result.filtered.trim();
    if remaining.is_empty() {
        return true;
    }
    let removed_ratio = result.removed_lines as f32 / result.total_lines as f32;
    let remaining_words = remaining.split_whitespace().count();
    removed_ratio >= 0.6 && remaining.len() < 200 && remaining_words < 40
}

fn is_banner_line(line: &str) -> bool {
    let len = line.len();
    if len == 0 {
        return false;
    }
    let token_count = line.split_whitespace().count();
    let separators = ['|', '•', '»', '›', '>', '/'];
    let sep_count = line.chars().filter(|ch| separators.contains(ch)).count();
    let alpha_count = line.chars().filter(|ch| ch.is_ascii_alphabetic()).count();
    let non_alpha_ratio = 1.0 - (alpha_count as f32 / len.max(1) as f32);
    if len < 80 && sep_count >= 2 {
        return true;
    }
    if len < 120 && non_alpha_ratio > 0.45 && token_count <= 8 {
        return true;
    }
    len < 100 && token_count <= 4 && non_alpha_ratio > 0.35
}

fn boilerplate_ratio(text: &str, phrases: &[String]) -> f32 {
    let mut total = 0usize;
    let mut boiler = 0usize;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        total += 1;
        let lower = trimmed.to_ascii_lowercase();
        if is_boilerplate_line(trimmed, &lower, phrases) {
            boiler += 1;
        }
    }
    if total == 0 {
        0.0
    } else {
        boiler as f32 / total as f32
    }
}

fn quality_penalty(boiler_ratio: f32, ad_markers: usize) -> f32 {
    if boiler_ratio >= 0.6 {
        return 0.0;
    }
    let mut penalty: f32 = 1.0;
    if boiler_ratio >= 0.4 {
        penalty *= 0.6;
    } else if boiler_ratio >= 0.25 {
        penalty *= 0.8;
    }
    if ad_markers >= 8 {
        penalty *= 0.7;
    } else if ad_markers >= 4 {
        penalty *= 0.85;
    }
    penalty.clamp(0.0, 1.0)
}

fn should_skip_status(status: Option<u16>) -> bool {
    matches!(status, Some(404 | 410))
}

fn is_js_challenge(html: &str, readable_text: &str) -> bool {
    let trimmed = readable_text.trim();
    let text_len = trimmed.chars().count();
    let html_len = html.chars().count();
    if html_len < 500 {
        return false;
    }
    let density = text_len as f32 / html_len.max(1) as f32;
    let lower = html.to_ascii_lowercase();
    let script_count = lower.matches("<script").count();
    let noscript_count = lower.matches("<noscript").count();
    let form_count = lower.matches("<form").count() + lower.matches("<input").count();
    if density < 0.015 && text_len < 400 && (script_count + noscript_count + form_count) >= 3 {
        return true;
    }
    text_len < 120 && html_len > 5000 && (script_count + noscript_count) >= 2
}

fn is_cookie_wall(html: &str, readable_text: &str) -> bool {
    let text = readable_text.trim();
    if text.is_empty() {
        return false;
    }
    let word_count = text.split_whitespace().count();
    if word_count > 180 {
        return false;
    }
    let lower = text.to_ascii_lowercase();
    let cookie_terms = [
        "cookie",
        "cookies",
        "consent",
        "gdpr",
        "privacy",
        "preferences",
        "tracking",
    ];
    let hits = cookie_terms
        .iter()
        .filter(|term| lower.contains(*term))
        .count();
    if hits >= 2 && word_count < 140 {
        return true;
    }
    let html_lower = html.to_ascii_lowercase();
    let html_hits = [
        "cookie-consent",
        "cookiebanner",
        "cookie-banner",
        "gdpr",
        "consent",
    ]
    .iter()
    .filter(|term| html_lower.contains(*term))
    .count();
    html_hits >= 2 && word_count < 160
}

fn count_ad_markers(html: &str) -> usize {
    let lower = html.to_ascii_lowercase();
    let iframe_count = lower.matches("<iframe").count();
    let embed_count = lower.matches("<embed").count();
    let object_count = lower.matches("<object").count();
    let aside_count = lower.matches("<aside").count();
    let script_count = lower.matches("<script").count();
    iframe_count
        .saturating_mul(2)
        .saturating_add(embed_count)
        .saturating_add(object_count)
        .saturating_add(aside_count)
        .saturating_add(script_count / 10)
}

fn is_boilerplate_line(line: &str, lower: &str, phrases: &[String]) -> bool {
    let len = line.len();
    if !phrases.is_empty() {
        for phrase in phrases {
            if phrase.is_empty() {
                continue;
            }
            if lower.contains(phrase) {
                return true;
            }
        }
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return len < 200;
    }
    let separators = ['|', '•', '»', '›', '>', '/'];
    let sep_count = line.chars().filter(|ch| separators.contains(ch)).count();
    if len < 80 && sep_count >= 2 {
        return true;
    }
    let alpha_count = line.chars().filter(|ch| ch.is_ascii_alphabetic()).count();
    let digit_count = line.chars().filter(|ch| ch.is_ascii_digit()).count();
    let ratio = alpha_count as f32 / len.max(1) as f32;
    if ratio < 0.5 && len < 140 {
        return true;
    }
    if digit_count > alpha_count && len < 120 {
        return true;
    }
    let mut token_count = 0usize;
    let mut token_len_sum = 0usize;
    for token in line.split_whitespace() {
        token_count += 1;
        token_len_sum += token.len();
    }
    if token_count > 0 {
        let avg_token = token_len_sum as f32 / token_count as f32;
        if avg_token <= 2.3 && len < 90 {
            return true;
        }
        if token_count <= 3 && len < 50 {
            return true;
        }
    }
    false
}

struct WebMatchStats {
    overlap_ratio: f32,
    matched: usize,
    query_len: usize,
}

fn web_match_stats(query: &str, content: &str, code_blocks: &[String]) -> WebMatchStats {
    let query_tokens = tokenize_terms(query);
    if query_tokens.is_empty() {
        return WebMatchStats {
            overlap_ratio: 0.0,
            matched: 0,
            query_len: 0,
        };
    }
    let mut hit_tokens = HashSet::new();
    collect_tokens(content, &mut hit_tokens);
    for block in code_blocks {
        collect_tokens(block, &mut hit_tokens);
    }
    if hit_tokens.is_empty() {
        return WebMatchStats {
            overlap_ratio: 0.0,
            matched: 0,
            query_len: query_tokens.len(),
        };
    }
    let matched = query_tokens
        .iter()
        .filter(|token| hit_tokens.contains(*token))
        .count();
    let overlap_ratio = matched as f32 / query_tokens.len() as f32;
    WebMatchStats {
        overlap_ratio,
        matched,
        query_len: query_tokens.len(),
    }
}

fn blend_relevance_score(model_score: f32, stats: &WebMatchStats) -> f32 {
    let model_score = model_score.clamp(0.0, 1.0);
    let overlap_score = stats.overlap_ratio.clamp(0.0, 1.0);
    let blended = (model_score * 0.6) + (overlap_score * 0.4);
    let penalty = if stats.query_len <= 1 {
        1.0
    } else if stats.query_len == 2 {
        if stats.matched <= 1 {
            0.75
        } else {
            1.0
        }
    } else if stats.matched <= 1 {
        0.5
    } else if stats.overlap_ratio < 0.5 {
        0.8
    } else {
        1.0
    };
    (blended * penalty).clamp(0.0, 1.0)
}

fn category_relevance_multiplier(
    category: QueryCategory,
    url: &url::Url,
    code_blocks: &[String],
    ai_kind: &str,
) -> f32 {
    let url_lc = url.as_str().to_ascii_lowercase();
    let host = url.host_str().unwrap_or("").to_ascii_lowercase();
    let has_code = !code_blocks.is_empty();
    match category {
        QueryCategory::CodeExample => {
            if ai_kind == "code" && has_code {
                1.15
            } else if !has_code {
                0.7
            } else {
                0.85
            }
        }
        QueryCategory::ApiReference => {
            if url_contains_any(&url_lc, &["/api", "/reference", "api", "reference", "sdk"])
                || url_contains_any(&host, &["docs.", "developer.", "api."])
            {
                1.1
            } else {
                0.95
            }
        }
        QueryCategory::HowToGuide => {
            if url_contains_any(
                &url_lc,
                &[
                    "how-to",
                    "howto",
                    "tutorial",
                    "guide",
                    "walkthrough",
                    "getting-started",
                ],
            ) {
                1.1
            } else {
                0.97
            }
        }
        QueryCategory::ConceptDefinition => {
            if url_contains_any(
                &url_lc,
                &["overview", "introduction", "what-is", "concept", "glossary"],
            ) {
                1.1
            } else {
                0.97
            }
        }
        QueryCategory::Troubleshooting => {
            if url_contains_any(&url_lc, &["error", "issues", "issue", "fix", "debug"])
                || url_contains_any(
                    &host,
                    &["stackoverflow.com", "serverfault.com", "superuser.com"],
                )
            {
                1.1
            } else {
                0.97
            }
        }
        QueryCategory::SpecStandard => {
            if url_contains_any(&url_lc, &["spec", "standard", "eip-", "erc-", "rfc"])
                || url_contains_any(
                    &host,
                    &["eips.ethereum.org", "rfc-editor.org", "ietf.org", "w3.org"],
                )
            {
                1.15
            } else {
                0.95
            }
        }
        QueryCategory::ComparisonOpinion => {
            if url_contains_any(
                &url_lc,
                &[
                    "compare",
                    "comparison",
                    "-vs-",
                    "/vs/",
                    "versus",
                    "best",
                    "top",
                ],
            ) {
                1.1
            } else {
                0.95
            }
        }
        QueryCategory::NewsRelease => {
            if url_contains_any(
                &url_lc,
                &[
                    "blog",
                    "news",
                    "release",
                    "changelog",
                    "announcement",
                    "press",
                ],
            ) {
                1.1
            } else {
                0.95
            }
        }
        QueryCategory::General => 1.0,
    }
}

fn should_stop_early(
    desired_count: usize,
    score: f32,
    match_stats: &WebMatchStats,
    query_category: QueryCategory,
    ai_kind: &str,
    has_content: bool,
    early_stop_score: f32,
) -> bool {
    if !has_content {
        return false;
    }
    if score >= early_stop_score {
        return true;
    }
    if desired_count != 1 {
        return false;
    }
    if matches!(
        query_category,
        QueryCategory::ConceptDefinition | QueryCategory::General | QueryCategory::ApiReference
    ) {
        let short_threshold = (early_stop_score * 0.8).clamp(0.35, early_stop_score);
        if match_stats.query_len <= 4 && score >= short_threshold {
            return true;
        }
    }
    if match_stats.query_len >= 3 && match_stats.overlap_ratio >= 0.75 {
        return true;
    }
    if matches!(
        query_category,
        QueryCategory::ConceptDefinition | QueryCategory::General | QueryCategory::ApiReference
    ) && match_stats.query_len >= 2
        && match_stats.overlap_ratio >= 0.6
        && !ai_kind.eq_ignore_ascii_case("code")
    {
        return true;
    }
    false
}

fn min_overlap_ratio_for_intent(intent: QueryIntent, query_len: usize) -> Option<f32> {
    if matches!(intent, QueryIntent::Code) && query_len >= 4 {
        return Some(0.5);
    }
    None
}

fn apply_code_intent_penalty(hit: &mut Hit, has_code: bool) {
    if !has_code {
        hit.score *= 0.6;
        return;
    }
    if is_markdown_path(&hit.rel_path) {
        hit.score *= 0.85;
    }
}

fn hit_has_code_markers(hit: &Hit) -> bool {
    if is_code_path(&hit.rel_path) {
        return true;
    }
    if hit.summary.contains("```") || hit.snippet.contains("```") {
        return true;
    }
    for line in hit.summary.lines().chain(hit.snippet.lines()) {
        if is_probable_code_line(line) {
            return true;
        }
    }
    false
}

fn hit_matches_specific_token(query_tokens: &[String], hit: &Hit) -> bool {
    if query_tokens.is_empty() {
        return false;
    }
    hit_match_stats(query_tokens, query_tokens.len(), hit)
        .map(|(matched, _)| matched > 0)
        .unwrap_or(false)
}

fn is_markdown_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".md") || lower.ends_with(".markdown") || lower.ends_with(".mdx")
}

fn is_code_path(path: &str) -> bool {
    let _ = path;
    false
}

fn push_token_with_filter(tokens: &mut Vec<String>, buf: &mut String, keep: fn(&str) -> bool) {
    if keep(buf) {
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

fn should_keep_match_token(token: &str) -> bool {
    let token = token.trim();
    if token.len() < 2 {
        return false;
    }
    !MATCH_STOPWORDS.contains(token)
}

fn should_keep_category_token(token: &str) -> bool {
    let token = token.trim();
    if token.len() < 2 {
        return false;
    }
    !COMMON_STOPWORDS.contains(&token)
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

        assert!(gate.should_attempt(Some(0.3), None, false, false));
        assert!(!gate.should_attempt(Some(0.8), Some(0.6), false, false));
        assert!(!gate.should_attempt(Some(0.8), Some(0.1), false, false));
        assert!(gate.should_attempt(Some(0.8), Some(0.1), false, true));
        assert!(gate.should_attempt(Some(0.8), None, true, false));
        assert!(gate.should_attempt(None, None, false, false));
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
        let status =
            evaluate_gate_status("req", &gate, Some(0.8), Some(0.8), Some(0.9), false, false);
        assert_eq!(status.status, WebDiscoveryStatusCode::Skipped);
        assert_eq!(status.reason.as_deref(), Some("confidence_above_threshold"));
    }

    #[test]
    fn evaluate_gate_status_reports_unavailable_without_browser() {
        let gate = WebGateConfig {
            enabled: true,
            trigger_threshold: 0.45,
            min_local_match_ratio: 0.2,
            browser_hint: Some("chromium".to_string()),
            browser_available: false,
        };
        let status = evaluate_gate_status("req", &gate, Some(0.1), Some(0.1), None, false, false);
        assert_eq!(status.status, WebDiscoveryStatusCode::Unavailable);
        assert_eq!(status.reason.as_deref(), Some("missing_dependency"));
        assert!(status.message.as_deref().unwrap().contains("chromium"));
    }

    #[test]
    fn detect_query_category_heuristic_code_example() {
        let category = detect_query_category_heuristic("user approval code sample");
        assert_eq!(category, QueryCategory::CodeExample);
    }

    #[test]
    fn detect_query_category_heuristic_troubleshooting() {
        let category = detect_query_category_heuristic("timeout error fix");
        assert_eq!(category, QueryCategory::Troubleshooting);
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

fn env_usize(key: &str) -> Option<usize> {
    let raw = env::var(key).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<usize>().ok()
}

fn env_u64(key: &str) -> Option<u64> {
    let raw = env::var(key).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<u64>().ok()
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

fn resolve_direct_fetch_max_bytes() -> usize {
    env_usize("DOCDEX_WEB_DIRECT_FETCH_MAX_BYTES")
        .unwrap_or(WEB_DIRECT_FETCH_MAX_BYTES_DEFAULT)
        .max(1024)
}

fn resolve_web_llm_concurrency() -> usize {
    env_usize("DOCDEX_WEB_MAX_CONCURRENT_LLM")
        .unwrap_or(1)
        .max(1)
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

fn config_web_max_hits() -> Option<usize> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(config.search.max_web_hits)
}

fn config_web_browser_path() -> Option<String> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    config
        .web
        .scraper
        .chrome_binary_path
        .map(|path| path.to_string_lossy().to_string())
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
        return false;
    }

    util::detect_browser_binary(None).is_some()
}

fn resolve_web_limit(requested: Option<usize>, fallback: usize) -> usize {
    let mut limit = requested.unwrap_or(fallback);
    if let Some(max_hits) = env_usize("DOCDEX_WEB_MAX_HITS").or_else(config_web_max_hits) {
        if max_hits > 0 {
            limit = limit.min(max_hits);
        }
    }
    limit.max(1)
}

fn resolve_fetch_url_limit(target_count: usize, total: usize) -> usize {
    let multiplier = 3usize;
    let max_batch = WEB_BATCH_SIZE.saturating_mul(WEB_MAX_BATCHES);
    let limit = target_count
        .saturating_mul(multiplier)
        .max(target_count)
        .min(max_batch)
        .max(1);
    limit.min(total)
}

fn resolve_web_fetch_budget(config: &WebConfig, target_count: usize) -> Option<Duration> {
    let env_ms = env_u64("DOCDEX_WEB_FETCH_BUDGET_MS");
    if let Some(ms) = env_ms {
        if ms == 0 {
            return None;
        }
        return Some(Duration::from_millis(ms.max(WEB_FETCH_BUDGET_MIN_MS)));
    }
    let per_item_ms = config
        .request_timeout
        .saturating_add(config.page_load_timeout)
        .as_millis()
        .saturating_add((WEB_SUMMARY_TIMEOUT_MS / 2) as u128) as u64;
    let estimated = per_item_ms.saturating_mul(target_count.max(1) as u64);
    let budget_ms = estimated
        .min(WEB_FETCH_BUDGET_DEFAULT_MS)
        .max(WEB_FETCH_BUDGET_MIN_MS);
    Some(Duration::from_millis(budget_ms))
}
