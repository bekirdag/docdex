use crate::config;
use crate::index::Hit;
use crate::index::Indexer;
use crate::libs::LibsIndexer;
use crate::ollama::OllamaClient;
use crate::search;
use crate::state_layout::StateLayout;
use crate::tier2::{Tier2Unavailable, Tier2UnavailableReason};
use crate::max_size::truncate_utf8_chars;
use crate::util;
use crate::web::cache;
use crate::web::chrome::{fetch_dom, ChromeFetchConfig};
use crate::web::ddg::{DdgDiscovery, WebDiscoveryResponse, WebDiscoveryResult};
use crate::web::normalize::{dedupe_urls, unwrap_ddg_redirect};
use crate::web::readability::extract_readable_text;
use crate::web::status::fetch_status;
use crate::web::WebConfig;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
const MAX_WEB_FALLBACK_EXCERPT_CHARS: usize = 480;
const MAX_WEB_FALLBACK_EXCERPT_LINES: usize = 4;
const WEB_CONTEXT_MIN_RELEVANCE_SCORE: f32 = 0.2;

const MAX_MATCH_HITS: usize = 3;
const LOCAL_RELEVANCE_TIMEOUT_MS: u64 = 8_000;
const LOCAL_RELEVANCE_MAX_TOKENS: u32 = 96;
const MAX_LOCAL_RELEVANCE_INPUT_CHARS: usize = 800;
const WEB_BATCH_SIZE: usize = 10;
const WEB_MAX_BATCHES: usize = 2;
const MAX_CODE_BLOCKS: usize = 4;
const MAX_CODE_BLOCK_CHARS: usize = 1800;
const WEB_CHUNK_MAX_CHARS: usize = 700;
const WEB_CHUNK_MIN: usize = 2;
const WEB_CHUNK_MAX: usize = 4;
const WEB_GOOD_RELEVANCE_SCORE: f32 = 0.7;
const WEB_DEF_SECTION_MAX: usize = 4;
const WEB_SECTION_MAX_CHARS: usize = 420;
const WEB_HEADING_MAX_CHARS: usize = 120;
const WEB_MIN_CONTENT_CHARS: usize = 200;
const WEB_MIN_CONTENT_WORDS: usize = 30;
const WEB_MAX_RESULTS_PER_DOMAIN: usize = 2;
const WEB_NOISE_RATIO_THRESHOLD: f32 = 0.5;
const WEB_STRUCTURED_MAX_ITEMS: usize = 24;
const WEB_STRUCTURED_MAX_LIST_ITEMS: usize = 12;
const WEB_STRUCTURED_MAX_GLOBAL_PARAS: usize = 2;
const WEB_QUALITY_FAIL_THRESHOLD: u32 = 3;
const WEB_QUALITY_BLOCK_THRESHOLD: u32 = 2;
const WEB_QUALITY_CHALLENGE_THRESHOLD: u32 = 1;
const WEB_QUALITY_COOLDOWN_SECS: u64 = 600;
const WEB_QUALITY_TTL_SECS: u64 = 86_400;

const COMMON_STOPWORDS: &[&str] = &[
    "a", "an", "and", "are", "as", "at", "be", "by", "do", "does", "for", "from",
    "how", "i", "if", "in", "is", "it", "of", "on", "or", "the", "to", "use",
    "using", "was", "we", "what", "when", "where", "who", "why", "with", "you",
    "your",
];

const MATCH_STOPWORDS_EXTRA: &[&str] = &[
    "add", "append", "build", "create", "insert", "make",
];

const DOMAIN_STOPWORDS: &[&str] = &[
    "css", "html", "javascript", "js", "plain", "simple",
    "code", "sample", "samples", "example", "examples", "tutorial", "tutorials",
    "guide", "guides", "docs", "documentation", "reference", "references",
    "overview", "intro", "introduction", "getting", "started", "learn", "learning",
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
        .copied()
        .collect()
});

static CODE_BLOCK_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"(?is)<pre[^>]*>(.*?)</pre>").expect("valid code block regex")
});

static CODE_TAG_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"(?is)<code[^>]*>(.*?)</code>").expect("valid code tag regex")
});

static TAG_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"(?is)<[^>]+>").expect("valid tag regex")
});

static BLOCK_BREAK_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"(?is)<br\\s*/?>|</(p|div|li|section|article|h[1-6]|ul|ol)>")
        .expect("valid block break regex")
});

static SCRIPT_STYLE_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"(?is)<(script|style)[^>]*>.*?</\\1>").expect("valid script/style regex")
});

static HEADING_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"(?is)<h([1-6])[^>]*>(.*?)</h\\1>").expect("valid heading regex")
});

static PARA_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"(?is)<p[^>]*>(.*?)</p>").expect("valid paragraph regex")
});

static STRUCTURED_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"(?is)<(h[1-6]|p|li)[^>]*>(.*?)</\\1>")
        .expect("valid structured regex")
});

static HEADING_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"([a-z0-9])#([A-Za-z])").expect("valid heading join regex")
});

static TAG_ATTR_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"(<[A-Za-z]+)([a-z]{2,})(=)").expect("valid tag attr join regex")
});

static TLD_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"\\.(com|org|net|io|dev|co|us|uk|edu|gov)([A-Z])")
        .expect("valid tld join regex")
});

static LOWER_UPPER_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"([a-z]{4,})([A-Z][a-z]{2,})").expect("valid lower upper join regex")
});

static AND_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"([a-z])and([A-Z])").expect("valid and join regex")
});

static PUNCT_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"([.!?])([A-Z])").expect("valid punctuation join regex")
});

static ALLCAPS_JOIN_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"([a-z])([A-Z]{2,})").expect("valid allcaps join regex")
});

static CAMEL_BREAK_RE: Lazy<regex::Regex> = Lazy::new(|| {
    regex::Regex::new(r"([A-Za-z]{6,})([A-Z][a-z]{3,})")
        .expect("valid camel break regex")
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
        if item
            .relevance_score
            .map_or(false, |score| score < WEB_CONTEXT_MIN_RELEVANCE_SCORE)
        {
            continue;
        }
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
        cloned.debug = None;
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
        let intent = detect_query_intent(query);
        let prompt = build_summary_prompt(query, trimmed, code_blocks);
        let result = self
            .client
            .generate(&self.model, &prompt, self.max_tokens, self.timeout)
            .await
            .ok()?;
        let parsed: WebEvalResponse = parse_json_response(&result)?;
        let relevant = parsed.relevant;
        let score = parsed.score.clamp(0.0, 1.0);
        let mut kind = parsed.kind.trim().to_ascii_lowercase();
        let allow_code = matches!(intent, QueryIntent::Code) && !code_blocks.is_empty();
        if kind == "code" && !allow_code {
            kind = "summary".to_string();
        }
        let output = if kind == "code" {
            let cleaned = clean_code_text(&parsed.output);
            format_md_code(&cleaned)
        } else {
            let cleaned = clean_summary_text(&parsed.output);
            format_md_summary(&cleaned)
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
        "\nInstructions:\n- Decide if the page is relevant to the query.\n- If relevant and the query asks for code/example, output ONLY the code from the provided code blocks as Markdown fenced code blocks. Do not add or rewrite code.\n- If relevant, code-focused, and there are no code blocks, output a short 2-4 bullet summary instead.\n- If relevant and not code-focused, output 2-4 bullet points in Markdown.\n- If irrelevant, set relevant=false and output empty string.\n\nReturn JSON ONLY in this shape:\n{\"relevant\":true|false,\"score\":0..1,\"kind\":\"summary\"|\"code\",\"output\":\"...\"}\n",
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
    let prefixes = ["copy code", "copycode", "javascriptcopy", "textcopy", "copy"];
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
        _ => format_md_summary(output),
    }
}

fn format_md_summary(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut bullet_lines = Vec::new();
    let mut has_bullets = true;
    for line in trimmed.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let is_bullet = line.starts_with("- ") || line.starts_with("* ");
        if !is_bullet {
            has_bullets = false;
        }
        bullet_lines.push(line.to_string());
    }
    if bullet_lines.is_empty() {
        return String::new();
    }
    if has_bullets {
        return bullet_lines.join("\n");
    }
    bullet_lines
        .into_iter()
        .map(|line| format!("- {}", line))
        .collect::<Vec<_>>()
        .join("\n")
}

fn fallback_excerpt_md(text: &str) -> String {
    let mut lines = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        lines.push(trimmed.to_string());
        if lines.len() >= MAX_WEB_FALLBACK_EXCERPT_LINES {
            break;
        }
    }
    if lines.is_empty() {
        return String::new();
    }
    let joined = lines.join("\n");
    let (snippet, _) = truncate_utf8_chars(&joined, MAX_WEB_FALLBACK_EXCERPT_CHARS);
    format_md_summary(&snippet)
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
    web_limit: Option<usize>,
    force_web: bool,
    gate: &WebGateConfig,
) -> Result<WebResearchResponse, anyhow::Error> {
    let query = query.trim();
    let search_response = search::run_query(indexer, libs_indexer, query, limit).await?;
    let original_top_score_normalized = search_response.top_score_normalized;
    let hits =
        filter_local_hits_with_llm(query, search_response.hits, original_top_score_normalized).await;
    let top_score = hits.first().map(|hit| hit.score);
    let top_score_normalized = top_score.map(search::normalize_score);
    let local_match_ratio = local_match_ratio(query, &hits);
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
            web_limit,
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
    let query_tokens = tokenize_terms_for_match(query);
    if query_tokens.is_empty() {
        return hits;
    }
    let query_len = query_tokens.len();
    let min_required = min_required_matches(query_len);
    let threshold = resolve_local_relevance_threshold();
    let client = load_local_relevance_client();
    if let (Some(score), None) = (top_score_normalized, client.as_ref()) {
        if score >= threshold {
            return hits;
        }
    }
    let Some(client) = client else {
        return hits
            .into_iter()
            .filter(|hit| local_hit_matches(&query_tokens, hit))
            .collect();
    };
    let all_hits = hits;
    let mut filtered = Vec::new();
    let mut llm_responses = 0usize;
    let mut llm_failures = 0usize;
    for hit in &all_hits {
        match client.evaluate(query, hit).await {
            Some(response) => {
                llm_responses += 1;
                if response.relevant {
                    let matched = hit_match_stats(&query_tokens, query_len, hit)
                        .map(|(matched, _)| matched)
                        .unwrap_or(0);
                    if matched < min_required {
                        continue;
                    }
                    filtered.push(hit.clone());
                }
            }
            None => {
                llm_failures += 1;
            }
        }
    }
    if llm_responses == 0 && llm_failures > 0 {
        return all_hits
            .into_iter()
            .filter(|hit| local_hit_matches(&query_tokens, hit))
            .collect();
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
    web_limit: usize,
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

    let mut discovery_limit = (web_limit * WEB_MAX_RESULTS_PER_DOMAIN).max(web_limit);
    discovery_limit = discovery_limit.min(config.max_results.max(web_limit));
    match discovery.discover(query, discovery_limit).await {
        Ok(response) => {
            let (discovery_response, urls) =
                normalize_discovery_response(response, &config, web_limit);
            let fetches = fetch_web_documents(query, &urls, &config, web_limit).await;
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
    urls.retain(|value| !is_tracking_url(value));
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

fn is_tracking_url(raw: &str) -> bool {
    let url = match url::Url::parse(raw) {
        Ok(url) => url,
        Err(_) => return true,
    };
    let host = url.host_str().unwrap_or("").trim().to_ascii_lowercase();
    if host.is_empty() {
        return true;
    }
    if host.ends_with("duckduckgo.com") {
        let path = url.path();
        if path.starts_with("/y.js") || path.starts_with("/l/") || path.starts_with("/u/") {
            return true;
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
        entry.cooldown_until_epoch_ms =
            now_ms.saturating_add(WEB_QUALITY_COOLDOWN_SECS * 1000);
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

fn normalize_query_key(query: &str) -> String {
    let mut parts = Vec::new();
    let mut buf = String::new();
    for ch in query.chars() {
        if ch.is_ascii_alphanumeric() {
            buf.push(ch.to_ascii_lowercase());
        } else if !buf.is_empty() {
            parts.push(buf.clone());
            buf.clear();
        }
    }
    if !buf.is_empty() {
        parts.push(buf);
    }
    parts.join(" ")
}

fn hash_text(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hex::encode(hasher.finalize())
}

fn summary_cache_key(query_hash: &str, content_hash: &str) -> String {
    format!("summary:{query_hash}:{content_hash}")
}

fn summary_cache_entry(
    query: &str,
    content_text: &str,
    code_blocks: &[String],
) -> (String, String) {
    let query_hash = hash_text(&normalize_query_key(query));
    let mut content_input = String::new();
    content_input.push_str(content_text);
    if !code_blocks.is_empty() {
        content_input.push_str("\n\n");
        content_input.push_str(&code_blocks.join("\n\n"));
    }
    let content_hash = hash_text(&content_input);
    (query_hash, content_hash)
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
        let _ = cache::write_cache_entry(layout, &summary_cache_key(query_hash, content_hash), &payload);
    }
}

async fn fetch_web_documents(
    query: &str,
    urls: &[String],
    config: &WebConfig,
    target_count: usize,
) -> Vec<WebFetchResult> {
    if urls.is_empty() {
        return Vec::new();
    }
    let desired_count = target_count.max(1);
    let layout = cache::cache_layout_from_config();
    let summary_client = load_web_summary_client();
    let debug_enabled = env_boolish("DOCDEX_WEB_DEBUG").unwrap_or(false);
    if !config
        .scraper_engine
        .trim()
        .eq_ignore_ascii_case("chrome")
    {
        return vec![WebFetchResult {
            url: String::new(),
            status: None,
            fetched_at_epoch_ms: None,
            cached: false,
            content: None,
            ai_digested_content: None,
            ai_digested_kind: None,
            relevance_score: None,
            error: Some(format!(
                "web fetch engine is {}; only chrome is supported",
                config.scraper_engine
            )),
            debug: None,
        }];
    }
    let chrome_config = match ChromeFetchConfig::from_web_config(config) {
        Some(config) => config,
        None => {
            return vec![WebFetchResult {
                url: String::new(),
                status: None,
                fetched_at_epoch_ms: None,
                cached: false,
                content: None,
                ai_digested_content: None,
                ai_digested_kind: None,
                relevance_score: None,
                error: Some("web fetch chrome binary not configured".to_string()),
                debug: None,
            }];
        }
    };
    let boilerplate_phrases = &config.boilerplate_phrases;

    let mut all_results = Vec::new();
    let mut good_count = 0usize;
    for batch in urls.chunks(WEB_BATCH_SIZE).take(WEB_MAX_BATCHES) {
        let mut batch_results = Vec::new();
        for raw in batch {
            let url = match url::Url::parse(raw) {
                Ok(url) => url,
                Err(_) => continue,
            };
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
            let intent = detect_query_intent(query);

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
                    }
                }
            }

            if content.is_none() {
                let now_ms = now_epoch_ms_u64();
                if let Some(layout) = layout.as_ref() {
                    if let Some(until_ms) = domain_in_cooldown(layout, &host, now_ms) {
                        batch_results.push(WebFetchResult {
                            url: url.to_string(),
                            status: None,
                            fetched_at_epoch_ms: None,
                            cached: false,
                            content: None,
                            ai_digested_content: None,
                            ai_digested_kind: None,
                            relevance_score: None,
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
                let status_probe =
                    fetch_status(&url, &config.user_agent, config.request_timeout).await;
                if should_skip_status(status_probe) {
                    batch_results.push(WebFetchResult {
                        url: url.to_string(),
                        status: status_probe,
                        fetched_at_epoch_ms,
                        cached: false,
                        content: None,
                        ai_digested_content: None,
                        ai_digested_kind: None,
                        relevance_score: None,
                        error: Some("web fetch skipped due to preflight status".to_string()),
                        debug: None,
                    });
                    continue;
                }
                match fetch_dom(&url, &chrome_config).await {
                    Ok(fetch_result) => {
                        status = fetch_result.status.or(status_probe);
                        let html = fetch_result.html;
                        if debug_enabled {
                            if let Some(final_url) = fetch_result.final_url.as_ref() {
                                if final_url == "about:blank" {
                                    debug_notes.push("chrome navigation stayed on about:blank".to_string());
                                }
                            } else {
                                debug_notes.push("chrome final_url missing".to_string());
                            }
                        }
                        code_blocks = extract_code_blocks(&html);
                        let ad_markers = count_ad_markers(&html);
                        let readable_opt = extract_readable_text(&html, &url);
                        if debug_enabled && readable_opt.is_none() {
                            debug_notes.push("readability failed; used fallback extraction".to_string());
                        }
                        let mut readable = readable_opt.unwrap_or_else(|| clean_web_text(&html));
                        readable = normalize_text_spacing(&readable);
                        let mut boiler_ratio = boilerplate_ratio(&readable, boilerplate_phrases);
                        if boiler_ratio >= WEB_NOISE_RATIO_THRESHOLD {
                            let structured = extract_structured_html_text(&html, boilerplate_phrases);
                            if !structured.trim().is_empty() {
                                readable = normalize_text_spacing(&structured);
                            }
                        }
                        if is_js_challenge(&html, &readable) {
                            record_domain_failure(
                                layout.as_ref(),
                                &host,
                                DomainFailureKind::Challenge,
                                now_ms,
                            );
                            if debug_enabled {
                                debug_notes.push("js challenge detected (multiple signals + short text)".to_string());
                            }
                            batch_results.push(WebFetchResult {
                                url: url.to_string(),
                                status,
                                fetched_at_epoch_ms,
                                cached: false,
                                content: None,
                                ai_digested_content: None,
                                ai_digested_kind: None,
                                relevance_score: None,
                                error: Some("web fetch blocked by JS challenge".to_string()),
                                debug: if debug_enabled && !debug_notes.is_empty() {
                                    Some(debug_notes.clone())
                                } else {
                                    None
                                },
                            });
                            continue;
                        }
                        let cookie_result = strip_cookie_consent_lines(&readable);
                        if cookie_result.removed_lines > 0 && debug_enabled {
                            debug_notes.push(format!(
                                "cookie/consent lines removed: {}/{}",
                                cookie_result.removed_lines, cookie_result.total_lines
                            ));
                        }
                        let cookie_only = is_cookie_only(&cookie_result);
                        let mut readable = cookie_result.filtered;
                        if cookie_only {
                            if debug_enabled {
                                debug_notes.push("content appears to be cookie/consent only".to_string());
                            }
                            content_error = Some("cookie/consent only".to_string());
                            content = None;
                        } else {
                            if debug_enabled && readable.trim().is_empty() {
                                debug_notes.push("text extraction empty after fallback".to_string());
                            }
                            boiler_ratio = boilerplate_ratio(&readable, boilerplate_phrases);
                            let penalty = quality_penalty(boiler_ratio, ad_markers);
                            if penalty == 0.0 {
                                batch_results.push(WebFetchResult {
                                    url: url.to_string(),
                                    status: status_probe,
                                    fetched_at_epoch_ms,
                                    cached: false,
                                    content: None,
                                    ai_digested_content: None,
                                    ai_digested_kind: None,
                                    relevance_score: None,
                                    error: Some("web fetch skipped due to boilerplate noise".to_string()),
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
                            let (content_input, should_chunk) = match intent {
                                QueryIntent::Code => (readable, true),
                                QueryIntent::Definition => {
                                    match extract_definition_sections(query, &html, boilerplate_phrases) {
                                        Some(value) => (value, false),
                                        None => (readable, true),
                                    }
                                }
                                QueryIntent::General => (readable, true),
                            };
                            let focused = if should_chunk {
                                select_top_chunks(query, &content_input)
                            } else {
                                content_input
                            };
                            let (trimmed, _) = truncate_utf8_chars(&focused, MAX_WEB_DOC_CHARS);
                            if trimmed.trim().is_empty() {
                                if debug_enabled {
                                    debug_notes.push("extracted text empty after chunking".to_string());
                                }
                                content = None;
                            } else {
                                let char_count = trimmed.chars().count();
                                let word_count = trimmed.split_whitespace().count();
                                let allow_short = matches!(intent, QueryIntent::Code)
                                    && !code_blocks.is_empty();
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
                        let failure_kind =
                            classify_status_failure(status_probe).unwrap_or(DomainFailureKind::Fetch);
                        record_domain_failure(layout.as_ref(), &host, failure_kind, now_ms);
                        batch_results.push(WebFetchResult {
                            url: url.to_string(),
                            status: status_probe,
                            fetched_at_epoch_ms,
                            cached: false,
                            content: None,
                            ai_digested_content: None,
                            ai_digested_kind: None,
                            relevance_score: None,
                            error: Some(format!("web fetch failed: {err}")),
                            debug: None,
                        });
                        continue;
                    }
                };
            }

            let Some(content_text) = content.as_ref() else {
                let empty_error = content_error.clone().unwrap_or_else(|| "content empty".to_string());
                batch_results.push(WebFetchResult {
                    url: url.to_string(),
                    status,
                    fetched_at_epoch_ms,
                    cached,
                    content: Some(String::new()),
                    ai_digested_content: None,
                    ai_digested_kind: None,
                    relevance_score: Some(0.0),
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
                            "low content (post-cache): {char_count} chars, {word_count} words"
                        ));
                    }
                }
            }

            if skip_summary {
                let error = content_error.clone().unwrap_or_else(|| "low_content".to_string());
                batch_results.push(WebFetchResult {
                    url: url.to_string(),
                    status,
                    fetched_at_epoch_ms,
                    cached,
                    content: Some(content_text.clone()),
                    ai_digested_content: None,
                    ai_digested_kind: None,
                    relevance_score: Some(0.0),
                    error: Some(error),
                    debug: if debug_enabled && !debug_notes.is_empty() {
                        Some(debug_notes.clone())
                    } else {
                        None
                    },
                });
                continue;
            }

            let (query_hash, content_hash) =
                summary_cache_entry(query, content_text, &code_blocks);
            let cached_summary = layout
                .as_ref()
                .and_then(|layout| {
                    read_summary_cache(layout, &query_hash, &content_hash, config.cache_ttl)
                });
            let used_cached_summary = cached_summary.is_some();
            let evaluation = if let Some(summary) = cached_summary {
                Some(summary)
            } else if let Some(summary_client) = summary_client.as_ref() {
                summary_client.evaluate(query, content_text, &code_blocks).await
            } else {
                Some(WebEvalOutput {
                    relevance_score: 0.0,
                    kind: "summary".to_string(),
                    output: format_md_summary(content_text),
                })
            };

            let mut evaluation = evaluation.unwrap_or_else(|| WebEvalOutput {
                relevance_score: 0.0,
                kind: "summary".to_string(),
                output: format_md_summary(content_text),
            });
            if matches!(intent, QueryIntent::Code) && !code_blocks.is_empty() {
                let selected = select_code_blocks_for_query(query, &code_blocks);
                let raw_code = join_code_blocks(&selected);
                let (snippet, _) = truncate_utf8_chars(&raw_code, MAX_WEB_SUMMARY_INPUT_CHARS);
                if !snippet.trim().is_empty() {
                    evaluation.kind = "code".to_string();
                    evaluation.output = snippet;
                }
            }
            if evaluation.kind == "summary" {
                evaluation.output = content_text.to_string();
            }
            let mut formatted_output = format_md_output(&evaluation.kind, &evaluation.output);
            let mut ai_kind = evaluation.kind.clone();
            let mut summary_error = None;
            if formatted_output.trim().is_empty() {
                let fallback = fallback_excerpt_md(content_text);
                if fallback.trim().is_empty() {
                    summary_error = Some("summary empty".to_string());
                } else {
                    formatted_output = fallback;
                    ai_kind = "summary".to_string();
                    summary_error = Some("summary empty; using excerpt".to_string());
                }
            }
            let ai_digested_content = if formatted_output.trim().is_empty() {
                None
            } else {
                Some(formatted_output)
            };
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
                        write_summary_cache(layout, &query_hash, &content_hash, &evaluation);
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
            record_domain_success(layout.as_ref(), &host);
            batch_results.push(WebFetchResult {
                url: url.to_string(),
                status,
                fetched_at_epoch_ms,
                cached,
                content: Some(content_text.clone()),
                ai_digested_content,
                ai_digested_kind,
                relevance_score: Some(relevance_score),
                error: summary_error,
                debug,
            });
        }

        if !batch_results.is_empty() {
            good_count += batch_results
                .iter()
                .filter(|item| item.relevance_score.unwrap_or(0.0) >= WEB_GOOD_RELEVANCE_SCORE)
                .count();
            all_results.extend(batch_results);
            if good_count >= desired_count {
                break;
            }
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
    all_results
}

fn clean_web_text(html: &str) -> String {
    let with_breaks = BLOCK_BREAK_RE.replace_all(html, "\n");
    let stripped_scripts = SCRIPT_STYLE_RE.replace_all(with_breaks.as_ref(), " ");
    let stripped_tags = TAG_RE.replace_all(stripped_scripts.as_ref(), "\n");
    let cleaned = html_unescape_text(stripped_tags.as_ref());
    let normalized = normalize_text_spacing(&cleaned);
    normalized
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn normalize_text_spacing(text: &str) -> String {
    let mut lines = Vec::new();
    for line in text.lines() {
        let trimmed = strip_invisible_chars(line).trim().to_string();
        let trimmed = trimmed.as_str();
        if trimmed.is_empty() {
            lines.push(String::new());
            continue;
        }
        if is_probable_code_line(trimmed) {
            lines.push(trimmed.to_string());
            continue;
        }
        let mut updated = trimmed.to_string();
        updated = TAG_ATTR_JOIN_RE.replace_all(&updated, "$1 $2$3").to_string();
        updated = HEADING_JOIN_RE.replace_all(&updated, "$1\n#$2").to_string();
        updated = TLD_JOIN_RE.replace_all(&updated, ".$1 $2").to_string();
        updated = LOWER_UPPER_JOIN_RE.replace_all(&updated, "$1 $2").to_string();
        updated = AND_JOIN_RE.replace_all(&updated, "$1 and $2").to_string();
        updated = PUNCT_JOIN_RE.replace_all(&updated, "$1 $2").to_string();
        updated = ALLCAPS_JOIN_RE.replace_all(&updated, "$1 $2").to_string();
        updated = CAMEL_BREAK_RE.replace_all(&updated, "$1 $2").to_string();
        let normalized = updated
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        lines.push(normalized);
    }
    lines.join("\n")
}

fn strip_invisible_chars(text: &str) -> String {
    text.replace('\u{200B}', " ")
        .replace('\u{200C}', " ")
        .replace('\u{200D}', " ")
        .replace('\u{FEFF}', " ")
        .replace('\u{00AD}', "")
}

fn is_probable_code_line(line: &str) -> bool {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.starts_with("```") {
        return true;
    }
    let symbols = ['{', '}', ';', '=', '<', '>', '[', ']', '(', ')'];
    let symbol_hits = trimmed.chars().filter(|ch| symbols.contains(ch)).count();
    if symbol_hits >= 2 {
        return true;
    }
    trimmed.contains("::") || trimmed.contains("->") || trimmed.contains("=>")
}

fn extract_structured_html_text(html: &str, phrases: &[String]) -> String {
    let cleaned = SCRIPT_STYLE_RE.replace_all(html, "");
    let mut out = Vec::new();
    let mut list_count = 0usize;
    let mut global_paras = 0usize;
    let mut need_paragraph = false;

    for caps in STRUCTURED_RE.captures_iter(cleaned.as_ref()) {
        let tag = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        let raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        let text = clean_html_fragment(raw);
        if text.is_empty() {
            continue;
        }
        let lower = text.to_ascii_lowercase();
        if is_boilerplate_line(&text, &lower, phrases) {
            continue;
        }
        if tag.starts_with('h') {
            out.push(text);
            need_paragraph = true;
        } else if tag == "p" {
            if need_paragraph || global_paras < WEB_STRUCTURED_MAX_GLOBAL_PARAS {
                out.push(text);
                if need_paragraph {
                    need_paragraph = false;
                } else {
                    global_paras += 1;
                }
            }
        } else if tag == "li" {
            if list_count >= WEB_STRUCTURED_MAX_LIST_ITEMS {
                continue;
            }
            out.push(format!("- {text}"));
            list_count += 1;
        }
        if out.len() >= WEB_STRUCTURED_MAX_ITEMS {
            break;
        }
    }

    out.join("\n")
}

fn extract_code_blocks(html: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut seen = HashSet::new();
    for caps in CODE_BLOCK_RE.captures_iter(html) {
        let raw = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
        push_code_block(&mut blocks, &mut seen, raw, false);
        if blocks.len() >= MAX_CODE_BLOCKS {
            break;
        }
    }
    if blocks.len() < MAX_CODE_BLOCKS {
        for caps in CODE_TAG_RE.captures_iter(html) {
            let raw = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            push_code_block(&mut blocks, &mut seen, raw, true);
            if blocks.len() >= MAX_CODE_BLOCKS {
                break;
            }
        }
    }
    blocks
}

fn push_code_block(
    blocks: &mut Vec<String>,
    seen: &mut HashSet<String>,
    raw: &str,
    require_blocklike: bool,
) {
    let stripped = TAG_RE.replace_all(raw, "");
    let unescaped = html_unescape_text(stripped.as_ref());
    let normalized = unescaped.replace("\r\n", "\n");
    let trimmed = normalized.trim();
    if trimmed.is_empty() {
        return;
    }
    let cleaned = sanitize_code_block_text(trimmed);
    if cleaned.is_empty() {
        return;
    }
    if require_blocklike && !is_probable_code_block(&cleaned) {
        return;
    }
    let lowered = cleaned.to_ascii_lowercase();
    let key = normalize_line(&lowered);
    if key.is_empty() || !seen.insert(key) {
        return;
    }
    let (snippet, _) = truncate_utf8_chars(&cleaned, MAX_CODE_BLOCK_CHARS);
    blocks.push(snippet);
}

fn is_probable_code_block(text: &str) -> bool {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed.contains('\n') {
        return true;
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

fn hit_match_stats(
    query_tokens: &[String],
    query_len: usize,
    hit: &Hit,
) -> Option<(usize, f32)> {
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
    if query_len >= 3 { 2 } else { 1 }
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
enum QueryIntent {
    Code,
    Definition,
    General,
}

fn detect_query_intent(query: &str) -> QueryIntent {
    let query_lc = query.trim().to_ascii_lowercase();
    if query_lc.is_empty() {
        return QueryIntent::General;
    }
    let tokens = tokenize_terms(&query_lc);
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
            "define"
                | "definition"
                | "meaning"
                | "explain"
                | "overview"
                | "concept"
                | "what"
        )
    }) || query_lc.starts_with("what is ")
        || query_lc.starts_with("what's ");
    if definition_intent {
        return QueryIntent::Definition;
    }
    QueryIntent::General
}

fn join_code_blocks(blocks: &[String]) -> String {
    let mut output = String::new();
    for (idx, block) in blocks.iter().enumerate() {
        let trimmed = block.trim();
        if trimmed.is_empty() {
            continue;
        }
        if idx > 0 {
            output.push_str("\n\n");
        }
        output.push_str(trimmed);
    }
    output
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

fn select_code_blocks_for_query(query: &str, blocks: &[String]) -> Vec<String> {
    if blocks.is_empty() {
        return Vec::new();
    }
    let tokens = tokenize_terms(query);
    let max_keep = 3usize;
    if tokens.is_empty() {
        return blocks.iter().take(max_keep).cloned().collect();
    }
    let mut scored: Vec<(usize, usize)> = blocks
        .iter()
        .enumerate()
        .map(|(idx, block)| {
            let lower = block.to_ascii_lowercase();
            let score = tokens.iter().filter(|token| lower.contains(*token)).count();
            (score, idx)
        })
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let mut selected = Vec::new();
    for (score, idx) in scored.into_iter() {
        if score == 0 {
            break;
        }
        selected.push(blocks[idx].clone());
        if selected.len() >= max_keep {
            break;
        }
    }
    if selected.is_empty() {
        blocks.iter().take(max_keep.min(2)).cloned().collect()
    } else {
        selected
    }
}

fn extract_definition_sections(query: &str, html: &str, phrases: &[String]) -> Option<String> {
    let query_tokens = tokenize_terms(query);
    if query_tokens.is_empty() {
        return None;
    }
    let cleaned = SCRIPT_STYLE_RE.replace_all(html, "");
    let mut headings = Vec::new();
    for caps in HEADING_RE.captures_iter(&cleaned) {
        let mat = caps.get(0)?;
        let heading_raw = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        let heading = clean_html_fragment(heading_raw);
        if heading.is_empty() {
            continue;
        }
        let (heading_trimmed, _) = truncate_utf8_chars(&heading, WEB_HEADING_MAX_CHARS);
        headings.push((mat.start(), mat.end(), heading_trimmed));
    }
    if headings.is_empty() {
        return None;
    }
    let mut sections: Vec<(f32, usize, String, String)> = Vec::new();
    for idx in 0..headings.len() {
        let (_, end, heading_text) = &headings[idx];
        let slice_end = headings.get(idx + 1).map(|item| item.0).unwrap_or(cleaned.len());
        if slice_end <= *end {
            continue;
        }
        let slice = &cleaned[*end..slice_end];
        let para_caps = PARA_RE.captures(slice);
        let para_raw = match para_caps.and_then(|caps| caps.get(1)) {
            Some(m) => m.as_str(),
            None => continue,
        };
        let paragraph = clean_html_fragment(para_raw);
        if paragraph.is_empty() {
            continue;
        }
        let lower = paragraph.to_ascii_lowercase();
        if is_boilerplate_line(&paragraph, &lower, phrases)
            && !query_tokens.iter().any(|token| lower.contains(token))
        {
            continue;
        }
        let score = section_score(&query_tokens, heading_text, &paragraph);
        if score <= 0.0 {
            continue;
        }
        let (paragraph_trimmed, _) = truncate_utf8_chars(&paragraph, WEB_SECTION_MAX_CHARS);
        sections.push((score, idx, heading_text.clone(), paragraph_trimmed));
    }
    if sections.is_empty() {
        return None;
    }
    sections.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let keep = sections.len().min(WEB_DEF_SECTION_MAX);
    let mut selected: Vec<(usize, String, String)> = sections
        .into_iter()
        .take(keep)
        .map(|(_, idx, heading, paragraph)| (idx, heading, paragraph))
        .collect();
    selected.sort_by_key(|item| item.0);
    let mut output = String::new();
    for (pos, (_, heading, paragraph)) in selected.into_iter().enumerate() {
        if pos > 0 {
            output.push_str("\n\n");
        }
        output.push_str("## ");
        output.push_str(&heading);
        output.push('\n');
        output.push_str(&paragraph);
    }
    if output.trim().is_empty() {
        None
    } else {
        Some(output)
    }
}

fn section_score(query_tokens: &[String], heading: &str, paragraph: &str) -> f32 {
    if query_tokens.is_empty() {
        return 0.0;
    }
    let mut tokens = HashSet::new();
    collect_tokens(heading, &mut tokens);
    collect_tokens(paragraph, &mut tokens);
    if tokens.is_empty() {
        return 0.0;
    }
    let matched = query_tokens
        .iter()
        .filter(|token| tokens.contains(*token))
        .count();
    matched as f32 / query_tokens.len() as f32
}

fn clean_html_fragment(value: &str) -> String {
    let stripped = TAG_RE.replace_all(value, "");
    let unescaped = html_unescape_text(stripped.as_ref());
    unescaped.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn filter_boilerplate_text(query: &str, text: &str, phrases: &[String]) -> String {
    let query_tokens = tokenize_terms(query);
    let mut seen = HashSet::new();
    let mut kept = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        let normalized = normalize_line(&lower);
        if !query_tokens.is_empty()
            && query_tokens.iter().any(|token| lower.contains(token))
        {
            if seen.insert(normalized.clone()) {
                kept.push(truncate_line(trimmed));
            }
            continue;
        }
        if is_boilerplate_line(trimmed, &lower, phrases) {
            continue;
        }
        if seen.insert(normalized) {
            kept.push(truncate_line(trimmed));
        }
    }
    kept.join("\n")
}

#[derive(Debug, Clone)]
struct CookieFilterResult {
    filtered: String,
    removed_lines: usize,
    total_lines: usize,
}

fn strip_cookie_consent_lines(text: &str) -> CookieFilterResult {
    let mut kept = Vec::new();
    let mut removed = 0usize;
    let mut total = 0usize;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        total += 1;
        if is_cookie_consent_line(trimmed) {
            removed += 1;
            continue;
        }
        kept.push(trimmed);
    }
    CookieFilterResult {
        filtered: kept.join("\n"),
        removed_lines: removed,
        total_lines: total,
    }
}

fn is_cookie_only(result: &CookieFilterResult) -> bool {
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

fn is_cookie_consent_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let cookie_hit = lower.contains("cookie");
    let consent_hit = lower.contains("consent")
        || lower.contains("privacy")
        || lower.contains("preferences")
        || lower.contains("personalized")
        || lower.contains("analytics")
        || lower.contains("marketing")
        || lower.contains("tracking");
    let action_hit = lower.contains("accept")
        || lower.contains("reject")
        || lower.contains("manage")
        || lower.contains("settings")
        || lower.contains("agree");
    let policy_hit = lower.contains("cookie policy")
        || lower.contains("privacy policy")
        || lower.contains("terms of use")
        || lower.contains("data processing");
    let privacy_banner_hit = lower.contains("we value your privacy")
        || lower.contains("your privacy is important")
        || lower.contains("privacy choices")
        || lower.contains("privacy preferences")
        || lower.contains("privacy settings")
        || lower.contains("manage your privacy")
        || lower.contains("cookie preferences")
        || lower.contains("cookie settings")
        || lower.contains("manage cookies")
        || lower.contains("cookie consent");
    let banner_hit = lower.contains("we use cookies")
        || lower.contains("use of cookies")
        || lower.contains("cookie notice")
        || lower.contains("cookie banner")
        || lower.contains("your privacy")
        || privacy_banner_hit;
    if (cookie_hit || privacy_banner_hit) && (consent_hit || action_hit || policy_hit || banner_hit) {
        return true;
    }
    consent_hit && action_hit && banner_hit
}

fn normalize_line(line: &str) -> String {
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

fn truncate_line(line: &str) -> String {
    let max_chars = 320usize;
    if line.chars().count() <= max_chars {
        return line.to_string();
    }
    let mut out = String::new();
    let mut count = 0usize;
    for ch in line.chars() {
        if count >= max_chars {
            break;
        }
        out.push(ch);
        count += 1;
    }
    out.trim_end().to_string()
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
    let lower = html.to_ascii_lowercase();
    let patterns = [
        "just a moment",
        "enable javascript",
        "checking your browser",
        "verify you are human",
        "cloudflare",
        "attention required",
        "captcha",
        "cf-challenge",
        "ddos protection",
        "access denied",
    ];
    let mut hits = 0usize;
    for pat in patterns {
        if lower.contains(pat) {
            hits += 1;
        }
    }
    if hits < 2 {
        return false;
    }
    let trimmed = readable_text.trim();
    if trimmed.is_empty() {
        return true;
    }
    let text_len = trimmed.len();
    let word_count = trimmed.split_whitespace().count();
    let short_text = text_len < 500 || word_count < 80;
    short_text
}

fn count_ad_markers(html: &str) -> usize {
    let lower = html.to_ascii_lowercase();
    let markers = [
        "googlesyndication",
        "doubleclick",
        "adsbygoogle",
        "adservice",
        "taboola",
        "outbrain",
        "advertisement",
        "sponsored",
        "adslot",
        "ad-unit",
    ];
    markers.iter().filter(|pat| lower.contains(*pat)).count()
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
    if lower.contains("cookie")
        || lower.contains("gdpr")
        || lower.contains("consent")
        || lower.contains("privacy policy")
        || lower.contains("terms of service")
        || lower.contains("all rights reserved")
    {
        return len < 200;
    }
    if lower.contains("subscribe")
        || lower.contains("sign in")
        || lower.contains("log in")
        || lower.contains("sign up")
        || lower.contains("newsletter")
    {
        return len < 160;
    }
    if lower.starts_with("share")
        || lower.contains("facebook")
        || lower.contains("twitter")
        || lower.contains("linkedin")
    {
        return len < 120;
    }
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return len < 200;
    }
    let nav_keywords = [
        "home",
        "about",
        "contact",
        "privacy",
        "terms",
        "login",
        "sign",
        "menu",
        "categories",
        "related",
        "advertisement",
    ];
    let mut nav_hits = 0usize;
    for word in nav_keywords {
        if lower.contains(word) {
            nav_hits += 1;
        }
    }
    if nav_hits >= 2 && len < 140 {
        return true;
    }
    let separators = ['|', '•', '»', '›', '>', '/'];
    let sep_count = line.chars().filter(|ch| separators.contains(ch)).count();
    if len < 80 && sep_count >= 2 {
        return true;
    }
    let alpha_count = line.chars().filter(|ch| ch.is_ascii_alphabetic()).count();
    let ratio = alpha_count as f32 / len.max(1) as f32;
    if ratio < 0.55 && len < 120 {
        return true;
    }
    let token_count = line.split_whitespace().count();
    if len < 45 && token_count <= 3 {
        return true;
    }
    false
}

fn select_top_chunks(query: &str, text: &str) -> String {
    let query_tokens = tokenize_terms(query);
    if query_tokens.is_empty() {
        return text.trim().to_string();
    }
    let chunks = split_into_chunks(text, WEB_CHUNK_MAX_CHARS);
    if chunks.is_empty() {
        return String::new();
    }
    let mut scored: Vec<(usize, f32)> = Vec::new();
    for (idx, chunk) in chunks.iter().enumerate() {
        let mut chunk_tokens = HashSet::new();
        collect_tokens(chunk, &mut chunk_tokens);
        if chunk_tokens.is_empty() {
            scored.push((idx, 0.0));
            continue;
        }
        let matched = query_tokens
            .iter()
            .filter(|token| chunk_tokens.contains(*token))
            .count();
        let score = matched as f32 / query_tokens.len() as f32;
        scored.push((idx, score));
    }
    scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let keep = if chunks.len() <= WEB_CHUNK_MIN {
        chunks.len()
    } else {
        WEB_CHUNK_MAX.min(chunks.len())
    };
    let mut selected: Vec<usize> = scored.into_iter().take(keep).map(|pair| pair.0).collect();
    selected.sort_unstable();
    let mut output = String::new();
    for (pos, idx) in selected.into_iter().enumerate() {
        if let Some(chunk) = chunks.get(idx) {
            if pos > 0 {
                output.push_str("\n\n");
            }
            output.push_str(chunk.trim());
        }
    }
    output
}

fn split_into_chunks(text: &str, max_len: usize) -> Vec<String> {
    let mut chunks = Vec::new();
    let mut current = String::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if !current.trim().is_empty() {
                push_chunk(&mut chunks, &mut current, max_len);
            }
            continue;
        }
        if !current.is_empty() {
            current.push('\n');
        }
        current.push_str(trimmed);
        if current.len() >= max_len {
            push_chunk(&mut chunks, &mut current, max_len);
        }
    }
    if !current.trim().is_empty() {
        push_chunk(&mut chunks, &mut current, max_len);
    }
    chunks
}

fn push_chunk(chunks: &mut Vec<String>, current: &mut String, max_len: usize) {
    let trimmed = current.trim();
    if trimmed.is_empty() {
        current.clear();
        return;
    }
    let mut start = 0;
    while start < trimmed.len() {
        let mut end = start;
        let mut count = 0usize;
        let mut last_space = None;
        for (rel_idx, ch) in trimmed[start..].char_indices() {
            if count >= max_len {
                break;
            }
            let abs_idx = start + rel_idx;
            if ch.is_whitespace() {
                last_space = Some(abs_idx);
            }
            count += 1;
            end = abs_idx + ch.len_utf8();
        }
        let split_at = last_space.unwrap_or(end);
        let chunk = trimmed[start..split_at].trim();
        if !chunk.is_empty() {
            chunks.push(chunk.to_string());
        }
        start = split_at;
        while start < trimmed.len() {
            let ch = trimmed[start..].chars().next().unwrap();
            if ch.is_whitespace() {
                start += ch.len_utf8();
            } else {
                break;
            }
        }
    }
    current.clear();
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
        if stats.matched <= 1 { 0.75 } else { 1.0 }
    } else if stats.matched <= 1 {
        0.5
    } else if stats.overlap_ratio < 0.5 {
        0.8
    } else {
        1.0
    };
    (blended * penalty).clamp(0.0, 1.0)
}

fn local_hit_matches(query_tokens: &[String], hit: &Hit) -> bool {
    if query_tokens.is_empty() {
        return true;
    }
    let query_len = query_tokens.len();
    let min_required = min_required_matches(query_len);
    hit_match_stats(query_tokens, query_len, hit)
        .map(|(matched, _)| matched >= min_required)
        .unwrap_or(false)
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

fn env_usize(key: &str) -> Option<usize> {
    let raw = env::var(key).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<usize>().ok()
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

fn config_web_max_hits() -> Option<usize> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(config.search.max_web_hits)
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

fn resolve_web_limit(requested: Option<usize>, fallback: usize) -> usize {
    let mut limit = requested.unwrap_or(fallback);
    if let Some(max_hits) = env_usize("DOCDEX_WEB_MAX_HITS").or_else(config_web_max_hits) {
        if max_hits > 0 {
            limit = limit.min(max_hits);
        }
    }
    limit.max(1)
}
