use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, REFERER};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::env;
use std::hash::{Hash, Hasher};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::{Host, Url};

use crate::error::{AppError, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MISSING_DEPENDENCY};
use crate::state_layout::StateLayout;
use crate::web::cache;
use crate::web::ddg_policy::{DdgDiscoveryPacer, DdgDiscoveryPolicyConfig};
use crate::web::normalize::dedupe_urls;
use crate::web::policy::{
    host_matches_blocklist, public_dns_resolver, validate_outbound_url_structure,
};
use crate::web::WebConfig;

const PROVIDER: &str = "duckduckgo_lite";
const DDG_LITE_PROVIDER: &str = "duckduckgo_lite";
const SEARXNG_PROVIDER: &str = "searxng_json";
/// SearXNG defaults to the `general` category when none is supplied, which
/// leaves its whole `it` engine set (Stack Overflow, GitHub, MDN, crates.io,
/// package registries) idle. Docdex asks code and documentation questions, so
/// those engines carry more signal per request than extra general engines.
const SEARXNG_CATEGORIES: &str = "general,it";
const BRAVE_PROVIDER: &str = "brave";
const GOOGLE_CSE_PROVIDER: &str = "google_cse";
const BING_PROVIDER: &str = "bing";
const TAVILY_PROVIDER: &str = "tavily";
const EXA_PROVIDER: &str = "exa";
const MSWARM_PROVIDER: &str = "mswarm";
const MAX_DDG_RESULTS: usize = 50;
const DISCOVERY_RESPONSE_MAX_BYTES: usize = 2 * 1024 * 1024;
const DDG_PREFETCH_PAUSE_MIN_MS: u64 = 1_000;
const DDG_PREFETCH_PAUSE_MAX_MS: u64 = 2_000;
const DDG_TYPING_DELAY_MIN_MS: u64 = 50;
const DDG_TYPING_DELAY_MAX_MS: u64 = 200;
const DDG_TYPING_PAUSE_MS: u64 = 350;
const DDG_TYPING_MAX_TOTAL_MS: u64 = 2_000;
const DDG_LITE_FALLBACK_URL: &str = "https://lite.duckduckgo.com/lite/";
const DDG_BLOCK_WINDOW_SECS: u64 = 86_400;
const DDG_BLOCK_CACHE_KEY: &str = "ddg:block";
/// How long a provider stays disabled after a rate-limit (429) response.
const PROVIDER_RATE_LIMIT_BLOCK_SECS: u64 = 900;
/// How long a provider stays disabled after an auth/quota refusal.
///
/// "Quota exceeded for the current billing window" is terminal until that window
/// resets, so retrying every few seconds only burns CPU and, when the failure
/// cascades into a browser fallback, memory. We cannot read the reset time, so
/// back off far enough that a stuck provider costs a handful of probes per day
/// rather than thousands.
const PROVIDER_QUOTA_BLOCK_SECS: u64 = 3_600;
const BRAVE_API_URL: &str = "https://api.search.brave.com/res/v1/web/search";
const GOOGLE_CSE_API_URL: &str = "https://www.googleapis.com/customsearch/v1";
const BING_API_URL: &str = "https://api.bing.microsoft.com/v7.0/search";
const TAVILY_API_URL: &str = "https://api.tavily.com/search";
const EXA_API_URL: &str = "https://api.exa.ai/search";

static RESULT_LINK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)<a[^>]*(?:class="[^"]*\bresult__a\b[^"]*"|data-testid="result-title-a")[^>]*href=(?:"([^"]+)"|'([^']+)')"#,
    )
    .expect("valid ddg regex")
});
static HTML_HREF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?is)<a[^>]*href=(?:"([^"]+)"|'([^']+)')"#).expect("valid href regex")
});
static MARKDOWN_LINK_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"\((https?://[^\s)]+)\)"#).expect("valid markdown link regex"));
static DDG_CLIENTS: Lazy<Mutex<HashMap<String, reqwest::Client>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static SEARXNG_CLIENTS: Lazy<Mutex<HashMap<String, reqwest::Client>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));
static DDG_PREFETCHED_HOSTS: Lazy<Mutex<HashSet<String>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

pub struct DdgDiscovery {
    config: WebConfig,
    pacer: Mutex<DdgDiscoveryPacer>,
    client: reqwest::Client,
    searxng_client: reqwest::Client,
    blocklist: Vec<String>,
    cache_layout: Option<crate::state_layout::StateLayout>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebDiscoveryResult {
    pub url: String,
    /// Result title as reported by the provider, when it supplies one.
    ///
    /// Kept so relevance can be judged before paying to fetch the page; a URL
    /// alone cannot tell `en.wikipedia.org/wiki/Tokyo` apart from a genuine
    /// `tokio` hit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Provider-supplied result summary, when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
}

impl WebDiscoveryResult {
    pub fn from_url(url: String) -> Self {
        Self {
            url,
            title: None,
            snippet: None,
        }
    }

    /// Text a relevance check can score against: title, snippet, and the URL.
    pub fn match_text(&self) -> String {
        let mut text = String::new();
        if let Some(title) = self.title.as_deref() {
            text.push_str(title);
            text.push(' ');
        }
        if let Some(snippet) = self.snippet.as_deref() {
            text.push_str(snippet);
            text.push(' ');
        }
        text.push_str(&self.url);
        text
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebDiscoveryResponse {
    pub provider: String,
    pub query: String,
    pub results: Vec<WebDiscoveryResult>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct DdgBlockRecord {
    blocked_at_ms: u64,
    blocked_until_ms: u64,
    reason: String,
}

struct DiscoveryResponses {
    response_for_cache: WebDiscoveryResponse,
    response: WebDiscoveryResponse,
}

#[derive(Clone, Debug)]
enum FallbackProvider {
    DdgLite(Url),
    SearxngJson(Url),
    Brave {
        api_key: String,
        base_url: Url,
    },
    GoogleCse {
        api_key: String,
        cx: String,
        base_url: Url,
    },
    Bing {
        api_key: String,
        base_url: Url,
    },
    Tavily {
        api_key: String,
        base_url: Url,
    },
    Exa {
        api_key: String,
        base_url: Url,
    },
    Mswarm {
        api_key: String,
        base_url: Url,
    },
}

struct FallbackChain {
    providers: Vec<FallbackProvider>,
    next_index: usize,
    skip_ddg: bool,
    preferred_provider: Option<String>,
}

impl FallbackChain {
    fn new(config: &WebConfig, _prefer_api: bool, preferred_provider: Option<&str>) -> Self {
        let mut providers = Vec::new();
        if is_duckduckgo_host(&config.ddg_base_url) {
            if let Some(ddg_lite) = ddg_lite_fallback_base(&config.ddg_base_url) {
                providers.push(FallbackProvider::DdgLite(ddg_lite));
            }
        }

        let mut api_providers = Vec::new();
        let mut brave_provider = None;

        providers.extend(searxng_fallbacks(config));

        if let Some(api_key) = config.mswarm_api_key.as_deref().and_then(nonempty_value) {
            api_providers.push(FallbackProvider::Mswarm {
                api_key,
                base_url: config.mswarm_base_url.clone(),
            });
        }
        if let Some(api_key) = config.brave_api_key.as_deref().and_then(nonempty_value) {
            let base_url = url_from_env("DOCDEX_BRAVE_API_URL")
                .or_else(|| Url::parse(BRAVE_API_URL).ok())
                .unwrap_or_else(|| Url::parse(BRAVE_API_URL).expect("default brave url"));
            brave_provider = Some(FallbackProvider::Brave { api_key, base_url });
        }
        if let (Some(api_key), Some(cx)) = (
            config
                .google_cse_api_key
                .as_deref()
                .and_then(nonempty_value),
            config.google_cse_cx.as_deref().and_then(nonempty_value),
        ) {
            let base_url = url_from_env("DOCDEX_GOOGLE_CSE_API_URL")
                .or_else(|| Url::parse(GOOGLE_CSE_API_URL).ok())
                .unwrap_or_else(|| Url::parse(GOOGLE_CSE_API_URL).expect("default google cse url"));
            api_providers.push(FallbackProvider::GoogleCse {
                api_key,
                cx,
                base_url,
            });
        }
        if let Some(api_key) = config.bing_api_key.as_deref().and_then(nonempty_value) {
            let base_url = url_from_env("DOCDEX_BING_API_URL")
                .or_else(|| Url::parse(BING_API_URL).ok())
                .unwrap_or_else(|| Url::parse(BING_API_URL).expect("default bing url"));
            api_providers.push(FallbackProvider::Bing { api_key, base_url });
        }
        if let Some(api_key) = env_nonempty("DOCDEX_TAVILY_API_KEY") {
            let base_url = url_from_env("DOCDEX_TAVILY_API_URL")
                .or_else(|| Url::parse(TAVILY_API_URL).ok())
                .unwrap_or_else(|| Url::parse(TAVILY_API_URL).expect("default tavily url"));
            api_providers.push(FallbackProvider::Tavily { api_key, base_url });
        }
        if let Some(api_key) = env_nonempty("DOCDEX_EXA_API_KEY") {
            let base_url = url_from_env("DOCDEX_EXA_API_URL")
                .or_else(|| Url::parse(EXA_API_URL).ok())
                .unwrap_or_else(|| Url::parse(EXA_API_URL).expect("default exa url"));
            api_providers.push(FallbackProvider::Exa { api_key, base_url });
        }

        providers.extend(api_providers);
        if let Some(brave_provider) = brave_provider {
            providers.push(brave_provider);
        }
        if let Some(preferred_provider) = preferred_provider {
            prioritize_fallback_provider(&mut providers, preferred_provider);
        }
        Self {
            providers,
            next_index: 0,
            skip_ddg: false,
            preferred_provider: preferred_provider.map(|value| value.to_string()),
        }
    }

    fn next(&mut self) -> Option<FallbackProvider> {
        while self.next_index < self.providers.len() {
            let provider = self.providers[self.next_index].clone();
            self.next_index += 1;
            if self.skip_ddg && matches!(provider, FallbackProvider::DdgLite(_)) {
                continue;
            }
            return Some(provider);
        }
        None
    }

    fn skip_ddg(&mut self) {
        self.skip_ddg = true;
    }

    fn preferred_provider(&self) -> Option<&str> {
        self.preferred_provider.as_deref()
    }
}

impl DdgDiscovery {
    pub fn new(config: WebConfig) -> Result<Self> {
        let client = resolve_ddg_client(&config)?;
        let searxng_client = resolve_searxng_client(&config)?;
        let pacer_config = DdgDiscoveryPolicyConfig {
            min_spacing: config.policy.min_spacing,
            jitter_ms: config.policy.jitter_ms,
            base_backoff: config.policy.base_backoff,
            max_backoff: config.policy.max_backoff,
            max_consecutive_failures: config.policy.max_consecutive_failures.max(1) as u32,
            stop_backoff: config.policy.cooldown,
        };
        let blocklist = normalize_blocklist(&config.blocklist);
        let cache_layout = cache::cache_layout_from_config();
        Ok(Self {
            pacer: Mutex::new(DdgDiscoveryPacer::new(pacer_config)),
            config,
            client,
            searxng_client,
            blocklist,
            cache_layout,
        })
    }

    pub fn max_results(&self) -> usize {
        self.config.max_results
    }

    pub async fn discover(&self, query: &str, limit: usize) -> Result<WebDiscoveryResponse> {
        let query = query.trim();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }
        if !self.config.enabled {
            return Err(
                AppError::new(ERR_MISSING_DEPENDENCY, "web discovery is disabled")
                    .with_details(json!({ "dependency": "web_discovery" }))
                    .into(),
            );
        }

        let limit = limit.clamp(1, MAX_DDG_RESULTS);
        let cache_limit = self.config.max_results.max(limit).min(MAX_DDG_RESULTS);
        let attempts = self.config.policy.max_attempts.max(1);
        let selected_provider = normalized_provider_name(&self.config.discovery_provider);
        let preferred_fallback_provider =
            if selected_provider == DDG_LITE_PROVIDER || selected_provider == PROVIDER {
                None
            } else {
                Some(selected_provider.as_str())
            };
        let url = build_ddg_url(&self.config.ddg_base_url, query)?;
        let cache_key = discovery_cache_key(&self.config, &selected_provider, query);
        let mut proxy_attempted = false;
        let proxy_base_url = self.config.ddg_proxy_base_url.as_ref();

        if let Some(layout) = self.cache_layout.as_ref() {
            if let Ok(Some(payload)) =
                cache::read_cache_entry_with_ttl(layout, &cache_key, self.config.cache_ttl)
            {
                if let Ok(cached) = serde_json::from_slice::<WebDiscoveryResponse>(&payload) {
                    // Keep cached titles/snippets so a cache hit can still be
                    // relevance-filtered before anything is fetched.
                    return Ok(build_response_for_limit(
                        &cached.provider,
                        query,
                        self.filter_results(cached.results),
                        limit,
                    ));
                }
            }
        }
        let mut last_error: Option<anyhow::Error> = None;
        let mut fallback_chain: Option<FallbackChain> = None;

        if let Some(preferred_provider) = preferred_fallback_provider {
            if let Some(response) = self
                .maybe_fallback_discovery(
                    self.fallback_chain_for(&mut fallback_chain, false, Some(preferred_provider)),
                    query,
                    limit,
                    cache_limit,
                    &cache_key,
                    &mut last_error,
                )
                .await
            {
                return Ok(response);
            }
        }

        if self.ddg_blocked() {
            let chain =
                self.fallback_chain_for(&mut fallback_chain, true, preferred_fallback_provider);
            chain.skip_ddg();
            if let Some(response) = self
                .maybe_fallback_discovery(
                    chain,
                    query,
                    limit,
                    cache_limit,
                    &cache_key,
                    &mut last_error,
                )
                .await
            {
                return Ok(response);
            }
            return Err(AppError::new(
                ERR_INTERNAL_ERROR,
                "duckduckgo discovery blocked (cooldown)",
            )
            .into());
        }

        for attempt in 0..attempts {
            let backoff = { self.pacer.lock().check_or_backoff() };
            if let Err(err) = backoff {
                if let Some(response) = self
                    .maybe_proxy_discovery(
                        proxy_base_url,
                        &mut proxy_attempted,
                        query,
                        limit,
                        cache_limit,
                        &cache_key,
                        &mut last_error,
                    )
                    .await
                {
                    return Ok(response);
                }
                if let Some(response) = self
                    .maybe_fallback_discovery(
                        self.fallback_chain_for(
                            &mut fallback_chain,
                            false,
                            preferred_fallback_provider,
                        ),
                        query,
                        limit,
                        cache_limit,
                        &cache_key,
                        &mut last_error,
                    )
                    .await
                {
                    return Ok(response);
                }
                return Err(err.into());
            }

            self.prefetch_homepage(&self.config.ddg_base_url).await;
            self.humanized_delay(query).await;
            let referer = ddg_referer(&self.config.ddg_base_url);
            match self
                .client
                .get(url.clone())
                .header(REFERER, referer)
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        let body = match read_discovery_text(resp, "duckduckgo discovery").await {
                            Ok(body) => body,
                            Err(err) => {
                                let (backoff_error, failures, max_failures, stop_backoff) = {
                                    let mut pacer = self.pacer.lock();
                                    let backoff_error = pacer.record_failure();
                                    let failures = pacer.consecutive_failures();
                                    let max_failures = pacer.config().max_consecutive_failures;
                                    let stop_backoff = pacer.config().stop_backoff;
                                    (backoff_error, failures, max_failures, stop_backoff)
                                };
                                if (failures < max_failures || stop_backoff.is_zero())
                                    && retry_remaining(attempt, attempts)
                                {
                                    sleep_for_retry(&backoff_error).await;
                                    continue;
                                }
                                return Err(AppError::new(
                                    ERR_INTERNAL_ERROR,
                                    format!("duckduckgo discovery failed: {err}"),
                                )
                                .into());
                            }
                        };
                        if is_ddg_anomaly_page(&body) {
                            let (backoff_error, failures, max_failures, stop_backoff) = {
                                let mut pacer = self.pacer.lock();
                                let err = pacer.record_failure();
                                let failures = pacer.consecutive_failures();
                                let max_failures = pacer.config().max_consecutive_failures;
                                let stop_backoff = pacer.config().stop_backoff;
                                (err, failures, max_failures, stop_backoff)
                            };
                            self.mark_ddg_blocked("anomaly_page");
                            self.fallback_chain_for(
                                &mut fallback_chain,
                                true,
                                preferred_fallback_provider,
                            )
                            .skip_ddg();
                            if let Some(response) = self
                                .maybe_fallback_discovery(
                                    self.fallback_chain_for(
                                        &mut fallback_chain,
                                        true,
                                        preferred_fallback_provider,
                                    ),
                                    query,
                                    limit,
                                    cache_limit,
                                    &cache_key,
                                    &mut last_error,
                                )
                                .await
                            {
                                return Ok(response);
                            }
                            if failures >= max_failures && !stop_backoff.is_zero() {
                                return Err(backoff_error.into());
                            }
                            return Err(backoff_with_message(
                                backoff_error,
                                "duckduckgo discovery blocked (anomaly page)",
                            )
                            .into());
                        }
                        let links = extract_links(&body);
                        let filtered = self.filter_links(links);
                        if filtered.is_empty() {
                            let chain = self.fallback_chain_for(
                                &mut fallback_chain,
                                true,
                                preferred_fallback_provider,
                            );
                            chain.skip_ddg();
                            if let Some(response) = self
                                .maybe_fallback_discovery(
                                    chain,
                                    query,
                                    limit,
                                    cache_limit,
                                    &cache_key,
                                    &mut last_error,
                                )
                                .await
                            {
                                return Ok(response);
                            }
                            return Err(AppError::new(
                                ERR_INTERNAL_ERROR,
                                "duckduckgo discovery returned empty results",
                            )
                            .into());
                        }
                        let responses = build_discovery_responses(
                            PROVIDER,
                            query,
                            filtered,
                            limit,
                            cache_limit,
                        );
                        self.pacer.lock().record_success();
                        self.cache_response(&cache_key, &responses.response_for_cache);
                        return Ok(responses.response);
                    }

                    let (backoff_error, failures, max_failures, stop_backoff) = {
                        let mut pacer = self.pacer.lock();
                        let err = pacer.record_failure();
                        let failures = pacer.consecutive_failures();
                        let max_failures = pacer.config().max_consecutive_failures;
                        let stop_backoff = pacer.config().stop_backoff;
                        (err, failures, max_failures, stop_backoff)
                    };
                    if is_ddg_block_status(status) {
                        self.mark_ddg_blocked("http_status");
                        self.fallback_chain_for(
                            &mut fallback_chain,
                            true,
                            preferred_fallback_provider,
                        )
                        .skip_ddg();
                        if let Some(response) = self
                            .maybe_fallback_discovery(
                                self.fallback_chain_for(
                                    &mut fallback_chain,
                                    true,
                                    preferred_fallback_provider,
                                ),
                                query,
                                limit,
                                cache_limit,
                                &cache_key,
                                &mut last_error,
                            )
                            .await
                        {
                            return Ok(response);
                        }
                        if failures >= max_failures && !stop_backoff.is_zero() {
                            return Err(backoff_error.into());
                        }
                        return Err(backoff_with_message(
                            backoff_error,
                            format!("duckduckgo discovery blocked ({status})"),
                        )
                        .into());
                    }
                    if let Some(response) = self
                        .maybe_proxy_discovery(
                            proxy_base_url,
                            &mut proxy_attempted,
                            query,
                            limit,
                            cache_limit,
                            &cache_key,
                            &mut last_error,
                        )
                        .await
                    {
                        return Ok(response);
                    }
                    if let Some(response) = self
                        .maybe_fallback_discovery(
                            self.fallback_chain_for(
                                &mut fallback_chain,
                                false,
                                preferred_fallback_provider,
                            ),
                            query,
                            limit,
                            cache_limit,
                            &cache_key,
                            &mut last_error,
                        )
                        .await
                    {
                        return Ok(response);
                    }
                    if failures >= max_failures && !stop_backoff.is_zero() {
                        return Err(backoff_error.into());
                    }

                    if should_retry(status) {
                        if retry_remaining(attempt, attempts) {
                            sleep_for_retry(&backoff_error).await;
                            continue;
                        }
                        return Err(backoff_with_message(
                            backoff_error,
                            format!("duckduckgo discovery blocked ({status})"),
                        )
                        .into());
                    }
                    return Err(AppError::new(
                        ERR_INTERNAL_ERROR,
                        format!("duckduckgo discovery failed with status {status}"),
                    )
                    .into());
                }
                Err(err) => {
                    let (backoff_error, failures, max_failures, stop_backoff) = {
                        let mut pacer = self.pacer.lock();
                        let err = pacer.record_failure();
                        let failures = pacer.consecutive_failures();
                        let max_failures = pacer.config().max_consecutive_failures;
                        let stop_backoff = pacer.config().stop_backoff;
                        (err, failures, max_failures, stop_backoff)
                    };
                    if let Some(response) = self
                        .maybe_proxy_discovery(
                            proxy_base_url,
                            &mut proxy_attempted,
                            query,
                            limit,
                            cache_limit,
                            &cache_key,
                            &mut last_error,
                        )
                        .await
                    {
                        return Ok(response);
                    }
                    if let Some(response) = self
                        .maybe_fallback_discovery(
                            self.fallback_chain_for(
                                &mut fallback_chain,
                                false,
                                preferred_fallback_provider,
                            ),
                            query,
                            limit,
                            cache_limit,
                            &cache_key,
                            &mut last_error,
                        )
                        .await
                    {
                        return Ok(response);
                    }
                    if failures >= max_failures && !stop_backoff.is_zero() {
                        return Err(backoff_error.into());
                    }
                    if retry_remaining(attempt, attempts) {
                        sleep_for_retry(&backoff_error).await;
                        continue;
                    }
                    return Err(AppError::new(
                        ERR_INTERNAL_ERROR,
                        format!("duckduckgo discovery failed: {err}"),
                    )
                    .into());
                }
            }
        }

        let message = if let Some(err) = last_error {
            format!("duckduckgo discovery failed: {err}")
        } else {
            "duckduckgo discovery failed".to_string()
        };
        Err(AppError::new(ERR_INTERNAL_ERROR, message).into())
    }

    pub async fn discover_fallback_only(
        &self,
        query: &str,
        limit: usize,
    ) -> Result<WebDiscoveryResponse> {
        let query = query.trim();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }
        if !self.config.enabled {
            return Err(
                AppError::new(ERR_MISSING_DEPENDENCY, "web discovery is disabled")
                    .with_details(json!({ "dependency": "web_discovery" }))
                    .into(),
            );
        }

        let limit = limit.clamp(1, MAX_DDG_RESULTS);
        let cache_limit = self.config.max_results.max(limit).min(MAX_DDG_RESULTS);
        let selected_provider = normalized_provider_name(&self.config.discovery_provider);
        let preferred_fallback_provider =
            if selected_provider == DDG_LITE_PROVIDER || selected_provider == PROVIDER {
                None
            } else {
                Some(selected_provider.as_str())
            };
        let cache_key = discovery_cache_key(&self.config, &selected_provider, query);
        let mut last_error: Option<anyhow::Error> = None;
        let mut fallback_chain = None;
        let chain = self.fallback_chain_for(&mut fallback_chain, true, preferred_fallback_provider);
        chain.skip_ddg();
        if let Some(response) = self
            .maybe_fallback_discovery(
                chain,
                query,
                limit,
                cache_limit,
                &cache_key,
                &mut last_error,
            )
            .await
        {
            return Ok(response);
        }
        let message = if let Some(err) = last_error {
            format!("fallback discovery failed: {err}")
        } else {
            "fallback discovery failed".to_string()
        };
        Err(AppError::new(ERR_INTERNAL_ERROR, message).into())
    }

    fn filter_links(&self, links: Vec<String>) -> Vec<String> {
        let deduped = dedupe_urls(links);
        filter_blocked_urls(deduped, &self.blocklist)
    }

    /// Dedupe and blocklist-filter discovery results, keeping their metadata.
    fn filter_results(&self, results: Vec<WebDiscoveryResult>) -> Vec<WebDiscoveryResult> {
        let mut by_url: HashMap<String, WebDiscoveryResult> = HashMap::new();
        let urls: Vec<String> = results
            .into_iter()
            .map(|result| {
                let url = result.url.clone();
                by_url.entry(url.clone()).or_insert(result);
                url
            })
            .collect();
        self.filter_links(urls)
            .into_iter()
            .map(|url| {
                by_url
                    .remove(&url)
                    .unwrap_or_else(|| WebDiscoveryResult::from_url(url))
            })
            .collect()
    }

    fn cache_response(&self, cache_key: &str, response: &WebDiscoveryResponse) {
        if let Some(layout) = self.cache_layout.as_ref() {
            if self.config.cache_ttl.as_secs() > 0 {
                if let Ok(payload) = serde_json::to_vec(response) {
                    let _ = cache::write_cache_entry(layout, cache_key, &payload);
                }
            }
        }
    }

    fn fallback_chain_for<'a>(
        &self,
        chain: &'a mut Option<FallbackChain>,
        prefer_api: bool,
        preferred_provider: Option<&str>,
    ) -> &'a mut FallbackChain {
        let replace = match chain.as_ref() {
            Some(existing) => existing.preferred_provider() != preferred_provider,
            None => true,
        };
        if replace {
            *chain = Some(FallbackChain::new(
                &self.config,
                prefer_api,
                preferred_provider,
            ));
        }
        chain.as_mut().expect("fallback chain must exist")
    }

    /// True when `provider` is inside a block window from an earlier quota or
    /// auth refusal, so the chain should skip it entirely.
    fn provider_blocked(&self, provider: &str) -> bool {
        let Some(layout) = self.cache_layout.as_ref() else {
            return false;
        };
        load_provider_block_record(layout, provider).is_some()
    }

    /// Record a terminal provider refusal. Returns true when the status was
    /// terminal, so callers can distinguish "out of quota" from "no results".
    fn note_provider_status(&self, provider: &str, status: StatusCode) -> bool {
        let Some(window) = provider_block_window_secs(status) else {
            return false;
        };
        if let Some(layout) = self.cache_layout.as_ref() {
            write_provider_block_record(layout, provider, status.as_str(), window);
        }
        tracing::warn!(
            target: "docdexd_web",
            provider,
            status = status.as_u16(),
            block_secs = window,
            "discovery provider refused; disabling it for the block window instead of retrying"
        );
        true
    }

    fn ddg_blocked(&self) -> bool {
        let Some(layout) = self.cache_layout.as_ref() else {
            return false;
        };
        load_ddg_block_record(layout).is_some()
    }

    fn mark_ddg_blocked(&self, reason: &str) {
        let Some(layout) = self.cache_layout.as_ref() else {
            return;
        };
        write_ddg_block_record(layout, reason);
    }

    async fn maybe_proxy_discovery(
        &self,
        proxy_base_url: Option<&Url>,
        proxy_attempted: &mut bool,
        query: &str,
        limit: usize,
        cache_limit: usize,
        cache_key: &str,
        last_error: &mut Option<anyhow::Error>,
    ) -> Option<WebDiscoveryResponse> {
        if *proxy_attempted || proxy_base_url.is_none() {
            return None;
        }
        *proxy_attempted = true;
        let proxy_base_url = proxy_base_url?;
        match self
            .try_proxy_discovery(proxy_base_url, query, limit, cache_limit, cache_key)
            .await
        {
            Ok(Some(response)) => Some(response),
            Ok(None) => None,
            Err(err) => {
                *last_error = Some(err);
                None
            }
        }
    }

    async fn maybe_fallback_discovery(
        &self,
        fallback_chain: &mut FallbackChain,
        query: &str,
        limit: usize,
        cache_limit: usize,
        cache_key: &str,
        last_error: &mut Option<anyhow::Error>,
    ) -> Option<WebDiscoveryResponse> {
        while let Some(provider) = fallback_chain.next() {
            // A provider inside its block window refused us for a reason that
            // does not clear between requests, so do not spend a round trip on
            // it at all.
            let name = fallback_provider_name(&provider);
            if self.provider_blocked(name) {
                tracing::debug!(
                    target: "docdexd_web",
                    provider = name,
                    "skipping discovery provider inside its block window"
                );
                continue;
            }
            let attempt = self
                .try_fallback_provider(provider, query, limit, cache_limit, cache_key)
                .await;
            match attempt {
                Ok(Some(response)) => return Some(response),
                Ok(None) => continue,
                Err(err) => {
                    *last_error = Some(err);
                    continue;
                }
            }
        }
        None
    }

    async fn try_fallback_provider(
        &self,
        provider: FallbackProvider,
        query: &str,
        limit: usize,
        cache_limit: usize,
        cache_key: &str,
    ) -> Result<Option<WebDiscoveryResponse>> {
        match provider {
            FallbackProvider::DdgLite(base_url) => {
                self.try_ddg_lite_discovery(&base_url, query, limit, cache_limit, cache_key)
                    .await
            }
            FallbackProvider::SearxngJson(base_url) => {
                self.try_searxng_discovery(&base_url, query, limit, cache_limit, cache_key)
                    .await
            }
            FallbackProvider::Brave { api_key, base_url } => {
                self.try_brave_discovery(&base_url, &api_key, query, limit, cache_limit, cache_key)
                    .await
            }
            FallbackProvider::GoogleCse {
                api_key,
                cx,
                base_url,
            } => {
                self.try_google_cse_discovery(
                    &base_url,
                    &api_key,
                    &cx,
                    query,
                    limit,
                    cache_limit,
                    cache_key,
                )
                .await
            }
            FallbackProvider::Bing { api_key, base_url } => {
                self.try_bing_discovery(&base_url, &api_key, query, limit, cache_limit, cache_key)
                    .await
            }
            FallbackProvider::Tavily { api_key, base_url } => {
                self.try_tavily_discovery(&base_url, &api_key, query, limit, cache_limit, cache_key)
                    .await
            }
            FallbackProvider::Exa { api_key, base_url } => {
                self.try_exa_discovery(&base_url, &api_key, query, limit, cache_limit, cache_key)
                    .await
            }
            FallbackProvider::Mswarm { api_key, base_url } => {
                self.try_mswarm_discovery(&base_url, &api_key, query, limit, cache_limit, cache_key)
                    .await
            }
        }
    }

    async fn try_ddg_lite_discovery(
        &self,
        fallback_base_url: &Url,
        query: &str,
        limit: usize,
        cache_limit: usize,
        cache_key: &str,
    ) -> Result<Option<WebDiscoveryResponse>> {
        self.prefetch_homepage(fallback_base_url).await;
        self.humanized_delay(query).await;
        let referer = ddg_referer(fallback_base_url);
        let fallback_url = build_ddg_url(fallback_base_url, query)?;
        let resp = self
            .client
            .get(fallback_url)
            .header(REFERER, referer)
            .send()
            .await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let body = read_discovery_text(resp, "duckduckgo fallback discovery").await?;
        if is_ddg_anomaly_page(&body) {
            return Ok(None);
        }
        let mut links = extract_ddg_lite_links(&body);
        if links.is_empty() {
            links = extract_links(&body);
        }
        let filtered = self.filter_links(links);
        if filtered.is_empty() {
            return Ok(None);
        }
        let responses =
            build_discovery_responses(DDG_LITE_PROVIDER, query, filtered, limit, cache_limit);
        self.cache_response(cache_key, &responses.response_for_cache);
        Ok(Some(responses.response))
    }

    async fn try_searxng_discovery(
        &self,
        base_url: &Url,
        query: &str,
        limit: usize,
        cache_limit: usize,
        cache_key: &str,
    ) -> Result<Option<WebDiscoveryResponse>> {
        let url = build_searxng_url(base_url, query)?;
        let resp = self.searxng_client.get(url).send().await?;
        if !resp.status().is_success() {
            self.note_provider_status(SEARXNG_PROVIDER, resp.status());
            return Ok(None);
        }
        let body = read_discovery_text(resp, "searxng discovery").await?;
        let results = extract_searxng_results(&body)?;
        let filtered = self.filter_results(results);
        if filtered.is_empty() {
            return Ok(None);
        }
        let responses = build_discovery_responses_with_meta(
            SEARXNG_PROVIDER,
            query,
            filtered,
            limit,
            cache_limit,
        );
        self.cache_response(cache_key, &responses.response_for_cache);
        Ok(Some(responses.response))
    }

    async fn try_brave_discovery(
        &self,
        base_url: &Url,
        api_key: &str,
        query: &str,
        limit: usize,
        cache_limit: usize,
        cache_key: &str,
    ) -> Result<Option<WebDiscoveryResponse>> {
        let count = limit.min(20);
        let url = build_brave_url(base_url, query, count)?;
        let mut resp = self
            .client
            .get(url.clone())
            .header("X-Subscription-Token", api_key)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .send()
            .await?;
        if resp.status() == StatusCode::TOO_MANY_REQUESTS {
            tokio::time::sleep(Duration::from_secs(1)).await;
            resp = self
                .client
                .get(url)
                .header("X-Subscription-Token", api_key)
                .header(ACCEPT, HeaderValue::from_static("application/json"))
                .send()
                .await?;
        }
        if !resp.status().is_success() {
            self.note_provider_status(BRAVE_PROVIDER, resp.status());
            return Ok(None);
        }
        let body = read_discovery_json(resp, "brave discovery").await?;
        let links = extract_brave_links(&body);
        let filtered = self.filter_links(links);
        if filtered.is_empty() {
            return Ok(None);
        }
        let responses =
            build_discovery_responses(BRAVE_PROVIDER, query, filtered, limit, cache_limit);
        self.cache_response(cache_key, &responses.response_for_cache);
        Ok(Some(responses.response))
    }

    async fn try_google_cse_discovery(
        &self,
        base_url: &Url,
        api_key: &str,
        cx: &str,
        query: &str,
        limit: usize,
        cache_limit: usize,
        cache_key: &str,
    ) -> Result<Option<WebDiscoveryResponse>> {
        let count = limit.min(10);
        let url = build_google_cse_url(base_url, query, count, api_key, cx)?;
        let resp = self.client.get(url).send().await?;
        if !resp.status().is_success() {
            self.note_provider_status(GOOGLE_CSE_PROVIDER, resp.status());
            return Ok(None);
        }
        let body = read_discovery_json(resp, "google cse discovery").await?;
        let links = extract_google_cse_links(&body);
        let filtered = self.filter_links(links);
        if filtered.is_empty() {
            return Ok(None);
        }
        let responses =
            build_discovery_responses(GOOGLE_CSE_PROVIDER, query, filtered, limit, cache_limit);
        self.cache_response(cache_key, &responses.response_for_cache);
        Ok(Some(responses.response))
    }

    async fn try_bing_discovery(
        &self,
        base_url: &Url,
        api_key: &str,
        query: &str,
        limit: usize,
        cache_limit: usize,
        cache_key: &str,
    ) -> Result<Option<WebDiscoveryResponse>> {
        let count = limit.min(50);
        let url = build_bing_url(base_url, query, count)?;
        let resp = self
            .client
            .get(url)
            .header("Ocp-Apim-Subscription-Key", api_key)
            .send()
            .await?;
        if !resp.status().is_success() {
            self.note_provider_status(BING_PROVIDER, resp.status());
            return Ok(None);
        }
        let body = read_discovery_json(resp, "bing discovery").await?;
        let links = extract_bing_links(&body);
        let filtered = self.filter_links(links);
        if filtered.is_empty() {
            return Ok(None);
        }
        let responses =
            build_discovery_responses(BING_PROVIDER, query, filtered, limit, cache_limit);
        self.cache_response(cache_key, &responses.response_for_cache);
        Ok(Some(responses.response))
    }

    async fn try_tavily_discovery(
        &self,
        base_url: &Url,
        api_key: &str,
        query: &str,
        limit: usize,
        cache_limit: usize,
        cache_key: &str,
    ) -> Result<Option<WebDiscoveryResponse>> {
        let payload = json!({
            "api_key": api_key,
            "query": query,
            "max_results": limit,
            "search_depth": "basic",
        });
        let resp = self
            .client
            .post(base_url.clone())
            .json(&payload)
            .send()
            .await?;
        if !resp.status().is_success() {
            self.note_provider_status(TAVILY_PROVIDER, resp.status());
            return Ok(None);
        }
        let body = read_discovery_json(resp, "tavily discovery").await?;
        let links = extract_json_links(&body);
        let filtered = self.filter_links(links);
        if filtered.is_empty() {
            return Ok(None);
        }
        let responses =
            build_discovery_responses(TAVILY_PROVIDER, query, filtered, limit, cache_limit);
        self.cache_response(cache_key, &responses.response_for_cache);
        Ok(Some(responses.response))
    }

    async fn try_exa_discovery(
        &self,
        base_url: &Url,
        api_key: &str,
        query: &str,
        limit: usize,
        cache_limit: usize,
        cache_key: &str,
    ) -> Result<Option<WebDiscoveryResponse>> {
        let payload = json!({
            "query": query,
            "num_results": limit,
        });
        let resp = self
            .client
            .post(base_url.clone())
            .header("x-api-key", api_key)
            .header(reqwest::header::AUTHORIZATION, format!("Bearer {api_key}"))
            .json(&payload)
            .send()
            .await?;
        if !resp.status().is_success() {
            self.note_provider_status(EXA_PROVIDER, resp.status());
            return Ok(None);
        }
        let body = read_discovery_json(resp, "exa discovery").await?;
        let links = extract_json_links(&body);
        let filtered = self.filter_links(links);
        if filtered.is_empty() {
            return Ok(None);
        }
        let responses =
            build_discovery_responses(EXA_PROVIDER, query, filtered, limit, cache_limit);
        self.cache_response(cache_key, &responses.response_for_cache);
        Ok(Some(responses.response))
    }

    async fn try_mswarm_discovery(
        &self,
        base_url: &Url,
        api_key: &str,
        query: &str,
        limit: usize,
        cache_limit: usize,
        cache_key: &str,
    ) -> Result<Option<WebDiscoveryResponse>> {
        let url = build_mswarm_search_url(base_url)?;
        let payload = json!({
            "query": query,
            "tool_id": "docdex",
        });
        let resp = self
            .client
            .post(url)
            .header("x-api-key", api_key)
            .header(ACCEPT, HeaderValue::from_static("application/json"))
            .json(&payload)
            .send()
            .await?;
        if !resp.status().is_success() {
            self.note_provider_status(MSWARM_PROVIDER, resp.status());
            return Ok(None);
        }
        let body = read_discovery_json(resp, "mswarm discovery").await?;
        let links = extract_json_links(&body);
        let filtered = self.filter_links(links);
        if filtered.is_empty() {
            return Ok(None);
        }
        let responses =
            build_discovery_responses(MSWARM_PROVIDER, query, filtered, limit, cache_limit);
        self.cache_response(cache_key, &responses.response_for_cache);
        Ok(Some(responses.response))
    }

    async fn prefetch_homepage(&self, base_url: &Url) {
        let Some(host) = base_url.host_str() else {
            return;
        };
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() {
            return;
        }
        {
            let mut guard = DDG_PREFETCHED_HOSTS.lock();
            if guard.contains(&host) {
                return;
            }
            guard.insert(host.clone());
        }
        let mut url = base_url.clone();
        url.set_query(None);
        let _ = self.client.get(url).send().await;
        let pause = random_delay_ms(DDG_PREFETCH_PAUSE_MIN_MS, DDG_PREFETCH_PAUSE_MAX_MS);
        if !pause.is_zero() {
            tokio::time::sleep(pause).await;
        }
    }

    async fn humanized_delay(&self, query: &str) {
        let delay = typing_delay_for_query(query);
        if !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
    }

    async fn try_proxy_discovery(
        &self,
        proxy_base_url: &Url,
        query: &str,
        limit: usize,
        cache_limit: usize,
        cache_key: &str,
    ) -> Result<Option<WebDiscoveryResponse>> {
        let proxy_url = build_ddg_url(proxy_base_url, query)?;
        let resp = self.client.get(proxy_url).send().await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let body = read_discovery_text(resp, "duckduckgo proxy discovery").await?;
        if is_ddg_anomaly_page(&body) {
            return Ok(None);
        }
        let links = extract_links(&body);
        let filtered = self.filter_links(links);
        if filtered.is_empty() {
            return Ok(None);
        }
        let responses = build_discovery_responses(PROVIDER, query, filtered, limit, cache_limit);
        self.cache_response(cache_key, &responses.response_for_cache);
        Ok(Some(responses.response))
    }
}

async fn read_discovery_body_limited(
    mut response: reqwest::Response,
    label: &str,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(AppError::new(
            ERR_INTERNAL_ERROR,
            format!("{label} response exceeds the {max_bytes}-byte limit"),
        )
        .into());
    }

    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(max_bytes as u64) as usize,
    );
    while let Some(chunk) = response.chunk().await.map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("{label} response read failed: {err}"),
        )
    })? {
        if body.len().saturating_add(chunk.len()) > max_bytes {
            return Err(AppError::new(
                ERR_INTERNAL_ERROR,
                format!("{label} response exceeds the {max_bytes}-byte limit"),
            )
            .into());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn read_discovery_text(response: reqwest::Response, label: &str) -> Result<String> {
    let body = read_discovery_body_limited(response, label, DISCOVERY_RESPONSE_MAX_BYTES).await?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

async fn read_discovery_json(response: reqwest::Response, label: &str) -> Result<Value> {
    let body = read_discovery_body_limited(response, label, DISCOVERY_RESPONSE_MAX_BYTES).await?;
    serde_json::from_slice(&body).map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("{label} returned invalid JSON: {err}"),
        )
        .into()
    })
}

fn build_ddg_url(base: &Url, query: &str) -> Result<Url> {
    let mut url = base.clone();
    url.query_pairs_mut().append_pair("q", query);
    Ok(url)
}

fn build_searxng_url(base: &Url, query: &str) -> Result<Url> {
    let mut url = base.clone();
    url.query_pairs_mut()
        .append_pair("q", query)
        .append_pair("format", "json")
        .append_pair("categories", SEARXNG_CATEGORIES);
    Ok(url)
}

fn build_brave_url(base: &Url, query: &str, count: usize) -> Result<Url> {
    let mut url = base.clone();
    url.query_pairs_mut()
        .append_pair("q", query)
        .append_pair("count", &count.to_string())
        .append_pair("safesearch", "moderate");
    Ok(url)
}

fn build_google_cse_url(
    base: &Url,
    query: &str,
    count: usize,
    api_key: &str,
    cx: &str,
) -> Result<Url> {
    let mut url = base.clone();
    url.query_pairs_mut()
        .append_pair("q", query)
        .append_pair("key", api_key)
        .append_pair("cx", cx)
        .append_pair("num", &count.to_string())
        .append_pair("start", "1");
    Ok(url)
}

fn build_bing_url(base: &Url, query: &str, count: usize) -> Result<Url> {
    let mut url = base.clone();
    url.query_pairs_mut()
        .append_pair("q", query)
        .append_pair("count", &count.to_string())
        .append_pair("offset", "0")
        .append_pair("mkt", "en-US")
        .append_pair("safesearch", "Moderate");
    Ok(url)
}

fn ddg_referer(base: &Url) -> HeaderValue {
    let mut url = base.clone();
    url.set_query(None);
    HeaderValue::from_str(url.as_str()).unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn ddg_lite_fallback_base(base: &Url) -> Option<Url> {
    if !is_duckduckgo_host(base) {
        return None;
    }
    if base
        .as_str()
        .to_ascii_lowercase()
        .contains("lite.duckduckgo.com")
    {
        return None;
    }
    Url::parse(DDG_LITE_FALLBACK_URL).ok()
}

fn is_duckduckgo_host(base: &Url) -> bool {
    base.host_str()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .ends_with("duckduckgo.com")
}

fn is_loopback_url(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(ip)) => ip.is_loopback(),
        Some(Host::Ipv6(ip)) => ip.is_loopback(),
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn discovery_cache_key(config: &WebConfig, provider: &str, query: &str) -> String {
    let searxng_origins = config
        .searxng_urls
        .iter()
        .map(Url::as_str)
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "discovery:{provider}:ddg={}:searxng={searxng_origins}:mswarm={}:q={query}",
        config.ddg_base_url, config.mswarm_base_url
    )
}

fn ddg_block_entry(layout: &StateLayout) -> std::path::PathBuf {
    cache::cache_entry_for_url(layout, DDG_BLOCK_CACHE_KEY)
}

/// Terminal-for-window responses from a discovery provider.
///
/// These mean "stop asking", not "try again": an exhausted quota or a rejected
/// key does not recover between requests seconds apart.
fn provider_block_window_secs(status: StatusCode) -> Option<u64> {
    match status {
        StatusCode::TOO_MANY_REQUESTS => Some(PROVIDER_RATE_LIMIT_BLOCK_SECS),
        StatusCode::UNAUTHORIZED | StatusCode::PAYMENT_REQUIRED | StatusCode::FORBIDDEN => {
            Some(PROVIDER_QUOTA_BLOCK_SECS)
        }
        _ => None,
    }
}

fn provider_block_cache_key(provider: &str) -> String {
    format!("provider:block:{provider}")
}

fn load_provider_block_record(layout: &StateLayout, provider: &str) -> Option<DdgBlockRecord> {
    let entry = cache::cache_entry_for_url(layout, &provider_block_cache_key(provider));
    if !entry.exists() {
        return None;
    }
    let payload = std::fs::read(&entry).ok()?;
    let record: DdgBlockRecord = serde_json::from_slice(&payload).ok()?;
    if now_ms() >= record.blocked_until_ms {
        let _ = std::fs::remove_file(&entry);
        return None;
    }
    Some(record)
}

fn write_provider_block_record(
    layout: &StateLayout,
    provider: &str,
    reason: &str,
    window_secs: u64,
) {
    let now = now_ms();
    let record = DdgBlockRecord {
        blocked_at_ms: now,
        blocked_until_ms: now.saturating_add(window_secs.saturating_mul(1_000)),
        reason: reason.to_string(),
    };
    if let Ok(payload) = serde_json::to_vec(&record) {
        let _ = cache::write_cache_entry(layout, &provider_block_cache_key(provider), &payload);
    }
}

fn load_ddg_block_record(layout: &StateLayout) -> Option<DdgBlockRecord> {
    let entry = ddg_block_entry(layout);
    if !entry.exists() {
        return None;
    }
    let payload = std::fs::read(&entry).ok()?;
    let record: DdgBlockRecord = serde_json::from_slice(&payload).ok()?;
    if now_ms() >= record.blocked_until_ms {
        let _ = std::fs::remove_file(&entry);
        return None;
    }
    Some(record)
}

fn write_ddg_block_record(layout: &StateLayout, reason: &str) {
    let now = now_ms();
    let window_ms = DDG_BLOCK_WINDOW_SECS.saturating_mul(1_000);
    let record = DdgBlockRecord {
        blocked_at_ms: now,
        blocked_until_ms: now.saturating_add(window_ms),
        reason: reason.to_string(),
    };
    if let Ok(payload) = serde_json::to_vec(&record) {
        let _ = cache::write_cache_entry(layout, DDG_BLOCK_CACHE_KEY, &payload);
    }
}

fn build_response_for_limit(
    provider: &str,
    query: &str,
    mut results: Vec<WebDiscoveryResult>,
    limit: usize,
) -> WebDiscoveryResponse {
    if results.len() > limit {
        results.truncate(limit);
    }
    WebDiscoveryResponse {
        provider: provider.to_string(),
        query: query.to_string(),
        results,
    }
}

fn build_discovery_responses(
    provider: &str,
    query: &str,
    urls: Vec<String>,
    limit: usize,
    cache_limit: usize,
) -> DiscoveryResponses {
    build_discovery_responses_with_meta(
        provider,
        query,
        urls.into_iter().map(WebDiscoveryResult::from_url).collect(),
        limit,
        cache_limit,
    )
}

/// Same as [`build_discovery_responses`] but keeps provider-supplied titles and
/// snippets, so downstream relevance checks have something to score.
fn build_discovery_responses_with_meta(
    provider: &str,
    query: &str,
    results: Vec<WebDiscoveryResult>,
    limit: usize,
    cache_limit: usize,
) -> DiscoveryResponses {
    let response_for_cache = build_response_for_limit(provider, query, results, cache_limit);
    let response =
        build_response_for_limit(provider, query, response_for_cache.results.clone(), limit);
    DiscoveryResponses {
        response_for_cache,
        response,
    }
}

fn build_mswarm_search_url(base: &Url) -> Result<Url> {
    base.join("/v1/swarm/web/search")
        .context("build mswarm web search url")
}

fn extract_links(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    for caps in RESULT_LINK_RE.captures_iter(html) {
        let href = caps
            .get(1)
            .or_else(|| caps.get(2))
            .map(|m| m.as_str())
            .unwrap_or_default();
        let href = html_unescape_attr(href);
        if !href.is_empty() {
            out.push(href);
        }
    }
    if !out.is_empty() {
        return out;
    }
    extract_markdown_links(html)
}

/// Parse SearXNG JSON keeping the title and snippet alongside each URL.
fn extract_searxng_results(body: &str) -> Result<Vec<WebDiscoveryResult>> {
    let value: Value = serde_json::from_str(body).map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("searxng discovery failed: {err}"),
        )
    })?;
    let entries = value
        .get("results")
        .and_then(|results| results.as_array())
        .map(|items| items.as_slice())
        .unwrap_or_default();
    let mut out = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(url) = entry
            .get("url")
            .and_then(|url| url.as_str())
            .or_else(|| entry.get("link").and_then(|url| url.as_str()))
        else {
            continue;
        };
        out.push(WebDiscoveryResult {
            url: url.to_string(),
            title: json_text_field(entry, "title"),
            // SearXNG names the result summary `content`.
            snippet: json_text_field(entry, "content"),
        });
    }
    Ok(out)
}

fn json_text_field(entry: &Value, key: &str) -> Option<String> {
    entry
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn extract_brave_links(value: &Value) -> Vec<String> {
    value
        .get("web")
        .and_then(|web| web.get("results"))
        .and_then(|results| results.as_array())
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry
                .get("url")
                .and_then(|url| url.as_str())
                .map(|url| url.to_string())
        })
        .collect()
}

fn extract_google_cse_links(value: &Value) -> Vec<String> {
    value
        .get("items")
        .and_then(|items| items.as_array())
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry
                .get("link")
                .and_then(|url| url.as_str())
                .map(|url| url.to_string())
        })
        .collect()
}

fn extract_bing_links(value: &Value) -> Vec<String> {
    value
        .get("webPages")
        .and_then(|web| web.get("value"))
        .and_then(|results| results.as_array())
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry
                .get("url")
                .and_then(|url| url.as_str())
                .map(|url| url.to_string())
        })
        .collect()
}

fn extract_ddg_lite_links(html: &str) -> Vec<String> {
    let mut out = Vec::new();
    for caps in HTML_HREF_RE.captures_iter(html) {
        let href = caps
            .get(1)
            .or_else(|| caps.get(2))
            .map(|m| m.as_str())
            .unwrap_or_default();
        let href = html_unescape_attr(href);
        if let Some(url) = normalize_ddg_lite_href(&href) {
            out.push(url);
        }
    }
    out
}

fn normalize_ddg_lite_href(href: &str) -> Option<String> {
    let trimmed = href.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("/l/") {
        let base = Url::parse("https://duckduckgo.com").ok()?;
        return base.join(trimmed).ok().map(|url| url.to_string());
    }
    if !trimmed.starts_with("http://") && !trimmed.starts_with("https://") {
        return None;
    }
    let url = Url::parse(trimmed).ok()?;
    if let Some(host) = url.host_str() {
        let host = host.to_ascii_lowercase();
        if host.ends_with("duckduckgo.com") {
            if url.path().starts_with("/l/") {
                return Some(url.to_string());
            }
            if url.query_pairs().any(|(key, _)| key == "uddg") {
                return Some(url.to_string());
            }
            return None;
        }
    }
    Some(url.to_string())
}

fn extract_markdown_links(markdown: &str) -> Vec<String> {
    let mut out = Vec::new();
    let content = markdown
        .split("Markdown Content:")
        .nth(1)
        .unwrap_or(markdown);
    for caps in MARKDOWN_LINK_RE.captures_iter(content) {
        if let Some(m) = caps.get(1) {
            out.push(m.as_str().to_string());
        }
    }
    out
}

fn extract_json_links(value: &Value) -> Vec<String> {
    value
        .get("results")
        .and_then(|results| results.as_array())
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry
                .get("url")
                .and_then(|url| url.as_str())
                .map(|url| url.to_string())
                .or_else(|| {
                    entry
                        .get("link")
                        .and_then(|url| url.as_str())
                        .map(|url| url.to_string())
                })
        })
        .collect()
}

fn normalized_provider_name(raw: &str) -> String {
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "duckduckgo" | "duckduckgo_lite" | "ddg" => DDG_LITE_PROVIDER.to_string(),
        "searxng" | "searxng_json" => SEARXNG_PROVIDER.to_string(),
        "brave" => BRAVE_PROVIDER.to_string(),
        "google" | "google_cse" => GOOGLE_CSE_PROVIDER.to_string(),
        "bing" => BING_PROVIDER.to_string(),
        "tavily" => TAVILY_PROVIDER.to_string(),
        "exa" => EXA_PROVIDER.to_string(),
        "mswarm" => MSWARM_PROVIDER.to_string(),
        _ => DDG_LITE_PROVIDER.to_string(),
    }
}

fn fallback_provider_name(provider: &FallbackProvider) -> &'static str {
    match provider {
        FallbackProvider::DdgLite(_) => DDG_LITE_PROVIDER,
        FallbackProvider::SearxngJson(_) => SEARXNG_PROVIDER,
        FallbackProvider::Brave { .. } => BRAVE_PROVIDER,
        FallbackProvider::GoogleCse { .. } => GOOGLE_CSE_PROVIDER,
        FallbackProvider::Bing { .. } => BING_PROVIDER,
        FallbackProvider::Tavily { .. } => TAVILY_PROVIDER,
        FallbackProvider::Exa { .. } => EXA_PROVIDER,
        FallbackProvider::Mswarm { .. } => MSWARM_PROVIDER,
    }
}

fn prioritize_fallback_provider(providers: &mut Vec<FallbackProvider>, preferred_provider: &str) {
    if let Some(index) = providers
        .iter()
        .position(|provider| fallback_provider_name(provider) == preferred_provider)
    {
        let provider = providers.remove(index);
        providers.insert(0, provider);
    }
}

fn is_ddg_anomaly_page(html: &str) -> bool {
    let body = html.to_ascii_lowercase();
    body.contains("anomaly.js")
        || body.contains("anomaly-modal")
        || body.contains("challenge-form")
        || body.contains("cc=botnet")
        || body.contains("cc=sre")
}

fn html_unescape_attr(value: &str) -> String {
    value
        .replace("&amp;", "&")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&#x27;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
}

fn should_retry(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS
        || status == StatusCode::FORBIDDEN
        || status.is_server_error()
}

fn retry_remaining(attempt: usize, attempts: usize) -> bool {
    attempt.saturating_add(1) < attempts
}

async fn sleep_for_retry(backoff: &AppError) {
    let retry_after_ms = backoff
        .details
        .as_ref()
        .and_then(|details| details.get("retry_after_ms"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    if retry_after_ms > 0 {
        tokio::time::sleep(Duration::from_millis(retry_after_ms)).await;
    }
}

fn is_ddg_block_status(status: StatusCode) -> bool {
    status == StatusCode::TOO_MANY_REQUESTS || status == StatusCode::FORBIDDEN
}

fn backoff_with_message(err: AppError, message: impl Into<String>) -> AppError {
    AppError {
        code: err.code,
        message: message.into(),
        details: err.details,
    }
}

fn resolve_ddg_client(config: &WebConfig) -> Result<reqwest::Client> {
    let key = ddg_client_key(config);
    if let Some(existing) = DDG_CLIENTS.lock().get(&key) {
        return Ok(existing.clone());
    }
    let client = build_ddg_client(config)?;
    DDG_CLIENTS.lock().insert(key, client.clone());
    Ok(client)
}

fn ddg_client_key(config: &WebConfig) -> String {
    let loopback = is_loopback_url(&config.ddg_base_url);
    let host = config.ddg_base_url.host_str().unwrap_or_default();
    format!("{}|{}|{}", config.user_agent, host, loopback)
}

fn build_ddg_client(config: &WebConfig) -> Result<reqwest::Client> {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    );
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    let mut builder = reqwest::Client::builder()
        .default_headers(headers)
        .user_agent(config.user_agent.clone())
        .timeout(config.request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .cookie_store(true);
    if !is_loopback_url(&config.ddg_base_url) {
        builder = builder.dns_resolver(public_dns_resolver());
    }
    builder.build().context("build ddg client")
}

fn resolve_searxng_client(config: &WebConfig) -> Result<reqwest::Client> {
    let key = format!(
        "{}|{}",
        config.user_agent,
        config.request_timeout.as_millis()
    );
    if let Some(existing) = SEARXNG_CLIENTS.lock().get(&key) {
        return Ok(existing.clone());
    }
    let client = build_searxng_client(config)?;
    SEARXNG_CLIENTS.lock().insert(key, client.clone());
    Ok(client)
}

fn build_searxng_client(config: &WebConfig) -> Result<reqwest::Client> {
    let mut headers = HeaderMap::new();
    headers.insert(
        ACCEPT,
        HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
    );
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    reqwest::Client::builder()
        .default_headers(headers)
        .user_agent(config.user_agent.clone())
        .timeout(config.request_timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .cookie_store(true)
        .build()
        .context("build searxng client")
}

fn typing_delay_for_query(query: &str) -> Duration {
    let chars = query.chars().count().max(1) as u64;
    let mut seed = random_seed() ^ hash_query(query);
    let mut total_ms = 0u64;
    for idx in 0..chars {
        seed = lcg_next(seed);
        let span = DDG_TYPING_DELAY_MAX_MS.saturating_sub(DDG_TYPING_DELAY_MIN_MS);
        let jitter = if span == 0 {
            DDG_TYPING_DELAY_MIN_MS
        } else {
            DDG_TYPING_DELAY_MIN_MS + (seed % (span + 1))
        };
        total_ms = total_ms.saturating_add(jitter);
        if idx > 0 && idx % 8 == 0 {
            total_ms = total_ms.saturating_add(DDG_TYPING_PAUSE_MS);
        }
        if total_ms >= DDG_TYPING_MAX_TOTAL_MS {
            total_ms = DDG_TYPING_MAX_TOTAL_MS;
            break;
        }
    }
    Duration::from_millis(total_ms)
}

fn random_delay_ms(min_ms: u64, max_ms: u64) -> Duration {
    if max_ms <= min_ms {
        return Duration::from_millis(min_ms);
    }
    let span = max_ms - min_ms;
    let jitter = random_seed() % (span + 1);
    Duration::from_millis(min_ms + jitter)
}

fn random_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64
}

fn hash_query(query: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    query.hash(&mut hasher);
    hasher.finish()
}

fn lcg_next(seed: u64) -> u64 {
    seed.wrapping_mul(6364136223846793005).wrapping_add(1)
}

fn normalize_blocklist(entries: &[String]) -> Vec<String> {
    entries
        .iter()
        .filter_map(|entry| normalize_blocklist_entry(entry))
        .collect()
}

fn normalize_blocklist_entry(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_start_matches('.');
    if trimmed.is_empty() {
        return None;
    }
    let value = if trimmed.contains("://") {
        Url::parse(trimmed)
            .ok()
            .and_then(|url| url.host_str().map(|host| host.to_string()))
    } else {
        Some(trimmed.to_string())
    }?;
    let lowered = value.to_ascii_lowercase();
    if lowered.is_empty() {
        None
    } else {
        Some(lowered)
    }
}

fn filter_blocked_urls(urls: Vec<String>, blocklist: &[String]) -> Vec<String> {
    urls.into_iter()
        .filter(|raw| is_url_allowed(raw, blocklist))
        .collect()
}

fn is_url_allowed(raw: &str, blocklist: &[String]) -> bool {
    let Ok(parsed) = Url::parse(raw) else {
        return false;
    };
    validate_outbound_url_structure(&parsed).is_ok() && !host_matches_blocklist(&parsed, blocklist)
}

fn searxng_fallbacks(config: &WebConfig) -> Vec<FallbackProvider> {
    config
        .searxng_urls
        .iter()
        .cloned()
        .map(FallbackProvider::SearxngJson)
        .collect()
}

fn url_from_env(key: &str) -> Option<Url> {
    env_nonempty(key).and_then(|value| Url::parse(value.trim()).ok())
}

fn env_nonempty(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn nonempty_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrator::web_policy::SpacingBackoffPolicy;
    use std::io::{Read, Write};
    use std::net::{Shutdown, TcpListener};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::Instant;

    fn retry_test_config(base_url: Url, max_attempts: usize) -> WebConfig {
        WebConfig {
            enabled: true,
            discovery_provider: DDG_LITE_PROVIDER.to_string(),
            user_agent: format!(
                "docdex-ddg-retry-test-{}",
                base_url.port_or_known_default().unwrap_or_default()
            ),
            ddg_base_url: base_url,
            ddg_proxy_base_url: None,
            searxng_urls: Vec::new(),
            mswarm_base_url: Url::parse("http://127.0.0.1:1").expect("valid mswarm url"),
            mswarm_api_key: None,
            request_timeout: Duration::from_secs(1),
            max_results: 5,
            policy: SpacingBackoffPolicy {
                min_spacing: Duration::ZERO,
                jitter_ms: 0,
                max_attempts,
                base_backoff: Duration::ZERO,
                backoff_multiplier: 2.0,
                max_backoff: Duration::ZERO,
                max_consecutive_failures: max_attempts.saturating_add(1),
                cooldown: Duration::ZERO,
            },
            cache_ttl: Duration::ZERO,
            blocklist: Vec::new(),
            boilerplate_phrases: Vec::new(),
            fetch_delay: Duration::ZERO,
            scraper_engine: "chromium".to_string(),
            scraper_headless: true,
            chrome_binary_path: None,
            scraper_auto_install: false,
            scraper_browser_kind: None,
            scraper_user_data_dir: None,
            page_load_timeout: Duration::from_secs(1),
            brave_api_key: None,
            google_cse_api_key: None,
            google_cse_cx: None,
            bing_api_key: None,
        }
    }

    fn spawn_raw_http_server(
        responses: Vec<Vec<u8>>,
    ) -> (
        Url,
        Arc<AtomicUsize>,
        mpsc::Sender<()>,
        thread::JoinHandle<()>,
    ) {
        assert!(!responses.is_empty(), "at least one response is required");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test server");
        listener
            .set_nonblocking(true)
            .expect("make test server nonblocking");
        let address = listener.local_addr().expect("test server address");
        let requests = Arc::new(AtomicUsize::new(0));
        let requests_for_server = Arc::clone(&requests);
        let (stop_tx, stop_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            let mut response_index = 0usize;
            loop {
                match stop_rx.try_recv() {
                    Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                    Err(mpsc::TryRecvError::Empty) => {}
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(250)));
                        let mut request = Vec::with_capacity(2_048);
                        let request_deadline = Instant::now() + Duration::from_secs(30);
                        loop {
                            let mut chunk = [0u8; 1_024];
                            match stream.read(&mut chunk) {
                                Ok(0) => break,
                                Ok(read) => {
                                    request.extend_from_slice(&chunk[..read]);
                                    assert!(
                                        request.len() <= 16 * 1_024,
                                        "test request headers exceeded their bound"
                                    );
                                    if request.windows(4).any(|window| window == b"\r\n\r\n") {
                                        break;
                                    }
                                }
                                Err(err)
                                    if matches!(
                                        err.kind(),
                                        std::io::ErrorKind::WouldBlock
                                            | std::io::ErrorKind::TimedOut
                                    ) && Instant::now() < request_deadline =>
                                {
                                    continue;
                                }
                                Err(err) => panic!("test server request read failed: {err}"),
                            }
                        }
                        assert!(
                            request.windows(4).any(|window| window == b"\r\n\r\n"),
                            "test server received incomplete request headers"
                        );
                        let response = &responses[response_index.min(responses.len() - 1)];
                        response_index = response_index.saturating_add(1);
                        requests_for_server.fetch_add(1, Ordering::SeqCst);
                        let _ = stream.write_all(response);
                        let _ = stream.flush();
                        let _ = stream.shutdown(Shutdown::Write);
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(err) => panic!("test server accept failed: {err}"),
                }
            }
        });
        (
            Url::parse(&format!("http://{address}/lite/")).expect("valid test server url"),
            requests,
            stop_tx,
            handle,
        )
    }

    fn truncated_success_response() -> Vec<u8> {
        b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 128\r\nConnection: close\r\n\r\nshort"
            .to_vec()
    }

    fn valid_success_response() -> Vec<u8> {
        let body = r#"<a class="result__a" href="https://example.com/docs">Docs</a>"#;
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    fn status_response(status: &str, content_type: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(previous) = self.previous.as_deref() {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    async fn fetch_single_raw_response(response: Vec<u8>) -> reqwest::Response {
        let (base_url, _requests, stop_tx, server) = spawn_raw_http_server(vec![response]);
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(0)
            .build()
            .expect("build test client");
        let result = client.get(base_url).send().await.expect("raw response");
        let _ = stop_tx.send(());
        server.join().expect("join test server");
        result
    }

    #[tokio::test]
    async fn discovery_response_reader_enforces_declared_and_streamed_limits() {
        let declared_oversize =
            b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\nConnection: close\r\n\r\nshort".to_vec();
        let streamed_oversize = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n9\r\n123456789\r\n0\r\n\r\n".to_vec();
        let exact =
            b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\n12345678".to_vec();
        let declared = fetch_single_raw_response(declared_oversize).await;
        let declared_error = read_discovery_body_limited(declared, "test", 8)
            .await
            .expect_err("declared oversize response must fail");
        assert!(declared_error.to_string().contains("8-byte limit"));

        let streamed = fetch_single_raw_response(streamed_oversize).await;
        let streamed_error = read_discovery_body_limited(streamed, "test", 8)
            .await
            .expect_err("streamed oversize response must fail");
        assert!(streamed_error.to_string().contains("8-byte limit"));

        let allowed = fetch_single_raw_response(exact).await;
        assert_eq!(
            read_discovery_body_limited(allowed, "test", 8)
                .await
                .expect("exact response is allowed"),
            b"12345678"
        );
    }

    async fn run_retry_test(
        responses: Vec<Vec<u8>>,
        max_attempts: usize,
    ) -> (Result<WebDiscoveryResponse>, usize) {
        let (base_url, requests, stop_tx, server) = spawn_raw_http_server(responses);
        DDG_PREFETCHED_HOSTS.lock().insert("127.0.0.1".to_string());
        let query = format!("r{}", base_url.port_or_known_default().unwrap_or_default());
        let mut discovery =
            DdgDiscovery::new(retry_test_config(base_url, max_attempts)).expect("discovery");
        discovery.cache_layout = None;
        let result = discovery.discover(&query, 1).await;
        let _ = stop_tx.send(());
        server.join().expect("join test server");
        (result, requests.load(Ordering::SeqCst))
    }

    #[test]
    fn fallback_chain_keeps_searxng_before_brave_for_legacy_order_flags() {
        let mut config =
            retry_test_config(Url::parse(DDG_LITE_FALLBACK_URL).expect("valid DDG URL"), 1);
        config.searxng_urls =
            vec![Url::parse("https://se.overrid.com/search").expect("valid SearXNG URL")];
        config.brave_api_key = Some("test-brave-key".to_string());

        for prefer_api in [false, true] {
            let chain = FallbackChain::new(&config, prefer_api, None);
            let names = chain
                .providers
                .iter()
                .map(fallback_provider_name)
                .collect::<Vec<_>>();
            assert_eq!(names, vec![SEARXNG_PROVIDER, BRAVE_PROVIDER]);
        }

        let explicitly_selected = FallbackChain::new(&config, true, Some(BRAVE_PROVIDER));
        assert_eq!(
            explicitly_selected
                .providers
                .first()
                .map(fallback_provider_name),
            Some(BRAVE_PROVIDER)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ddg_block_uses_searxng_without_calling_brave() {
        static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));
        let _env_lock = ENV_LOCK.lock();
        let (ddg_url, ddg_requests, ddg_stop, ddg_server) =
            spawn_raw_http_server(vec![status_response(
                "403 Forbidden",
                "text/plain",
                "blocked",
            )]);
        let searxng_body = r#"{"results":[{"url":"https://example.com/from-searxng"}]}"#;
        let (searxng_url, searxng_requests, searxng_stop, searxng_server) = spawn_raw_http_server(
            vec![status_response("200 OK", "application/json", searxng_body)],
        );
        let (brave_url, brave_requests, brave_stop, brave_server) =
            spawn_raw_http_server(vec![status_response(
                "200 OK",
                "application/json",
                searxng_body,
            )]);
        let _brave_url = EnvGuard::set("DOCDEX_BRAVE_API_URL", brave_url.as_str());
        DDG_PREFETCHED_HOSTS.lock().insert("127.0.0.1".to_string());

        let mut config = retry_test_config(ddg_url, 1);
        config.searxng_urls = vec![searxng_url];
        config.brave_api_key = Some("test-brave-key".to_string());
        let mut discovery = DdgDiscovery::new(config).expect("discovery");
        discovery.cache_layout = None;

        let response = discovery
            .discover("ordered fallback", 1)
            .await
            .expect("SearXNG fallback succeeds");

        let _ = ddg_stop.send(());
        let _ = searxng_stop.send(());
        let _ = brave_stop.send(());
        ddg_server.join().expect("join DDG server");
        searxng_server.join().expect("join SearXNG server");
        brave_server.join().expect("join Brave server");

        assert_eq!(response.provider, SEARXNG_PROVIDER);
        assert_eq!(response.results[0].url, "https://example.com/from-searxng");
        assert_eq!(ddg_requests.load(Ordering::SeqCst), 1);
        assert_eq!(searxng_requests.load(Ordering::SeqCst), 1);
        assert_eq!(brave_requests.load(Ordering::SeqCst), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn searxng_uses_system_dns_for_operator_configured_hostnames() {
        let searxng_body = r#"{"results":[{"url":"https://example.com/from-private-searxng"}]}"#;
        let (mut searxng_url, requests, stop, server) =
            spawn_raw_http_server(vec![status_response(
                "200 OK",
                "application/json",
                searxng_body,
            )]);
        searxng_url
            .set_host(Some("localhost"))
            .expect("replace loopback IP with localhost");

        let config =
            retry_test_config(Url::parse(DDG_LITE_FALLBACK_URL).expect("valid DDG URL"), 1);
        let mut discovery = DdgDiscovery::new(config).expect("discovery");
        discovery.cache_layout = None;
        let response = discovery
            .try_searxng_discovery(
                &searxng_url,
                "private service hostname",
                1,
                1,
                "searxng-system-dns-test",
            )
            .await
            .expect("configured SearXNG hostname resolves with system DNS")
            .expect("SearXNG returns a result");

        let _ = stop.send(());
        server.join().expect("join SearXNG server");
        assert_eq!(response.provider, SEARXNG_PROVIDER);
        assert_eq!(
            response.results[0].url,
            "https://example.com/from-private-searxng"
        );
        assert_eq!(requests.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn extract_links_from_ddg_html() {
        let html = r#"
            <a class="result__a" href="https://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fdoc">Example</a>
            <a data-testid="result-title-a" href="https://example.com/other">Other</a>
        "#;
        let links = extract_links(html);
        assert_eq!(links.len(), 2);
        assert!(links[0].contains("duckduckgo.com/l/"));
        assert_eq!(links[1], "https://example.com/other");
    }

    #[test]
    fn extract_links_from_markdown() {
        let markdown = r#"
Title: Example

Markdown Content:
[Result](http://duckduckgo.com/l/?uddg=https%3A%2F%2Fexample.com%2Fdoc)
[Other](https://example.org/other)
"#;
        let links = extract_links(markdown);
        assert_eq!(links.len(), 2);
        assert!(links[0].contains("duckduckgo.com/l/"));
        assert_eq!(links[1], "https://example.org/other");
    }

    #[test]
    fn extract_links_from_ddg_lite_html() {
        let html = r#"
            <a rel="nofollow" href="/l/?uddg=https%3A%2F%2Fexample.com%2Fdoc">Example</a>
            <a rel="nofollow" href="https://example.org/other">Other</a>
            <a href="https://duckduckgo.com/?q=test">Ignore</a>
        "#;
        let links = extract_ddg_lite_links(html);
        assert_eq!(links.len(), 2);
        assert!(links[0].contains("duckduckgo.com/l/"));
        assert_eq!(links[1], "https://example.org/other");
    }

    #[test]
    fn detects_anomaly_page() {
        let html = r#"
            <form id="challenge-form" action="//duckduckgo.com/anomaly.js?sv=html&cc=botnet"></form>
        "#;
        assert!(is_ddg_anomaly_page(html));
        assert!(!is_ddg_anomaly_page(
            "<a class=\"result__a\" href=\"https://example.com\">ok</a>"
        ));
    }

    #[test]
    fn typing_delay_stays_within_expected_bounds() {
        let query = "docdex ddg hardening";
        let chars = query.chars().count().max(1) as u64;
        let pause_count = chars / 8;
        let min_ms = chars * DDG_TYPING_DELAY_MIN_MS + pause_count * DDG_TYPING_PAUSE_MS;
        let max_ms = chars * DDG_TYPING_DELAY_MAX_MS + pause_count * DDG_TYPING_PAUSE_MS;
        let delay = typing_delay_for_query(query);
        let ms = delay.as_millis() as u64;
        let max_ms = max_ms.min(DDG_TYPING_MAX_TOTAL_MS);
        let min_ms = min_ms.min(DDG_TYPING_MAX_TOTAL_MS);
        assert!(ms >= min_ms, "delay {ms}ms below min {min_ms}ms");
        assert!(ms <= max_ms, "delay {ms}ms above max {max_ms}ms");
    }

    #[test]
    fn result_filter_rejects_unsafe_outbound_urls() {
        assert!(!is_url_allowed("file:///etc/passwd", &[]));
        assert!(!is_url_allowed("http://127.0.0.1/admin", &[]));
        assert!(!is_url_allowed("https://user:pass@example.com", &[]));
        assert!(!is_url_allowed("https://metadata.google.internal/", &[]));
        assert!(is_url_allowed("https://example.com/docs", &[]));
    }

    #[tokio::test]
    async fn discovery_retries_transient_body_failure_then_succeeds() {
        let (result, requests) = run_retry_test(
            vec![truncated_success_response(), valid_success_response()],
            2,
        )
        .await;

        let response = result.expect("second attempt should succeed");
        assert_eq!(requests, 2);
        assert_eq!(response.results.len(), 1);
        assert_eq!(response.results[0].url, "https://example.com/docs");
    }

    #[tokio::test]
    async fn discovery_stops_after_configured_attempts() {
        let (result, requests) = run_retry_test(vec![truncated_success_response()], 2).await;

        let err = result.expect_err("all attempts should fail");
        assert_eq!(requests, 2);
        assert!(err.to_string().contains("duckduckgo discovery failed"));
    }

    #[test]
    fn searxng_results_keep_titles_and_snippets() {
        let body = r#"{"results":[
            {"url":"https://docs.rs/tokio/latest/tokio/task/fn.block_in_place.html",
             "title":"block_in_place in tokio::task",
             "content":"Runs the provided blocking function on the current thread."},
            {"url":"https://en.wikipedia.org/wiki/Tokyo","title":"Tokyo","content":"Capital of Japan."}
        ]}"#;

        let results = extract_searxng_results(body).expect("parse searxng body");

        assert_eq!(results.len(), 2);
        assert_eq!(
            results[0].title.as_deref(),
            Some("block_in_place in tokio::task")
        );
        assert!(results[0]
            .snippet
            .as_deref()
            .unwrap_or_default()
            .contains("blocking function"));
        assert_eq!(results[1].title.as_deref(), Some("Tokyo"));
        assert!(results[0]
            .match_text()
            .contains("block_in_place in tokio::task"));
    }

    #[test]
    fn searxng_results_tolerate_missing_metadata() {
        let body = r#"{"results":[{"url":"https://example.com/a"},{"title":"no url"}]}"#;

        let results = extract_searxng_results(body).expect("parse searxng body");

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].url, "https://example.com/a");
        assert!(results[0].title.is_none());
        assert!(results[0].snippet.is_none());
    }

    #[test]
    fn searxng_url_requests_general_and_it_categories() {
        let base = Url::parse("http://127.0.0.1:18888/search").expect("base url");

        let url = build_searxng_url(&base, "tokio block_in_place").expect("searxng url");

        let pairs: Vec<(String, String)> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert!(pairs.contains(&("format".to_string(), "json".to_string())));
        assert!(pairs.contains(&("categories".to_string(), "general,it".to_string())));
    }

    #[test]
    fn provider_block_window_treats_quota_and_auth_as_terminal() {
        // "Quota exceeded for the current billing window" does not clear between
        // requests seconds apart, so these must disable the provider, not retry.
        assert_eq!(
            provider_block_window_secs(StatusCode::FORBIDDEN),
            Some(PROVIDER_QUOTA_BLOCK_SECS)
        );
        assert_eq!(
            provider_block_window_secs(StatusCode::UNAUTHORIZED),
            Some(PROVIDER_QUOTA_BLOCK_SECS)
        );
        assert_eq!(
            provider_block_window_secs(StatusCode::PAYMENT_REQUIRED),
            Some(PROVIDER_QUOTA_BLOCK_SECS)
        );
        assert_eq!(
            provider_block_window_secs(StatusCode::TOO_MANY_REQUESTS),
            Some(PROVIDER_RATE_LIMIT_BLOCK_SECS)
        );
        // Transient and not-found responses stay retryable.
        assert_eq!(provider_block_window_secs(StatusCode::BAD_GATEWAY), None);
        assert_eq!(provider_block_window_secs(StatusCode::NOT_FOUND), None);
        assert_eq!(
            provider_block_window_secs(StatusCode::INTERNAL_SERVER_ERROR),
            None
        );
    }

    #[test]
    fn provider_block_record_round_trips_and_is_scoped_per_provider() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let layout = StateLayout::new(temp.path().join("state"));

        assert!(load_provider_block_record(&layout, MSWARM_PROVIDER).is_none());

        write_provider_block_record(&layout, MSWARM_PROVIDER, "403", PROVIDER_QUOTA_BLOCK_SECS);

        let record = load_provider_block_record(&layout, MSWARM_PROVIDER).expect("block recorded");
        assert_eq!(record.reason, "403");
        assert!(record.blocked_until_ms > record.blocked_at_ms);
        // Blocking one provider must not disable the others.
        assert!(load_provider_block_record(&layout, SEARXNG_PROVIDER).is_none());
        assert!(load_provider_block_record(&layout, BRAVE_PROVIDER).is_none());
    }

    #[test]
    fn provider_block_record_expires_after_its_window() {
        let temp = tempfile::TempDir::new().expect("temp dir");
        let layout = StateLayout::new(temp.path().join("state"));

        // A zero-length window is already in the past, so the next read clears it.
        write_provider_block_record(&layout, BRAVE_PROVIDER, "429", 0);

        assert!(load_provider_block_record(&layout, BRAVE_PROVIDER).is_none());
    }
}
