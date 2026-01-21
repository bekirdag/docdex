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
use crate::web::WebConfig;

const PROVIDER: &str = "duckduckgo_lite";
const DDG_LITE_PROVIDER: &str = "duckduckgo_lite";
const SEARXNG_PROVIDER: &str = "searxng_json";
const BRAVE_PROVIDER: &str = "brave";
const GOOGLE_CSE_PROVIDER: &str = "google_cse";
const BING_PROVIDER: &str = "bing";
const TAVILY_PROVIDER: &str = "tavily";
const EXA_PROVIDER: &str = "exa";
const MAX_DDG_RESULTS: usize = 50;
const DDG_PREFETCH_PAUSE_MIN_MS: u64 = 1_000;
const DDG_PREFETCH_PAUSE_MAX_MS: u64 = 2_000;
const DDG_TYPING_DELAY_MIN_MS: u64 = 50;
const DDG_TYPING_DELAY_MAX_MS: u64 = 200;
const DDG_TYPING_PAUSE_MS: u64 = 350;
const DDG_TYPING_MAX_TOTAL_MS: u64 = 2_000;
const DDG_LITE_FALLBACK_URL: &str = "https://lite.duckduckgo.com/lite/";
const DDG_BLOCK_WINDOW_SECS: u64 = 86_400;
const DDG_BLOCK_CACHE_KEY: &str = "ddg:block";
const DEFAULT_SEARXNG_URLS: &[&str] = &[
    "https://searx.be/search",
    "https://searx.tiekoetter.com/search",
    "https://searx.si/search",
];
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
static DDG_PREFETCHED_HOSTS: Lazy<Mutex<HashSet<String>>> =
    Lazy::new(|| Mutex::new(HashSet::new()));

pub struct DdgDiscovery {
    config: WebConfig,
    pacer: Mutex<DdgDiscoveryPacer>,
    client: reqwest::Client,
    blocklist: Vec<String>,
    cache_layout: Option<crate::state_layout::StateLayout>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebDiscoveryResult {
    pub url: String,
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
}

struct FallbackChain {
    providers: Vec<FallbackProvider>,
    next_index: usize,
    skip_ddg: bool,
    prefer_api: bool,
}

impl FallbackChain {
    fn new(config: &WebConfig, prefer_api: bool) -> Self {
        let mut providers = Vec::new();
        if is_duckduckgo_host(&config.ddg_base_url) {
            if let Some(ddg_lite) = ddg_lite_fallback_base(&config.ddg_base_url) {
                providers.push(FallbackProvider::DdgLite(ddg_lite));
            }
        }

        let mut api_providers = Vec::new();
        let mut free_providers = Vec::new();

        free_providers.extend(searxng_fallbacks());

        if let Some(api_key) = config.brave_api_key.as_deref().and_then(nonempty_value) {
            let base_url = url_from_env("DOCDEX_BRAVE_API_URL")
                .or_else(|| Url::parse(BRAVE_API_URL).ok())
                .unwrap_or_else(|| Url::parse(BRAVE_API_URL).expect("default brave url"));
            api_providers.push(FallbackProvider::Brave { api_key, base_url });
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

        if prefer_api {
            providers.extend(api_providers);
            providers.extend(free_providers);
        } else {
            providers.extend(free_providers);
            providers.extend(api_providers);
        }
        Self {
            providers,
            next_index: 0,
            skip_ddg: false,
            prefer_api,
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

    fn prefer_api(&self) -> bool {
        self.prefer_api
    }
}

impl DdgDiscovery {
    pub fn new(config: WebConfig) -> Result<Self> {
        let client = resolve_ddg_client(&config)?;
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
        let url = build_ddg_url(&self.config.ddg_base_url, query)?;
        let cache_key = ddg_cache_key(&self.config.ddg_base_url, query);
        let mut proxy_attempted = false;
        let proxy_base_url = self.config.ddg_proxy_base_url.as_ref();

        if let Some(layout) = self.cache_layout.as_ref() {
            if let Ok(Some(payload)) =
                cache::read_cache_entry_with_ttl(layout, &cache_key, self.config.cache_ttl)
            {
                if let Ok(cached) = serde_json::from_slice::<WebDiscoveryResponse>(&payload) {
                    let urls = cached
                        .results
                        .into_iter()
                        .map(|result| result.url)
                        .collect();
                    return Ok(build_response_for_limit(
                        PROVIDER,
                        query,
                        filter_blocked_urls(dedupe_urls(urls), &self.blocklist),
                        limit,
                    ));
                }
            }
        }
        let mut last_error: Option<anyhow::Error> = None;
        let mut fallback_chain: Option<FallbackChain> = None;

        if self.ddg_blocked() {
            let chain = self.fallback_chain_for(&mut fallback_chain, true);
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

        for _ in 0..attempts {
            loop {
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
                            self.fallback_chain_for(&mut fallback_chain, false),
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
                break;
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
                        let body = resp.text().await.map_err(|err| {
                            AppError::new(
                                ERR_INTERNAL_ERROR,
                                format!("duckduckgo discovery failed: {err}"),
                            )
                        })?;
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
                            self.fallback_chain_for(&mut fallback_chain, true)
                                .skip_ddg();
                            if let Some(response) = self
                                .maybe_fallback_discovery(
                                    self.fallback_chain_for(&mut fallback_chain, true),
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
                            let chain = self.fallback_chain_for(&mut fallback_chain, true);
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
                        self.fallback_chain_for(&mut fallback_chain, true)
                            .skip_ddg();
                        if let Some(response) = self
                            .maybe_fallback_discovery(
                                self.fallback_chain_for(&mut fallback_chain, true),
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
                            self.fallback_chain_for(&mut fallback_chain, false),
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
                            self.fallback_chain_for(&mut fallback_chain, false),
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
        let cache_key = ddg_cache_key(&self.config.ddg_base_url, query);
        let mut last_error: Option<anyhow::Error> = None;
        let mut fallback_chain = None;
        let chain = self.fallback_chain_for(&mut fallback_chain, true);
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
    ) -> &'a mut FallbackChain {
        let replace = match chain.as_ref() {
            Some(existing) => existing.prefer_api() != prefer_api,
            None => true,
        };
        if replace {
            *chain = Some(FallbackChain::new(&self.config, prefer_api));
        }
        chain.as_mut().expect("fallback chain must exist")
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
        let body = resp.text().await.map_err(|err| {
            AppError::new(
                ERR_INTERNAL_ERROR,
                format!("duckduckgo fallback discovery failed: {err}"),
            )
        })?;
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
        let resp = self.client.get(url).send().await?;
        if !resp.status().is_success() {
            return Ok(None);
        }
        let body = resp.text().await.map_err(|err| {
            AppError::new(
                ERR_INTERNAL_ERROR,
                format!("searxng discovery failed: {err}"),
            )
        })?;
        let links = extract_searxng_links(&body)?;
        let filtered = self.filter_links(links);
        if filtered.is_empty() {
            return Ok(None);
        }
        let responses =
            build_discovery_responses(SEARXNG_PROVIDER, query, filtered, limit, cache_limit);
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
            return Ok(None);
        }
        let body: Value = resp.json().await.map_err(|err| {
            AppError::new(ERR_INTERNAL_ERROR, format!("brave discovery failed: {err}"))
        })?;
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
            return Ok(None);
        }
        let body: Value = resp.json().await.map_err(|err| {
            AppError::new(
                ERR_INTERNAL_ERROR,
                format!("google cse discovery failed: {err}"),
            )
        })?;
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
            return Ok(None);
        }
        let body: Value = resp.json().await.map_err(|err| {
            AppError::new(ERR_INTERNAL_ERROR, format!("bing discovery failed: {err}"))
        })?;
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
            return Ok(None);
        }
        let body: Value = resp.json().await.map_err(|err| {
            AppError::new(
                ERR_INTERNAL_ERROR,
                format!("tavily discovery failed: {err}"),
            )
        })?;
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
            return Ok(None);
        }
        let body: Value = resp.json().await.map_err(|err| {
            AppError::new(ERR_INTERNAL_ERROR, format!("exa discovery failed: {err}"))
        })?;
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
        let body = resp.text().await.map_err(|err| {
            AppError::new(
                ERR_INTERNAL_ERROR,
                format!("duckduckgo proxy discovery failed: {err}"),
            )
        })?;
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

fn build_ddg_url(base: &Url, query: &str) -> Result<Url> {
    let mut url = base.clone();
    url.query_pairs_mut().append_pair("q", query);
    Ok(url)
}

fn build_searxng_url(base: &Url, query: &str) -> Result<Url> {
    let mut url = base.clone();
    url.query_pairs_mut()
        .append_pair("q", query)
        .append_pair("format", "json");
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

fn ddg_cache_key(base: &Url, query: &str) -> String {
    format!("ddg:{}:{}:{}", PROVIDER, base.as_str(), query)
}

fn ddg_block_entry(layout: &StateLayout) -> std::path::PathBuf {
    cache::cache_entry_for_url(layout, DDG_BLOCK_CACHE_KEY)
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
    urls: Vec<String>,
    limit: usize,
) -> WebDiscoveryResponse {
    let mut results: Vec<WebDiscoveryResult> = urls
        .into_iter()
        .map(|url| WebDiscoveryResult { url })
        .collect();
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
    let response_for_cache = build_response_for_limit(provider, query, urls, cache_limit);
    let limited_urls = response_for_cache
        .results
        .iter()
        .map(|result| result.url.clone())
        .collect();
    let response = build_response_for_limit(provider, query, limited_urls, limit);
    DiscoveryResponses {
        response_for_cache,
        response,
    }
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

fn extract_searxng_links(body: &str) -> Result<Vec<String>> {
    let value: Value = serde_json::from_str(body).map_err(|err| {
        AppError::new(
            ERR_INTERNAL_ERROR,
            format!("searxng discovery failed: {err}"),
        )
    })?;
    Ok(extract_json_links(&value))
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
        .cookie_store(true);
    if is_loopback_url(&config.ddg_base_url) {
        builder = builder.no_proxy();
    }
    builder.build().context("build ddg client")
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
    if blocklist.is_empty() {
        return urls;
    }
    urls.into_iter()
        .filter(|raw| is_url_allowed(raw, blocklist))
        .collect()
}

fn is_url_allowed(raw: &str, blocklist: &[String]) -> bool {
    let Ok(parsed) = Url::parse(raw) else {
        return true;
    };
    let Some(host) = parsed.host_str() else {
        return true;
    };
    let host = host.to_ascii_lowercase();
    for entry in blocklist {
        if host == *entry || host.ends_with(&format!(".{entry}")) {
            return false;
        }
    }
    true
}

fn searxng_fallbacks() -> Vec<FallbackProvider> {
    let mut urls = env_url_list("DOCDEX_WEB_SEARXNG_URLS");
    if urls.is_empty() {
        urls = env_url_list("DOCDEX_SEARXNG_URLS");
    }
    if urls.is_empty() {
        for entry in DEFAULT_SEARXNG_URLS {
            if let Ok(url) = Url::parse(entry) {
                urls.push(url);
            }
        }
    }
    urls.into_iter()
        .map(FallbackProvider::SearxngJson)
        .collect()
}

fn env_url_list(key: &str) -> Vec<Url> {
    env_nonempty(key)
        .map(|value| {
            value
                .split(',')
                .filter_map(|entry| Url::parse(entry.trim()).ok())
                .collect()
        })
        .unwrap_or_default()
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
}
