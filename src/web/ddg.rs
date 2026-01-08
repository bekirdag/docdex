use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, REFERER};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use url::{Host, Url};

use crate::error::{
    AppError, ERR_BACKOFF_REQUIRED, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT,
    ERR_MISSING_DEPENDENCY,
};
use crate::web::cache;
use crate::web::ddg_policy::{DdgDiscoveryPacer, DdgDiscoveryPolicyConfig};
use crate::web::normalize::dedupe_urls;
use crate::web::WebConfig;

const PROVIDER: &str = "duckduckgo_html";
const MAX_DDG_RESULTS: usize = 50;
const DDG_PREFETCH_PAUSE_MIN_MS: u64 = 1_000;
const DDG_PREFETCH_PAUSE_MAX_MS: u64 = 2_000;
const DDG_TYPING_DELAY_MIN_MS: u64 = 50;
const DDG_TYPING_DELAY_MAX_MS: u64 = 200;
const DDG_TYPING_PAUSE_MS: u64 = 350;
const DDG_TYPING_MAX_TOTAL_MS: u64 = 2_000;
const DDG_LITE_FALLBACK_URL: &str = "https://lite.duckduckgo.com/lite/";

static RESULT_LINK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)<a[^>]*(?:class="[^"]*\bresult__a\b[^"]*"|data-testid="result-title-a")[^>]*href=(?:"([^"]+)"|'([^']+)')"#,
    )
    .expect("valid ddg regex")
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

struct DiscoveryResponses {
    response_for_cache: WebDiscoveryResponse,
    response: WebDiscoveryResponse,
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
                        query,
                        filter_blocked_urls(dedupe_urls(urls), &self.blocklist),
                        limit,
                    ));
                }
            }
        }
        let mut last_error: Option<anyhow::Error> = None;
        let mut fallback_attempted = false;
        let fallback_base_url = ddg_lite_fallback_base(&self.config.ddg_base_url);

        for attempt in 0..attempts {
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
                    if err.code == ERR_BACKOFF_REQUIRED {
                        if let Some(delay) = retry_after_from_error(&err) {
                            tokio::time::sleep(delay).await;
                            continue;
                        }
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
                                    fallback_base_url.as_ref(),
                                    &mut fallback_attempted,
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
                            let retry_after = retry_after_from_error(&backoff_error)
                                .unwrap_or_else(|| Duration::from_millis(0));
                            if attempt + 1 < attempts {
                                if !retry_after.is_zero() {
                                    tokio::time::sleep(retry_after).await;
                                }
                                continue;
                            }
                            return Err(backoff_with_message(
                                backoff_error,
                                "duckduckgo discovery blocked (anomaly page)",
                            )
                            .into());
                        }
                        let links = extract_links(&body);
                        let filtered = self.filter_links(links);
                        let responses =
                            build_discovery_responses(query, filtered, limit, cache_limit);
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
                            fallback_base_url.as_ref(),
                            &mut fallback_attempted,
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

                    let retry_after = retry_after_from_response(&resp)
                        .or_else(|| retry_after_from_error(&backoff_error))
                        .unwrap_or_else(|| Duration::from_millis(0));

                    if should_retry(status) && attempt + 1 < attempts {
                        if !retry_after.is_zero() {
                            tokio::time::sleep(retry_after).await;
                        }
                        continue;
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
                            fallback_base_url.as_ref(),
                            &mut fallback_attempted,
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
                    if attempt + 1 < attempts {
                        if let Some(delay) = retry_after_from_error(&backoff_error) {
                            tokio::time::sleep(delay).await;
                        }
                    }
                    last_error = Some(err.into());
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
        fallback_base_url: Option<&Url>,
        fallback_attempted: &mut bool,
        query: &str,
        limit: usize,
        cache_limit: usize,
        cache_key: &str,
        last_error: &mut Option<anyhow::Error>,
    ) -> Option<WebDiscoveryResponse> {
        if *fallback_attempted || fallback_base_url.is_none() {
            return None;
        }
        *fallback_attempted = true;
        let fallback_base_url = fallback_base_url?;
        match self
            .try_fallback_discovery(fallback_base_url, query, limit, cache_limit, cache_key)
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

    async fn try_fallback_discovery(
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
        let links = extract_links(&body);
        let filtered = self.filter_links(links);
        if filtered.is_empty() {
            return Ok(None);
        }
        let responses = build_discovery_responses(query, filtered, limit, cache_limit);
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
        let responses = build_discovery_responses(query, filtered, limit, cache_limit);
        self.cache_response(cache_key, &responses.response_for_cache);
        Ok(Some(responses.response))
    }
}

fn build_ddg_url(base: &Url, query: &str) -> Result<Url> {
    let mut url = base.clone();
    url.query_pairs_mut().append_pair("q", query);
    Ok(url)
}

fn ddg_referer(base: &Url) -> HeaderValue {
    let mut url = base.clone();
    url.set_query(None);
    HeaderValue::from_str(url.as_str()).unwrap_or_else(|_| HeaderValue::from_static(""))
}

fn ddg_lite_fallback_base(base: &Url) -> Option<Url> {
    if !base
        .host_str()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .ends_with("duckduckgo.com")
    {
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

fn build_response_for_limit(query: &str, urls: Vec<String>, limit: usize) -> WebDiscoveryResponse {
    let mut results: Vec<WebDiscoveryResult> = urls
        .into_iter()
        .map(|url| WebDiscoveryResult { url })
        .collect();
    if results.len() > limit {
        results.truncate(limit);
    }
    WebDiscoveryResponse {
        provider: PROVIDER.to_string(),
        query: query.to_string(),
        results,
    }
}

fn build_discovery_responses(
    query: &str,
    urls: Vec<String>,
    limit: usize,
    cache_limit: usize,
) -> DiscoveryResponses {
    let response_for_cache = build_response_for_limit(query, urls, cache_limit);
    let limited_urls = response_for_cache
        .results
        .iter()
        .map(|result| result.url.clone())
        .collect();
    let response = build_response_for_limit(query, limited_urls, limit);
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

fn retry_after_from_response(resp: &reqwest::Response) -> Option<std::time::Duration> {
    resp.headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|text| text.trim().parse::<u64>().ok())
        .map(std::time::Duration::from_secs)
}

fn retry_after_from_error(err: &AppError) -> Option<Duration> {
    err.details
        .as_ref()
        .and_then(|value| value.get("retry_after_ms"))
        .and_then(|value| value.as_u64())
        .map(Duration::from_millis)
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
