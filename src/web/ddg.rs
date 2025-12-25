use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use regex::Regex;
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::json;
use std::time::Duration;
use url::Url;

use crate::error::{
    AppError, ERR_BACKOFF_REQUIRED, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT,
    ERR_MISSING_DEPENDENCY,
};
use crate::web::cache;
use crate::web::ddg_policy::{DdgDiscoveryPacer, DdgDiscoveryPolicyConfig};
use crate::web::normalize::dedupe_urls;
use crate::web::WebConfig;

const PROVIDER: &str = "duckduckgo_html";

static RESULT_LINK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?is)<a[^>]*(?:class="[^"]*\bresult__a\b[^"]*"|data-testid="result-title-a")[^>]*href=(?:"([^"]+)"|'([^']+)')"#,
    )
    .expect("valid ddg regex")
});

#[derive(Clone)]
pub struct DdgDiscovery {
    config: WebConfig,
    pacer: Mutex<DdgDiscoveryPacer>,
    client: reqwest::Client,
    blocklist: Vec<String>,
    cache_layout: Option<crate::state_layout::StateLayout>,
}

#[derive(Debug, Serialize)]
pub struct WebDiscoveryResult {
    pub url: String,
}

#[derive(Debug, Serialize)]
pub struct WebDiscoveryResponse {
    pub provider: &'static str,
    pub query: String,
    pub results: Vec<WebDiscoveryResult>,
}

impl DdgDiscovery {
    pub fn new(config: WebConfig) -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent(config.user_agent.clone())
            .timeout(config.request_timeout)
            .build()
            .context("build ddg client")?;
        let pacer_config = DdgDiscoveryPolicyConfig {
            min_spacing: config.policy.min_spacing,
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

        let limit = limit.clamp(1, self.config.max_results);
        let attempts = self.config.policy.max_attempts.max(1);
        let url = build_ddg_url(&self.config.ddg_base_url, query)?;
        let url_key = url.to_string();

        if let Some(layout) = self.cache_layout.as_ref() {
            if let Ok(Some(payload)) =
                cache::read_cache_entry_with_ttl(layout, &url_key, self.config.cache_ttl)
            {
                if let Ok(mut cached) =
                    serde_json::from_slice::<WebDiscoveryResponse>(&payload)
                {
                    if cached.results.len() > limit {
                        cached.results.truncate(limit);
                    }
                    return Ok(cached);
                }
            }
        }
        let mut last_error: Option<anyhow::Error> = None;

        for attempt in 0..attempts {
            loop {
                let backoff = { self.pacer.lock().check_or_backoff() };
                if let Err(err) = backoff {
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

            match self.client.get(url.clone()).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        let body = resp.text().await.context("read ddg html")?;
                        let links = extract_links(&body);
                        let deduped = dedupe_urls(links);
                        let filtered = filter_blocked_urls(deduped, &self.blocklist);
                        let results = filtered
                            .into_iter()
                            .take(limit)
                            .map(|url| WebDiscoveryResult { url })
                            .collect();
                        self.pacer.lock().record_success();
                        let response = WebDiscoveryResponse {
                            provider: PROVIDER,
                            query: query.to_string(),
                            results,
                        };
                        if let Some(layout) = self.cache_layout.as_ref() {
                            if self.config.cache_ttl.as_secs() > 0 {
                                if let Ok(payload) = serde_json::to_vec(&response) {
                                    let _ = cache::write_cache_entry(layout, &url_key, &payload);
                                }
                            }
                        }
                        return Ok(response);
                    }

                    let (backoff_error, failures, max_failures, stop_backoff) = {
                        let mut pacer = self.pacer.lock();
                        let err = pacer.record_failure();
                        let failures = pacer.consecutive_failures();
                        let max_failures = pacer.config().max_consecutive_failures;
                        let stop_backoff = pacer.config().stop_backoff;
                        (err, failures, max_failures, stop_backoff)
                    };
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
                        return Err(
                            backoff_with_message(backoff_error, format!("duckduckgo discovery blocked ({status})"))
                                .into(),
                        );
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
}

fn build_ddg_url(base: &Url, query: &str) -> Result<Url> {
    let mut url = base.clone();
    url.query_pairs_mut().append_pair("q", query);
    Ok(url)
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
    out
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
}
