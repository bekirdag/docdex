use anyhow::{Context, Result};
use once_cell::sync::Lazy;
use regex::Regex;
use reqwest::StatusCode;
use serde::Serialize;
use serde_json::json;
use url::Url;

use crate::error::{AppError, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MISSING_DEPENDENCY};
use crate::web::normalize::dedupe_urls;
use crate::web::policy::{backoff_error, SpacingBackoff};
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
    spacing: SpacingBackoff,
    client: reqwest::Client,
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
        Ok(Self {
            spacing: SpacingBackoff::new(config.policy.clone()),
            config,
            client,
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
            return Err(AppError::new(ERR_MISSING_DEPENDENCY, "web discovery is disabled")
                .with_details(json!({ "dependency": "web_discovery" }))
                .into());
        }

        let limit = limit.clamp(1, self.config.max_results);
        let attempts = self.config.policy.max_attempts.max(1);
        let url = build_ddg_url(&self.config.ddg_base_url, query)?;
        let mut last_error: Option<anyhow::Error> = None;

        for attempt in 0..attempts {
            if attempt > 0 {
                let delay = self.spacing.backoff_delay(attempt);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
            }
            if let Err(err) = self.spacing.wait_for_slot().await {
                return Err(err.into());
            }

            match self.client.get(url.clone()).send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() {
                        let body = resp.text().await.context("read ddg html")?;
                        let links = extract_links(&body);
                        let deduped = dedupe_urls(links);
                        let results = deduped
                            .into_iter()
                            .take(limit)
                            .map(|url| WebDiscoveryResult { url })
                            .collect();
                        self.spacing.register_success().await;
                        return Ok(WebDiscoveryResponse {
                            provider: PROVIDER,
                            query: query.to_string(),
                            results,
                        });
                    }

                    if let Some(backoff) = self.spacing.register_failure().await {
                        return Err(backoff.into());
                    }

                    let retry_after = retry_after_from_response(&resp)
                        .unwrap_or_else(|| self.spacing.backoff_delay(attempt + 1));

                    if should_retry(status) && attempt + 1 < attempts {
                        continue;
                    }
                    if should_retry(status) {
                        return Err(backoff_error(
                            format!("duckduckgo discovery blocked ({status})"),
                            retry_after,
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
                    if let Some(backoff) = self.spacing.register_failure().await {
                        return Err(backoff.into());
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
