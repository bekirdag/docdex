use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use tracing::warn;
use url::Url;

use crate::error::{ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MISSING_DEPENDENCY};
use crate::search::{json_error, json_error_with_details, AppState};
use crate::util;
use crate::web;
use crate::web::scraper::ScraperEngine;
use crate::web::readability::extract_readable_text;
use crate::web::status::fetch_status;

#[derive(Deserialize)]
pub struct WebSearchRequest {
    pub query: String,
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Deserialize)]
pub struct WebFetchRequest {
    pub url: String,
}

#[derive(Serialize, Deserialize)]
struct WebFetchCacheEntry {
    url: String,
    status: Option<u16>,
    fetched_at_epoch_ms: u128,
    content: String,
    #[serde(default)]
    code_blocks: Vec<String>,
}

pub async fn web_search_handler(
    State(state): State<AppState>,
    axum::Json(payload): axum::Json<WebSearchRequest>,
) -> Response {
    let query = payload.query.trim();
    if query.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "query is required",
        );
    }
    let limit = payload.limit.unwrap_or(8).max(1);
    let config = web::WebConfig::from_env();
    let discovery = match web::ddg::DdgDiscovery::new(config) {
        Ok(discovery) => discovery,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "web discovery unavailable");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "web discovery unavailable",
            );
        }
    };
    match discovery.discover(query, limit).await {
        Ok(response) => Json(response).into_response(),
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "web discovery failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "web discovery failed",
            )
        }
    }
}

pub async fn web_fetch_handler(
    State(state): State<AppState>,
    axum::Json(payload): axum::Json<WebFetchRequest>,
) -> Response {
    let url_raw = payload.url.trim();
    if url_raw.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "url is required",
        );
    }
    let url = match Url::parse(url_raw) {
        Ok(value) => value,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                format!("invalid url: {err}"),
            )
        }
    };

    let config = web::WebConfig::from_env();
    let layout = web::cache::cache_layout_from_config();
    if let Some(layout) = layout.as_ref() {
        if let Ok(Some(payload)) =
            web::cache::read_cache_entry_with_ttl(layout, url.as_str(), config.cache_ttl)
        {
            if let Ok(entry) = serde_json::from_slice::<WebFetchCacheEntry>(&payload) {
                return Json(entry).into_response();
            }
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&payload) {
                return Json(value).into_response();
            }
        }
    }

    let scraper = match ScraperEngine::from_web_config(&config) {
        Ok(scraper) => scraper,
        Err(_err) => {
            return json_error_with_details(
                StatusCode::CONFLICT,
                ERR_MISSING_DEPENDENCY,
                "playwright browser not configured",
                browser_missing_details(&config),
            );
        }
    };
    web::fetch::enforce_domain_delay(&url, config.fetch_delay).await;
    let status_probe = fetch_status(&url, &config.user_agent, config.request_timeout).await;
    let fetch_result = match scraper.fetch_dom(&url).await {
        Ok(result) => result,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "web fetch failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "web fetch failed",
            );
        }
    };
    let status = fetch_result.status.or(status_probe);
    let body = extract_readable_text(&fetch_result.html, &url).unwrap_or_else(|| {
        let cleaned = ammonia::Builder::default()
            .tags(std::collections::HashSet::new())
            .clean(&fetch_result.html)
            .to_string();
        cleaned.split_whitespace().collect::<Vec<_>>().join(" ")
    });
    let entry = WebFetchCacheEntry {
        url: url.as_str().to_string(),
        status,
        fetched_at_epoch_ms: now_epoch_ms(),
        content: body,
        code_blocks: Vec::new(),
    };
    if let Some(layout) = layout.as_ref() {
        if config.cache_ttl.as_secs() > 0 {
            if let Ok(serialized) = serde_json::to_vec(&entry) {
                let _ = web::cache::write_cache_entry(layout, url.as_str(), &serialized);
            }
        }
    }
    Json(entry).into_response()
}

pub async fn web_cache_flush_handler(State(state): State<AppState>) -> Response {
    let Some(layout) = web::cache::cache_layout_from_config() else {
        return Json(serde_json::json!({
            "status": "skipped",
            "message": "web cache is not configured"
        }))
        .into_response();
    };
    let dir = web::cache::web_cache_dir(&layout);
    if dir.exists() {
        if let Err(err) = std::fs::remove_dir_all(&dir) {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "web cache flush failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "web cache flush failed",
            );
        }
    }
    if let Err(err) = std::fs::create_dir_all(&dir) {
        state.metrics.inc_error();
        warn!(target: "docdexd", error = ?err, "web cache flush failed");
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            "web cache flush failed",
        );
    }
    Json(serde_json::json!({
        "status": "ok",
        "path": dir.to_string_lossy(),
    }))
    .into_response()
}

fn now_epoch_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn browser_missing_details(config: &web::WebConfig) -> serde_json::Value {
    let manifest_path = util::resolve_playwright_manifest_path();
    let browsers = util::read_playwright_manifest()
        .map(|manifest| {
            manifest
                .browsers
                .into_iter()
                .filter(|browser| browser.path.is_file())
                .map(|browser| {
                    serde_json::json!({
                        "name": browser.name,
                        "version": browser.version,
                        "path": browser.path.to_string_lossy(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    serde_json::json!({
        "browser_available": !browsers.is_empty(),
        "install_action": "docdexd browser setup",
        "configured_browser": config.scraper_browser_kind.as_deref(),
        "manifest_path": manifest_path.map(|path| path.to_string_lossy().to_string()),
        "browsers": browsers,
    })
}
