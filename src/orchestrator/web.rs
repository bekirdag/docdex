use crate::index::Hit;
use crate::index::Indexer;
use crate::libs::LibsIndexer;
use crate::search;
use crate::tier2::{Tier2Unavailable, Tier2UnavailableReason};
use serde::Serialize;
use std::env;
use std::path::Path;
use which::which;

const DEFAULT_WEB_TRIGGER_THRESHOLD: f32 = 0.45;

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
        let trigger_threshold =
            env_f32("DOCDEX_WEB_TRIGGER_THRESHOLD").unwrap_or(DEFAULT_WEB_TRIGGER_THRESHOLD);
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

    pub fn should_attempt(&self, top_score: Option<f32>, force_web: bool) -> bool {
        if force_web {
            return true;
        }
        top_score.map_or(true, |score| score < self.trigger_threshold)
    }
}

pub(crate) fn build_gate_meta(
    gate: &WebGateConfig,
    top_score: Option<f32>,
    force_web: bool,
) -> WebGateMeta {
    WebGateMeta {
        enabled: gate.enabled,
        forced: force_web,
        threshold: gate.trigger_threshold,
        top_score,
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WebDiscoveryStatusCode {
    Skipped,
    Disabled,
    Unavailable,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebGateMeta {
    pub enabled: bool,
    pub forced: bool,
    pub threshold: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_score: Option<f32>,
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
    pub gate: WebGateMeta,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebResearchResponse {
    pub completion: String,
    pub hits: Vec<Hit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_score: Option<f32>,
    #[serde(rename = "topScore", skip_serializing_if = "Option::is_none")]
    pub top_score_camel: Option<f32>,
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
    let hits = search_response.hits;
    let completion = build_completion(query, &hits);
    let web_discovery = evaluate_gate_status(request_id, gate, top_score, force_web);
    Ok(WebResearchResponse {
        completion,
        hits,
        top_score,
        top_score_camel: top_score,
        web_discovery,
    })
}

pub(crate) fn evaluate_gate_status(
    request_id: &str,
    gate: &WebGateConfig,
    top_score: Option<f32>,
    force_web: bool,
) -> WebDiscoveryStatus {
    let gate_meta = build_gate_meta(gate, top_score, force_web);

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
            gate: gate_meta,
        };
    }

    if !gate.should_attempt(top_score, force_web) {
        return WebDiscoveryStatus {
            status: WebDiscoveryStatusCode::Skipped,
            reason: Some("confidence_above_threshold".to_string()),
            message: Some("web discovery skipped by confidence gate".to_string()),
            unavailable: None,
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
        gate: gate_meta,
    }
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
        let status = evaluate_gate_status("req", &gate, Some(0.8), false);
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
        let status = evaluate_gate_status("req", &gate, Some(0.1), false);
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

fn resolve_browser_available(hint: Option<&str>) -> bool {
    if let Some(path) = hint {
        if Path::new(path).is_file() {
            return true;
        }
        if which(path).is_ok() {
            return true;
        }
        return false;
    }

    let candidates = ["google-chrome", "chromium", "chromium-browser", "chrome"];
    candidates.iter().any(|cmd| which(cmd).is_ok())
}
