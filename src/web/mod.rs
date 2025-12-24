pub mod cache;
pub mod ddg;
pub mod ddg_policy;
pub mod discovery;
pub mod normalize;
pub mod policy;
pub mod research;
pub mod scraper;

use std::env;
use std::time::Duration;

use url::Url;

use crate::web::policy::SpacingBackoffPolicy;

#[derive(Clone, Debug)]
pub struct WebConfig {
    pub enabled: bool,
    pub user_agent: String,
    pub ddg_base_url: Url,
    pub request_timeout: Duration,
    pub max_results: usize,
    pub policy: SpacingBackoffPolicy,
}

impl WebConfig {
    pub fn from_env() -> Self {
        let enabled = env_bool("DOCDEX_WEB_ENABLED", true);
        let user_agent = env::var("DOCDEX_WEB_USER_AGENT")
            .unwrap_or_else(|_| format!("docdexd/{}", env!("CARGO_PKG_VERSION")));
        let base_url = env::var("DOCDEX_DDG_BASE_URL")
            .unwrap_or_else(|_| "https://html.duckduckgo.com/html/".to_string());
        let ddg_base_url = Url::parse(&base_url).unwrap_or_else(|_| {
            Url::parse("https://html.duckduckgo.com/html/").expect("default url is valid")
        });
        let max_results = env_u64("DOCDEX_WEB_MAX_RESULTS", 8).max(1) as usize;
        let request_timeout_ms = env_u64("DOCDEX_WEB_REQUEST_TIMEOUT_MS", 10_000).max(1);
        let min_spacing_ms = env_u64("DOCDEX_WEB_MIN_SPACING_MS", 2000);
        let jitter_ms = env_u64("DOCDEX_WEB_JITTER_MS", 250);
        let max_attempts = env_u64("DOCDEX_WEB_MAX_ATTEMPTS", 3).max(1) as usize;
        let base_backoff_ms = env_u64("DOCDEX_WEB_BACKOFF_BASE_MS", 500);
        let backoff_multiplier = env_f64("DOCDEX_WEB_BACKOFF_MULTIPLIER", 2.0).max(1.0);
        let max_backoff_ms = env_u64("DOCDEX_WEB_BACKOFF_MAX_MS", 8000).max(base_backoff_ms);
        let max_consecutive_failures = env_u64("DOCDEX_WEB_MAX_CONSEC_FAIL", 3) as usize;
        let cooldown_ms = env_u64("DOCDEX_WEB_COOLDOWN_MS", 60_000);

        Self {
            enabled,
            user_agent,
            ddg_base_url,
            request_timeout: Duration::from_millis(request_timeout_ms),
            max_results,
            policy: SpacingBackoffPolicy {
                min_spacing: Duration::from_millis(min_spacing_ms),
                jitter_ms,
                max_attempts,
                base_backoff: Duration::from_millis(base_backoff_ms),
                backoff_multiplier,
                max_backoff: Duration::from_millis(max_backoff_ms),
                max_consecutive_failures,
                cooldown: Duration::from_millis(cooldown_ms),
            },
        }
    }
}

fn env_bool(key: &str, default: bool) -> bool {
    match env::var(key) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "y" | "on" => true,
            "0" | "false" | "no" | "n" | "off" => false,
            _ => default,
        },
        Err(_) => default,
    }
}

fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_f64(key: &str, default: f64) -> f64 {
    env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<f64>().ok())
        .unwrap_or(default)
}
