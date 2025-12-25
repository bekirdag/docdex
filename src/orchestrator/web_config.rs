use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use url::Url;

use crate::config;
use crate::orchestrator::web_policy::SpacingBackoffPolicy;

#[derive(Clone, Debug)]
pub struct WebConfig {
    pub enabled: bool,
    pub user_agent: String,
    pub ddg_base_url: Url,
    pub request_timeout: Duration,
    pub max_results: usize,
    pub policy: SpacingBackoffPolicy,
    pub cache_ttl: Duration,
    pub blocklist: Vec<String>,
    pub boilerplate_phrases: Vec<String>,
    pub fetch_delay: Duration,
    pub scraper_engine: String,
    pub scraper_headless: bool,
    pub chrome_binary_path: Option<PathBuf>,
    pub page_load_timeout: Duration,
}

impl WebConfig {
    pub fn from_env() -> Self {
        let enabled = env_bool("DOCDEX_WEB_ENABLED", false);
        let user_agent = env::var("DOCDEX_WEB_USER_AGENT")
            .unwrap_or_else(|_| format!("docdexd/{}", env!("CARGO_PKG_VERSION")));
        let base_url = env::var("DOCDEX_DDG_BASE_URL")
            .unwrap_or_else(|_| "https://html.duckduckgo.com/html/".to_string());
        let ddg_base_url = Url::parse(&base_url).unwrap_or_else(|_| {
            Url::parse("https://html.duckduckgo.com/html/").expect("default url is valid")
        });
        let max_results = env_u64("DOCDEX_WEB_MAX_RESULTS", 20).max(1) as usize;
        let request_timeout_ms = env_u64("DOCDEX_WEB_REQUEST_TIMEOUT_MS", 10_000).max(1);
        let min_spacing_ms = env::var("DOCDEX_WEB_MIN_SPACING_MS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .or_else(config_min_spacing_ms)
            .unwrap_or(2000);
        let min_spacing_ms = min_spacing_ms.max(2_000);
        let jitter_ms = env_u64("DOCDEX_WEB_JITTER_MS", 250);
        let max_attempts = env_u64("DOCDEX_WEB_MAX_ATTEMPTS", 3).max(1) as usize;
        let base_backoff_ms = env_u64("DOCDEX_WEB_BACKOFF_BASE_MS", 500);
        let backoff_multiplier = env_f64("DOCDEX_WEB_BACKOFF_MULTIPLIER", 2.0).max(1.0);
        let max_backoff_ms = env_u64("DOCDEX_WEB_BACKOFF_MAX_MS", 8000).max(base_backoff_ms);
        let max_consecutive_failures = env_u64("DOCDEX_WEB_MAX_CONSEC_FAIL", 3) as usize;
        let cooldown_ms = env_u64("DOCDEX_WEB_COOLDOWN_MS", 60_000);
        let cache_ttl_secs = env::var("DOCDEX_WEB_CACHE_TTL_SECS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .or_else(config_cache_ttl_secs)
            .unwrap_or(86_400);
        let blocklist = env::var("DOCDEX_WEB_BLOCKLIST")
            .ok()
            .map(|value| split_blocklist(&value))
            .or_else(config_blocklist)
            .unwrap_or_default();
        let fetch_delay_ms = env::var("DOCDEX_WEB_REQUEST_DELAY_MS")
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .or_else(config_request_delay_ms)
            .unwrap_or(1_000);
        let fetch_delay_ms = fetch_delay_ms.max(1_000);
        let mut boilerplate_phrases = config_boilerplate_phrases().unwrap_or_default();
        if let Some(path) = config_boilerplate_phrases_path() {
            boilerplate_phrases.extend(load_boilerplate_file(&path));
        }
        let boilerplate_phrases = normalize_phrases(boilerplate_phrases);
        let scraper_engine = config_scraper_engine().unwrap_or_else(|| "chrome".to_string());
        let scraper_headless = config_scraper_headless().unwrap_or(true);
        let chrome_binary_path = config_scraper_chrome_binary();
        let page_load_timeout_secs = config_page_load_timeout_secs().unwrap_or(15);
        let page_load_timeout = Duration::from_secs(page_load_timeout_secs.max(1));

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
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            blocklist,
            boilerplate_phrases,
            fetch_delay: Duration::from_millis(fetch_delay_ms),
            scraper_engine,
            scraper_headless,
            chrome_binary_path,
            page_load_timeout,
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

fn config_cache_ttl_secs() -> Option<u64> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(config.web.cache_ttl_secs)
}

fn config_min_spacing_ms() -> Option<u64> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(config.web.min_spacing_ms)
}

fn config_request_delay_ms() -> Option<u64> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(config.web.scraper.request_delay_ms)
}

fn config_page_load_timeout_secs() -> Option<u64> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(config.web.scraper.page_load_timeout_secs)
}

fn config_scraper_engine() -> Option<String> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(config.web.scraper.engine.clone())
}

fn config_scraper_headless() -> Option<bool> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(config.web.scraper.headless)
}

fn config_scraper_chrome_binary() -> Option<PathBuf> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    config.web.scraper.chrome_binary_path
}

fn config_blocklist() -> Option<Vec<String>> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(split_blocklist_list(&config.web.blocklist))
}

fn config_boilerplate_phrases() -> Option<Vec<String>> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(config.web.boilerplate_phrases.clone())
}

fn config_boilerplate_phrases_path() -> Option<PathBuf> {
    let config_path = config::default_config_path().ok()?;
    if !config_path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&config_path).ok()?;
    let path = config.web.boilerplate_phrases_path.clone()?;
    if path.is_absolute() {
        return Some(path);
    }
    let base = config_path.parent().unwrap_or_else(|| std::path::Path::new("."));
    Some(base.join(path))
}

fn split_blocklist(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect()
}

fn split_blocklist_list(values: &[String]) -> Vec<String> {
    values
        .iter()
        .flat_map(|value| split_blocklist(value))
        .collect()
}

fn normalize_phrases(values: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            continue;
        }
        out.push(trimmed.to_ascii_lowercase());
    }
    out
}

fn load_boilerplate_file(path: &PathBuf) -> Vec<String> {
    let data = match fs::read_to_string(path) {
        Ok(data) => data,
        Err(_) => return Vec::new(),
    };
    data.lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with('#'))
        .map(|line| line.to_ascii_lowercase())
        .collect()
}
