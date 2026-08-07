use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use url::Url;

use crate::config;
use crate::orchestrator::web_policy::SpacingBackoffPolicy;
use crate::state_layout::StateLayout;

#[derive(Clone, Debug)]
pub struct WebConfig {
    pub enabled: bool,
    pub discovery_provider: String,
    pub user_agent: String,
    pub ddg_base_url: Url,
    pub ddg_proxy_base_url: Option<Url>,
    pub searxng_urls: Vec<Url>,
    pub mswarm_base_url: Url,
    pub mswarm_api_key: Option<String>,
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
    pub scraper_auto_install: bool,
    pub scraper_browser_kind: Option<String>,
    pub scraper_user_data_dir: Option<PathBuf>,
    pub page_load_timeout: Duration,
    pub brave_api_key: Option<String>,
    pub google_cse_api_key: Option<String>,
    pub google_cse_cx: Option<String>,
    pub bing_api_key: Option<String>,
}

impl WebConfig {
    pub fn from_env() -> Self {
        // Precedence: an explicit environment value wins, then `[web] enabled`
        // from config.toml, then the historical default.
        let enabled = match env_bool_opt("DOCDEX_WEB_ENABLED") {
            Some(value) => value,
            None => config_web_enabled().unwrap_or(false),
        };
        let discovery_provider = env::var("DOCDEX_WEB_DISCOVERY_PROVIDER")
            .ok()
            .and_then(|value| normalize_nonempty(value))
            .or_else(config_discovery_provider)
            .unwrap_or_else(config::default_discovery_provider);
        let user_agent = env::var("DOCDEX_WEB_USER_AGENT")
            .ok()
            .and_then(|value| normalize_nonempty(value))
            .or_else(config_user_agent)
            .unwrap_or_else(config::default_web_user_agent);
        let base_url = env::var("DOCDEX_DDG_BASE_URL")
            .ok()
            .and_then(|value| normalize_nonempty(value))
            .or_else(config_ddg_base_url)
            .unwrap_or_else(|| "https://lite.duckduckgo.com/lite/".to_string());
        let ddg_base_url = Url::parse(&base_url).unwrap_or_else(|_| {
            Url::parse("https://lite.duckduckgo.com/lite/").expect("default url is valid")
        });
        let ddg_proxy_base_url = env::var("DOCDEX_DDG_PROXY_BASE_URL")
            .ok()
            .and_then(|value| normalize_nonempty(value))
            .or_else(config_ddg_proxy_base_url)
            .and_then(|value| Url::parse(&value).ok());
        let searxng_urls = env_searxng_urls("DOCDEX_WEB_SEARXNG_URLS")
            .or_else(|| env_searxng_urls("DOCDEX_SEARXNG_URLS"))
            .or_else(config_searxng_urls)
            .unwrap_or_else(default_runtime_searxng_urls);
        let mswarm_base_url = env::var("DOCDEX_MSWARM_BASE_URL")
            .ok()
            .and_then(|value| normalize_nonempty(value))
            .or_else(config_mswarm_base_url)
            .unwrap_or_else(config::default_mswarm_base_url);
        let mswarm_base_url = Url::parse(&mswarm_base_url).unwrap_or_else(|_| {
            Url::parse(&config::default_mswarm_base_url()).expect("default mswarm url is valid")
        });
        let mswarm_api_key = env_nonempty("DOCDEX_MSWARM_API_KEY").or_else(config_mswarm_api_key);
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
            .unwrap_or(2_592_000);
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
        let scraper_engine = config_scraper_engine().unwrap_or_else(|| "chromium".to_string());
        let scraper_headless = config_scraper_headless().unwrap_or(true);
        let chrome_binary_path = config_scraper_chrome_binary();
        let scraper_auto_install = env_bool(
            "DOCDEX_BROWSER_AUTO_INSTALL",
            config_scraper_auto_install().unwrap_or(true),
        );
        let scraper_browser_kind =
            config_scraper_browser_kind().or_else(|| Some("chromium".to_string()));
        let scraper_user_data_dir = env::var("DOCDEX_BROWSER_USER_DATA_DIR")
            .ok()
            .and_then(|value| normalize_nonempty(value))
            .map(PathBuf::from)
            .or_else(config_scraper_user_data_dir)
            .or_else(|| default_scraper_user_data_dir(&scraper_engine));
        let page_load_timeout_secs = config_page_load_timeout_secs().unwrap_or(15);
        let page_load_timeout = Duration::from_secs(page_load_timeout_secs.max(1));
        let brave_api_key = env_nonempty("DOCDEX_BRAVE_API_KEY").or_else(config_brave_api_key);
        let google_cse_api_key =
            env_nonempty("DOCDEX_GOOGLE_CSE_API_KEY").or_else(config_google_cse_api_key);
        let google_cse_cx = env_nonempty("DOCDEX_GOOGLE_CSE_CX").or_else(config_google_cse_cx);
        let bing_api_key = env_nonempty("DOCDEX_BING_API_KEY").or_else(config_bing_api_key);

        Self {
            enabled,
            discovery_provider,
            user_agent,
            ddg_base_url,
            ddg_proxy_base_url,
            searxng_urls,
            mswarm_base_url,
            mswarm_api_key,
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
            scraper_auto_install,
            scraper_browser_kind,
            scraper_user_data_dir,
            page_load_timeout,
            brave_api_key,
            google_cse_api_key,
            google_cse_cx,
            bing_api_key,
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

fn normalize_nonempty(value: String) -> Option<String> {
    let trimmed = value.trim().to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn env_nonempty(key: &str) -> Option<String> {
    env::var(key).ok().and_then(normalize_nonempty)
}

fn config_user_agent() -> Option<String> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    normalize_nonempty(config.web.user_agent)
}

/// True when an operator has explicitly turned web access off, via
/// `DOCDEX_WEB_ENABLED` or `[web] enabled` in config.toml.
///
/// The CLI enables web by default because a bare `docdexd web-search` is an
/// explicit request for it, but an explicit "off" has to win — otherwise the
/// kill switch only covers the daemon and not the subprocesses that do the
/// actual fetching.
pub fn web_explicitly_disabled() -> bool {
    match env_bool_opt("DOCDEX_WEB_ENABLED") {
        Some(value) => !value,
        None => config_web_enabled() == Some(false),
    }
}

fn env_bool_opt(key: &str) -> Option<bool> {
    let raw = env::var(key).ok()?;
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

fn config_web_enabled() -> Option<bool> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    config::load_config_from_path(&path).ok()?.web.enabled
}

fn config_discovery_provider() -> Option<String> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    normalize_nonempty(config.web.discovery_provider)
}

fn config_ddg_base_url() -> Option<String> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    config.web.ddg_base_url.and_then(normalize_nonempty)
}

fn config_ddg_proxy_base_url() -> Option<String> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    config.web.ddg_proxy_base_url.and_then(normalize_nonempty)
}

fn config_searxng_urls() -> Option<Vec<Url>> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    let mut config = config::parse_config_text(&text).ok()?;
    config.apply_defaults().ok()?;
    Some(
        config::normalize_searxng_urls(&config.web.searxng_urls)
            .into_iter()
            .filter_map(|value| Url::parse(&value).ok())
            .collect(),
    )
}

fn env_searxng_urls(key: &str) -> Option<Vec<Url>> {
    env::var_os(key).map(|raw| runtime_searxng_urls(&raw.to_string_lossy()))
}

fn runtime_searxng_urls(raw: &str) -> Vec<Url> {
    let values = vec![raw.to_string()];
    config::normalize_searxng_urls(&values)
        .into_iter()
        .filter_map(|value| Url::parse(&value).ok())
        .collect()
}

fn default_runtime_searxng_urls() -> Vec<Url> {
    config::default_searxng_urls()
        .into_iter()
        .filter_map(|value| Url::parse(&value).ok())
        .collect()
}

fn config_brave_api_key() -> Option<String> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    config
        .web
        .providers
        .brave_api_key
        .and_then(normalize_nonempty)
}

fn config_google_cse_api_key() -> Option<String> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    config
        .web
        .providers
        .google_cse_api_key
        .and_then(normalize_nonempty)
}

fn config_google_cse_cx() -> Option<String> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    config
        .web
        .providers
        .google_cse_cx
        .and_then(normalize_nonempty)
}

fn config_bing_api_key() -> Option<String> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    config
        .web
        .providers
        .bing_api_key
        .and_then(normalize_nonempty)
}

fn config_mswarm_base_url() -> Option<String> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    normalize_nonempty(config.integrations.mswarm.base_url)
}

fn config_mswarm_api_key() -> Option<String> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    config
        .integrations
        .mswarm
        .api_key
        .and_then(normalize_nonempty)
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

fn config_scraper_auto_install() -> Option<bool> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(config.web.scraper.auto_install)
}

fn config_scraper_chrome_binary() -> Option<PathBuf> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    config.web.scraper.chrome_binary_path
}

fn config_scraper_user_data_dir() -> Option<PathBuf> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    config.web.scraper.user_data_dir
}

fn config_scraper_browser_kind() -> Option<String> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    config.web.scraper.browser_kind.clone()
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
    let base = config_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
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

pub(crate) fn default_scraper_user_data_dir(engine: &str) -> Option<PathBuf> {
    let config = config::AppConfig::load_default().ok()?;
    let base_dir = config.core.global_state_dir?;
    let layout = StateLayout::new(base_dir);
    layout.ensure_global_dirs().ok()?;
    let normalized = engine.trim().to_ascii_lowercase();
    let profile_dir = match normalized.as_str() {
        "chrome" | "chromium" | "chromium-browser" => "chrome",
        other if other.is_empty() => "chrome",
        other => other,
    };
    Some(layout.browser_profiles_dir().join(profile_dir))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::test_support::ENV_LOCK;
    use parking_lot::ReentrantMutexGuard;
    use tempfile::TempDir;

    struct EnvSnapshot {
        entries: Vec<(&'static str, Option<String>)>,
        _lock: ReentrantMutexGuard<'static, ()>,
    }

    impl EnvSnapshot {
        fn new(keys: &[&'static str]) -> Self {
            let lock = ENV_LOCK.lock();
            let entries = keys
                .iter()
                .map(|key| (*key, std::env::var(key).ok()))
                .collect();
            Self {
                entries,
                _lock: lock,
            }
        }

        fn set(&self, key: &'static str, value: &str) {
            std::env::set_var(key, value);
        }

        fn clear(&self, key: &'static str) {
            std::env::remove_var(key);
        }
    }

    impl Drop for EnvSnapshot {
        fn drop(&mut self) {
            for (key, value) in &self.entries {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }

    #[test]
    fn resolves_default_scraper_user_data_dir_from_state_dir(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let state_dir = temp.path().join("state");
        let config_path = temp.path().join("config.toml");

        let mut config = config::AppConfig::default();
        config.core.global_state_dir = Some(state_dir.clone());
        config.web.scraper.engine = "chromium".to_string();
        config.web.scraper.user_data_dir = None;
        config.apply_defaults()?;
        config::write_config(&config_path, &config)?;

        let env = EnvSnapshot::new(&[
            "DOCDEX_CONFIG_PATH",
            "DOCDEX_BROWSER_AUTO_INSTALL",
            "DOCDEX_BROWSER_USER_DATA_DIR",
            "DOCDEX_WEB_DISCOVERY_PROVIDER",
            "DOCDEX_MSWARM_BASE_URL",
            "DOCDEX_MSWARM_API_KEY",
        ]);
        env.set("DOCDEX_CONFIG_PATH", config_path.to_string_lossy().as_ref());
        env.set("DOCDEX_BROWSER_AUTO_INSTALL", "0");
        env.clear("DOCDEX_BROWSER_USER_DATA_DIR");

        let web_config = WebConfig::from_env();
        let expected = state_dir.join("browser_profiles").join("chrome");
        assert_eq!(web_config.scraper_user_data_dir, Some(expected));
        Ok(())
    }

    #[test]
    fn web_config_reads_mswarm_settings_from_config() -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let config_path = temp.path().join("config.toml");

        let mut config = config::AppConfig::default();
        config.web.discovery_provider = "mswarm".to_string();
        config.integrations.mswarm.base_url = "https://api.mswarm.org/".to_string();
        config.integrations.mswarm.api_key = Some("mswarm-key".to_string());
        config.apply_defaults()?;
        config::write_config(&config_path, &config)?;

        let env = EnvSnapshot::new(&[
            "DOCDEX_CONFIG_PATH",
            "DOCDEX_BROWSER_AUTO_INSTALL",
            "DOCDEX_WEB_DISCOVERY_PROVIDER",
            "DOCDEX_MSWARM_BASE_URL",
            "DOCDEX_MSWARM_API_KEY",
        ]);
        env.set("DOCDEX_CONFIG_PATH", config_path.to_string_lossy().as_ref());
        env.set("DOCDEX_BROWSER_AUTO_INSTALL", "0");
        env.clear("DOCDEX_WEB_DISCOVERY_PROVIDER");
        env.clear("DOCDEX_MSWARM_BASE_URL");
        env.clear("DOCDEX_MSWARM_API_KEY");

        let web_config = WebConfig::from_env();
        assert_eq!(web_config.discovery_provider, "mswarm");
        assert_eq!(
            web_config.mswarm_base_url,
            Url::parse("https://api.mswarm.org/").expect("valid url")
        );
        assert_eq!(web_config.mswarm_api_key.as_deref(), Some("mswarm-key"));
        Ok(())
    }

    #[test]
    fn web_config_resolves_searxng_precedence_and_ignores_invalid_urls(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let config_path = temp.path().join("config.toml");

        let mut config = config::AppConfig::default();
        config.web.searxng_urls = vec!["https://typed.example".to_string()];
        config.apply_defaults()?;
        config::write_config(&config_path, &config)?;

        let env = EnvSnapshot::new(&[
            "DOCDEX_CONFIG_PATH",
            "DOCDEX_BROWSER_AUTO_INSTALL",
            "DOCDEX_WEB_SEARXNG_URLS",
            "DOCDEX_SEARXNG_URLS",
        ]);
        env.set("DOCDEX_CONFIG_PATH", config_path.to_string_lossy().as_ref());
        env.set("DOCDEX_BROWSER_AUTO_INSTALL", "0");
        env.clear("DOCDEX_WEB_SEARXNG_URLS");
        env.clear("DOCDEX_SEARXNG_URLS");
        let _ = config::load_config_from_path(&config_path)?;
        env.set(
            "DOCDEX_WEB_SEARXNG_URLS",
            "https://primary.example, ftp://invalid.example",
        );
        env.set("DOCDEX_SEARXNG_URLS", "https://legacy.example/base");

        assert_eq!(
            WebConfig::from_env().searxng_urls,
            vec![Url::parse("https://primary.example/search")?]
        );

        env.clear("DOCDEX_WEB_SEARXNG_URLS");
        assert_eq!(
            WebConfig::from_env().searxng_urls,
            vec![Url::parse("https://legacy.example/base/search")?]
        );

        env.clear("DOCDEX_SEARXNG_URLS");
        assert_eq!(
            WebConfig::from_env().searxng_urls,
            vec![Url::parse("https://typed.example/search")?]
        );

        env.set(
            "DOCDEX_WEB_SEARXNG_URLS",
            "not-a-url, ftp://invalid.example",
        );
        assert!(WebConfig::from_env().searxng_urls.is_empty());

        env.set("DOCDEX_WEB_SEARXNG_URLS", "");
        assert!(WebConfig::from_env().searxng_urls.is_empty());
        Ok(())
    }

    #[test]
    fn config_file_can_disable_web_when_env_is_unset() {
        let env = EnvSnapshot::new(&["DOCDEX_WEB_ENABLED", "DOCDEX_CONFIG_PATH"]);
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[web]\nenabled = false\n").expect("write config");
        env.set("DOCDEX_CONFIG_PATH", &path.to_string_lossy());
        env.clear("DOCDEX_WEB_ENABLED");

        // `[web] enabled` used to be absent from the schema, so serde discarded
        // it and operators had no supported way to turn web research off.
        assert_eq!(config_web_enabled(), Some(false));
        assert!(!WebConfig::from_env().enabled);
    }

    #[test]
    fn config_file_can_enable_web_when_env_is_unset() {
        let env = EnvSnapshot::new(&["DOCDEX_WEB_ENABLED", "DOCDEX_CONFIG_PATH"]);
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[web]\nenabled = true\n").expect("write config");
        env.set("DOCDEX_CONFIG_PATH", &path.to_string_lossy());
        env.clear("DOCDEX_WEB_ENABLED");

        assert!(WebConfig::from_env().enabled);
    }

    #[test]
    fn environment_overrides_the_config_file_in_both_directions() {
        let env = EnvSnapshot::new(&["DOCDEX_WEB_ENABLED", "DOCDEX_CONFIG_PATH"]);
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[web]\nenabled = false\n").expect("write config");
        env.set("DOCDEX_CONFIG_PATH", &path.to_string_lossy());

        env.set("DOCDEX_WEB_ENABLED", "1");
        assert!(WebConfig::from_env().enabled, "env must win over config");

        env.set("DOCDEX_WEB_ENABLED", "0");
        assert!(!WebConfig::from_env().enabled);

        // An unparseable value is not an opinion; fall back to the config file.
        env.set("DOCDEX_WEB_ENABLED", "maybe");
        assert!(!WebConfig::from_env().enabled);
    }

    #[test]
    fn omitting_web_enabled_leaves_the_environment_default() {
        let env = EnvSnapshot::new(&["DOCDEX_WEB_ENABLED", "DOCDEX_CONFIG_PATH"]);
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[web]\nuser_agent = \"x\"\n").expect("write config");
        env.set("DOCDEX_CONFIG_PATH", &path.to_string_lossy());
        env.clear("DOCDEX_WEB_ENABLED");

        assert_eq!(config_web_enabled(), None);
        assert!(!WebConfig::from_env().enabled);
    }

    #[test]
    fn explicit_disable_is_detected_from_either_source() {
        let env = EnvSnapshot::new(&["DOCDEX_WEB_ENABLED", "DOCDEX_CONFIG_PATH"]);
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("config.toml");
        env.set("DOCDEX_CONFIG_PATH", &path.to_string_lossy());

        // Nothing configured: the CLI keeps its default-on behaviour.
        std::fs::write(&path, "[web]\nuser_agent = \"x\"\n").expect("write config");
        env.clear("DOCDEX_WEB_ENABLED");
        assert!(!web_explicitly_disabled());

        // Config file says off.
        std::fs::write(&path, "[web]\nenabled = false\n").expect("write config");
        assert!(web_explicitly_disabled());

        // Environment overrides the file in both directions.
        env.set("DOCDEX_WEB_ENABLED", "1");
        assert!(!web_explicitly_disabled());
        env.set("DOCDEX_WEB_ENABLED", "0");
        assert!(web_explicitly_disabled());

        // Config file says on.
        std::fs::write(&path, "[web]\nenabled = true\n").expect("write config");
        env.clear("DOCDEX_WEB_ENABLED");
        assert!(!web_explicitly_disabled());
    }
}
