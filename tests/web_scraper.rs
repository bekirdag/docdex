use docdexd::orchestrator::web_policy::SpacingBackoffPolicy;
use docdexd::web::scraper::ScraperEngine;
use docdexd::web::WebConfig;
use once_cell::sync::Lazy;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;
use tempfile::TempDir;
use url::Url;

static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

struct EnvGuard {
    key: &'static str,
    prev: Option<OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, prev }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(value) = self.prev.take() {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

fn touch_file(path: &Path) {
    std::fs::create_dir_all(path.parent().unwrap()).expect("create parent dir");
    std::fs::write(path, b"bin").expect("write file");
}

fn base_config(chrome_binary_path: Option<PathBuf>, headless: bool) -> WebConfig {
    WebConfig {
        enabled: true,
        discovery_provider: "duckduckgo_lite".to_string(),
        user_agent: "docdex-test-agent".to_string(),
        ddg_base_url: Url::parse("https://html.duckduckgo.com/html/").expect("valid url"),
        ddg_proxy_base_url: None,
        mswarm_base_url: Url::parse("http://127.0.0.1:8080").expect("valid url"),
        mswarm_api_key: None,
        request_timeout: Duration::from_millis(1000),
        max_results: 5,
        policy: SpacingBackoffPolicy {
            min_spacing: Duration::from_millis(1),
            jitter_ms: 0,
            max_attempts: 1,
            base_backoff: Duration::from_millis(1),
            backoff_multiplier: 1.0,
            max_backoff: Duration::from_millis(1),
            max_consecutive_failures: 1,
            cooldown: Duration::from_millis(1),
        },
        cache_ttl: Duration::from_secs(0),
        blocklist: Vec::new(),
        boilerplate_phrases: Vec::new(),
        fetch_delay: Duration::from_millis(1),
        scraper_engine: "chromium".to_string(),
        scraper_headless: headless,
        chrome_binary_path,
        scraper_browser_kind: Some("chromium".to_string()),
        scraper_user_data_dir: None,
        page_load_timeout: Duration::from_secs(1),
        brave_api_key: None,
        google_cse_api_key: None,
        google_cse_cx: None,
        bing_api_key: None,
    }
}

#[test]
fn chromium_engine_uses_configured_binary() {
    let _lock = ENV_LOCK.lock().unwrap();
    let temp = TempDir::new().expect("tempdir");
    let chromium_path = temp.path().join("docdex-chromium");
    touch_file(&chromium_path);
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _env_browser = EnvGuard::set("DOCDEX_WEB_BROWSER", "");
    let _chrome_path_env = EnvGuard::set("DOCDEX_CHROME_PATH", "");
    let _chrome_path_env_alias = EnvGuard::set("CHROME_PATH", "");

    let config = base_config(Some(chromium_path.clone()), false);

    let scraper = ScraperEngine::from_web_config(&config).expect("scraper");
    let ScraperEngine::Chrome { config } = scraper;
    assert_eq!(config.chrome_binary, chromium_path);
    assert!(!config.headless);
    assert_eq!(config.user_agent, "docdex-test-agent");
}

#[test]
fn scraper_engine_defaults_to_chromium() {
    let _lock = ENV_LOCK.lock().unwrap();
    let temp = TempDir::new().expect("tempdir");
    let chromium_path = temp.path().join("docdex-chromium");
    touch_file(&chromium_path);
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _env_browser = EnvGuard::set("DOCDEX_WEB_BROWSER", "");
    let _chrome_path_env = EnvGuard::set("DOCDEX_CHROME_PATH", "");
    let _chrome_path_env_alias = EnvGuard::set("CHROME_PATH", "");

    let mut config = base_config(Some(chromium_path), true);
    config.scraper_engine = "unknown".to_string();

    let scraper = ScraperEngine::from_web_config(&config).expect("scraper");
    match scraper {
        ScraperEngine::Chrome { .. } => {}
    }
}
