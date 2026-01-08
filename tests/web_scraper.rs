use docdexd::orchestrator::web_policy::SpacingBackoffPolicy;
use docdexd::web::scraper::ScraperEngine;
use docdexd::web::WebConfig;
use once_cell::sync::Lazy;
use std::ffi::OsString;
use std::path::Path;
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

fn write_playwright_manifest(root: &Path, browsers: &[(&str, &Path)]) {
    let manifest_dir = root.join("playwright");
    std::fs::create_dir_all(&manifest_dir).expect("create manifest dir");
    let browser_entries: Vec<_> = browsers
        .iter()
        .map(|(name, path)| {
            serde_json::json!({
                "name": name,
                "version": "12345",
                "path": path,
            })
        })
        .collect();
    let payload = serde_json::json!({
        "installed_at": "2024-01-01T00:00:00Z",
        "browsers_path": manifest_dir.to_string_lossy(),
        "playwright_version": "1.2.3",
        "browsers": browser_entries
    });
    std::fs::write(manifest_dir.join("manifest.json"), payload.to_string())
        .expect("write manifest");
}

fn base_config() -> WebConfig {
    WebConfig {
        enabled: true,
        user_agent: "docdex-test-agent".to_string(),
        ddg_base_url: Url::parse("https://html.duckduckgo.com/html/").expect("valid url"),
        ddg_proxy_base_url: None,
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
        scraper_engine: "playwright".to_string(),
        scraper_headless: true,
        chrome_binary_path: None,
        scraper_browser_kind: None,
        scraper_user_data_dir: None,
        page_load_timeout: Duration::from_secs(1),
    }
}

#[test]
fn playwright_engine_uses_browser_kind() {
    let _lock = ENV_LOCK.lock().unwrap();
    let temp = TempDir::new().expect("tempdir");
    let chromium_path = temp.path().join("pw-chromium");
    let firefox_path = temp.path().join("pw-firefox");
    touch_file(&chromium_path);
    touch_file(&firefox_path);
    write_playwright_manifest(
        temp.path(),
        &[("chromium", &chromium_path), ("firefox", &firefox_path)],
    );
    let _pw_path = EnvGuard::set(
        "PLAYWRIGHT_BROWSERS_PATH",
        temp.path().join("playwright").to_string_lossy().as_ref(),
    );

    let mut config = base_config();
    config.scraper_engine = "playwright".to_string();
    config.scraper_browser_kind = Some("firefox".to_string());
    config.scraper_headless = false;

    let scraper = ScraperEngine::from_web_config(&config).expect("scraper");
    match scraper {
        ScraperEngine::Playwright { config } => {
            assert_eq!(config.browser, "firefox");
            assert!(!config.headless);
        }
        _ => panic!("expected playwright engine"),
    }
}

#[test]
fn scraper_engine_defaults_to_playwright() {
    let _lock = ENV_LOCK.lock().unwrap();
    let temp = TempDir::new().expect("tempdir");
    let chromium_path = temp.path().join("pw-chromium");
    touch_file(&chromium_path);
    write_playwright_manifest(temp.path(), &[("chromium", &chromium_path)]);
    let _pw_path = EnvGuard::set(
        "PLAYWRIGHT_BROWSERS_PATH",
        temp.path().join("playwright").to_string_lossy().as_ref(),
    );

    let mut config = base_config();
    config.scraper_engine = "unknown".to_string();

    let scraper = ScraperEngine::from_web_config(&config).expect("scraper");
    match scraper {
        ScraperEngine::Playwright { .. } => {}
    }
}
