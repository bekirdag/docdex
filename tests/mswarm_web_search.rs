use docdexd::orchestrator::web_policy::SpacingBackoffPolicy;
use docdexd::web::ddg::DdgDiscovery;
use docdexd::web::WebConfig;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use url::Url;

struct EnvGuard {
    key: &'static str,
    prev: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set_path(key: &'static str, value: &std::path::Path) -> Self {
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

struct MswarmServer {
    addr: SocketAddr,
    last_request: Arc<Mutex<Option<String>>>,
    shutdown: Option<mpsc::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}

impl MswarmServer {
    fn spawn() -> Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let last_request = Arc::new(Mutex::new(None));
        let captured = Arc::clone(&last_request);
        let (tx, rx) = mpsc::channel::<()>();
        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if rx.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                        let _ = stream.set_write_timeout(Some(Duration::from_millis(500)));
                        let mut buffer = Vec::new();
                        let mut chunk = [0u8; 1024];
                        loop {
                            match stream.read(&mut chunk) {
                                Ok(0) => break,
                                Ok(read) => {
                                    buffer.extend_from_slice(&chunk[..read]);
                                    if buffer.windows(4).any(|window| window == b"\r\n\r\n") {
                                        break;
                                    }
                                }
                                Err(err)
                                    if err.kind() == std::io::ErrorKind::WouldBlock
                                        || err.kind() == std::io::ErrorKind::TimedOut =>
                                {
                                    break;
                                }
                                Err(_) => break,
                            }
                        }
                        let request = String::from_utf8_lossy(&buffer).to_string();
                        if let Ok(mut slot) = captured.lock() {
                            *slot = Some(request);
                        }
                        let body = serde_json::json!({
                            "results": [
                                {
                                    "title": "Example",
                                    "url": "https://example.com/docdex-mswarm",
                                    "snippet": "Docdex via mswarm",
                                    "provider": "brave_search"
                                }
                            ],
                            "cache_hit": false,
                            "normalized_query": "rust http client",
                            "cache_key": "search:rust-http-client",
                            "cache_key_version": "ck-v0",
                            "ttl_tier": "1m",
                            "provenance": {
                                "provider": "brave_search",
                                "fetched_at_ms": 1,
                                "policy_version": "v0"
                            }
                        })
                        .to_string();
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                        break;
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        if Instant::now() > deadline {
                            break;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            addr,
            last_request,
            shutdown: Some(tx),
            join: Some(join),
        })
    }

    fn base_url(&self) -> Url {
        Url::parse(&format!("http://{}", self.addr)).expect("valid server url")
    }
}

impl Drop for MswarmServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

#[test]
fn discovery_uses_mswarm_web_search() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let config_path = temp.path().join("config.toml");
    let state_dir = temp.path().join("state");
    let mut state_dir_text = state_dir.display().to_string();
    if cfg!(windows) {
        state_dir_text = state_dir_text.replace('\\', "\\\\");
    }
    std::fs::write(
        &config_path,
        format!("[core]\nglobal_state_dir = \"{state_dir_text}\"\n"),
    )?;
    let _config_guard = EnvGuard::set_path("DOCDEX_CONFIG_PATH", &config_path);
    let server = MswarmServer::spawn()?;
    let config = WebConfig {
        enabled: true,
        discovery_provider: "mswarm".to_string(),
        user_agent: "docdexd-test".to_string(),
        ddg_base_url: Url::parse("https://lite.duckduckgo.com/lite/").expect("valid url"),
        ddg_proxy_base_url: None,
        searxng_urls: Vec::new(),
        mswarm_base_url: server.base_url(),
        mswarm_api_key: Some("mswarm-key".to_string()),
        request_timeout: Duration::from_millis(500),
        max_results: 5,
        policy: SpacingBackoffPolicy {
            min_spacing: Duration::ZERO,
            jitter_ms: 0,
            max_attempts: 1,
            base_backoff: Duration::from_millis(1),
            backoff_multiplier: 1.0,
            max_backoff: Duration::from_millis(1),
            max_consecutive_failures: 1,
            cooldown: Duration::ZERO,
        },
        cache_ttl: Duration::ZERO,
        blocklist: Vec::new(),
        boilerplate_phrases: Vec::new(),
        fetch_delay: Duration::ZERO,
        scraper_engine: "chromium".to_string(),
        scraper_headless: true,
        chrome_binary_path: None,
        scraper_auto_install: false,
        scraper_browser_kind: None,
        scraper_user_data_dir: None,
        page_load_timeout: Duration::from_secs(1),
        brave_api_key: None,
        google_cse_api_key: None,
        google_cse_cx: None,
        bing_api_key: None,
    };

    let rt = tokio::runtime::Runtime::new()?;
    let response = rt.block_on(async {
        let discovery = DdgDiscovery::new(config)?;
        discovery.discover("rust http client", 3).await
    })?;

    assert_eq!(response.provider, "mswarm");
    assert_eq!(response.results.len(), 1);
    assert_eq!(response.results[0].url, "https://example.com/docdex-mswarm");

    let request = server
        .last_request
        .lock()
        .expect("captured request")
        .clone()
        .expect("request payload");
    assert!(request.contains("POST /v1/swarm/web/search HTTP/1.1"));
    assert!(request
        .to_ascii_lowercase()
        .contains("x-api-key: mswarm-key"));
    assert!(request.contains("\"query\":\"rust http client\""));
    assert!(request.contains("\"tool_id\":\"docdex\""));
    Ok(())
}
