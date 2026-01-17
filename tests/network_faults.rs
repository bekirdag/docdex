use docdexd::error::{AppError, ERR_BACKOFF_REQUIRED, ERR_INTERNAL_ERROR};
use docdexd::orchestrator::web_policy::SpacingBackoffPolicy;
use docdexd::web::ddg::DdgDiscovery;
use docdexd::web::WebConfig;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use url::Url;

#[derive(Clone, Copy)]
enum FaultMode {
    Hang,
    Partial,
    Status(u16),
}

struct FaultServer {
    addr: SocketAddr,
    shutdown: Option<mpsc::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}

impl FaultServer {
    fn spawn(mode: FaultMode) -> Result<Self, Box<dyn Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let (tx, rx) = mpsc::channel::<()>();
        let join = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if rx.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                        let _ = stream.set_write_timeout(Some(Duration::from_millis(200)));
                        let mut buffer = [0u8; 512];
                        let _ = stream.read(&mut buffer);
                        match mode {
                            FaultMode::Hang => {
                                thread::sleep(Duration::from_millis(200));
                            }
                            FaultMode::Partial => {
                                let response = concat!(
                                    "HTTP/1.1 200 OK\r\n",
                                    "Content-Length: 100\r\n",
                                    "Connection: close\r\n",
                                    "\r\n",
                                    "partial"
                                );
                                let _ = stream.write_all(response.as_bytes());
                                let _ = stream.flush();
                            }
                            FaultMode::Status(code) => {
                                let response = format!(
                                    "HTTP/1.1 {code} Fault\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                                );
                                let _ = stream.write_all(response.as_bytes());
                                let _ = stream.flush();
                            }
                        }
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
            shutdown: Some(tx),
            join: Some(join),
        })
    }

    fn base_url(&self) -> Url {
        Url::parse(&format!("http://{}/html/", self.addr))
            .expect("fault server url should be valid")
    }
}

impl Drop for FaultServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct EnvGuard {
    key: &'static str,
    prev: Option<std::ffi::OsString>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &std::path::Path) -> Self {
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

fn can_bind_localhost() -> Result<bool, std::io::Error> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => {
            drop(listener);
            Ok(true)
        }
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => Ok(false),
        Err(err) => Err(err),
    }
}

fn build_config(base_url: Url, request_timeout: Duration) -> WebConfig {
    WebConfig {
        enabled: true,
        user_agent: "docdexd-test".to_string(),
        ddg_base_url: base_url,
        ddg_proxy_base_url: None,
        request_timeout,
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
        scraper_browser_kind: None,
        scraper_user_data_dir: None,
        page_load_timeout: Duration::from_secs(1),
        brave_api_key: None,
        google_cse_api_key: None,
        google_cse_cx: None,
        bing_api_key: None,
    }
}

fn assert_app_error(err: &anyhow::Error, expected_code: &str, message_contains: &str) {
    let app = err.downcast_ref::<AppError>().expect("expected AppError");
    assert_eq!(app.code, expected_code);
    assert!(
        app.message.contains(message_contains),
        "expected message to include `{message_contains}`, got `{}`",
        app.message
    );
}

#[test]
fn network_faults_surface_stable_errors() -> Result<(), Box<dyn Error>> {
    if !can_bind_localhost()? {
        eprintln!("skipping test: TCP bind not permitted in this environment");
        return Ok(());
    }
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
    let _config_guard = EnvGuard::set("DOCDEX_CONFIG_PATH", &config_path);
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        run_case(
            FaultMode::Hang,
            Duration::from_millis(50),
            ERR_INTERNAL_ERROR,
            "duckduckgo discovery failed",
        )
        .await?;
        run_case(
            FaultMode::Partial,
            Duration::from_millis(200),
            ERR_INTERNAL_ERROR,
            "duckduckgo discovery failed",
        )
        .await?;
        run_case(
            FaultMode::Status(404),
            Duration::from_millis(200),
            ERR_INTERNAL_ERROR,
            "status 404",
        )
        .await?;
        run_case(
            FaultMode::Status(429),
            Duration::from_secs(1),
            ERR_BACKOFF_REQUIRED,
            "duckduckgo discovery blocked",
        )
        .await?;
        Ok::<(), Box<dyn Error>>(())
    })?;
    Ok(())
}

async fn run_case(
    mode: FaultMode,
    timeout: Duration,
    expected_code: &'static str,
    message_contains: &'static str,
) -> Result<(), Box<dyn Error>> {
    let server = FaultServer::spawn(mode)?;
    let discovery = DdgDiscovery::new(build_config(server.base_url(), timeout))?;
    let err = discovery
        .discover("docdex", 3)
        .await
        .expect_err("expected discovery to fail");
    assert_app_error(&err, expected_code, message_contains);
    Ok(())
}
