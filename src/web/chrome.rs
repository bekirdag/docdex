use anyhow::{anyhow, Context, Result};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tempfile::TempDir;
use tokio::process::Command;
use url::Url;

use crate::browser_session::{BrowserSession, BrowserSessionOptions};
use crate::orchestrator::web_config::WebConfig;
use crate::util;

#[derive(Clone, Debug)]
pub struct ChromeFetchConfig {
    pub chrome_binary: PathBuf,
    pub headless: bool,
    pub user_agent: String,
    pub timeout: Duration,
}

impl ChromeFetchConfig {
    pub fn from_web_config(config: &WebConfig) -> Option<Self> {
        let chrome_binary = config
            .chrome_binary_path
            .clone()
            .or_else(util::detect_chrome_binary)?;
        Some(Self {
            chrome_binary,
            headless: config.scraper_headless,
            user_agent: config.user_agent.clone(),
            timeout: config.page_load_timeout,
        })
    }
}

pub async fn fetch_dom(url: &Url, config: &ChromeFetchConfig) -> Result<String> {
    let mut command = Command::new(&config.chrome_binary);
    let user_data_dir =
        TempDir::new().context("create chrome user data directory")?;
    if config.headless {
        command.arg("--headless=new");
    }
    command.arg("--disable-gpu");
    command.arg("--disable-extensions");
    command.arg("--disable-dev-shm-usage");
    command.arg("--no-sandbox");
    command.arg("--no-first-run");
    command.arg("--no-default-browser-check");
    command.arg("--incognito");
    command.arg(format!(
        "--user-data-dir={}",
        user_data_dir.path().display()
    ));
    command.arg("--disable-background-timer-throttling");
    command.arg("--disable-backgrounding-occluded-windows");
    command.arg("--disable-renderer-backgrounding");
    command.arg("--run-all-compositor-stages-before-draw");
    command.arg(format!("--user-agent={}", config.user_agent));
    command.arg("--dump-dom");
    let settle_ms: u64 = 1500;
    if !config.timeout.is_zero() {
        let budget_ms = config.timeout.as_millis().max(1) + settle_ms as u128;
        command.arg(format!("--virtual-time-budget={budget_ms}"));
    }
    command.arg(url.as_str());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let wait_timeout = if config.timeout.is_zero() {
        config.timeout
    } else {
        config.timeout + Duration::from_millis(settle_ms)
    };
    let session = BrowserSession::spawn(command, BrowserSessionOptions::default())
        .await
        .map_err(|err| anyhow!("chrome launch failed: {err}"))?;
    let output = session
        .wait_for_output(wait_timeout)
        .await
        .map_err(|err| anyhow!("chrome fetch failed: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!(
            "chrome fetch exited with {}: {}",
            output.status,
            stderr.trim()
        ));
    }
    let html = String::from_utf8(output.stdout).context("chrome output not utf-8")?;
    Ok(html)
}
