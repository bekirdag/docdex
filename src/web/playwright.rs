use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;
use tokio::process::Command;
use url::Url;

use crate::orchestrator::web_config::WebConfig;
use crate::util;
use crate::web::browser_install;
use crate::web::chrome::ChromeFetchResult;
use crate::web::playwright_scripts;

const FETCHER_ENV: &str = "DOCDEX_PLAYWRIGHT_FETCHER";
const INSTALLER_ENV: &str = "DOCDEX_PLAYWRIGHT_INSTALLER";

#[derive(Clone, Debug)]
pub struct PlaywrightFetchConfig {
    pub browser: String,
    pub headless: bool,
    pub user_agent: String,
    pub timeout: Duration,
    pub user_data_dir: Option<PathBuf>,
    pub browsers_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct PlaywrightFetchResponse {
    html: String,
    status: Option<u16>,
    final_url: Option<String>,
}

impl PlaywrightFetchConfig {
    pub fn from_web_config(config: &WebConfig) -> Option<Self> {
        let browser = normalize_playwright_browser(
            config.scraper_browser_kind.as_deref().unwrap_or("chromium"),
        );
        if !browser_install::playwright_dependency_status().installed {
            return None;
        }
        let manifest = util::read_playwright_manifest()?;
        let installed = manifest
            .browsers
            .iter()
            .any(|entry| entry.name.eq_ignore_ascii_case(&browser) && entry.path.is_file());
        if !installed {
            return None;
        }
        let manifest_path = util::resolve_playwright_manifest_path()?;
        let browsers_path = manifest
            .browsers_path
            .clone()
            .or_else(|| manifest_path.parent().map(|dir| dir.to_path_buf()));
        Some(Self {
            browser,
            headless: config.scraper_headless,
            user_agent: config.user_agent.clone(),
            timeout: config.page_load_timeout,
            user_data_dir: config.scraper_user_data_dir.clone(),
            browsers_path,
        })
    }
}

pub async fn fetch_dom(url: &Url, config: &PlaywrightFetchConfig) -> Result<ChromeFetchResult> {
    let script = resolve_playwright_fetcher_path()?;
    let timeout_ms = if config.timeout.is_zero() {
        15_000
    } else {
        config.timeout.as_millis().min(u128::from(u64::MAX)) as u64
    };
    let node_bin = browser_install::resolve_node_binary()?;

    let mut command = Command::new(&node_bin);
    command
        .arg(script.as_os_str())
        .arg("--url")
        .arg(url.as_str())
        .arg("--browser")
        .arg(&config.browser)
        .arg("--timeout-ms")
        .arg(timeout_ms.to_string())
        .arg("--user-agent")
        .arg(&config.user_agent);

    if config.headless {
        command.arg("--headless");
    } else {
        command.arg("--headed");
    }
    if let Some(dir) = config.user_data_dir.as_ref() {
        command.arg("--user-data-dir").arg(dir);
    }
    if let Some(path) = config.browsers_path.as_ref() {
        command.env("PLAYWRIGHT_BROWSERS_PATH", path);
    }
    if let Some(node_path) = browser_install::playwright_dependency_status().node_path {
        command.env("NODE_PATH", browser_install::merge_node_path(&node_path));
    }
    if let Some((key, value)) = browser_install::playwright_host_platform_override_env() {
        command.env(key, value);
    }

    let output = command.output().await.with_context(|| {
        format!(
            "spawn playwright fetcher {} via {}",
            script.display(),
            node_bin.display()
        )
    })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let message = stderr.trim();
        if message.is_empty() {
            return Err(anyhow!(
                "playwright fetch failed with status {}",
                output.status
            ));
        }
        return Err(anyhow!("playwright fetch failed: {message}"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let trimmed = stdout.trim();
    let payload: PlaywrightFetchResponse =
        serde_json::from_str(trimmed).context("parse playwright fetch response")?;
    if payload.html.trim().is_empty() {
        return Err(anyhow!("playwright fetch returned empty HTML"));
    }
    Ok(ChromeFetchResult {
        html: payload.html,
        inner_text: None,
        text_content: None,
        status: payload.status,
        final_url: payload.final_url,
    })
}

fn normalize_playwright_browser(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "chrome" | "chromium" | "chromium-browser" => "chromium".to_string(),
        "firefox" => "firefox".to_string(),
        "webkit" => "webkit".to_string(),
        _ => "chromium".to_string(),
    }
}

fn resolve_playwright_fetcher_path() -> Result<PathBuf> {
    if let Ok(value) = std::env::var(FETCHER_ENV) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            if path.is_file() {
                return Ok(path);
            }
            return Err(anyhow!(
                "Playwright fetcher not found at {}; set DOCDEX_PLAYWRIGHT_FETCHER to npm/lib/playwright_fetch.js",
                path.display()
            ));
        }
    }

    if let Ok(value) = std::env::var(INSTALLER_ENV) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            if let Some(parent) = path.parent() {
                let candidate = parent.join("playwright_fetch.js");
                if candidate.is_file() {
                    return Ok(candidate);
                }
            }
        }
    }

    let exe = std::env::current_exe().context("resolve current exe")?;
    let mut cursor = exe
        .parent()
        .ok_or_else(|| anyhow!("resolve current exe directory"))?
        .to_path_buf();

    for _ in 0..8 {
        let candidate = cursor.join("lib").join("playwright_fetch.js");
        if candidate.is_file() {
            return Ok(candidate);
        }
        let candidate = cursor.join("npm").join("lib").join("playwright_fetch.js");
        if candidate.is_file() {
            return Ok(candidate);
        }
        if !cursor.pop() {
            break;
        }
    }

    playwright_scripts::ensure_playwright_fetcher_script().context(
        "Playwright fetcher script not found; set DOCDEX_PLAYWRIGHT_FETCHER to npm/lib/playwright_fetch.js",
    )
}
