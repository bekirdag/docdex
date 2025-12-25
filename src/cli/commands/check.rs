use crate::config;
use crate::ollama;
use crate::orchestrator::web;
use crate::state_layout::StateLayout;
use anyhow::Result;
use serde::Serialize;
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;

#[derive(Serialize)]
struct CheckItem {
    name: &'static str,
    status: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct CheckReport {
    status: &'static str,
    success: bool,
    checks: Vec<CheckItem>,
}

pub async fn run() -> Result<()> {
    let mut checks = Vec::new();
    let mut success = true;

    let config_path = config::default_config_path().ok();
    let config = match config::AppConfig::load_default() {
        Ok(config) => {
            checks.push(CheckItem {
                name: "config",
                status: "ok",
                message: "config loaded".to_string(),
                details: config_path
                    .as_ref()
                    .map(|path| json!({ "path": path.to_string_lossy() })),
            });
            Some(config)
        }
        Err(err) => {
            checks.push(CheckItem {
                name: "config",
                status: "fail",
                message: format!("config load failed: {err}"),
                details: config_path
                    .as_ref()
                    .map(|path| json!({ "path": path.to_string_lossy() })),
            });
            success = false;
            None
        }
    };

    if let Some(config) = config {
        if let Some(state_dir) = config.core.global_state_dir.clone() {
            let layout = StateLayout::new(state_dir.clone());
            match layout.ensure_global_dirs() {
                Ok(()) => checks.push(CheckItem {
                    name: "state",
                    status: "ok",
                    message: "state directories are writable".to_string(),
                    details: Some(json!({ "path": state_dir.to_string_lossy() })),
                }),
                Err(err) => {
                    checks.push(CheckItem {
                        name: "state",
                        status: "fail",
                        message: format!("state directory not writable: {err}"),
                        details: Some(json!({ "path": state_dir.to_string_lossy() })),
                    });
                    success = false;
                }
            }
        } else {
            checks.push(CheckItem {
                name: "state",
                status: "fail",
                message: "global_state_dir is not configured".to_string(),
                details: None,
            });
            success = false;
        }

        let bind_addr_raw = config.server.http_bind_addr.trim();
        match bind_addr_raw.parse::<SocketAddr>() {
            Ok(addr) => {
                let loopback = addr.ip().is_loopback();
                let token = env_non_empty("DOCDEX_AUTH_TOKEN");
                let needs_token = !loopback;
                let message = if needs_token && token.is_none() {
                    success = false;
                    "non-loopback bind requires DOCDEX_AUTH_TOKEN (or --auth-token when serving)"
                        .to_string()
                } else {
                    "bind address validated".to_string()
                };
                checks.push(CheckItem {
                    name: "bind",
                    status: if needs_token && token.is_none() {
                        "fail"
                    } else {
                        "ok"
                    },
                    message,
                    details: Some(json!({
                        "bind_addr": bind_addr_raw,
                        "loopback": loopback,
                    })),
                });
            }
            Err(err) => {
                checks.push(CheckItem {
                    name: "bind",
                    status: "fail",
                    message: format!("invalid bind address: {err}"),
                    details: Some(json!({ "bind_addr": bind_addr_raw })),
                });
                success = false;
            }
        }

        let provider = config.llm.provider.trim();
        if provider.eq_ignore_ascii_case("ollama") {
            let base_url = config.llm.base_url.trim();
            let timeout = Duration::from_secs(2);
            match ollama::check_reachable(base_url, timeout).await {
                Ok(()) => checks.push(CheckItem {
                    name: "ollama",
                    status: "ok",
                    message: "ollama reachable".to_string(),
                    details: Some(json!({ "base_url": base_url })),
                }),
                Err(err) => {
                    checks.push(CheckItem {
                        name: "ollama",
                        status: "fail",
                        message: format!("ollama unreachable: {err}"),
                        details: Some(json!({ "base_url": base_url })),
                    });
                    success = false;
                }
            }
        } else {
            checks.push(CheckItem {
                name: "ollama",
                status: "warn",
                message: format!("llm provider is {provider}; skipping ollama check"),
                details: None,
            });
        }

        let engine = config.web.scraper.engine.trim();
        let engine_lower = engine.to_ascii_lowercase();
        let needs_chrome = matches!(
            engine_lower.as_str(),
            "chrome" | "chromium" | "chromium-browser"
        );
        if needs_chrome {
            let hint = config
                .web
                .scraper
                .chrome_binary_path
                .as_ref()
                .map(|path| path.to_string_lossy().to_string());
            let available = web::resolve_browser_available(hint.as_deref());
            if available {
                checks.push(CheckItem {
                    name: "chrome",
                    status: "ok",
                    message: "chrome binary available".to_string(),
                    details: hint.as_ref().map(|value| json!({ "path": value })),
                });
            } else {
                checks.push(CheckItem {
                    name: "chrome",
                    status: "fail",
                    message: "chrome binary not found".to_string(),
                    details: hint.as_ref().map(|value| json!({ "path": value })),
                });
                success = false;
            }
        } else {
            checks.push(CheckItem {
                name: "chrome",
                status: "warn",
                message: format!("web scraper engine is {engine}; skipping chrome check"),
                details: None,
            });
        }
    } else {
        for name in ["state", "bind", "ollama", "chrome"] {
            checks.push(CheckItem {
                name,
                status: "skipped",
                message: "skipped due to config load failure".to_string(),
                details: None,
            });
        }
    }

    let status = if success { "ok" } else { "failed" };
    let report = CheckReport {
        status,
        success,
        checks,
    };
    let payload = serde_json::to_string(&report)?;
    println!("{payload}");
    if success {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key).ok().and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}
