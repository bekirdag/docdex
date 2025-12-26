use crate::config;
use crate::dag::logging as dag_logging;
use crate::hardware;
use crate::memory::MemoryStore;
use crate::ollama;
use crate::orchestrator::web;
use crate::state_layout::StateLayout;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;
use uuid::Uuid;

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

#[derive(Deserialize)]
struct RepoRegistryFile {
    #[serde(default)]
    repos: BTreeMap<String, RepoRegistryEntry>,
}

#[derive(Deserialize)]
struct RepoRegistryEntry {
    state_key: String,
}

pub async fn run() -> Result<()> {
    let mut checks = Vec::new();
    let mut success = true;

    let profile = hardware::detect_hardware();
    checks.push(CheckItem {
        name: "hardware",
        status: "ok",
        message: format!(
            "hardware summary: {}; recommended model: {}",
            hardware::format_hardware_summary(&profile),
            hardware::recommend_model(&profile)
        ),
        details: None,
    });

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
        let state_dir = config.core.global_state_dir.clone();
        if let Some(state_dir) = state_dir.clone() {
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
        let provider_is_ollama = provider.eq_ignore_ascii_case("ollama");
        let agent_override = env_agent_override();
        let memory_enabled =
            env_boolish("DOCDEX_ENABLE_MEMORY").unwrap_or(config.memory.enabled);
        let allow_non_ollama = agent_override.is_some();
        let max_answer_tokens = config.llm.max_answer_tokens;
        if max_answer_tokens == 0 {
            checks.push(CheckItem {
                name: "llm_budget",
                status: "fail",
                message: "max_answer_tokens must be >= 1".to_string(),
                details: Some(json!({ "max_answer_tokens": max_answer_tokens })),
            });
            success = false;
        } else {
            checks.push(CheckItem {
                name: "llm_budget",
                status: "ok",
                message: "token budget configuration validated".to_string(),
                details: Some(json!({ "max_answer_tokens": max_answer_tokens })),
            });
        }
        checks.push(CheckItem {
            name: "llm_provider",
            status: if provider_is_ollama || allow_non_ollama {
                "ok"
            } else {
                "fail"
            },
            message: if provider_is_ollama {
                "llm provider is ollama".to_string()
            } else if let Some(agent) = agent_override.as_deref() {
                format!("llm provider `{provider}` allowed via agent override `{agent}`")
            } else {
                format!("unsupported llm provider `{provider}`; only ollama is supported")
            },
            details: Some(json!({
                "provider": provider,
                "agent_override": agent_override,
            })),
        });
        if !provider_is_ollama && !allow_non_ollama {
            success = false;
        }
        if provider_is_ollama || memory_enabled {
            let base_url = config.llm.base_url.trim();
            let timeout = Duration::from_secs(2);
            let mut ollama_ok = true;
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
                    ollama_ok = false;
                }
            }

            if ollama_ok {
                let default_model = config.llm.default_model.trim();
                let embed_model = config.llm.embedding_model.trim();
                let mut missing = Vec::new();
                if default_model.is_empty() {
                    missing.push("<default_model not set>".to_string());
                }
                if embed_model.is_empty() {
                    missing.push("<embedding_model not set>".to_string());
                }
                match ollama::list_models(base_url, timeout).await {
                    Ok(installed) => {
                        if !default_model.is_empty()
                            && !model_installed(&installed, default_model)
                        {
                            missing.push(default_model.to_string());
                        }
                        if !embed_model.is_empty()
                            && !model_installed(&installed, embed_model)
                        {
                            missing.push(embed_model.to_string());
                        }
                        if missing.is_empty() {
                            checks.push(CheckItem {
                                name: "ollama_models",
                                status: "ok",
                                message: "ollama models available".to_string(),
                                details: Some(json!({
                                    "default_model": default_model,
                                    "embedding_model": embed_model,
                                })),
                            });
                        } else {
                            checks.push(CheckItem {
                                name: "ollama_models",
                                status: "fail",
                                message: "ollama models missing or not configured".to_string(),
                                details: Some(json!({
                                    "missing": missing,
                                    "hint": "pull missing models with `ollama pull <model>`",
                                })),
                            });
                            success = false;
                        }
                    }
                    Err(err) => {
                        checks.push(CheckItem {
                            name: "ollama_models",
                            status: "fail",
                            message: format!("ollama model list failed: {err}"),
                            details: Some(json!({ "base_url": base_url })),
                        });
                        success = false;
                    }
                }
            } else {
                checks.push(CheckItem {
                    name: "ollama_models",
                    status: "skipped",
                    message: "skipped due to ollama unreachable".to_string(),
                    details: None,
                });
            }
        } else {
            checks.push(CheckItem {
                name: "ollama",
                status: "skipped",
                message: "skipped; mcoda agent override in use and memory disabled".to_string(),
                details: None,
            });
            checks.push(CheckItem {
                name: "ollama_models",
                status: "skipped",
                message: "skipped; mcoda agent override in use and memory disabled".to_string(),
                details: None,
            });
        }

        let (repo_state_keys, repo_state_error) = match state_dir.as_ref() {
            Some(state_dir) => match load_repo_state_keys(state_dir) {
                Ok(keys) => (keys, None),
                Err(err) => (Vec::new(), Some(err.to_string())),
            },
            None => (Vec::new(), None),
        };

        if memory_enabled {
            match state_dir.as_ref() {
                Some(state_dir) => {
                    if let Some(err) = repo_state_error.as_deref() {
                        let registry_path = StateLayout::new(state_dir.clone())
                            .repos_dir()
                            .join("repo_registry.json");
                        checks.push(CheckItem {
                            name: "memory_db",
                            status: "fail",
                            message: format!("memory.db check failed: {err}"),
                            details: Some(json!({ "path": registry_path.to_string_lossy() })),
                        });
                        success = false;
                    } else if repo_state_keys.is_empty() {
                        let scratch = state_dir
                            .join("checks")
                            .join(format!("memory-{}", Uuid::new_v4()));
                        let store = MemoryStore::new(&scratch);
                        match store.check_access() {
                            Ok(()) => checks.push(CheckItem {
                                name: "memory_db",
                                status: "ok",
                                message: "memory.db is writable (scratch)".to_string(),
                                details: Some(json!({
                                    "path": scratch.join("memory.db").to_string_lossy()
                                })),
                            }),
                            Err(err) => {
                                checks.push(CheckItem {
                                    name: "memory_db",
                                    status: "fail",
                                    message: format!("memory.db not writable: {err}"),
                                    details: Some(json!({
                                        "path": scratch.join("memory.db").to_string_lossy()
                                    })),
                                });
                                success = false;
                            }
                        }
                        let _ = std::fs::remove_dir_all(&scratch);
                    } else {
                        let repos_dir = StateLayout::new(state_dir.clone()).repos_dir();
                        let mut ok_count = 0usize;
                        let mut fail_count = 0usize;
                        let mut failures = Vec::new();
                        for state_key in &repo_state_keys {
                            let repo_state_root = repos_dir.join(state_key);
                            if !repo_state_root.exists() {
                                fail_count += 1;
                                if failures.len() < 5 {
                                    failures.push(format!(
                                        "{}: repo state dir missing",
                                        repo_state_root.display()
                                    ));
                                }
                                continue;
                            }
                            let store = MemoryStore::new(&repo_state_root);
                            match store.check_access() {
                                Ok(()) => ok_count += 1,
                                Err(err) => {
                                    fail_count += 1;
                                    if failures.len() < 5 {
                                        failures.push(format!(
                                            "{}: {err}",
                                            repo_state_root.display()
                                        ));
                                    }
                                }
                            }
                        }
                        let total = repo_state_keys.len();
                        let status = if fail_count == 0 { "ok" } else { "fail" };
                        let message = if fail_count == 0 {
                            format!("memory.db writable for {ok_count}/{total} repos")
                        } else {
                            format!(
                                "memory.db check failed for {fail_count}/{total} repos"
                            )
                        };
                        checks.push(CheckItem {
                            name: "memory_db",
                            status,
                            message,
                            details: Some(json!({
                                "checked": total,
                                "ok": ok_count,
                                "failed": fail_count,
                                "failures": failures,
                            })),
                        });
                        if fail_count > 0 {
                            success = false;
                        }
                    }
                }
                None => {
                    checks.push(CheckItem {
                        name: "memory_db",
                        status: "fail",
                        message: "memory.db check failed: global_state_dir is not configured"
                            .to_string(),
                        details: None,
                    });
                    success = false;
                }
            }
        } else {
            checks.push(CheckItem {
                name: "memory_db",
                status: "skipped",
                message: "skipped; memory disabled".to_string(),
                details: None,
            });
        }

        match state_dir.as_ref() {
            Some(state_dir) => {
                if let Some(err) = repo_state_error.as_deref() {
                    let registry_path = StateLayout::new(state_dir.clone())
                        .repos_dir()
                        .join("repo_registry.json");
                    checks.push(CheckItem {
                        name: "dag_db",
                        status: "fail",
                        message: format!("dag.db check failed: {err}"),
                        details: Some(json!({ "path": registry_path.to_string_lossy() })),
                    });
                    success = false;
                } else if repo_state_keys.is_empty() {
                    let scratch = state_dir
                        .join("checks")
                        .join(format!("dag-{}", Uuid::new_v4()));
                    match dag_logging::check_access(&scratch) {
                        Ok(()) => checks.push(CheckItem {
                            name: "dag_db",
                            status: "ok",
                            message: "dag.db is writable (scratch)".to_string(),
                            details: Some(json!({
                                "path": scratch.join("dag.db").to_string_lossy()
                            })),
                        }),
                        Err(err) => {
                            checks.push(CheckItem {
                                name: "dag_db",
                                status: "fail",
                                message: format!("dag.db not writable: {err}"),
                                details: Some(json!({
                                    "path": scratch.join("dag.db").to_string_lossy()
                                })),
                            });
                            success = false;
                        }
                    }
                    let _ = std::fs::remove_dir_all(&scratch);
                } else {
                    let repos_dir = StateLayout::new(state_dir.clone()).repos_dir();
                    let mut ok_count = 0usize;
                    let mut fail_count = 0usize;
                    let mut failures = Vec::new();
                    for state_key in &repo_state_keys {
                        let repo_state_root = repos_dir.join(state_key);
                        if !repo_state_root.exists() {
                            fail_count += 1;
                            if failures.len() < 5 {
                                failures.push(format!(
                                    "{}: repo state dir missing",
                                    repo_state_root.display()
                                ));
                            }
                            continue;
                        }
                        match dag_logging::check_access(&repo_state_root) {
                            Ok(()) => ok_count += 1,
                            Err(err) => {
                                fail_count += 1;
                                if failures.len() < 5 {
                                    failures.push(format!(
                                        "{}: {err}",
                                        repo_state_root.display()
                                    ));
                                }
                            }
                        }
                    }
                    let total = repo_state_keys.len();
                    let status = if fail_count == 0 { "ok" } else { "fail" };
                    let message = if fail_count == 0 {
                        format!("dag.db writable for {ok_count}/{total} repos")
                    } else {
                        format!("dag.db check failed for {fail_count}/{total} repos")
                    };
                    checks.push(CheckItem {
                        name: "dag_db",
                        status,
                        message,
                        details: Some(json!({
                            "checked": total,
                            "ok": ok_count,
                            "failed": fail_count,
                            "failures": failures,
                        })),
                    });
                    if fail_count > 0 {
                        success = false;
                    }
                }
            }
            None => {
                checks.push(CheckItem {
                    name: "dag_db",
                    status: "fail",
                    message: "dag.db check failed: global_state_dir is not configured"
                        .to_string(),
                    details: None,
                });
                success = false;
            }
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
                    status: "warn",
                    message: "chrome binary not found (web scraping disabled)".to_string(),
                    details: hint.as_ref().map(|value| json!({ "path": value })),
                });
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
        for name in [
            "state",
            "bind",
            "llm_budget",
            "llm_provider",
            "ollama",
            "ollama_models",
            "memory_db",
            "dag_db",
            "chrome",
        ] {
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

fn load_repo_state_keys(state_dir: &Path) -> Result<Vec<String>> {
    let layout = StateLayout::new(state_dir.to_path_buf());
    let registry_path = layout.repos_dir().join("repo_registry.json");
    let mut keys = Vec::new();
    match fs::read_to_string(&registry_path) {
        Ok(raw) => {
            let parsed: RepoRegistryFile =
                serde_json::from_str(&raw).with_context(|| format!("parse {}", registry_path.display()))?;
            for entry in parsed.repos.values() {
                let trimmed = entry.state_key.trim();
                if !trimmed.is_empty() {
                    keys.push(trimmed.to_string());
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("read {}", registry_path.display()));
        }
    }

    if keys.is_empty() {
        if let Ok(entries) = fs::read_dir(layout.repos_dir()) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                if let Some(name) = path.file_name().and_then(|value| value.to_str()) {
                    let trimmed = name.trim();
                    if !trimmed.is_empty() {
                        keys.push(trimmed.to_string());
                    }
                }
            }
        }
    }

    keys.sort();
    keys.dedup();
    Ok(keys)
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

fn env_boolish(key: &str) -> Option<bool> {
    let raw = std::env::var(key).ok()?;
    let trimmed = raw.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "1" | "true" | "t" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "f" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

fn env_agent_override() -> Option<String> {
    env_non_empty("DOCDEX_LLM_AGENT").or_else(|| env_non_empty("DOCDEX_AGENT"))
}

fn model_installed(installed: &std::collections::HashSet<String>, required: &str) -> bool {
    let required = required.trim();
    if required.is_empty() {
        return true;
    }
    if installed.contains(required) {
        return true;
    }
    if let Some((base, tag)) = required.rsplit_once(':') {
        if tag.eq_ignore_ascii_case("latest") && installed.contains(base) {
            return true;
        }
        return false;
    }
    let prefix = format!("{required}:");
    installed
        .iter()
        .any(|name| name == required || name.starts_with(&prefix))
}
