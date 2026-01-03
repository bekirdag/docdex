use crate::config;
use crate::dag::logging as dag_logging;
use crate::hardware;
use crate::mcp;
use crate::memory::MemoryStore;
use crate::ollama;
use crate::profiles::ProfileManager;
use crate::state_layout::StateLayout;
use crate::symbols::SymbolsStore;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use uuid::Uuid;

#[derive(Serialize)]
pub(crate) struct CheckItem {
    name: &'static str,
    status: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub(crate) struct CheckReport {
    status: &'static str,
    pub(crate) success: bool,
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
    #[serde(default)]
    canonical_path: Option<String>,
}

#[derive(Clone)]
struct RepoStateEntry {
    state_key: String,
    canonical_path: Option<PathBuf>,
}

pub async fn run() -> Result<()> {
    let report = build_report(CheckOptions::default()).await?;
    let payload = serde_json::to_string(&report)?;
    println!("{payload}");
    if report.success {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

#[derive(Default)]
pub(crate) struct CheckOptions {
    pub(crate) bind_addr_override: Option<String>,
    pub(crate) mcp_enabled_override: Option<bool>,
    pub(crate) mcp_spawn_check_override: Option<bool>,
    pub(crate) mcp_spawn_timeout_ms: Option<u64>,
}

pub(crate) async fn build_report(options: CheckOptions) -> Result<CheckReport> {
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

        let bind_addr_raw = options
            .bind_addr_override
            .as_deref()
            .unwrap_or_else(|| config.server.http_bind_addr.trim());
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
                let bind_available = match probe_bind(addr) {
                    Ok(()) => CheckItem {
                        name: "bind_available",
                        status: "ok",
                        message: "bind address available".to_string(),
                        details: Some(json!({
                            "bind_addr": bind_addr_raw,
                        })),
                    },
                    Err(err) => {
                        if err.kind == "permission_denied"
                            && (addr.port() == 0 || addr.port() >= 1024)
                        {
                            CheckItem {
                                name: "bind_available",
                                status: "skipped",
                                message: "bind permission denied; skipping availability check"
                                    .to_string(),
                                details: Some(json!({
                                    "bind_addr": bind_addr_raw,
                                    "error_kind": err.kind,
                                    "error": err.error,
                                })),
                            }
                        } else {
                            success = false;
                            CheckItem {
                                name: "bind_available",
                                status: "fail",
                                message: err.message,
                                details: Some(json!({
                                    "bind_addr": bind_addr_raw,
                                    "error_kind": err.kind,
                                    "error": err.error,
                                })),
                            }
                        }
                    }
                };
                checks.push(bind_available);
            }
            Err(err) => {
                checks.push(CheckItem {
                    name: "bind",
                    status: "fail",
                    message: format!("invalid bind address: {err}"),
                    details: Some(json!({ "bind_addr": bind_addr_raw })),
                });
                checks.push(CheckItem {
                    name: "bind_available",
                    status: "fail",
                    message: format!("invalid bind address: {err}"),
                    details: Some(json!({
                        "bind_addr": bind_addr_raw,
                        "error_kind": "invalid_address",
                        "error": err.to_string(),
                    })),
                });
                success = false;
            }
        }

        let mcp_env_value = std::env::var("DOCDEX_ENABLE_MCP").ok();
        let mcp_env_bool = env_boolish("DOCDEX_ENABLE_MCP");
        let (mcp_enabled, mcp_source) = match options.mcp_enabled_override {
            Some(value) => (value, "override"),
            None => match mcp_env_bool {
                Some(value) => (value, "env"),
                None => (config.server.enable_mcp, "config"),
            },
        };
        let mcp_spawn_check = options
            .mcp_spawn_check_override
            .or_else(|| env_boolish("DOCDEX_CHECK_MCP_SPAWN"))
            .unwrap_or(false);
        let mcp_spawn_timeout_ms = options
            .mcp_spawn_timeout_ms
            .or_else(resolve_mcp_spawn_timeout_ms)
            .unwrap_or(2000)
            .max(1);
        if !mcp_enabled {
            checks.push(CheckItem {
                name: "mcp_ready",
                status: "skipped",
                message: "mcp disabled".to_string(),
                details: Some(json!({
                    "enabled": false,
                    "source": mcp_source,
                    "env_value": mcp_env_value,
                })),
            });
        } else {
            let env_bin = env_non_empty("DOCDEX_MCP_SERVER_BIN");
            match mcp::resolve_mcp_server_binary() {
                Ok(path) => {
                    let mut spawn_ok = None;
                    let mut spawn_details = None;
                    if mcp_spawn_check {
                        let timeout = Duration::from_millis(mcp_spawn_timeout_ms);
                        let probe = probe_mcp_spawn(&path, timeout);
                        spawn_ok = Some(probe.ok);
                        spawn_details = Some(json!({
                            "spawn_status": probe.status,
                            "spawn_exit_code": probe.exit_code,
                            "spawn_timeout_ms": probe.timeout_ms,
                            "spawn_error": probe.error,
                        }));
                    }
                    let status = if spawn_ok == Some(false) {
                        "fail"
                    } else {
                        "ok"
                    };
                    let message = if spawn_ok == Some(false) {
                        "mcp server binary resolved but spawn check failed".to_string()
                    } else if mcp_spawn_check {
                        "mcp server binary resolved (spawn check ok)".to_string()
                    } else {
                        "mcp server binary resolved".to_string()
                    };
                    if status == "fail" {
                        success = false;
                    }
                    checks.push(CheckItem {
                        name: "mcp_ready",
                        status,
                        message,
                        details: Some(json!({
                            "enabled": true,
                            "source": mcp_source,
                            "env_value": mcp_env_value,
                            "binary": path.to_string_lossy(),
                            "binary_override": env_bin,
                            "spawn_check": mcp_spawn_check,
                            "spawn_ok": spawn_ok,
                            "spawn_timeout_ms": mcp_spawn_timeout_ms,
                            "spawn_details": spawn_details,
                        })),
                    });
                }
                Err(err) => {
                    checks.push(CheckItem {
                        name: "mcp_ready",
                        status: "fail",
                        message: format!("mcp server binary resolution failed: {err}"),
                        details: Some(json!({
                            "enabled": true,
                            "source": mcp_source,
                            "env_value": mcp_env_value,
                            "binary_override": env_bin,
                            "error": err.to_string(),
                        })),
                    });
                    success = false;
                }
            }
        }

        let provider = config.llm.provider.trim();
        let provider_is_ollama = provider.eq_ignore_ascii_case("ollama");
        let agent_override = env_agent_override();
        let memory_enabled = env_boolish("DOCDEX_ENABLE_MEMORY").unwrap_or(config.memory.enabled);
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
                        if !default_model.is_empty() && !model_installed(&installed, default_model)
                        {
                            missing.push(default_model.to_string());
                        }
                        if !embed_model.is_empty() && !model_installed(&installed, embed_model) {
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

        let (repo_state_entries, repo_state_error) = match state_dir.as_ref() {
            Some(state_dir) => match load_repo_state_entries(state_dir) {
                Ok(entries) => (entries, None),
                Err(err) => (Vec::new(), Some(err.to_string())),
            },
            None => (Vec::new(), None),
        };
        let repo_state_keys = repo_state_entries
            .iter()
            .map(|entry| entry.state_key.clone())
            .collect::<Vec<_>>();

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
                                        failures
                                            .push(format!("{}: {err}", repo_state_root.display()));
                                    }
                                }
                            }
                        }
                        let total = repo_state_keys.len();
                        let status = if fail_count == 0 { "ok" } else { "fail" };
                        let message = if fail_count == 0 {
                            format!("memory.db writable for {ok_count}/{total} repos")
                        } else {
                            format!("memory.db check failed for {fail_count}/{total} repos")
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
                let profile_db_path = StateLayout::new(state_dir.clone())
                    .profiles_dir()
                    .join("main.db");
                match ProfileManager::new(state_dir, config.memory.profile.embedding_dim) {
                    Ok(manager) => match manager.check_access() {
                        Ok(()) => checks.push(CheckItem {
                            name: "profile_db",
                            status: "ok",
                            message: "profile.db is writable".to_string(),
                            details: Some(json!({
                                "path": profile_db_path.to_string_lossy(),
                                "embedding_dim": config.memory.profile.embedding_dim
                            })),
                        }),
                        Err(err) => {
                            checks.push(CheckItem {
                                name: "profile_db",
                                status: "fail",
                                message: format!("profile.db check failed: {err}"),
                                details: Some(json!({
                                    "path": profile_db_path.to_string_lossy(),
                                    "embedding_dim": config.memory.profile.embedding_dim
                                })),
                            });
                            success = false;
                        }
                    },
                    Err(err) => {
                        checks.push(CheckItem {
                            name: "profile_db",
                            status: "fail",
                            message: format!("profile.db check failed: {err}"),
                            details: Some(json!({
                                "path": profile_db_path.to_string_lossy(),
                                "embedding_dim": config.memory.profile.embedding_dim
                            })),
                        });
                        success = false;
                    }
                }
            }
            None => {
                checks.push(CheckItem {
                    name: "profile_db",
                    status: "fail",
                    message: "profile.db check failed: global_state_dir is not configured"
                        .to_string(),
                    details: None,
                });
                success = false;
            }
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
                                    failures.push(format!("{}: {err}", repo_state_root.display()));
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
                    message: "dag.db check failed: global_state_dir is not configured".to_string(),
                    details: None,
                });
                success = false;
            }
        }

        match state_dir.as_ref() {
            Some(state_dir) => {
                if let Some(err) = repo_state_error.as_deref() {
                    let registry_path = StateLayout::new(state_dir.clone())
                        .repos_dir()
                        .join("repo_registry.json");
                    checks.push(CheckItem {
                        name: "symbols_db",
                        status: "fail",
                        message: format!("symbols.db check failed: {err}"),
                        details: Some(json!({ "path": registry_path.to_string_lossy() })),
                    });
                    checks.push(CheckItem {
                        name: "symbols_parser",
                        status: "fail",
                        message: format!("symbols parser check failed: {err}"),
                        details: Some(json!({ "path": registry_path.to_string_lossy() })),
                    });
                    success = false;
                } else if repo_state_entries.is_empty() {
                    let scratch = state_dir
                        .join("checks")
                        .join(format!("symbols-{}", Uuid::new_v4()));
                    let repo_root = scratch.join("repo");
                    if let Err(err) = std::fs::create_dir_all(&repo_root) {
                        checks.push(CheckItem {
                            name: "symbols_db",
                            status: "fail",
                            message: format!("symbols.db check failed: {err}"),
                            details: Some(json!({ "path": repo_root.to_string_lossy() })),
                        });
                        checks.push(CheckItem {
                            name: "symbols_parser",
                            status: "fail",
                            message: format!("symbols parser check failed: {err}"),
                            details: Some(json!({ "path": repo_root.to_string_lossy() })),
                        });
                        success = false;
                    } else {
                        match SymbolsStore::new(&repo_root, &scratch) {
                            Ok(store) => {
                                match store.check_access() {
                                    Ok(()) => checks.push(CheckItem {
                                        name: "symbols_db",
                                        status: "ok",
                                        message: "symbols.db is writable (scratch)".to_string(),
                                        details: Some(json!({
                                            "path": scratch.join("symbols.db").to_string_lossy()
                                        })),
                                    }),
                                    Err(err) => {
                                        checks.push(CheckItem {
                                            name: "symbols_db",
                                            status: "fail",
                                            message: format!("symbols.db not writable: {err}"),
                                            details: Some(json!({
                                                "path": scratch.join("symbols.db").to_string_lossy()
                                            })),
                                        });
                                        success = false;
                                    }
                                }
                                match store.parser_status() {
                                    Ok(status) => checks.push(CheckItem {
                                        name: "symbols_parser",
                                        status: if status.requires_reindex || status.drift {
                                            "warn"
                                        } else {
                                            "ok"
                                        },
                                        message: if status.requires_reindex || status.drift {
                                            "symbols parser versions drifted; reindex required".to_string()
                                        } else {
                                            "symbols parser versions aligned".to_string()
                                        },
                                        details: Some(json!({
                                            "requires_reindex": status.requires_reindex,
                                            "drift": status.drift,
                                            "current_parser_versions": status.current_parser_versions,
                                            "stored_parser_versions": status.stored_parser_versions,
                                        })),
                                    }),
                                    Err(err) => {
                                        checks.push(CheckItem {
                                            name: "symbols_parser",
                                            status: "fail",
                                            message: format!("symbols parser status failed: {err}"),
                                            details: Some(json!({
                                                "path": scratch.join("symbols.db").to_string_lossy()
                                            })),
                                        });
                                        success = false;
                                    }
                                }
                            }
                            Err(err) => {
                                checks.push(CheckItem {
                                    name: "symbols_db",
                                    status: "fail",
                                    message: format!("symbols.db check failed: {err}"),
                                    details: Some(json!({
                                        "path": scratch.join("symbols.db").to_string_lossy()
                                    })),
                                });
                                checks.push(CheckItem {
                                    name: "symbols_parser",
                                    status: "fail",
                                    message: format!("symbols parser status failed: {err}"),
                                    details: Some(json!({
                                        "path": scratch.join("symbols.db").to_string_lossy()
                                    })),
                                });
                                success = false;
                            }
                        }
                    }
                    let _ = std::fs::remove_dir_all(&scratch);
                } else {
                    let repos_dir = StateLayout::new(state_dir.clone()).repos_dir();
                    let mut ok_count = 0usize;
                    let mut fail_count = 0usize;
                    let mut failures = Vec::new();
                    let mut parser_drift = Vec::new();
                    let mut parser_reindex = Vec::new();
                    let mut parser_failures = Vec::new();
                    for entry in &repo_state_entries {
                        let repo_state_root = repos_dir.join(&entry.state_key);
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
                        let repo_root = entry
                            .canonical_path
                            .clone()
                            .unwrap_or_else(|| repo_state_root.clone());
                        match SymbolsStore::new(&repo_root, &repo_state_root) {
                            Ok(store) => {
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
                                match store.parser_status() {
                                    Ok(status) => {
                                        if status.drift && parser_drift.len() < 5 {
                                            parser_drift.push(entry.state_key.clone());
                                        }
                                        if status.requires_reindex && parser_reindex.len() < 5 {
                                            parser_reindex.push(entry.state_key.clone());
                                        }
                                    }
                                    Err(err) => {
                                        if parser_failures.len() < 5 {
                                            parser_failures.push(format!(
                                                "{}: {err}",
                                                repo_state_root.display()
                                            ));
                                        }
                                    }
                                }
                            }
                            Err(err) => {
                                fail_count += 1;
                                if failures.len() < 5 {
                                    failures.push(format!("{}: {err}", repo_state_root.display()));
                                }
                                if parser_failures.len() < 5 {
                                    parser_failures
                                        .push(format!("{}: {err}", repo_state_root.display()));
                                }
                            }
                        }
                    }
                    let total = repo_state_entries.len();
                    let status = if fail_count == 0 { "ok" } else { "fail" };
                    let message = if fail_count == 0 {
                        format!("symbols.db writable for {ok_count}/{total} repos")
                    } else {
                        format!("symbols.db check failed for {fail_count}/{total} repos")
                    };
                    checks.push(CheckItem {
                        name: "symbols_db",
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

                    let parser_status = if parser_failures.is_empty()
                        && parser_drift.is_empty()
                        && parser_reindex.is_empty()
                    {
                        "ok"
                    } else if parser_failures.is_empty() {
                        "warn"
                    } else {
                        "fail"
                    };
                    let parser_message = if parser_failures.is_empty()
                        && parser_drift.is_empty()
                        && parser_reindex.is_empty()
                    {
                        "symbols parser versions aligned".to_string()
                    } else if parser_failures.is_empty() {
                        "symbols parser versions drifted; reindex required".to_string()
                    } else {
                        "symbols parser status failed for one or more repos".to_string()
                    };
                    checks.push(CheckItem {
                        name: "symbols_parser",
                        status: parser_status,
                        message: parser_message,
                        details: Some(json!({
                            "drifted": parser_drift,
                            "requires_reindex": parser_reindex,
                            "failures": parser_failures,
                        })),
                    });
                    if parser_status == "fail" {
                        success = false;
                    }
                }
            }
            None => {
                checks.push(CheckItem {
                    name: "symbols_db",
                    status: "fail",
                    message: "symbols.db check failed: global_state_dir is not configured"
                        .to_string(),
                    details: None,
                });
                checks.push(CheckItem {
                    name: "symbols_parser",
                    status: "fail",
                    message: "symbols parser check failed: global_state_dir is not configured"
                        .to_string(),
                    details: None,
                });
                success = false;
            }
        }

        match state_dir.as_ref() {
            Some(state_dir) => {
                if let Some(err) = repo_state_error.as_deref() {
                    let registry_path = StateLayout::new(state_dir.clone())
                        .repos_dir()
                        .join("repo_registry.json");
                    checks.push(CheckItem {
                        name: "impact_graph",
                        status: "fail",
                        message: format!("impact_graph.json check failed: {err}"),
                        details: Some(json!({ "path": registry_path.to_string_lossy() })),
                    });
                    success = false;
                } else if repo_state_entries.is_empty() {
                    let scratch = state_dir
                        .join("checks")
                        .join(format!("impact-{}", Uuid::new_v4()));
                    match check_impact_graph_access(&scratch) {
                        Ok(()) => checks.push(CheckItem {
                            name: "impact_graph",
                            status: "ok",
                            message: "impact_graph.json is writable (scratch)".to_string(),
                            details: Some(json!({
                                "path": scratch.join("impact_graph.json").to_string_lossy()
                            })),
                        }),
                        Err(err) => {
                            checks.push(CheckItem {
                                name: "impact_graph",
                                status: "fail",
                                message: format!("impact_graph.json not writable: {err}"),
                                details: Some(json!({
                                    "path": scratch.join("impact_graph.json").to_string_lossy()
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
                    for entry in &repo_state_entries {
                        let repo_state_root = repos_dir.join(&entry.state_key);
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
                        match check_impact_graph_access(&repo_state_root) {
                            Ok(()) => ok_count += 1,
                            Err(err) => {
                                fail_count += 1;
                                if failures.len() < 5 {
                                    failures.push(format!("{}: {err}", repo_state_root.display()));
                                }
                            }
                        }
                    }
                    let total = repo_state_entries.len();
                    let status = if fail_count == 0 { "ok" } else { "fail" };
                    let message = if fail_count == 0 {
                        format!("impact_graph.json writable for {ok_count}/{total} repos")
                    } else {
                        format!("impact_graph.json check failed for {fail_count}/{total} repos")
                    };
                    checks.push(CheckItem {
                        name: "impact_graph",
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
                    name: "impact_graph",
                    status: "fail",
                    message: "impact_graph.json check failed: global_state_dir is not configured"
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
            let auto_install_enabled = env_boolish("DOCDEX_BROWSER_AUTO_INSTALL")
                .unwrap_or(config.web.scraper.auto_install);
            let candidate = crate::util::detect_browser_binary(
                config.web.scraper.chrome_binary_path.as_deref(),
            );
            if let Some(candidate) = candidate {
                checks.push(CheckItem {
                    name: "chrome",
                    status: "ok",
                    message: format!("browser available ({})", candidate.kind.as_str()),
                    details: Some(json!({
                        "path": candidate.path.to_string_lossy(),
                        "kind": candidate.kind.as_str(),
                        "source": candidate.source.as_str(),
                        "auto_install_enabled": auto_install_enabled,
                        "configured_kind": config.web.scraper.browser_kind.as_deref(),
                    })),
                });
            } else {
                checks.push(CheckItem {
                    name: "chrome",
                    status: "warn",
                    message: "browser binary not found (web scraping disabled)".to_string(),
                    details: config
                        .web
                        .scraper
                        .chrome_binary_path
                        .as_ref()
                        .map(|path| {
                            json!({
                                "path": path.to_string_lossy(),
                                "auto_install_enabled": auto_install_enabled,
                                "install_hint": "docdexd browser setup",
                            })
                        })
                        .or_else(|| {
                            Some(json!({
                                "auto_install_enabled": auto_install_enabled,
                                "install_hint": "docdexd browser setup",
                            }))
                        }),
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
            "bind_available",
            "mcp_ready",
            "llm_budget",
            "llm_provider",
            "ollama",
            "ollama_models",
            "memory_db",
            "dag_db",
            "symbols_db",
            "symbols_parser",
            "impact_graph",
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
    Ok(CheckReport {
        status,
        success,
        checks,
    })
}

fn load_repo_state_entries(state_dir: &Path) -> Result<Vec<RepoStateEntry>> {
    let layout = StateLayout::new(state_dir.to_path_buf());
    let registry_path = layout.repos_dir().join("repo_registry.json");
    let mut entries = Vec::new();
    match fs::read_to_string(&registry_path) {
        Ok(raw) => {
            let parsed: RepoRegistryFile = serde_json::from_str(&raw)
                .with_context(|| format!("parse {}", registry_path.display()))?;
            for entry in parsed.repos.values() {
                let trimmed = entry.state_key.trim();
                if !trimmed.is_empty() {
                    let canonical_path = entry.canonical_path.as_deref().and_then(|value| {
                        let trimmed = value.trim();
                        if trimmed.is_empty() {
                            None
                        } else {
                            Some(PathBuf::from(trimmed))
                        }
                    });
                    entries.push(RepoStateEntry {
                        state_key: trimmed.to_string(),
                        canonical_path,
                    });
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| format!("read {}", registry_path.display()));
        }
    }

    if entries.is_empty() {
        if let Ok(dir_entries) = fs::read_dir(layout.repos_dir()) {
            for entry in dir_entries.flatten() {
                let path = entry.path();
                if !path.is_dir() {
                    continue;
                }
                if let Some(name) = path.file_name().and_then(|value| value.to_str()) {
                    let trimmed = name.trim();
                    if !trimmed.is_empty() {
                        entries.push(RepoStateEntry {
                            state_key: trimmed.to_string(),
                            canonical_path: None,
                        });
                    }
                }
            }
        }
    }

    entries.sort_by(|a, b| a.state_key.cmp(&b.state_key));
    entries.dedup_by(|a, b| a.state_key == b.state_key);
    Ok(entries)
}

fn check_impact_graph_access(repo_state_root: &Path) -> Result<()> {
    fs::create_dir_all(repo_state_root)
        .with_context(|| format!("create {}", repo_state_root.display()))?;
    let graph_path = repo_state_root.join("impact_graph.json");
    if graph_path.exists() {
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&graph_path)
            .with_context(|| format!("open {}", graph_path.display()))?;
        return Ok(());
    }
    let scratch_path = repo_state_root.join(format!("impact_graph.check-{}", Uuid::new_v4()));
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&scratch_path)
        .with_context(|| format!("create {}", scratch_path.display()))?;
    let _ = fs::remove_file(&scratch_path);
    Ok(())
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

fn resolve_mcp_spawn_timeout_ms() -> Option<u64> {
    std::env::var("DOCDEX_CHECK_MCP_SPAWN_TIMEOUT_MS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

struct BindProbeError {
    kind: &'static str,
    message: String,
    error: Option<String>,
}

fn probe_bind(addr: SocketAddr) -> Result<(), BindProbeError> {
    match TcpListener::bind(addr) {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(err) => {
            let (kind, message) = match err.kind() {
                ErrorKind::AddrInUse => ("addr_in_use", "bind address already in use".to_string()),
                ErrorKind::PermissionDenied => (
                    "permission_denied",
                    "bind permission denied (requires elevated privileges)".to_string(),
                ),
                _ => ("bind_failed", format!("bind failed: {err}")),
            };
            Err(BindProbeError {
                kind,
                message,
                error: Some(err.to_string()),
            })
        }
    }
}

struct McpSpawnProbe {
    ok: bool,
    status: &'static str,
    exit_code: Option<i32>,
    timeout_ms: Option<u64>,
    error: Option<String>,
}

fn probe_mcp_spawn(path: &Path, timeout: Duration) -> McpSpawnProbe {
    let mut cmd = if cfg!(windows) {
        let ext = path
            .extension()
            .and_then(|value| value.to_str())
            .map(|value| value.to_ascii_lowercase());
        if matches!(ext.as_deref(), Some("cmd") | Some("bat")) {
            let mut cmd = Command::new("cmd.exe");
            cmd.arg("/C").arg(path);
            cmd
        } else {
            Command::new(path)
        }
    } else {
        Command::new(path)
    };
    cmd.arg("--help");
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(err) => {
            return McpSpawnProbe {
                ok: false,
                status: "spawn_error",
                exit_code: None,
                timeout_ms: Some(timeout.as_millis().min(u128::from(u64::MAX)) as u64),
                error: Some(err.to_string()),
            }
        }
    };

    let deadline = std::time::Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let ok = status.success();
                return McpSpawnProbe {
                    ok,
                    status: if ok { "ok" } else { "exit" },
                    exit_code: status.code(),
                    timeout_ms: Some(timeout.as_millis().min(u128::from(u64::MAX)) as u64),
                    error: None,
                };
            }
            Ok(None) => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return McpSpawnProbe {
                        ok: false,
                        status: "timeout",
                        exit_code: None,
                        timeout_ms: Some(timeout.as_millis().min(u128::from(u64::MAX)) as u64),
                        error: None,
                    };
                }
                thread::sleep(Duration::from_millis(25));
            }
            Err(err) => {
                let _ = child.kill();
                let _ = child.wait();
                return McpSpawnProbe {
                    ok: false,
                    status: "spawn_error",
                    exit_code: None,
                    timeout_ms: Some(timeout.as_millis().min(u128::from(u64::MAX)) as u64),
                    error: Some(err.to_string()),
                };
            }
        }
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
