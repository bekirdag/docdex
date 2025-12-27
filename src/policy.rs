use crate::error::{
    repo_resolution_details, AppError, ERR_MEMORY_DISABLED, ERR_MISSING_DEPENDENCY,
    ERR_MISSING_REPO_PATH, ERR_UNKNOWN_REPO,
};
use serde_json::json;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy)]
pub enum Dependency {
    Memory,
    Symbols,
}

struct DependencyMeta {
    code: &'static str,
    message: &'static str,
    env: &'static str,
    flag: &'static str,
}

fn dependency_meta(dep: Dependency) -> DependencyMeta {
    match dep {
        Dependency::Memory => DependencyMeta {
            code: ERR_MEMORY_DISABLED,
            message: "memory is disabled; enable DOCDEX_ENABLE_MEMORY=1 or --enable-memory=true",
            env: "DOCDEX_ENABLE_MEMORY",
            flag: "--enable-memory=true",
        },
        Dependency::Symbols => DependencyMeta {
            code: ERR_MISSING_DEPENDENCY,
            message:
                "symbol extraction is unavailable; symbols are always enabled but the store may be missing or unhealthy",
            env: "DOCDEX_ENABLE_SYMBOL_EXTRACTION",
            flag: "--enable-symbol-extraction=true",
        },
    }
}

fn dependency_error(dep: Dependency) -> AppError {
    let meta = dependency_meta(dep);
    AppError::new(meta.code, meta.message).with_details(json!({
        "dependency": meta.env,
        "flag": meta.flag,
    }))
}

pub fn require_enabled(dep: Dependency, enabled: bool) -> Result<(), AppError> {
    if enabled {
        Ok(())
    } else {
        Err(dependency_error(dep))
    }
}

pub fn require_option<T>(dep: Dependency, value: Option<T>) -> Result<T, AppError> {
    value.ok_or_else(|| dependency_error(dep))
}

#[derive(Debug, Clone, Copy)]
pub enum RepoSurface {
    Cli,
    Mcp,
}

fn normalize_for_details(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn missing_repo_steps(surface: RepoSurface) -> Vec<String> {
    match surface {
        RepoSurface::Cli => vec![
            "Repo may have moved or been renamed.".to_string(),
            "Re-run with the repo's current path.".to_string(),
            "If you previously indexed this repo, you may need to reindex after moving it: `docdexd index --repo <repo>`."
                .to_string(),
        ],
        RepoSurface::Mcp => vec![
            "Repo may have moved or been renamed.".to_string(),
            "Pass the current repo path (or omit `project_root` to use the MCP server default)."
                .to_string(),
            "If the MCP server is pointed at the wrong path, restart it with `docdexd mcp --repo <repo>`."
                .to_string(),
        ],
    }
}

fn unknown_repo_steps(surface: RepoSurface) -> Vec<String> {
    match surface {
        RepoSurface::Cli => vec![
            "Repo may have moved or been renamed.".to_string(),
            "Re-run with the repo's current path.".to_string(),
        ],
        RepoSurface::Mcp => vec![
            "Repo may have moved or been renamed.".to_string(),
            "Restart the MCP server with `docdexd mcp --repo <repo>` matching the repo you want to use."
                .to_string(),
            "Alternatively, omit `project_root` in tool arguments to use the MCP server default."
                .to_string(),
        ],
    }
}

pub fn missing_repo_path_error(repo_root: &Path, surface: RepoSurface) -> AppError {
    AppError::new(ERR_MISSING_REPO_PATH, "repo path not found").with_details(repo_resolution_details(
        normalize_for_details(repo_root),
        None,
        None,
        missing_repo_steps(surface),
    ))
}

fn unknown_repo_error(candidate: &Path, expected: &Path, surface: RepoSurface) -> AppError {
    let attempted_fingerprint = crate::repo_manager::repo_fingerprint_sha256(candidate).ok();
    AppError::new(ERR_UNKNOWN_REPO, "unknown repo").with_details(repo_resolution_details(
        normalize_for_details(candidate),
        attempted_fingerprint,
        Some(normalize_for_details(expected)),
        unknown_repo_steps(surface),
    ))
}

pub fn ensure_repo_match(
    candidate: &Path,
    expected: &Path,
    surface: RepoSurface,
) -> Result<PathBuf, AppError> {
    if !candidate.exists() {
        return Err(missing_repo_path_error(candidate, surface));
    }
    let normalized = candidate.canonicalize().unwrap_or_else(|_| candidate.to_path_buf());
    if normalized != expected {
        return Err(unknown_repo_error(&normalized, expected, surface));
    }
    Ok(normalized)
}

pub fn ensure_project_root(
    candidate: Option<&Path>,
    default_root: Option<&Path>,
    expected: &Path,
    surface: RepoSurface,
) -> Result<(), AppError> {
    if let Some(path) = candidate {
        ensure_repo_match(path, expected, surface).map(|_| ())
    } else if let Some(default_root) = default_root {
        ensure_repo_match(default_root, expected, surface).map(|_| ())
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebGateReason {
    Disabled,
    Offline,
}

#[derive(Debug, Clone)]
pub struct WebGateDecision {
    pub allowed: bool,
    pub reason: Option<WebGateReason>,
}

impl WebGateDecision {
    fn allowed() -> Self {
        Self {
            allowed: true,
            reason: None,
        }
    }

    fn denied(reason: WebGateReason) -> Self {
        Self {
            allowed: false,
            reason: Some(reason),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WebAvailabilityConfig {
    pub enabled: bool,
    pub offline: bool,
}

impl Default for WebAvailabilityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            offline: false,
        }
    }
}

impl WebAvailabilityConfig {
    pub fn from_env() -> Self {
        let mut config = Self::default();
        if let Some(enabled) = env_boolish("DOCDEX_WEB_ENABLED") {
            config.enabled = enabled;
        }
        if let Some(offline) = env_boolish("DOCDEX_OFFLINE") {
            config.offline = offline;
        }
        config
    }
}

fn env_boolish(name: &str) -> Option<bool> {
    std::env::var(name).ok().and_then(|value| {
        let value = value.trim().to_ascii_lowercase();
        if value.is_empty() {
            None
        } else {
            Some(matches!(value.as_str(), "1" | "true" | "yes" | "on"))
        }
    })
}

pub fn web_gate_from_env() -> WebGateDecision {
    let config = WebAvailabilityConfig::from_env();
    if !config.enabled {
        return WebGateDecision::denied(WebGateReason::Disabled);
    }
    if config.offline {
        return WebGateDecision::denied(WebGateReason::Offline);
    }
    WebGateDecision::allowed()
}
