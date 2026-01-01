use crate::error::{AppError, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_UNKNOWN_REPO};
use crate::search::{json_error, status_for_app_error, AppState};
use axum::{extract::State, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use url::Url;

#[derive(Debug, Deserialize)]
pub struct InitializeRequest {
    #[serde(default, alias = "rootUri")]
    pub root_uri: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InitializeResponse {
    pub repo_id: String,
    pub status: &'static str,
    pub repo_root: String,
}

pub async fn initialize_handler(
    State(state): State<AppState>,
    Json(req): Json<InitializeRequest>,
) -> impl IntoResponse {
    match resolve_initialize(&state, req.root_uri.as_deref()) {
        Ok(response) => Json(response).into_response(),
        Err(err) => json_error(status_for_app_error(err.code), err.code, err.message),
    }
}

pub(crate) fn resolve_initialize(
    state: &AppState,
    root_uri: Option<&str>,
) -> Result<InitializeResponse, AppError> {
    let mut resolved_repo = state.indexer.repo_root().to_path_buf();
    if let Some(root_uri) = root_uri {
        let client_root = parse_root_uri(root_uri)?;
        resolved_repo = client_root
            .canonicalize()
            .unwrap_or_else(|_| client_root.clone());
    }

    if state.multi_repo {
        let manager = state
            .repos
            .as_ref()
            .ok_or_else(|| AppError::new(ERR_INTERNAL_ERROR, "repo manager unavailable"))?;
        let mount = manager.mount_repo(&resolved_repo).map_err(|err| {
            if let Some(app) = err.downcast_ref::<AppError>() {
                return app.clone();
            }
            AppError::new(ERR_INTERNAL_ERROR, "failed to initialize repo")
        })?;
        return Ok(InitializeResponse {
            repo_id: mount.repo.repo_id.clone(),
            status: mount.status.as_str(),
            repo_root: mount.repo.repo_root.display().to_string(),
        });
    }

    let default_repo = state
        .indexer
        .repo_root()
        .canonicalize()
        .unwrap_or_else(|_| state.indexer.repo_root().to_path_buf());
    if resolved_repo != default_repo {
        return Err(AppError::new(ERR_UNKNOWN_REPO, "unknown repo"));
    }
    Ok(InitializeResponse {
        repo_id: state.repo_id.clone(),
        status: "ready",
        repo_root: default_repo.display().to_string(),
    })
}

pub(crate) fn parse_root_uri(raw: &str) -> Result<PathBuf, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "rootUri must not be empty",
        ));
    }
    if looks_like_windows_path(trimmed) {
        return Ok(PathBuf::from(trimmed));
    }
    if let Ok(url) = Url::parse(trimmed) {
        if url.scheme() != "file" {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("unsupported rootUri scheme: {}", url.scheme()),
            ));
        }
        let path = url.to_file_path().map_err(|_| {
            AppError::new(ERR_INVALID_ARGUMENT, "rootUri must be a local file path")
        })?;
        return Ok(path);
    }
    Ok(PathBuf::from(trimmed))
}

fn looks_like_windows_path(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() >= 2 && bytes[1] == b':' && bytes[0].is_ascii_alphabetic()
}
