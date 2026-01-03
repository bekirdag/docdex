use crate::error::{AppError, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_UNKNOWN_REPO};
use crate::index::Indexer;
use crate::search::{json_error, status_for_app_error, AppState};
use axum::{extract::State, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use url::Url;
use tracing::{info, warn};

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
        let mut status = mount.status;
        if status == crate::daemon::multi_repo::RepoMountStatus::Ready
            && maybe_start_background_index(mount.repo.indexer.clone(), &mount.repo.repo_id)
        {
            status = crate::daemon::multi_repo::RepoMountStatus::Indexing;
        }
        return Ok(InitializeResponse {
            repo_id: mount.repo.repo_id.clone(),
            status: status.as_str(),
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
    let status = if maybe_start_background_index(state.indexer.clone(), &state.repo_id) {
        "indexing"
    } else {
        "ready"
    };
    Ok(InitializeResponse {
        repo_id: state.repo_id.clone(),
        status,
        repo_root: default_repo.display().to_string(),
    })
}

fn maybe_start_background_index(indexer: Arc<Indexer>, repo_id: &str) -> bool {
    if indexer.num_docs() > 0 {
        return false;
    }
    let repo_id = repo_id.to_string();
    if tokio::runtime::Handle::try_current().is_err() {
        warn!(repo_id = %repo_id, "no Tokio runtime available; skipping background reindex");
        return false;
    }
    tokio::spawn(async move {
        if let Err(err) = indexer.reindex_all().await {
            warn!(repo_id = %repo_id, error = ?err, "background reindex failed");
        } else {
            info!(repo_id = %repo_id, "background reindex complete");
        }
    });
    true
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
