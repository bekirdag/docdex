use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD as Base64Engine;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Component, Path as FsPath, PathBuf};

use crate::auth::RepoAccessBinding;
use crate::error::{status_for_app_error, AppError, ERR_INVALID_ARGUMENT};
use crate::http_api::{json_error, json_error_with_details};
use crate::repo_manager;
use crate::search::AppState;

#[derive(Debug, Deserialize)]
pub struct AdminRepoProvisionRequest {
    #[serde(default)]
    repo_id: Option<String>,
    #[serde(default)]
    repo_root: Option<String>,
    #[serde(default)]
    access_bindings: Vec<RepoAccessBindingInput>,
}

#[derive(Debug, Deserialize)]
pub struct AccessBindingsRequest {
    #[serde(alias = "access_bindings")]
    bindings: Vec<RepoAccessBindingInput>,
}

#[derive(Debug, Default, Deserialize)]
pub struct AdminRepoDeleteRequest {
    #[serde(default)]
    repo_root: Option<String>,
    #[serde(default)]
    delete_repo_root: Option<bool>,
    #[serde(default)]
    delete_state: Option<bool>,
    #[serde(default)]
    delete_access_bindings: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RepoAccessBindingInput {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    issuer: String,
    #[serde(default)]
    principal_type: String,
    #[serde(default)]
    principal_id: String,
    #[serde(default)]
    credential_id: Option<String>,
    #[serde(default)]
    required_scopes: Vec<String>,
    #[serde(default)]
    allowed_operations: Vec<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    expires_at_ms: Option<i64>,
    #[serde(default)]
    metadata_json: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct AdminRepoProvisionResponse {
    repo_id: String,
    repo_root: Option<String>,
    bindings: Vec<RepoAccessBinding>,
}

#[derive(Debug, Serialize)]
pub struct AccessBindingsResponse {
    repo_id: String,
    bindings: Vec<RepoAccessBinding>,
}

#[derive(Debug, Serialize)]
pub struct AdminRepoDeleteResponse {
    repo_id: String,
    repo_root: Option<String>,
    repo_root_deleted: bool,
    state_dir: Option<String>,
    state_deleted: bool,
    access_bindings_deleted: usize,
}

#[derive(Debug, Deserialize)]
pub struct AdminRepoDocumentIngestRequest {
    #[serde(default)]
    documents: Vec<AdminRepoDocumentInput>,
}

#[derive(Debug, Deserialize)]
pub struct AdminRepoDocumentInput {
    path: String,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    content_base64: Option<String>,
    #[serde(default)]
    metadata_json: Option<Value>,
}

#[derive(Debug, Serialize)]
pub struct AdminRepoDocumentIngestResponse {
    repo_id: String,
    repo_root: String,
    count: usize,
    ingested: Vec<AdminRepoDocumentIngestItem>,
}

#[derive(Debug, Serialize)]
pub struct AdminRepoDocumentIngestItem {
    path: String,
    indexed: bool,
}

#[derive(Debug, Serialize)]
pub struct CacheInvalidateResponse {
    invalidated_entries: usize,
}

pub async fn admin_repo_provision_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AdminRepoProvisionRequest>,
) -> Response {
    if let Err(response) = require_service_admin(&state, &headers, "/v1/admin/repos/provision") {
        return response;
    }
    let (repo_id, repo_root) = match resolve_admin_repo(&state, request.repo_id, request.repo_root)
    {
        Ok(value) => value,
        Err(err) => return app_error_to_response(err),
    };
    let mut bindings = Vec::new();
    for input in request.access_bindings {
        let binding = input.into_binding(repo_id.clone());
        match state.auth.access_store().upsert_binding(binding) {
            Ok(binding) => bindings.push(binding),
            Err(err) => return app_error_to_response(err),
        }
    }
    Json(AdminRepoProvisionResponse {
        repo_id,
        repo_root,
        bindings,
    })
    .into_response()
}

pub async fn admin_repo_access_bindings_handler(
    State(state): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<AccessBindingsRequest>,
) -> Response {
    if let Err(response) = require_service_admin(
        &state,
        &headers,
        "/v1/admin/repos/{repo_id}/access-bindings",
    ) {
        return response;
    }
    let repo_id = repo_id.trim().to_string();
    if repo_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "repo_id is required",
        );
    }
    let mut bindings = Vec::new();
    for input in request.bindings {
        match state
            .auth
            .access_store()
            .upsert_binding(input.into_binding(repo_id.clone()))
        {
            Ok(binding) => bindings.push(binding),
            Err(err) => return app_error_to_response(err),
        }
    }
    Json(AccessBindingsResponse { repo_id, bindings }).into_response()
}

pub async fn admin_repo_delete_handler(
    State(state): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    request: Option<Json<AdminRepoDeleteRequest>>,
) -> Response {
    if let Err(response) = require_service_admin(&state, &headers, "/v1/admin/repos/{repo_id}") {
        return response;
    }
    let repo_id = repo_id.trim().to_string();
    if repo_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "repo_id is required",
        );
    }
    let request = request.map(|Json(payload)| payload).unwrap_or_default();
    let delete_repo_root = request.delete_repo_root.unwrap_or(true);
    let delete_state = request.delete_state.unwrap_or(true);
    let delete_access_bindings = request.delete_access_bindings.unwrap_or(true);
    let requested_repo_root = match resolve_delete_repo_root(&repo_id, request.repo_root.as_deref())
    {
        Ok(root) => root,
        Err(err) => return app_error_to_response(err),
    };

    let mut mounted_repo_root: Option<PathBuf> = None;
    let mut mounted_state_dir: Option<PathBuf> = None;
    if let Some(manager) = state.repos.as_ref() {
        let runtime = manager.get_by_id(&repo_id).or_else(|| {
            requested_repo_root.as_ref().and_then(|root| {
                if root.exists() {
                    manager.mount_repo(root).ok().map(|mount| mount.repo)
                } else {
                    None
                }
            })
        });
        if let Some(runtime) = runtime {
            mounted_repo_root = Some(runtime.repo_root.clone());
            mounted_state_dir = Some(runtime.indexer.state_dir().to_path_buf());
            let _removed = manager.remove_repo_by_id(&repo_id);
        }
    }

    let repo_root = mounted_repo_root.or(requested_repo_root);
    let state_dir =
        mounted_state_dir.map(|path| crate::state_layout::repo_state_root_from_state_dir(&path));
    let access_bindings_deleted = if delete_access_bindings {
        match state.auth.access_store().delete_bindings_for_repo(&repo_id) {
            Ok(count) => count,
            Err(err) => return app_error_to_response(err),
        }
    } else {
        0
    };
    let state_deleted = if delete_state {
        match state_dir.as_deref() {
            Some(path) => match remove_dir_all_if_exists(path).await {
                Ok(deleted) => deleted,
                Err(err) => return app_error_to_response(err),
            },
            None => false,
        }
    } else {
        false
    };
    let repo_root_deleted = if delete_repo_root {
        match repo_root.as_deref() {
            Some(path) => match remove_dir_all_if_exists(path).await {
                Ok(deleted) => deleted,
                Err(err) => return app_error_to_response(err),
            },
            None => false,
        }
    } else {
        false
    };
    Json(AdminRepoDeleteResponse {
        repo_id,
        repo_root: repo_root.map(|path| path.display().to_string()),
        repo_root_deleted,
        state_dir: state_dir.map(|path| path.display().to_string()),
        state_deleted,
        access_bindings_deleted,
    })
    .into_response()
}

pub async fn admin_repo_documents_ingest_handler(
    State(state): State<AppState>,
    Path(repo_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<AdminRepoDocumentIngestRequest>,
) -> Response {
    if let Err(response) = require_service_admin(
        &state,
        &headers,
        "/v1/admin/repos/{repo_id}/documents/ingest",
    ) {
        return response;
    }
    let repo_id = repo_id.trim().to_string();
    if repo_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "repo_id is required",
        );
    }
    if request.documents.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "documents must not be empty",
        );
    }
    if request.documents.len() > 200 {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "documents exceeds the maximum batch size of 200",
        );
    }
    let repo = match crate::http_api::resolve_repo_context(
        &state,
        &headers,
        None,
        Some(repo_id.as_str()),
        true,
    ) {
        Ok(repo) => repo,
        Err(err) => return crate::http_api::repo_error_response(err),
    };
    let repo_root = repo.indexer.repo_root().to_path_buf();
    let mut ingested = Vec::with_capacity(request.documents.len());
    for document in request.documents {
        let relative_path = match safe_repo_relative_path(&document.path) {
            Ok(path) => path,
            Err(err) => return app_error_to_response(err),
        };
        let bytes = match document.into_bytes() {
            Ok(bytes) => bytes,
            Err(err) => return app_error_to_response(err),
        };
        let full_path = repo_root.join(&relative_path);
        if let Some(parent) = full_path.parent() {
            if let Err(err) = tokio::fs::create_dir_all(parent).await {
                return app_error_to_response(AppError::new(
                    ERR_INVALID_ARGUMENT,
                    format!("failed to create document directory: {err}"),
                ));
            }
        }
        if let Err(err) = tokio::fs::write(&full_path, bytes).await {
            return app_error_to_response(AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("failed to write document: {err}"),
            ));
        }
        let encrypted_repo = repo.indexer.config().repo_encryption().is_enabled();
        let ingest_result = repo.indexer.ingest_file(full_path.clone()).await;
        if encrypted_repo {
            if let Err(err) = remove_encrypted_ingest_source(&full_path).await {
                return app_error_to_response(err);
            }
        }
        if let Err(err) = ingest_result {
            return app_error_to_response(AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("failed to index document: {err}"),
            ));
        }
        ingested.push(AdminRepoDocumentIngestItem {
            path: relative_path.display().to_string(),
            indexed: true,
        });
    }
    Json(AdminRepoDocumentIngestResponse {
        repo_id: repo.repo_id.clone(),
        repo_root: repo_root.display().to_string(),
        count: ingested.len(),
        ingested,
    })
    .into_response()
}

pub async fn admin_auth_cache_invalidate_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Response {
    if let Err(response) =
        require_service_admin(&state, &headers, "/v1/admin/auth/cache/invalidate")
    {
        return response;
    }
    let invalidated_entries = state.auth.invalidate_cache();
    Json(CacheInvalidateResponse {
        invalidated_entries,
    })
    .into_response()
}

impl RepoAccessBindingInput {
    fn into_binding(self, repo_id: String) -> RepoAccessBinding {
        RepoAccessBinding {
            id: self.id.unwrap_or_default(),
            repo_id,
            issuer: self.issuer,
            principal_type: self.principal_type,
            principal_id: self.principal_id,
            credential_id: self.credential_id,
            required_scopes: self.required_scopes,
            allowed_operations: self.allowed_operations,
            status: self.status.unwrap_or_else(|| "active".to_string()),
            expires_at_ms: self.expires_at_ms,
            metadata_json: self.metadata_json.unwrap_or_else(|| json!({})),
        }
    }
}

impl AdminRepoDocumentInput {
    fn into_bytes(self) -> Result<Vec<u8>, AppError> {
        let _metadata = self.metadata_json;
        match (self.content, self.content_base64) {
            (Some(content), None) => Ok(content.into_bytes()),
            (None, Some(content_base64)) => {
                Base64Engine.decode(content_base64.trim()).map_err(|err| {
                    AppError::new(
                        ERR_INVALID_ARGUMENT,
                        format!("content_base64 is invalid: {err}"),
                    )
                })
            }
            (Some(_), Some(_)) => Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "provide either content or content_base64, not both",
            )),
            (None, None) => Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "document content is required",
            )),
        }
    }
}

fn safe_repo_relative_path(raw: &str) -> Result<PathBuf, AppError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "document path is required",
        ));
    }
    let path = FsPath::new(trimmed);
    if path.is_absolute() {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "document path must be relative",
        ));
    }
    let mut safe = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(value) => safe.push(value),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(AppError::new(
                    ERR_INVALID_ARGUMENT,
                    "document path must not escape the repository",
                ))
            }
        }
    }
    if safe.as_os_str().is_empty() {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "document path is required",
        ));
    }
    Ok(safe)
}

async fn remove_encrypted_ingest_source(path: &FsPath) -> Result<(), AppError> {
    tokio::fs::remove_file(path).await.map_err(|err| {
        AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("failed to remove plaintext encrypted-repo ingest source: {err}"),
        )
    })
}

fn resolve_delete_repo_root(
    repo_id: &str,
    raw_repo_root: Option<&str>,
) -> Result<Option<PathBuf>, AppError> {
    let Some(raw_repo_root) = raw_repo_root
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let path = PathBuf::from(raw_repo_root);
    if !path.exists() {
        return Ok(Some(path));
    }
    if !path.is_dir() {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "repo_root must be a directory",
        ));
    }
    let canonical = path.canonicalize().unwrap_or(path);
    let computed = repo_manager::repo_fingerprint_sha256(&canonical).map_err(|err| {
        AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("failed to compute repository id for deletion: {err}"),
        )
    })?;
    if computed != repo_id {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "provided repo_id does not match repo_root",
        ));
    }
    Ok(Some(canonical))
}

async fn remove_dir_all_if_exists(path: &FsPath) -> Result<bool, AppError> {
    if !path.exists() {
        return Ok(false);
    }
    if !path.is_dir() {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "delete target must be a directory",
        ));
    }
    if path.parent().is_none() {
        return Err(AppError::new(
            ERR_INVALID_ARGUMENT,
            "refusing to delete filesystem root",
        ));
    }
    tokio::fs::remove_dir_all(path).await.map_err(|err| {
        AppError::new(
            ERR_INVALID_ARGUMENT,
            format!("failed to delete directory {}: {err}", path.display()),
        )
    })?;
    Ok(true)
}

fn require_service_admin(
    state: &AppState,
    headers: &HeaderMap,
    path: &str,
) -> Result<(), Response> {
    match state.auth.authorize_service_admin(headers) {
        Ok(_) => {
            if let Some(audit) = state.audit.as_ref() {
                audit.log(
                    "admin_auth",
                    "allow",
                    None,
                    Some(path),
                    None,
                    Some(StatusCode::OK.as_u16()),
                    None,
                    None,
                );
            }
            Ok(())
        }
        Err(err) => {
            state.metrics.inc_auth_deny();
            if let Some(audit) = state.audit.as_ref() {
                audit.log(
                    "admin_auth",
                    "deny",
                    None,
                    Some(path),
                    None,
                    Some(status_for_app_error(err.code).as_u16()),
                    None,
                    None,
                );
            }
            Err(app_error_to_response(err))
        }
    }
}

fn resolve_admin_repo(
    state: &AppState,
    repo_id: Option<String>,
    repo_root: Option<String>,
) -> Result<(String, Option<String>), AppError> {
    if let Some(repo_root) = repo_root
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        let path = PathBuf::from(repo_root);
        if !path.exists() {
            std::fs::create_dir_all(&path).map_err(|err| {
                AppError::new(
                    ERR_INVALID_ARGUMENT,
                    format!("failed to create repository root for provisioning: {err}"),
                )
            })?;
        }
        let canonical = path.canonicalize().unwrap_or(path);
        if let Some(manager) = state.repos.as_ref() {
            let mount = manager.mount_repo(&canonical).map_err(|err| {
                AppError::new(
                    ERR_INVALID_ARGUMENT,
                    format!("failed to mount repository for provisioning: {err}"),
                )
            })?;
            return Ok((
                mount.repo.repo_id.clone(),
                Some(mount.repo.repo_root.display().to_string()),
            ));
        }
        let computed = repo_manager::repo_fingerprint_sha256(&canonical).map_err(|err| {
            AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("failed to compute repository id: {err}"),
            )
        })?;
        if let Some(requested) = repo_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            if requested != computed {
                return Err(AppError::new(
                    ERR_INVALID_ARGUMENT,
                    "provided repo_id does not match repo_root",
                ));
            }
        }
        return Ok((computed, Some(canonical.display().to_string())));
    }
    if let Some(repo_id) = repo_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok((repo_id.to_string(), None));
    }
    Ok((
        state.repo_id.clone(),
        Some(state.indexer.repo_root().display().to_string()),
    ))
}

fn app_error_to_response(err: AppError) -> Response {
    let status = status_for_app_error(err.code);
    match err.details {
        Some(details) => json_error_with_details(status, err.code, err.message, details),
        None => json_error(status, err.code, err.message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn safe_repo_relative_path_rejects_escape_attempts() {
        assert!(safe_repo_relative_path("../secret.txt").is_err());
        assert!(safe_repo_relative_path("/absolute/secret.txt").is_err());
        assert_eq!(
            safe_repo_relative_path("daily-logs/log-1.md")
                .expect("valid path")
                .to_string_lossy(),
            "daily-logs/log-1.md"
        );
    }

    #[tokio::test]
    async fn encrypted_ingest_cleanup_removes_plaintext_source_file() {
        let dir = TempDir::new().expect("temp dir");
        let path = dir.path().join("daily-log.md");
        tokio::fs::write(&path, "sensitive uploaded OKACAM log")
            .await
            .expect("write test source");

        remove_encrypted_ingest_source(&path)
            .await
            .expect("remove encrypted ingest source");

        assert!(!path.exists());
    }

    #[test]
    fn delete_repo_root_rejects_mismatched_repo_id() {
        let dir = TempDir::new().expect("temp dir");
        std::fs::write(dir.path().join("README.md"), "# repo\n").expect("write marker");

        let err = resolve_delete_repo_root("not-the-real-repo-id", dir.path().to_str())
            .expect_err("repo id mismatch should fail");

        assert_eq!(err.code, ERR_INVALID_ARGUMENT);
    }

    #[tokio::test]
    async fn remove_dir_all_if_exists_deletes_directory_tree() {
        let dir = TempDir::new().expect("temp dir");
        let target = dir.path().join("repo-state");
        tokio::fs::create_dir_all(target.join("index"))
            .await
            .expect("create target");
        tokio::fs::write(target.join("index").join("marker"), "indexed")
            .await
            .expect("write marker");

        assert!(remove_dir_all_if_exists(&target)
            .await
            .expect("delete target"));
        assert!(!target.exists());
    }
}
