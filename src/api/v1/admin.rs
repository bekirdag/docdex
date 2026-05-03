use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;

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
    bindings: Vec<RepoAccessBindingInput>,
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
